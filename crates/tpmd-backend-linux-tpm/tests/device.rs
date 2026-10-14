//! Device-gated integration tests for the Linux TPM backend.
//!
//! These need a real TPM and enough privilege to open it (`/dev/tpmrm*` is
//! `tss:tss 0660`, so an unprivileged caller is refused). GitHub runners have
//! no TPM, so each test returns early when the backend reports itself
//! unusable; the marshalling and store behaviour is covered by device-free
//! tests elsewhere.
//!
//! Run locally with rights to the device, e.g.
//! `sudo ./target/debug/deps/device-<hash>`.

#![cfg(target_os = "linux")]

use p256::ecdsa::VerifyingKey;
use p256::ecdsa::signature::Verifier as _;
use tpmd_backend::{Backend, BackendError, Owner, Principal};
use tpmd_backend_linux_tpm::{DEVICE_ENV, LinuxTpmBackend};
use tpmd_proto::{Algorithm, KeyId, SecurityLevel, Signature};

/// The Tunnel Weaver handshake transcript the WVR-141 proof signs.
fn transcript() -> Vec<u8> {
    let mut transcript = b"weaver-mux-v1".to_vec();
    transcript.extend(std::iter::repeat_n(1u8, 32));
    transcript.extend(std::iter::repeat_n(2u8, 32));
    transcript.extend_from_slice(b"example.com");
    transcript
}

fn owner() -> Owner {
    Owner::new(Principal("uid:0".to_owned()), "tpmd-test")
}

fn other_owner() -> Owner {
    Owner::new(Principal("uid:1000".to_owned()), "tpmd-test")
}

/// Verify with the p256 crate directly, not through tpmd's own code.
fn verify(key_id: &KeyId, message: &[u8], signature: &Signature) -> bool {
    let Ok(verifying) = VerifyingKey::from_sec1_bytes(key_id.as_bytes()) else {
        return false;
    };
    let Ok(sig) = p256::ecdsa::Signature::from_slice(signature.as_bytes()) else {
        return false;
    };
    verifying.verify(message, &sig).is_ok()
}

/// Open a backend, or return `None` when this host has no usable TPM.
async fn usable_backend() -> Option<(tempfile::TempDir, LinuxTpmBackend)> {
    let dir = tempfile::tempdir().ok()?;
    let backend = LinuxTpmBackend::open(dir.path()).await.ok()?;
    if !backend.can_be_used() {
        eprintln!("skipping: no usable TPM device (override with {DEVICE_ENV})");
        return None;
    }
    Some((dir, backend))
}

#[tokio::test]
async fn hardware_key_signs_verifies_and_survives_a_restart() {
    let Some((dir, backend)) = usable_backend().await else {
        return;
    };

    let info = backend
        .provision(
            &owner(),
            Algorithm::EcdsaP256Sha256,
            SecurityLevel::Hardware,
        )
        .await
        .unwrap();
    assert_eq!(info.security_level, SecurityLevel::Hardware);
    assert_eq!(info.key_id.as_bytes().len(), 33);
    assert_eq!(info.key_id.as_bytes()[0] & 0xfe, 0x02, "SEC1 compressed");

    let message = transcript();
    let signature = backend
        .sign(&owner(), &info.key_id, &message)
        .await
        .unwrap();
    assert!(verify(&info.key_id, &message, &signature));

    // Negative controls: a mutated transcript and a mutated signature both fail.
    assert!(!verify(&info.key_id, b"mutated transcript", &signature));
    let mut mutated = [0u8; 64];
    mutated.copy_from_slice(signature.as_bytes());
    mutated[10] ^= 0x01;
    assert!(!verify(&info.key_id, &message, &Signature::P256(mutated)));

    // A fresh process reopening the store resumes the same identity, because
    // the storage parent is deterministic.
    let reopened = LinuxTpmBackend::open(dir.path()).await.unwrap();
    let resumed = reopened.identify(&owner(), &info.key_id).await.unwrap();
    assert_eq!(resumed.key_id, info.key_id);
    assert_eq!(resumed.security_level, SecurityLevel::Hardware);
    let again = reopened
        .sign(&owner(), &info.key_id, &message)
        .await
        .unwrap();
    assert!(verify(&info.key_id, &message, &again));
}

#[tokio::test]
async fn sealed_key_signs_verifies_and_survives_a_restart() {
    let Some((dir, backend)) = usable_backend().await else {
        return;
    };

    let info = backend
        .provision(&owner(), Algorithm::EcdsaP256Sha256, SecurityLevel::Sealed)
        .await
        .unwrap();
    assert_eq!(info.security_level, SecurityLevel::Sealed);

    let message = transcript();
    let signature = backend
        .sign(&owner(), &info.key_id, &message)
        .await
        .unwrap();
    assert!(verify(&info.key_id, &message, &signature));
    assert!(!verify(&info.key_id, b"mutated transcript", &signature));

    let reopened = LinuxTpmBackend::open(dir.path()).await.unwrap();
    let again = reopened
        .sign(&owner(), &info.key_id, &message)
        .await
        .unwrap();
    assert!(verify(&info.key_id, &message, &again));
}

#[tokio::test]
async fn keys_are_scoped_to_the_principal() {
    let Some((_dir, backend)) = usable_backend().await else {
        return;
    };

    let info = backend
        .provision(
            &owner(),
            Algorithm::EcdsaP256Sha256,
            SecurityLevel::Hardware,
        )
        .await
        .unwrap();

    // Another principal knowing the fingerprint learns nothing.
    assert!(matches!(
        backend.identify(&other_owner(), &info.key_id).await,
        Err(BackendError::UnknownKey)
    ));
    assert!(matches!(
        backend.sign(&other_owner(), &info.key_id, b"x").await,
        Err(BackendError::UnknownKey)
    ));
}

#[tokio::test]
async fn an_unsupported_level_is_refused_not_downgraded() {
    let Some((_dir, backend)) = usable_backend().await else {
        return;
    };

    let error = backend
        .provision(&owner(), Algorithm::EcdsaP256Sha256, SecurityLevel::File)
        .await
        .unwrap_err();
    match error {
        BackendError::IncompatiblePolicy {
            required,
            available,
        } => {
            assert_eq!(required, SecurityLevel::File);
            assert_eq!(available, SecurityLevel::Hardware);
        }
        other => panic!("expected an incompatible-policy refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn destroy_removes_and_then_reports_unknown() {
    let Some((_dir, backend)) = usable_backend().await else {
        return;
    };

    let info = backend
        .provision(
            &owner(),
            Algorithm::EcdsaP256Sha256,
            SecurityLevel::Hardware,
        )
        .await
        .unwrap();
    backend.destroy(&owner(), &info.key_id).await.unwrap();
    assert!(matches!(
        backend.identify(&owner(), &info.key_id).await,
        Err(BackendError::UnknownKey)
    ));
}
