//! Device-gated integration tests for the Windows CNG backend.
//!
//! These need a live TPM 2.0 **and** a logon that can create a Platform Crypto
//! Provider *user* key. GitHub's `windows-latest` runner has neither, so every
//! test returns early when the backend reports itself unusable — the probe in
//! `open()` is what decides, and the ticket requires that to be verified rather
//! than assumed precisely because a network logon (WinRM) opens the provider
//! and is then refused at key creation.
//!
//! On the rig, run them from the user's interactive session (a scheduled task
//! with `/IT`), not over WinRM.

#![cfg(target_os = "windows")]

use p256::ecdsa::VerifyingKey;
use p256::ecdsa::signature::Verifier as _;
use tpmd_backend::{Backend, BackendError, Owner, Principal};
use tpmd_backend_windows_cng::WindowsCngBackend;
use tpmd_proto::{Algorithm, KeyId, SecurityLevel, Signature};

/// The Tunnel Weaver handshake transcript every platform signs identically.
fn transcript() -> Vec<u8> {
    let mut transcript = b"weaver-mux-v1".to_vec();
    transcript.extend(std::iter::repeat_n(1u8, 32));
    transcript.extend(std::iter::repeat_n(2u8, 32));
    transcript.extend_from_slice(b"example.com");
    transcript
}

fn owner() -> Owner {
    Owner::new(Principal("S-1-5-21-tpmd-test".to_owned()), "tpmd-test")
}

fn other_owner() -> Owner {
    Owner::new(Principal("S-1-5-21-tpmd-other".to_owned()), "tpmd-test")
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

/// Open a backend, or `None` when this host cannot hold a hardware key.
async fn usable_backend() -> Option<(tempfile::TempDir, WindowsCngBackend)> {
    let dir = tempfile::tempdir().ok()?;
    let backend = WindowsCngBackend::open(dir.path()).await.ok()?;
    if !backend.can_be_used() {
        eprintln!(
            "skipping: no usable Platform Crypto Provider user key custody here \
             (needs a TPM 2.0 and an interactive logon)"
        );
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

    // Negative controls: a mutated transcript and a mutated signature fail.
    assert!(!verify(&info.key_id, b"mutated transcript", &signature));
    let mut mutated = [0u8; 64];
    mutated.copy_from_slice(signature.as_bytes());
    mutated[10] ^= 0x01;
    assert!(!verify(&info.key_id, &message, &Signature::P256(mutated)));

    // A second backend over the same store (i.e. a daemon restart) resumes the
    // same identity: the private key lives in the user's CNG store, not in the
    // process.
    let reopened = WindowsCngBackend::open(dir.path()).await.unwrap();
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
async fn two_signatures_over_the_same_digest_differ() {
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
    let message = transcript();
    let first = backend
        .sign(&owner(), &info.key_id, &message)
        .await
        .unwrap();
    let second = backend
        .sign(&owner(), &info.key_id, &message)
        .await
        .unwrap();

    // ECDSA in the TPM draws a fresh nonce, so unlike a software (RFC 6979)
    // signer the two signatures differ — and both still verify.
    assert_ne!(first, second);
    assert!(verify(&info.key_id, &message, &first));
    assert!(verify(&info.key_id, &message, &second));
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
async fn lower_levels_are_refused_not_downgraded() {
    let Some((_dir, backend)) = usable_backend().await else {
        return;
    };

    // This backend offers `hardware` only; asking for a weaker level is a
    // mismatch, and asking for a *stronger* one is impossible, so both must be
    // refused rather than silently satisfied.
    for level in [SecurityLevel::File, SecurityLevel::Sealed] {
        let error = backend
            .provision(&owner(), Algorithm::EcdsaP256Sha256, level)
            .await
            .unwrap_err();
        match error {
            BackendError::IncompatiblePolicy {
                required,
                available,
            } => {
                assert_eq!(required, level);
                assert_eq!(available, SecurityLevel::Hardware);
            }
            other => panic!("expected an incompatible-policy refusal, got {other:?}"),
        }
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
