//! Device-gated integration tests for the macOS Secure Enclave backend.
//!
//! These need the real thing: a process running **from a signed bundle, in the
//! Aqua session**, whose bundle identifier the team has provisioned. GitHub's
//! `macos-latest` runners have none of that, so every test returns early when the
//! backend reports itself unusable — which is exactly the state its startup probe
//! exists to detect, and precisely why that probe stores a key instead of merely
//! generating one: an *ephemeral* enclave key is created happily over SSH, while
//! keeping one is refused.
//!
//! On the rig, run them through a LaunchAgent (`packaging/macos/scripts/validate-agent.sh`)
//! with `TPMD_TEST_SE=require`, which turns a skip into a failure — the difference
//! between "this host has no enclave" and "these tests were supposed to have run".

#![cfg(target_os = "macos")]

use p256::ecdsa::VerifyingKey;
use p256::ecdsa::signature::Verifier as _;
use tpmd_backend::{Backend, BackendError, Owner, Principal};
use tpmd_backend_macos_se::SecureEnclaveBackend;
use tpmd_proto::{Algorithm, KeyId, SecurityLevel, Signature};

/// What to do when this process cannot reach the enclave.
enum NoEnclave {
    /// Skip the test: a host may legitimately not have one.
    Skip,
    /// Fail the test: an enclave was arranged, so there had better be one.
    Fail,
}

fn no_enclave() -> NoEnclave {
    if std::env::var("TPMD_TEST_SE").is_ok_and(|value| value == "require") {
        NoEnclave::Fail
    } else {
        NoEnclave::Skip
    }
}

/// The Tunnel Weaver handshake transcript every platform signs identically.
fn transcript() -> Vec<u8> {
    let mut transcript = b"weaver-mux-v1".to_vec();
    transcript.extend(std::iter::repeat_n(1u8, 32));
    transcript.extend(std::iter::repeat_n(2u8, 32));
    transcript.extend_from_slice(b"example.com");
    transcript
}

fn owner(principal: &str) -> Owner {
    Owner::new(Principal(principal.to_owned()), "tpmd-test")
}

/// Verify with the `p256` crate directly, not through tpmd's own code.
///
/// `verify` hashes the message with SHA-256 first, which is what makes this an
/// independent check of the wire contract: the backend signs the digest of these
/// bytes, so the verifier must arrive at exactly the same digest.
fn verify(key_id: &KeyId, message: &[u8], signature: &Signature) -> bool {
    let Ok(verifying) = VerifyingKey::from_sec1_bytes(key_id.as_bytes()) else {
        return false;
    };
    let Ok(signature) = p256::ecdsa::Signature::from_slice(signature.as_bytes()) else {
        return false;
    };
    verifying.verify(message, &signature).is_ok()
}

/// Open a backend, or return `None` when this process cannot reach the enclave.
async fn usable_backend() -> Option<(tempfile::TempDir, SecureEnclaveBackend)> {
    if std::env::var("TPMD_TEST_SE").is_ok_and(|value| value == "0") {
        eprintln!("skipping: TPMD_TEST_SE=0");
        return None;
    }
    let dir = tempfile::tempdir().ok()?;
    let backend = SecureEnclaveBackend::open(dir.path()).await.ok()?;
    if backend.can_be_used() {
        return Some((dir, backend));
    }
    match no_enclave() {
        NoEnclave::Fail => panic!(
            "no usable Secure Enclave here, and TPMD_TEST_SE=require — these tests \
             are meant to have really run. Is this process running from a signed \
             bundle, in the Aqua session, under a provisioned identifier?"
        ),
        NoEnclave::Skip => {
            eprintln!(
                "skipping: the Secure Enclave is not reachable from this process \
                 ({}); device tests need a signed bundle in the Aqua session",
                backend.store_mechanism().unwrap_or("no mechanism")
            );
            None
        }
    }
}

#[tokio::test]
async fn an_enclave_key_signs_verifies_and_survives_a_restart() {
    let Some((dir, backend)) = usable_backend().await else {
        return;
    };
    let owner = owner("uid:501");

    let info = backend
        .provision(&owner, Algorithm::EcdsaP256Sha256, SecurityLevel::Hardware)
        .await
        .expect("an enclave key");
    assert_eq!(info.security_level, SecurityLevel::Hardware);
    assert_eq!(info.key_id.as_bytes().len(), 33, "SEC1 compressed");

    let message = transcript();
    let signature = backend
        .sign(&owner, &info.key_id, &message)
        .await
        .expect("a signature");
    assert!(
        verify(&info.key_id, &message, &signature),
        "an independently verified signature"
    );
    assert_eq!(signature.as_bytes().len(), 64, "raw r || s");

    // The restart story: a fresh backend over the same store and the same
    // keychain must find the key again — which is what the recorded label is for.
    let restarted = SecureEnclaveBackend::open(dir.path())
        .await
        .expect("the store reopens");
    let identified = restarted
        .identify(&owner, &info.key_id)
        .await
        .expect("the key survives a restart");
    assert_eq!(identified.key_id, info.key_id);
    assert_eq!(identified.created_unix, info.created_unix);
    let again = restarted
        .sign(&owner, &info.key_id, &message)
        .await
        .expect("it signs after the restart");
    assert!(verify(&info.key_id, &message, &again));

    restarted
        .destroy(&owner, &info.key_id)
        .await
        .expect("destroy");
    assert!(matches!(
        restarted.identify(&owner, &info.key_id).await,
        Err(BackendError::UnknownKey)
    ));
    assert!(matches!(
        restarted.sign(&owner, &info.key_id, &message).await,
        Err(BackendError::UnknownKey)
    ));
}

#[tokio::test]
async fn a_mutated_transcript_or_signature_does_not_verify() {
    let Some((_dir, backend)) = usable_backend().await else {
        return;
    };
    let owner = owner("uid:501");

    let info = backend
        .provision(&owner, Algorithm::EcdsaP256Sha256, SecurityLevel::Hardware)
        .await
        .expect("an enclave key");
    let message = transcript();
    let signature = backend
        .sign(&owner, &info.key_id, &message)
        .await
        .expect("a signature");

    let mut other_message = message.clone();
    other_message[0] ^= 0x01;
    assert!(
        !verify(&info.key_id, &other_message, &signature),
        "a signature must not travel to another transcript"
    );

    let mut other_bytes = [0u8; 64];
    other_bytes.copy_from_slice(signature.as_bytes());
    other_bytes[0] ^= 0x01;
    assert!(
        !verify(&info.key_id, &message, &Signature::P256(other_bytes)),
        "a mutated signature must not verify"
    );

    backend.destroy(&owner, &info.key_id).await.ok();
}

#[tokio::test]
async fn another_principal_cannot_reach_the_key() {
    let Some((_dir, backend)) = usable_backend().await else {
        return;
    };
    let principal = owner("uid:501");
    let stranger = owner("uid:502");

    let info = backend
        .provision(
            &principal,
            Algorithm::EcdsaP256Sha256,
            SecurityLevel::Hardware,
        )
        .await
        .expect("an enclave key");

    // Keys are addressed by (principal, namespace, fingerprint) and never
    // enumerated, so another principal's key is indistinguishable from one that
    // does not exist — which is the point.
    assert!(matches!(
        backend.identify(&stranger, &info.key_id).await,
        Err(BackendError::UnknownKey)
    ));
    assert!(matches!(
        backend.sign(&stranger, &info.key_id, &transcript()).await,
        Err(BackendError::UnknownKey)
    ));
    assert!(matches!(
        backend.destroy(&stranger, &info.key_id).await,
        Err(BackendError::UnknownKey)
    ));

    backend.destroy(&principal, &info.key_id).await.ok();
}

#[tokio::test]
async fn a_level_this_backend_cannot_reach_is_refused() {
    let Some((_dir, backend)) = usable_backend().await else {
        return;
    };
    let owner = owner("uid:501");

    // macOS has no `sealed` rung, so asking for one must be refused by name
    // rather than quietly answered with hardware.
    match backend
        .provision(&owner, Algorithm::EcdsaP256Sha256, SecurityLevel::Sealed)
        .await
    {
        Err(BackendError::IncompatiblePolicy {
            required,
            available,
        }) => {
            assert_eq!(required, SecurityLevel::Sealed);
            assert_eq!(available, SecurityLevel::Hardware);
        }
        other => panic!("expected a policy refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn each_key_is_its_own_identity() {
    let Some((_dir, backend)) = usable_backend().await else {
        return;
    };
    let owner = owner("uid:501");

    let first = backend
        .provision(&owner, Algorithm::EcdsaP256Sha256, SecurityLevel::Hardware)
        .await
        .expect("a first key");
    let second = backend
        .provision(&owner, Algorithm::EcdsaP256Sha256, SecurityLevel::Hardware)
        .await
        .expect("a second key");

    assert_ne!(
        first.key_id, second.key_id,
        "two keys are two identities, not one reused label"
    );
    // And they sign differently, so the fingerprints are not two views of one key.
    let message = transcript();
    let a = backend.sign(&owner, &first.key_id, &message).await.unwrap();
    let b = backend
        .sign(&owner, &second.key_id, &message)
        .await
        .unwrap();
    assert!(verify(&first.key_id, &message, &a));
    assert!(verify(&second.key_id, &message, &b));
    assert!(
        !verify(&first.key_id, &message, &b),
        "one key's signature must not verify under the other"
    );

    backend.destroy(&owner, &first.key_id).await.ok();
    backend.destroy(&owner, &second.key_id).await.ok();
}
