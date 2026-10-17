//! Store-gated integration tests for the keyring backend.
//!
//! These exercise the **real** operating system credential store, which the
//! unit tests deliberately avoid (they run against an in-crate mock). That
//! makes them environment-dependent: a container, a CI runner or an SSH session
//! usually has no session bus, no reachable keychain or no loaded user profile.
//! Each test therefore returns early when the backend reports itself unusable,
//! and the store-independent behaviour is covered by the unit tests.
//!
//! **They write real credentials.** Keys are minted under the namespace
//! `tpmd-test` and destroyed before the test returns, so nothing is left behind
//! in the user's login keychain, Secret Service collection or Credential
//! Manager.
//!
//! `TPMD_TEST_KEYRING` decides what happens when no store answers:
//!
//! | value | behaviour |
//! | --- | --- |
//! | `0` | never run these tests |
//! | `require` | run them, and **fail** if no store answers |
//! | unset / anything else | run them, self-skipping where no store answers |
//!
//! CI sets `require`, having provisioned a keyring in the first place: there, a
//! store that cannot be reached is a real failure, and a self-skip would be
//! reported as a pass. A developer's headless machine keeps the lenient default.

use p256::ecdsa::VerifyingKey;
use p256::ecdsa::signature::Verifier as _;
use std::time::Duration;
use tpmd_backend::{Backend, BackendError, Owner, Principal};
use tpmd_backend_keyring::KeyringBackend;
use tpmd_proto::{Algorithm, KeyId, SecurityLevel, Signature};

/// The namespace every key in this file is minted under.
const NAMESPACE: &str = "tpmd-test";

/// What to do when this host has no usable credential store.
#[derive(PartialEq, Eq)]
enum NoStore {
    /// Skip the test: a host may legitimately have none.
    Skip,
    /// Fail the test: a store was arranged, so one must be there.
    Fail,
}

fn no_store() -> NoStore {
    if std::env::var("TPMD_TEST_KEYRING").is_ok_and(|value| value == "require") {
        NoStore::Fail
    } else {
        NoStore::Skip
    }
}

fn owner(principal: &str) -> Owner {
    Owner::new(Principal(principal.to_owned()), NAMESPACE)
}

/// Verify with the p256 crate directly, not through tpmd's own code.
fn verify(key_id: &KeyId, message: &[u8], signature: &Signature) -> bool {
    let Ok(verifying) = VerifyingKey::from_sec1_bytes(key_id.as_bytes()) else {
        return false;
    };
    let Ok(signature) = p256::ecdsa::Signature::from_slice(signature.as_bytes()) else {
        return false;
    };
    verifying.verify(message, &signature).is_ok()
}

/// Open a backend, or return `None` when this host has no usable store.
async fn usable_backend() -> Option<(tempfile::TempDir, KeyringBackend)> {
    if std::env::var("TPMD_TEST_KEYRING").is_ok_and(|value| value == "0") {
        eprintln!("skipping: TPMD_TEST_KEYRING=0");
        return None;
    }
    let dir = tempfile::tempdir().ok()?;
    let backend = KeyringBackend::open(dir.path()).await.ok()?;
    if backend.can_be_used() {
        return Some((dir, backend));
    }
    match no_store() {
        NoStore::Fail => panic!(
            "no usable {} store on this host, and TPMD_TEST_KEYRING=require — \
             these tests are meant to have really run",
            backend.store_mechanism().unwrap_or("credential")
        ),
        NoStore::Skip => {
            eprintln!("skipping: no usable credential store on this host");
            None
        }
    }
}

#[tokio::test]
async fn a_keyring_key_signs_verifies_and_survives_a_restart() {
    let Some((dir, backend)) = usable_backend().await else {
        return;
    };
    let message = b"weaver-mux-v1 transcript bytes";

    let info = backend
        .provision(
            &owner("uid:1000"),
            Algorithm::EcdsaP256Sha256,
            SecurityLevel::Keyring,
        )
        .await
        .unwrap();
    assert_eq!(info.security_level, SecurityLevel::Keyring);

    let signature = backend
        .sign(&owner("uid:1000"), &info.key_id, message)
        .await
        .unwrap();
    assert!(
        verify(&info.key_id, message, &signature),
        "signature must verify with p256 alone"
    );

    // A new backend over the same directory is what a daemon restart looks
    // like: the metadata is re-read from SQLite, the scalar from the OS store.
    let reopened = KeyringBackend::open(dir.path()).await.unwrap();
    let found = reopened
        .identify(&owner("uid:1000"), &info.key_id)
        .await
        .unwrap();
    assert_eq!(found.key_id, info.key_id);

    let signature = reopened
        .sign(&owner("uid:1000"), &info.key_id, message)
        .await
        .unwrap();
    assert!(
        verify(&info.key_id, message, &signature),
        "the stored scalar must survive a restart"
    );

    reopened
        .destroy(&owner("uid:1000"), &info.key_id)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_keyring_key_is_scoped_to_its_principal() {
    let Some((_dir, backend)) = usable_backend().await else {
        return;
    };
    let info = backend
        .provision(
            &owner("uid:1000"),
            Algorithm::EcdsaP256Sha256,
            SecurityLevel::Keyring,
        )
        .await
        .unwrap();

    for error in [
        backend
            .identify(&owner("uid:2000"), &info.key_id)
            .await
            .unwrap_err(),
        backend
            .sign(&owner("uid:2000"), &info.key_id, b"x")
            .await
            .unwrap_err(),
    ] {
        assert!(matches!(error, BackendError::UnknownKey), "got {error}");
    }

    backend
        .destroy(&owner("uid:1000"), &info.key_id)
        .await
        .unwrap();
}

/// The point of the level: the scalar is not in the SQLite file, so destroying
/// the key really does take the private half out of the OS store, and the
/// credential is gone rather than merely unlinked.
#[tokio::test]
async fn destroy_removes_the_key_for_good() {
    let Some((_dir, backend)) = usable_backend().await else {
        return;
    };
    let info = backend
        .provision(
            &owner("uid:1000"),
            Algorithm::EcdsaP256Sha256,
            SecurityLevel::Keyring,
        )
        .await
        .unwrap();
    backend
        .destroy(&owner("uid:1000"), &info.key_id)
        .await
        .unwrap();

    assert!(matches!(
        backend.identify(&owner("uid:1000"), &info.key_id).await,
        Err(BackendError::UnknownKey)
    ));
    assert!(matches!(
        backend.destroy(&owner("uid:1000"), &info.key_id).await,
        Err(BackendError::UnknownKey)
    ));
}

/// A `sealed` floor is refused explicitly, not silently downgraded.
#[tokio::test]
async fn a_sealed_floor_is_refused() {
    let Some((_dir, backend)) = usable_backend().await else {
        return;
    };
    let error = backend
        .provision(
            &owner("uid:1000"),
            Algorithm::EcdsaP256Sha256,
            SecurityLevel::Sealed,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, BackendError::IncompatiblePolicy { .. }));
}

#[tokio::test]
async fn the_backend_names_the_store_it_uses() {
    let Some((_dir, backend)) = usable_backend().await else {
        return;
    };
    let mechanism = backend.store_mechanism().unwrap();
    assert!(
        ["secret-service", "login-keychain", "credential-manager"].contains(&mechanism),
        "unexpected mechanism {mechanism}"
    );
    assert_eq!(backend.name(), "keyring");
}

/// **Experiment**: does the bus actually wake us, or are we only ever saved by
/// the safety net?
///
/// Writing a credential changes the default collection, which should show up as a
/// signal on the bus. The bound here is *below* the safety net, so passing means
/// a real signal arrived. Failing does not mean the provider is broken — it means
/// this store does not announce writes, and the unlock case is the one to verify
/// on a machine where the collection can be locked and unlocked.
#[tokio::test]
async fn the_bus_wakes_us_for_a_real_change() {
    let Some((_dir, backend)) = usable_backend().await else {
        return;
    };
    let Some(hints) = backend.unlock_hints() else {
        return;
    };

    // Wait for a hint while something real happens to the store.
    let waiting = tokio::spawn(async move {
        let started = std::time::Instant::now();
        hints.next_hint().await;
        started.elapsed()
    });

    // Give the subscription a moment to be established, then write.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let info = backend
        .provision(
            &owner("uid:1000"),
            Algorithm::EcdsaP256Sha256,
            SecurityLevel::Keyring,
        )
        .await
        .unwrap();

    let elapsed = waiting.await.unwrap();
    backend
        .destroy(&owner("uid:1000"), &info.key_id)
        .await
        .unwrap();

    eprintln!("hint arrived after {elapsed:?}");
    assert!(
        elapsed < Duration::from_secs(4),
        "expected a bus signal well before the safety net, waited {elapsed:?}"
    );
}
/// A hint must always arrive, however long it takes.
///
/// This is the one property the whole closed-store design leans on: a provider
/// that never fires would park a client for ever, and "wait for ever" is exactly
/// the failure the `closed`/`gone` distinction exists to avoid. The bound here is
/// generous — a bus signal should arrive in milliseconds and the safety net is
/// seconds — and what it catches is a subscription that neither signals nor falls
/// back.
#[tokio::test]
async fn a_hint_always_arrives() {
    let Some((_dir, backend)) = usable_backend().await else {
        return;
    };
    let Some(hints) = backend.unlock_hints() else {
        panic!("a store that can be locked must be able to say when it reopens");
    };
    let arrived = tokio::time::timeout(Duration::from_secs(30), hints.next_hint()).await;
    assert!(arrived.is_ok(), "a hint must eventually arrive");
}
