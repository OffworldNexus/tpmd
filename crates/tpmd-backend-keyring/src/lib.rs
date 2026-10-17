//! The keyring backend: software P-256 keys in the operating system's own
//! credential store.
//!
//! This is the rung above [`SecurityLevel::File`] and below the hardware
//! backends. The scalar is still used in software — signing happens here — but
//! it is *stored* in the store every platform already has and already protects
//! with the user's own login credentials, rather than in a plaintext SQLite
//! file. That is exactly what [`SecurityLevel::Keyring`] claims, and this
//! backend never claims more: it advertises `keyring` and nothing stronger.
//!
//! | OS      | Store                                |
//! | ------- | ------------------------------------ |
//! | Linux   | Secret Service on the session bus     |
//! | macOS   | the login keychain (Aqua session)     |
//! | Windows | Credential Manager (loaded profile)   |
//!
//! Three properties are load-bearing:
//!
//! * **Ownership before storage.** `(principal, namespace, key_id)` is resolved
//!   against the `keyring_keys` table *first*; the credential store is only
//!   touched once the caller is known to own the key. A foreign key and a key
//!   that does not exist are therefore the same answer, and the store never
//!   learns that someone asked about a key that is not theirs.
//! * **The store is never assumed reachable.** A store that cannot answer
//!   surfaces as `store_locked`, never as a missing key, and the daemon's
//!   selection can skip this backend entirely when the store is absent.
//! * **Never weaken silently.** A request to provision at any level other than
//!   `keyring` is refused rather than downgraded.
//!
//! The storage itself (schema, migrations, file protection) lives in
//! `tpmd-store`, because every backend shares one file.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod address;
mod error;
mod store;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use keyring_core::{CredentialStore, Error as KeyringError};
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer as _;
use p256::elliptic_curve::sec1::ToSec1Point as _;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, Set};
use tpmd_backend::{Backend, BackendError, Owner};
use tpmd_proto::{Algorithm, KeyId, KeyInfo, SecurityLevel, Signature};
use tpmd_store::entities::keyring_keys;
use tpmd_store::map_db_error;
use tracing::warn;
use zeroize::Zeroize as _;

/// The only security level this backend can achieve.
const LEVELS: &[SecurityLevel] = &[SecurityLevel::Keyring];

/// The only algorithm this backend can offer.
const ALGORITHMS: &[Algorithm] = &[Algorithm::EcdsaP256Sha256];

/// Serialises every credential-store call in the process.
///
/// The stores are the opposite of concurrent-safe: the Windows store documents
/// that operating on one entry from several threads does not reliably sequence
/// the operations, and the Secret Service store warns about the same. The
/// daemon serves connections concurrently and two of them may well name the
/// same key, so the serialisation has to be here rather than per connection.
///
/// It is taken on the calling side, in [`on_store_thread`], and never around a
/// nested store call, because a `std::sync::Mutex` does not re-enter.
static STORE_LOCK: Mutex<()> = Mutex::new(());

/// Whether this backend can reach its store.
///
/// Probed once, at open time, because the question is blocking and the answer
/// cannot improve mid-run: a daemon started without a session bus will not grow
/// one.
enum Access {
    /// The store answered a probe; operations may proceed.
    Ready(&'static CredentialStore),
    /// The store could not be reached. Every operation reports `store_locked`,
    /// which is what a host with no session bus, no reachable keychain or no
    /// loaded profile should see — and it is also why forcing this backend with
    /// `--backend keyring` still produces a useful answer instead of a
    /// selection error.
    Unavailable(String),
}

/// Keep a store alive for the rest of the process.
///
/// The store is never dropped, deliberately. The Linux store disconnects on
/// `Drop` by calling `block_on` on a runtime of its own (`zbus`'s blocking
/// API), and that panics on any thread that already has a runtime context —
/// which is every thread the daemon does async work on. Dropping it elsewhere
/// would mean tracking every clone's last reference; not dropping it at all
/// means one session-bus connection, which the daemon holds for its whole life
/// anyway and which the process exit closes.
fn keep_alive(store: Arc<CredentialStore>) -> &'static CredentialStore {
    let kept: &'static Arc<CredentialStore> = Box::leak(Box::new(store));
    &**kept
}

/// A software P-256 store whose scalars live in the OS credential store.
///
/// Key *metadata* stays in the shared SQLite file, next to every other
/// backend's, because it is not secret and because the ownership lookup has to
/// happen before the credential store is touched. Only the scalar itself — the
/// `key_name` entry — lives in the OS store.
pub struct KeyringBackend {
    db: DatabaseConnection,
    db_path: PathBuf,
    access: Access,
}

impl KeyringBackend {
    /// Open the backend, probing the platform credential store.
    ///
    /// Succeeds even when the store is unreachable: the backend then exists and
    /// answers `store_locked`, rather than failing to construct. Refusing here
    /// instead would collapse "this host has no keyring" into "this build has
    /// no keyring backend", which are very different things to a user.
    pub async fn open(state_dir: &Path) -> Result<Self, BackendError> {
        let db = tpmd_store::open(state_dir).await?;
        let access = open_store().await;
        Ok(Self {
            db,
            db_path: tpmd_store::database_path(state_dir),
            access,
        })
    }

    /// The database path, for diagnostics.
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// The store, or the reason there is none.
    fn store(&self) -> Result<&'static CredentialStore, BackendError> {
        match &self.access {
            Access::Ready(store) => Ok(*store),
            Access::Unavailable(why) => Err(BackendError::StoreLocked(why.clone())),
        }
    }
}

/// Run `call` on a thread that carries **no** async runtime context, and await
/// its result.
///
/// The stores are synchronous, so they must not run on the executor — but
/// `tokio::task::spawn_blocking` is *also* unusable, and for a subtler reason:
/// Tokio enters the runtime context on its blocking threads, and the Linux
/// store reaches the session bus through zbus's blocking API, which builds a
/// static runtime of its own and calls `block_on` on it. `Runtime::block_on`
/// panics when a runtime context is already entered, which is exactly what a
/// `spawn_blocking` thread has. A plain OS thread has none, so this is where
/// store calls go.
///
/// The store lock is taken on the worker thread, so every store call in the
/// process is serialised. Nothing here may call back into a store operation:
/// the lock does not re-enter.
async fn on_store_thread<T, F>(call: F) -> Result<T, BackendError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, BackendError> + Send + 'static,
{
    let (sender, receiver) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let _guard = STORE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // A send failure means the awaiting side went away, which is fine: the
        // call has already happened and its effect stands either way.
        let _ = sender.send(call());
    });
    receiver
        .await
        .map_err(|_| BackendError::Internal("the credential store thread went away".into()))?
}

/// Build the platform store and ask it whether it can answer.
async fn open_store() -> Access {
    match on_store_thread(probe_store).await {
        Ok(store) => Access::Ready(store),
        Err(error) => Access::Unavailable(error.to_string()),
    }
}

/// The store, or the reason it cannot serve.
///
/// A store that cannot be **built** and a store that will not **answer** are
/// both `store_locked` here: from the caller's point of view the storage that
/// holds the keys is not reachable right now, which is the class the protocol
/// reserves for exactly this and which a retry may clear.
fn probe_store() -> Result<&'static CredentialStore, BackendError> {
    match store::platform_store() {
        Err(error) => Err(error),
        // A store that answered is kept for the life of the process, so it is
        // never dropped on a thread whose `Drop` would panic.
        Ok(store) if store::probe(store.as_ref()) => Ok(keep_alive(store)),
        Ok(_) => Err(BackendError::StoreLocked(format!(
            "the {} store does not answer on this host",
            store::mechanism()
        ))),
    }
}

/// Run one credential-store call, serialised against every other call.
async fn with_store<T, F>(store: &'static CredentialStore, call: F) -> Result<T, BackendError>
where
    T: Send + 'static,
    F: FnOnce(&CredentialStore) -> Result<T, BackendError> + Send + 'static,
{
    on_store_thread(move || call(store)).await
}

/// Build the entry for `key_name` in the credential store.
///
/// `modifiers` are applied when the entry is created; reading and deleting ignore
/// them, so those paths pass an empty slice. Creation goes through
/// [`write_secret`], which walks the platform's list of attempts.
fn entry_for(
    store: &CredentialStore,
    key_name: &str,
    modifiers: &[(&str, &str)],
) -> Result<keyring_core::Entry, BackendError> {
    build_entry(store, key_name, modifiers)
}

/// Ask the store for an entry with `modifiers`, falling back to asking without
/// them when the store does not take any.
///
/// The fallback is not a convenience: the mock store the unit tests run against
/// rejects every modifier, and a future platform store may implement none, and
/// neither should make the backend unusable over a modifier that exists only to
/// pin down Windows persistence.
fn build_entry(
    store: &CredentialStore,
    key_name: &str,
    modifiers: &[(&str, &str)],
) -> Result<keyring_core::Entry, BackendError> {
    let map: HashMap<&str, &str> = modifiers.iter().copied().collect();
    let borrowed = (!map.is_empty()).then_some(&map);
    let build = |modifiers| store.build(store::SERVICE, key_name, modifiers);
    match build(borrowed) {
        Err(KeyringError::NotSupportedByStore(_)) if borrowed.is_some() => build(None),
        result => result,
    }
    .map_err(|error| error::map_store_error("opening the credential", error))
}

/// Whether a refused write is worth trying again with weaker persistence.
///
/// Only the "the store would not take it" classes: a key name that is too long,
/// a corrupt store, or a store that cannot answer at all will not do any better
/// on the second attempt, and retrying those would only double the latency
/// before the same failure.
fn worth_weakening(error: &BackendError) -> bool {
    matches!(
        error,
        BackendError::StoreLocked(_) | BackendError::Unavailable(_)
    )
}

/// Write `secret` to `key_name`, trying each persistence attempt in order.
///
/// Creation is the only operation that has a persistence to choose, which is why
/// the retry lives here rather than in [`entry_for`]. Weakening is logged, never
/// silent: the difference between the attempts is whether the key outlives the
/// logon session, and that is the user's business.
async fn write_secret(
    store: &'static CredentialStore,
    key_name: String,
    secret: String,
    attempts: Vec<Vec<(&'static str, &'static str)>>,
) -> Result<(), BackendError> {
    let last = attempts.len();
    for (index, modifiers) in attempts.into_iter().enumerate() {
        let outcome = with_store(store, {
            let key_name = key_name.clone();
            let secret = secret.clone();
            move |store| {
                let mut secret = secret;
                let result = entry_for(store, &key_name, &modifiers)?
                    .set_password(&secret)
                    .map_err(|error| error::map_store_error("writing the credential", error));
                secret.zeroize();
                result
            }
        })
        .await;

        match outcome {
            Ok(()) => return Ok(()),
            Err(error) => {
                let is_last = index + 1 == last;
                if is_last || !worth_weakening(&error) {
                    return Err(error);
                }
                warn!(
                    backend = "keyring",
                    attempt = index + 1,
                    of = last,
                    rejected = %error,
                    "credential store refused this persistence; retrying weaker"
                );
            }
        }
    }
    Err(BackendError::Internal(
        "no credential persistence attempts were configured".into(),
    ))
}

/// Read the stored scalar for `key_name`, as the hex text it was written as.
async fn read_scalar(
    store: &'static CredentialStore,
    key_name: String,
) -> Result<String, BackendError> {
    with_store(store, move |store| {
        entry_for(store, &key_name, &[])?
            .get_password()
            .map_err(|error| error::map_store_error("reading the credential", error))
    })
    .await
}

/// Remove the credential for `key_name` from the store.
async fn delete_credential(
    store: &'static CredentialStore,
    key_name: String,
) -> Result<(), BackendError> {
    with_store(store, move |store| {
        entry_for(store, &key_name, &[])?
            .delete_credential()
            .map_err(|error| error::map_store_error("deleting the credential", error))
    })
    .await
}

/// The composite primary key of a key row.
fn row_id(owner: &Owner, key_id: &KeyId) -> (String, String, Vec<u8>) {
    (
        owner.principal.as_str().to_owned(),
        owner.namespace.clone(),
        key_id.as_bytes().to_vec(),
    )
}

#[async_trait]
impl Backend for KeyringBackend {
    fn name(&self) -> &'static str {
        "keyring"
    }

    fn algorithms(&self) -> &'static [Algorithm] {
        ALGORITHMS
    }

    fn levels(&self) -> &'static [SecurityLevel] {
        LEVELS
    }

    /// True only where the store answered at open time.
    ///
    /// Selection therefore skips this backend on a host with no reachable
    /// store and falls to the next rung, rather than serving a backend whose
    /// every operation would fail.
    fn can_be_used(&self) -> bool {
        matches!(self.access, Access::Ready(_))
    }

    /// The store this build talks to, for `tpmd status` and the logs.
    fn store_mechanism(&self) -> Option<&'static str> {
        Some(store::mechanism())
    }

    /// Forcing this backend is honoured even when the store is unreachable.
    ///
    /// `--backend keyring` is an explicit request to be told what is wrong with
    /// the keyring on this host; answering `store_locked` is more useful than
    /// refusing to start.
    fn forced_when_unusable(&self) -> bool {
        true
    }

    async fn provision(
        &self,
        owner: &Owner,
        algorithm: Algorithm,
        level: SecurityLevel,
    ) -> Result<KeyInfo, BackendError> {
        if algorithm != Algorithm::EcdsaP256Sha256 {
            return Err(BackendError::UnsupportedAlgorithm(algorithm));
        }
        if level != SecurityLevel::Keyring {
            // The daemon only ever passes a level this backend advertised, so
            // reaching here means a genuine mismatch. Refuse rather than
            // silently weaken.
            return Err(BackendError::IncompatiblePolicy {
                required: level,
                available: SecurityLevel::Keyring,
            });
        }

        let store = self.store()?;
        let (mut secret, key_id) = generate_key()?;
        let key_name = address::entry_address(owner, &key_id);
        let created_unix = now_unix();
        // Hex text rather than raw bytes: the Secret Service implementation
        // some desktops ship (KDE Wallet) is UTF-8 only, so an arbitrary binary
        // secret cannot be written through it. Hex is ASCII, so it survives
        // every store.
        let mut encoded = hex::encode(secret);
        secret.zeroize();

        write_secret(
            store,
            key_name.clone(),
            encoded.clone(),
            store::entry_modifier_attempts(),
        )
        .await?;
        encoded.zeroize();

        let (principal, namespace, id) = row_id(owner, &key_id);
        let row = keyring_keys::ActiveModel {
            principal: Set(principal),
            namespace: Set(namespace),
            key_id: Set(id),
            algorithm: Set(algorithm_index(algorithm)),
            level: Set(level_index(level)),
            key_name: Set(key_name.clone()),
            created_unix: Set(created_unix),
        };
        if let Err(error) = row
            .insert(&self.db)
            .await
            .map_err(|error| map_db_error("recording key", error))
        {
            // The credential is written but unrecorded, so it could never be
            // found again and would hold a live scalar. Undo it; if that fails
            // too, the original error is still the useful one to report.
            let _ = delete_credential(store, key_name).await;
            return Err(error);
        }

        Ok(KeyInfo {
            key_id,
            algorithm,
            security_level: level,
            created_unix,
        })
    }

    async fn identify(&self, owner: &Owner, key_id: &KeyId) -> Result<KeyInfo, BackendError> {
        // Ownership first: a foreign or unknown key never reaches the store.
        let store = self.store()?;
        let row = keyring_keys::Entity::find_by_id(row_id(owner, key_id))
            .one(&self.db)
            .await
            .map_err(|error| map_db_error("querying key", error))?
            .ok_or(BackendError::UnknownKey)?;

        // Then prove the credential is still there, so a key the OS store has
        // lost is reported as lost rather than as present.
        read_scalar(store, row.key_name.clone()).await?;

        Ok(KeyInfo {
            key_id: *key_id,
            algorithm: algorithm_from_index(row.algorithm)?,
            security_level: level_from_index(row.level)?,
            created_unix: row.created_unix,
        })
    }

    async fn sign(
        &self,
        owner: &Owner,
        key_id: &KeyId,
        message: &[u8],
    ) -> Result<Signature, BackendError> {
        let store = self.store()?;
        let row = keyring_keys::Entity::find_by_id(row_id(owner, key_id))
            .one(&self.db)
            .await
            .map_err(|error| map_db_error("querying key", error))?
            .ok_or(BackendError::UnknownKey)?;

        let encoded = read_scalar(store, row.key_name.clone()).await?;
        let mut secret = hex::decode(encoded.trim()).map_err(|error| {
            BackendError::KeyLoss(format!("the stored credential is not a tpmd key: {error}"))
        })?;
        let signing_key = match SigningKey::from_slice(&secret) {
            Ok(signing_key) => signing_key,
            Err(error) => {
                secret.zeroize();
                return Err(BackendError::KeyLoss(format!(
                    "the stored scalar is not a P-256 key: {error}"
                )));
            }
        };
        // `Signer::sign` applies SHA-256 to `message` internally, which is
        // exactly the contract weaver_mux::auth::verify expects.
        let signature: p256::ecdsa::Signature = signing_key.sign(message);
        // The scalar was only in memory for the duration of the signature.
        secret.zeroize();

        let mut out = [0u8; 64];
        out.copy_from_slice(&signature.to_bytes());
        Ok(Signature::P256(out))
    }

    async fn destroy(&self, owner: &Owner, key_id: &KeyId) -> Result<(), BackendError> {
        let store = self.store()?;
        let row = keyring_keys::Entity::find_by_id(row_id(owner, key_id))
            .one(&self.db)
            .await
            .map_err(|error| map_db_error("querying key", error))?
            .ok_or(BackendError::UnknownKey)?;

        // The recorded address, not a recomputed one: it is what was actually
        // written, so a key stays destroyable even if the scheme changes.
        delete_credential(store, row.key_name).await?;

        let result = keyring_keys::Entity::delete_by_id(row_id(owner, key_id))
            .exec(&self.db)
            .await
            .map_err(|error| map_db_error("deleting key", error))?;
        if result.rows_affected == 0 {
            return Err(BackendError::UnknownKey);
        }
        Ok(())
    }
}

/// Draw a fresh P-256 secret scalar and derive its compressed public key.
///
/// A random 32-byte string is a valid P-256 scalar except with negligible
/// probability; the loop retries in that case.
fn generate_key() -> Result<([u8; 32], KeyId), BackendError> {
    for _ in 0..16 {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret)
            .map_err(|error| BackendError::Internal(format!("drawing randomness: {error}")))?;
        if let Ok(signing_key) = SigningKey::from_slice(&secret) {
            let point = signing_key.verifying_key().as_affine().to_sec1_point(true);
            let mut pubkey = [0u8; 33];
            pubkey.copy_from_slice(point.as_bytes());
            return Ok((secret, KeyId::P256(pubkey)));
        }
    }
    Err(BackendError::Internal(
        "failed to draw a valid P-256 scalar in 16 attempts".into(),
    ))
}

/// Wire enum indices, persisted as integers. These are coupled to the order of
/// the enum variants in `tpmd-proto`, which is why new variants are appended.
fn algorithm_index(algorithm: Algorithm) -> i64 {
    match algorithm {
        Algorithm::EcdsaP256Sha256 => 0,
    }
}

fn algorithm_from_index(index: i64) -> Result<Algorithm, BackendError> {
    match index {
        0 => Ok(Algorithm::EcdsaP256Sha256),
        other => Err(BackendError::Internal(format!(
            "unknown algorithm index {other} in store"
        ))),
    }
}

fn level_index(level: SecurityLevel) -> i64 {
    match level {
        SecurityLevel::File => 0,
        SecurityLevel::Keyring => 1,
        SecurityLevel::Sealed => 2,
        SecurityLevel::Hardware => 3,
    }
}

fn level_from_index(index: i64) -> Result<SecurityLevel, BackendError> {
    match index {
        0 => Ok(SecurityLevel::File),
        1 => Ok(SecurityLevel::Keyring),
        2 => Ok(SecurityLevel::Sealed),
        3 => Ok(SecurityLevel::Hardware),
        other => Err(BackendError::Internal(format!(
            "unknown security level index {other} in store"
        ))),
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier as _;

    fn owner(principal: &str, namespace: &str) -> Owner {
        Owner::new(tpmd_backend::Principal(principal.into()), namespace)
    }

    /// A backend over the in-crate mock store, so the tests exercise the real
    /// call path without needing a session bus or a keychain.
    async fn open_at(dir: &Path, store: &'static CredentialStore) -> KeyringBackend {
        let db = tpmd_store::open(dir).await.unwrap();
        KeyringBackend {
            db,
            db_path: tpmd_store::database_path(dir),
            access: Access::Ready(store),
        }
    }

    async fn over(store: &'static CredentialStore) -> (tempfile::TempDir, KeyringBackend) {
        let dir = tempfile::tempdir().unwrap();
        let backend = open_at(dir.path(), store).await;
        (dir, backend)
    }

    async fn backend() -> (tempfile::TempDir, KeyringBackend) {
        over(mock_store()).await
    }

    /// The backend keeps stores for the life of the process (see
    /// [`keep_alive`]), so the mock is handed over the same way.
    fn mock_store() -> &'static CredentialStore {
        keep_alive(keyring_core::mock::Store::new().unwrap())
    }

    async fn provisioned(backend: &KeyringBackend) -> KeyInfo {
        backend
            .provision(
                &owner("uid:1000", "app"),
                Algorithm::EcdsaP256Sha256,
                SecurityLevel::Keyring,
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn provision_reports_keyring_level_and_a_33_byte_fingerprint() {
        let (_dir, backend) = backend().await;
        let info = provisioned(&backend).await;
        assert_eq!(info.security_level, SecurityLevel::Keyring);
        assert_eq!(info.key_id.as_bytes().len(), 33);
    }

    #[tokio::test]
    async fn provision_refuses_a_stronger_level() {
        let (_dir, backend) = backend().await;
        let error = backend
            .provision(
                &owner("uid:1000", "app"),
                Algorithm::EcdsaP256Sha256,
                SecurityLevel::Sealed,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, BackendError::IncompatiblePolicy { .. }));
    }

    #[tokio::test]
    async fn signatures_verify_independently() {
        let (_dir, backend) = backend().await;
        let info = provisioned(&backend).await;
        let message = b"weaver-mux-v1 transcript bytes";
        let signature = backend
            .sign(&owner("uid:1000", "app"), &info.key_id, message)
            .await
            .unwrap();

        // Verify with the p256 crate directly, not with tpmd's own code path.
        let verifying = VerifyingKey::from_sec1_bytes(info.key_id.as_bytes()).unwrap();
        let signature = p256::ecdsa::Signature::from_slice(signature.as_bytes()).unwrap();
        verifying.verify(message, &signature).unwrap();
        assert!(
            verifying
                .verify(b"different transcript", &signature)
                .is_err()
        );
    }

    #[tokio::test]
    async fn keys_are_scoped_to_principal_and_namespace() {
        let (_dir, backend) = backend().await;
        let info = provisioned(&backend).await;

        assert!(matches!(
            backend
                .identify(&owner("uid:2000", "app"), &info.key_id)
                .await,
            Err(BackendError::UnknownKey)
        ));
        assert!(matches!(
            backend
                .identify(&owner("uid:1000", "other"), &info.key_id)
                .await,
            Err(BackendError::UnknownKey)
        ));
        assert!(matches!(
            backend
                .sign(&owner("uid:2000", "app"), &info.key_id, b"x")
                .await,
            Err(BackendError::UnknownKey)
        ));
        assert!(matches!(
            backend
                .destroy(&owner("uid:2000", "app"), &info.key_id)
                .await,
            Err(BackendError::UnknownKey)
        ));
    }

    /// A wrong-principal request and a request for a key that was never minted
    /// must be indistinguishable, or the error itself leaks that the key exists.
    #[tokio::test]
    async fn a_foreign_key_is_indistinguishable_from_a_missing_one() {
        let (_dir, backend) = backend().await;
        let info = provisioned(&backend).await;
        let foreign = backend
            .identify(&owner("uid:2000", "app"), &info.key_id)
            .await
            .unwrap_err();
        let missing = backend
            .identify(&owner("uid:2000", "app"), &KeyId::P256([9; 33]))
            .await
            .unwrap_err();
        assert_eq!(foreign.to_string(), missing.to_string());
    }

    #[tokio::test]
    async fn keys_survive_reopening_the_backend() {
        // The mock store has no persistence of its own, so the same store is
        // handed to the reopened backend — which is what the OS store does for
        // real, and what makes this a test of the metadata, not of the mock.
        let dir = tempfile::tempdir().unwrap();
        let store = mock_store();
        let info = {
            let backend = open_at(dir.path(), store).await;
            provisioned(&backend).await
        };

        let reopened = open_at(dir.path(), store).await;
        let found = reopened
            .identify(&owner("uid:1000", "app"), &info.key_id)
            .await
            .unwrap();
        assert_eq!(found.key_id, info.key_id);
        assert_eq!(found.security_level, SecurityLevel::Keyring);
    }

    #[tokio::test]
    async fn destroy_removes_and_then_reports_unknown() {
        let (_dir, backend) = backend().await;
        let info = provisioned(&backend).await;
        backend
            .destroy(&owner("uid:1000", "app"), &info.key_id)
            .await
            .unwrap();
        assert!(matches!(
            backend
                .destroy(&owner("uid:1000", "app"), &info.key_id)
                .await,
            Err(BackendError::UnknownKey)
        ));
    }

    /// The key is on record but the OS store has lost the credential: that is
    /// key loss, never a missing key.
    #[tokio::test]
    async fn a_key_whose_credential_vanished_is_reported_as_loss() {
        let store = mock_store();
        let (_dir, backend) = over(store).await;
        let info = provisioned(&backend).await;
        let key_name = address::entry_address(&owner("uid:1000", "app"), &info.key_id);
        delete_credential(store, key_name).await.unwrap();

        assert!(matches!(
            backend
                .identify(&owner("uid:1000", "app"), &info.key_id)
                .await,
            Err(BackendError::KeyLoss(_))
        ));
        assert!(matches!(
            backend
                .sign(&owner("uid:1000", "app"), &info.key_id, b"x")
                .await,
            Err(BackendError::KeyLoss(_))
        ));
    }

    /// A store that cannot answer must say so on every operation — this is the
    /// shape a host with no session bus, a locked keychain or no loaded profile
    /// produces, including under `--backend keyring`.
    #[tokio::test]
    async fn an_unreachable_store_reports_store_locked_everywhere() {
        let dir = tempfile::tempdir().unwrap();
        let db = tpmd_store::open(dir.path()).await.unwrap();
        let backend = KeyringBackend {
            db,
            db_path: tpmd_store::database_path(dir.path()),
            access: Access::Unavailable("no session bus".into()),
        };
        assert!(!backend.can_be_used());

        let key_id = KeyId::P256([7; 33]);
        for error in [
            backend
                .provision(
                    &owner("uid:1000", "app"),
                    Algorithm::EcdsaP256Sha256,
                    SecurityLevel::Keyring,
                )
                .await
                .unwrap_err(),
            backend
                .identify(&owner("uid:1000", "app"), &key_id)
                .await
                .unwrap_err(),
            backend
                .sign(&owner("uid:1000", "app"), &key_id, b"x")
                .await
                .unwrap_err(),
            backend
                .destroy(&owner("uid:1000", "app"), &key_id)
                .await
                .unwrap_err(),
        ] {
            assert!(
                matches!(error, BackendError::StoreLocked(_)),
                "expected store_locked, got {error}"
            );
        }
    }

    /// The store's own failure modes have to reach the protocol intact, through
    /// the real call path rather than through the mapping in isolation.
    #[tokio::test]
    async fn the_stores_own_failures_are_mapped_on_the_real_path() {
        use keyring_core::Error as KeyringError;

        let store = mock_store();
        let (_dir, backend) = over(store).await;
        let info = provisioned(&backend).await;
        let key_name = address::entry_address(&owner("uid:1000", "app"), &info.key_id);
        let entry = store.build(store::SERVICE, &key_name, None).unwrap();
        let mock: &keyring_core::mock::Cred = entry.as_any().downcast_ref().unwrap();

        mock.set_error(KeyringError::NoStorageAccess(Box::from(
            "the keychain is locked",
        )));
        assert!(matches!(
            backend
                .identify(&owner("uid:1000", "app"), &info.key_id)
                .await,
            Err(BackendError::StoreLocked(_))
        ));

        mock.set_error(KeyringError::Ambiguous(Vec::new()));
        assert!(matches!(
            backend
                .sign(&owner("uid:1000", "app"), &info.key_id, b"x")
                .await,
            Err(BackendError::Internal(_))
        ));

        mock.set_error(KeyringError::BadEncoding(vec![0xff]));
        assert!(matches!(
            backend
                .sign(&owner("uid:1000", "app"), &info.key_id, b"x")
                .await,
            Err(BackendError::KeyLoss(_))
        ));
    }

    #[tokio::test]
    async fn the_backend_advertises_only_keyring() {
        let (_dir, backend) = backend().await;
        assert_eq!(backend.levels(), &[SecurityLevel::Keyring]);
        assert_eq!(backend.store_mechanism(), Some(store::mechanism()));
        assert!(backend.forced_when_unusable());
    }

    /// A store that answers "no such credential" is usable: that is the normal
    /// state before any key exists.
    #[test]
    fn the_probe_accepts_a_store_that_answers() {
        let store = mock_store();
        assert!(store::probe(store));
    }

    /// A store that refuses modifiers must still yield a usable entry: the unit
    /// tests' mock store rejects every one, and a platform store may implement
    /// none.
    #[test]
    fn a_store_that_refuses_modifiers_still_yields_a_usable_entry() {
        let store = mock_store();
        let entry = build_entry(store, "modifier-probe", &[("persistence", "Local")])
            .expect("a refused modifier must not be fatal");
        entry.set_password("x").unwrap();
        assert_eq!(entry.get_password().unwrap(), "x");
    }

    /// Only Windows has a persistence to pin; everywhere else every entry is
    /// created with no modifiers at all.
    #[test]
    fn only_windows_grades_persistence() {
        let attempts = store::entry_modifier_attempts();
        if cfg!(target_os = "windows") {
            assert_eq!(attempts.len(), 2, "Windows tries durable, then session");
            assert_eq!(
                attempts[0],
                vec![("persistence", "Local")],
                "the durable attempt comes first: a device identity must not roam"
            );
            assert_eq!(attempts[1], vec![("persistence", "Session")]);
        } else {
            assert_eq!(attempts, vec![Vec::new()], "one attempt, no modifiers");
        }
    }

    /// A store that refuses the durable write must be asked again more weakly,
    /// and the key must still end up stored. This is the Windows path — a logon
    /// session with no profile-backed credential manager answers a durable write
    /// with `ERROR_NO_SUCH_LOGON_SESSION` but accepts a session one — exercised
    /// here against the mock store, which can be told to fail once.
    #[tokio::test]
    async fn a_refused_durable_write_falls_back_to_a_weaker_one() {
        use keyring_core::Error as KeyringError;

        let store = mock_store();
        let key_name = "persistence-fallback-probe";
        let entry = build_entry(store, key_name, &[]).unwrap();
        let mock: &keyring_core::mock::Cred = entry.as_any().downcast_ref().unwrap();

        // The first write is refused the way Windows refuses it.
        mock.set_error(KeyringError::PlatformFailure(Box::from(
            "Windows ERROR_NO_SUCH_LOGON_SESSION",
        )));

        let attempts = vec![
            vec![("persistence", "Local")],
            vec![("persistence", "Session")],
        ];
        write_secret(store, key_name.to_owned(), "deadbeef".to_owned(), attempts)
            .await
            .expect("the weaker attempt must succeed");

        // And it really landed.
        let written = entry.get_password().unwrap();
        assert_eq!(written, "deadbeef");
    }

    /// Weakening is for "the store would not take it", not for failures that
    /// will fail identically the second time.
    #[test]
    fn only_store_refusals_are_worth_weakening_for() {
        assert!(worth_weakening(&BackendError::StoreLocked("locked".into())));
        assert!(worth_weakening(&BackendError::Unavailable("no".into())));
        assert!(!worth_weakening(&BackendError::UnknownKey));
        assert!(!worth_weakening(&BackendError::KeyLoss("gone".into())));
        assert!(!worth_weakening(&BackendError::Internal("bad".into())));
    }
}
