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
use keyring_core::CredentialStore;
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer as _;
use p256::elliptic_curve::sec1::ToSec1Point as _;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, Set};
use tpmd_backend::{Backend, BackendError, Owner, StoreStatus, UnlockHints};
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

/// Whether this backend can reach its store, and what that means for waiting.
///
/// A **cached observation, not a one-time verdict**. WVR-151 assumed the answer
/// could not change mid-run ("a daemon started without a session bus will not
/// grow one") and that was half right: the bus will not appear, but a *locked*
/// keychain or collection is something the user unlocks all the time, and a store
/// that was open shuts when the screen locks. So the state is re-checked by
/// [`KeyringBackend::probe_store`], and the distinction that matters is who can
/// change it — the user ([`StoreStatus::Closed`]) or nobody
/// ([`StoreStatus::Gone`]).
#[derive(Clone)]
struct Access {
    /// The built store, once we have managed to build one.
    store: Option<&'static CredentialStore>,
    /// What we last observed, which is what callers are told.
    status: StoreStatus,
}

impl Access {
    /// What a client sees when the store is not open.
    fn error(&self) -> BackendError {
        match &self.status {
            StoreStatus::Open => {
                BackendError::Internal("asked for the error of an open store".to_owned())
            }
            // A locked store is a *retryable* condition: the user can change it.
            StoreStatus::Closed(reason) => BackendError::StoreLocked(reason.clone()),
            // A gone dependency is not: nothing in this process brings it back.
            StoreStatus::Gone(reason) => BackendError::Unavailable(reason.clone()),
        }
    }
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
    /// The store's last observed state. Behind a mutex because a *probe*, which
    /// takes `&self`, has to be able to record what it saw.
    access: Mutex<Access>,
}

impl KeyringBackend {
    /// Open the backend: build the platform credential store and observe it.
    ///
    /// Succeeds even when the store will not answer — the backend then exists and
    /// reports *why* (`Closed` for a locked store, `Gone` for a missing one)
    /// rather than failing to construct. Refusing here would collapse "this host's
    /// store is shut" into "this build has no keyring backend", which are very
    /// different things to a user, and the first is a state a client may wait out.
    pub async fn open(state_dir: &Path) -> Result<Self, BackendError> {
        let db = tpmd_store::open(state_dir).await?;
        let access = on_store_thread(|| Ok(observe_store()))
            .await
            .unwrap_or_else(|error| Access {
                store: None,
                status: StoreStatus::Gone(error.to_string()),
            });
        Ok(Self {
            db,
            db_path: tpmd_store::database_path(state_dir),
            access: Mutex::new(access),
        })
    }

    /// The database path, for diagnostics.
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// The cached observation.
    fn access(&self) -> Access {
        self.access
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// The store, or the error its observed state implies.
    fn store(&self) -> Result<&'static CredentialStore, BackendError> {
        let access = self.access();
        match access.store {
            Some(store) if access.status.is_open() => Ok(store),
            _ => Err(access.error()),
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

/// Observe the store from scratch: build the platform store, then ask it whether
/// it will answer.
///
/// **Blocking** — this is the store thread's work.
fn observe_store() -> Access {
    match store::platform_store() {
        Err(status) => Access {
            store: None,
            status,
        },
        Ok(built) => {
            // Built, so the handle is worth keeping: a later probe can ask it
            // again instead of paying for another bus connection. It is kept for
            // the life of the process, so it is never dropped on a thread whose
            // `Drop` would panic.
            let store = keep_alive(built);
            Access {
                store: Some(store),
                status: store::probe_status(store),
            }
        }
    }
}

/// Observe again, reusing the handle when we already have one.
///
/// **Blocking** — this is the store thread's work.
fn observe_access(current: &Access) -> Access {
    match current.store {
        Some(store) => Access {
            store: Some(store),
            status: store::probe_status(store),
        },
        // We never got a handle, so the only way to find out is to try again.
        None => observe_store(),
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
/// `modifiers` are applied when the entry is created; reading and deleting pass
/// an empty slice, because persistence is a question only creating has to answer.
///
/// A store that refuses the modifiers is **not** quietly asked again without
/// them. The modifiers say what custody the key is getting, so a refusal is a
/// failure, not a hint to try something weaker.
fn entry_for(
    store: &CredentialStore,
    key_name: &str,
    modifiers: &[(&str, &str)],
) -> Result<keyring_core::Entry, BackendError> {
    let map: HashMap<&str, &str> = modifiers.iter().copied().collect();
    let borrowed = (!map.is_empty()).then_some(&map);
    store
        .build(store::SERVICE, key_name, borrowed)
        .map_err(|error| error::map_store_error("opening the credential", error))
}

/// Write `secret` to `key_name`, at the custody [`store::entry_modifiers`] asks
/// for and at no other.
///
/// There is deliberately **no fallback**. How long a device key lives is the one
/// custody question this backend has to answer, so answering it differently from
/// the way it was asked — because the first answer was inconvenient — would
/// weaken exactly the guarantee the `keyring` level makes, and it would do so
/// where nobody is looking: the caller would be handed a key that evaporates at
/// logoff, the device would come back as a stranger needing re-pairing, and a
/// line in a background service's log would be the only trace. A store that will
/// not hold the key durably fails here, and the caller is told.
async fn write_secret(
    store: &'static CredentialStore,
    key_name: String,
    secret: String,
) -> Result<(), BackendError> {
    let modifiers = store::entry_modifiers();
    let context = store::write_context();
    with_store(store, move |store| {
        let mut secret = secret;
        let written = entry_for(store, &key_name, modifiers).and_then(|entry| {
            entry
                .set_password(&secret)
                .map_err(|error| error::map_store_error(context, error))
        });
        // The scalar was on this thread only for the duration of the write.
        secret.zeroize();
        if let Err(error) = &written {
            // Logged *and* returned: the caller has to handle it, and an operator
            // reading the daemon's log should not have to infer it.
            warn!(
                backend = "keyring",
                reason = %error,
                "the credential store refused to hold the key"
            );
        }
        written
    })
    .await
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

    /// True only where the store is open *now*.
    ///
    /// Note this is "usable now", not "a candidate": a **closed** store is still a
    /// candidate for selection, because a locked keychain is a state the user can
    /// change and the daemon answers it with the non-fatal `closed` reply. The
    /// selection ladder asks [`Backend::store_status`] for that distinction; this
    /// method stays the narrow question of whether an operation would succeed
    /// right now.
    fn can_be_used(&self) -> bool {
        self.access().status.is_open()
    }

    /// What the store is doing right now, from the last observation.
    fn store_status(&self) -> StoreStatus {
        self.access().status
    }

    /// Ask the store again, and remember the answer.
    ///
    /// This is what a parked client is waiting on: read-only, cheap, and safe to
    /// call whenever there is reason to think something changed. It runs on a
    /// store thread because asking is blocking — on Linux it may reconnect to the
    /// session bus if we never managed to build the store at all.
    async fn probe_store(&self) -> StoreStatus {
        let current = self.access();
        let for_thread = current.clone();
        let observed = on_store_thread(move || Ok(observe_access(&for_thread)))
            .await
            .unwrap_or_else(|error| Access {
                store: current.store,
                status: StoreStatus::Gone(error.to_string()),
            });
        let status = observed.status.clone();
        *self
            .access
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = observed;
        status
    }

    /// How to find out that this host's store has opened.
    ///
    /// Linux's Secret Service gets a real event — a collection unlocking, or the
    /// service reappearing on the bus — while the platforms with nothing to
    /// subscribe to get an interval. Either way it is only a *hint*: the daemon
    /// probes the store after every one.
    fn unlock_hints(&self) -> Option<Arc<dyn UnlockHints>> {
        Some(store::unlock_hints())
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
        let encoded = hex::encode(secret);
        secret.zeroize();

        write_secret(store, key_name.clone(), encoded).await?;

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
    use keyring_core::Error as KeyringError;
    use keyring_core::api::CredentialStoreApi;
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier as _;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
            access: Mutex::new(Access {
                store: Some(store),
                status: StoreStatus::Open,
            }),
        }
    }

    impl KeyringBackend {
        /// The error each store-touching operation gives, for a backend whose
        /// store cannot serve.
        async fn every_operation_error(&self, key_id: &KeyId) -> Vec<BackendError> {
            vec![
                self.provision(
                    &owner("uid:1000", "app"),
                    Algorithm::EcdsaP256Sha256,
                    SecurityLevel::Keyring,
                )
                .await
                .unwrap_err(),
                self.identify(&owner("uid:1000", "app"), key_id)
                    .await
                    .unwrap_err(),
                self.sign(&owner("uid:1000", "app"), key_id, b"x")
                    .await
                    .unwrap_err(),
                self.destroy(&owner("uid:1000", "app"), key_id)
                    .await
                    .unwrap_err(),
            ]
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
    ///
    /// It is wrapped in [`ModifierFreeStore`] because Windows legitimately asks
    /// for a persistence modifier and the mock rejects every modifier by design:
    /// without the wrapper, the unit tests would fail on Windows over a *store
    /// capability* rather than over the code under test.
    fn mock_store() -> &'static CredentialStore {
        let store: Arc<CredentialStore> =
            Arc::new(ModifierFreeStore(keyring_core::mock::Store::new().unwrap()));
        keep_alive(store)
    }

    /// The in-crate mock store, minus modifiers.
    ///
    /// This fakes a store *capability*, never a custody: the mock has no
    /// persistence concept to choose from, so dropping the modifier cannot hide a
    /// weakened key. The platform paths keep their modifiers.
    struct ModifierFreeStore(Arc<keyring_core::mock::Store>);

    impl CredentialStoreApi for ModifierFreeStore {
        fn vendor(&self) -> String {
            self.0.vendor()
        }
        fn id(&self) -> String {
            self.0.id()
        }
        fn build(
            &self,
            service: &str,
            user: &str,
            _modifiers: Option<&HashMap<&str, &str>>,
        ) -> keyring_core::Result<keyring_core::Entry> {
            self.0.build(service, user, None)
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    /// A store that refuses every write, counting the asks.
    ///
    /// Counted, not merely refused: it stands in for the Windows logon session
    /// that answers a durable write with `ERROR_NO_SUCH_LOGON_SESSION`, and a
    /// fallback to weaker persistence would ask it a second time — which is what
    /// [`a_refused_write_fails_rather_than_weakening_quietly`] catches.
    struct RefusingStore {
        asks: Arc<AtomicUsize>,
    }

    impl CredentialStoreApi for RefusingStore {
        fn vendor(&self) -> String {
            "refusing".into()
        }
        fn id(&self) -> String {
            "refusing".into()
        }
        fn build(
            &self,
            _service: &str,
            _user: &str,
            _modifiers: Option<&HashMap<&str, &str>>,
        ) -> keyring_core::Result<keyring_core::Entry> {
            self.asks.fetch_add(1, Ordering::Relaxed);
            Err(KeyringError::PlatformFailure(Box::from(
                "Windows ERROR_NO_SUCH_LOGON_SESSION",
            )))
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
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

    /// A store whose state the daemon cannot improve must say so on every
    /// operation, and it must say *which* state: `store_locked` for a store the
    /// user can unlock, `unavailable` for a dependency that is never coming back.
    /// Neither is ever "key missing", and neither silently returns a signature.
    #[tokio::test]
    async fn a_store_that_cannot_serve_reports_its_own_class_everywhere() {
        let dir = tempfile::tempdir().unwrap();
        let db = tpmd_store::open(dir.path()).await.unwrap();
        let key_id = KeyId::P256([7; 33]);

        // Locked: the user can change this, so it is `StoreLocked`.
        let closed = KeyringBackend {
            db: db.clone(),
            db_path: tpmd_store::database_path(dir.path()),
            access: Mutex::new(Access {
                store: None,
                status: StoreStatus::Closed("the keychain is locked".into()),
            }),
        };
        assert!(!closed.can_be_used());
        assert!(closed.store_status().is_waitable());
        for error in closed.every_operation_error(&key_id).await {
            assert!(
                matches!(error, BackendError::StoreLocked(_)),
                "a locked store is retryable, so store_locked: {error}"
            );
        }

        // Gone: no session bus, no device, nothing the user does inside this
        // session changes it, so it is `Unavailable` — and *not* waitable.
        let gone = KeyringBackend {
            db,
            db_path: tpmd_store::database_path(dir.path()),
            access: Mutex::new(Access {
                store: None,
                status: StoreStatus::Gone("no session bus".into()),
            }),
        };
        assert!(!gone.can_be_used());
        assert!(!gone.store_status().is_waitable());
        for error in gone.every_operation_error(&key_id).await {
            assert!(
                matches!(error, BackendError::Unavailable(_)),
                "a gone dependency is not retryable: {error}"
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
        assert!(matches!(store::probe_status(store), StoreStatus::Open));
    }

    /// A store that refuses a modifier must **fail**, not be quietly asked again
    /// without it: the modifier says what custody the key is getting.
    #[test]
    fn a_refused_modifier_is_a_failure_not_a_hint_to_weaken() {
        let raw = keyring_core::mock::Store::new().unwrap();
        let store: &CredentialStore = &*raw;
        let error = entry_for(store, "modifier-probe", &[("persistence", "Local")]).unwrap_err();
        assert!(
            matches!(error, BackendError::Unavailable(_)),
            "a refused modifier must fail loudly, got {error}"
        );
    }

    /// Only Windows pins persistence, and it pins exactly one thing: the key is
    /// per-machine, because a device identity must not roam.
    #[test]
    fn only_windows_pins_persistence() {
        let modifiers = store::entry_modifiers();
        if cfg!(target_os = "windows") {
            assert_eq!(
                modifiers.to_vec(),
                vec![("persistence", "Local")],
                "durable, non-roaming persistence is the only custody asked for"
            );
            assert!(store::write_context().contains("local persistence"));
        } else {
            assert!(modifiers.is_empty(), "no other store takes modifiers");
            assert_eq!(store::write_context(), "writing the credential");
        }
    }

    /// The refusal a Windows logon session with no profile-backed credential
    /// manager gives must reach the caller, and must **not** be followed by a
    /// second, weaker attempt. If that fallback comes back, the store here is
    /// asked twice and this fails.
    #[tokio::test]
    async fn a_refused_write_fails_rather_than_weakening_quietly() {
        let asks = Arc::new(AtomicUsize::new(0));
        let store: Arc<CredentialStore> = Arc::new(RefusingStore {
            asks: Arc::clone(&asks),
        });
        let (_dir, backend) = over(keep_alive(store)).await;

        let error = backend
            .provision(
                &owner("uid:1000", "app"),
                Algorithm::EcdsaP256Sha256,
                SecurityLevel::Keyring,
            )
            .await
            .unwrap_err();

        assert!(
            matches!(error, BackendError::StoreLocked(_)),
            "a refused write must be store_locked, got {error}"
        );
        assert!(
            error.to_string().contains("NO_SUCH_LOGON_SESSION"),
            "the store's own reason must survive: {error}"
        );
        assert_eq!(
            asks.load(Ordering::Relaxed),
            1,
            "a refused write must not be retried at a weaker custody"
        );
        assert!(
            keyring_keys::Entity::find()
                .all(&backend.db)
                .await
                .unwrap()
                .is_empty(),
            "a refused key must not be recorded"
        );
    }

    /// What a refusal *means* is the whole basis for parking a client or not, and
    /// the answer is per-platform because the remedies are: a locked keychain is
    /// something the user can unlock, while Windows' refused-durable-write is a
    /// logon-session property that nothing in this process changes.
    #[test]
    fn a_refusal_is_waitable_except_where_a_logon_would_be_needed() {
        let status = store::refusal_status("Windows ERROR_NO_SUCH_LOGON_SESSION");
        if cfg!(target_os = "windows") {
            assert!(
                !status.is_waitable(),
                "no user action changes this: {status:?}"
            );
            assert!(matches!(status, StoreStatus::Gone(_)));
        } else {
            assert!(status.is_waitable(), "the user can unlock this: {status:?}");
            assert!(matches!(status, StoreStatus::Closed(_)));
        }
    }

    /// A store that cannot even be built is gone, never merely closed: "no
    /// session bus" is not something the user unlocks.
    #[test]
    fn a_store_that_cannot_be_built_is_gone() {
        let status = store::unreachable_status(KeyringError::PlatformFailure(Box::from("no bus")));
        assert!(matches!(status, StoreStatus::Gone(_)));
        assert!(!status.is_waitable());
        assert!(status.reason().unwrap().contains("no bus"));
    }
}
