//! The macOS Secure Enclave backend: P-256 keys the enclave holds and never
//! releases, at security level `hardware`.
//!
//! There is deliberately no `sealed` rung here. macOS has nothing between the
//! login keychain (`keyring`, WVR-151's universal backend) and a non-exportable
//! enclave key; a `sealed` worth the name would need a design of its own, and
//! inventing one quietly is how a security level stops meaning anything.
//!
//! Four things about this platform are load-bearing enough to state where a reader
//! will trip over them, and each one cost real time to learn (see `docs/macos.md`):
//!
//! * **The agent must run from a signed `.app` bundle with an embedded
//!   provisioning profile, and the bundle's identifier must be one the team has
//!   provisioned.** Without either, the keychain refuses to *store* a key with
//!   `errSecMissingEntitlement` — which reads like a signing bug and, from the
//!   keychain's point of view, is one. A hard platform restriction: documented,
//!   never worked around.
//! * **It must run in the Aqua session** — a per-user LaunchAgent, the shape
//!   WVR-149 owns on Windows. An SSH login lands in launchd's Background domain,
//!   where the login keychain is out of reach. An *ephemeral* enclave key works
//!   from anywhere, which is why a naive liveness check passes while nothing
//!   useful does; usability is therefore probed by storing.
//! * **A locked keychain and a wrong deployment both refuse, differently.** Only
//!   the first is the user's to fix, and telling them apart is the whole basis of
//!   `Closed` versus `Gone`.
//! * **No user-presence policy is imposed.** A biometric or passcode prompt on an
//!   unattended agent is a hang, not a security win.
//!
//! Everything platform-shaped lives in [`enclave`]; this module is the store, the
//! contract, and the classification.

#![cfg(target_os = "macos")]
#![deny(unsafe_code)]
#![warn(missing_docs)]

mod enclave;

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, Set};
use sha2::{Digest as _, Sha256};
use tpmd_backend::{Backend, BackendError, Owner, StoreStatus};
use tpmd_proto::{Algorithm, KeyId, KeyInfo, SecurityLevel, Signature};
use tpmd_store::entities::se_keys;
use tpmd_store::map_db_error;

use crate::enclave::{Access, Refusal};

/// The only security level this backend can reach.
const LEVELS: &[SecurityLevel] = &[SecurityLevel::Hardware];

/// The only algorithm this backend offers.
const ALGORITHMS: &[Algorithm] = &[Algorithm::EcdsaP256Sha256];

/// Serialises every Security.framework call in the process.
///
/// The daemon serves connections concurrently and two of them may name the same
/// key; the framework's keychain APIs do not promise to sequence that for us.
/// Taken on the calling side, in [`on_security_thread`], and never held across a
/// nested call — a `std::sync::Mutex` does not re-enter.
static SECURITY_LOCK: Mutex<()> = Mutex::new(());

/// A user's private P-256 keys, held by the Secure Enclave.
pub struct SecureEnclaveBackend {
    db: DatabaseConnection,
    db_path: PathBuf,
    /// The last verdict from the keychain.
    ///
    /// A cached *observation*, not a one-time verdict: the user locks and unlocks
    /// their login keychain all the time, and WVR-152 exists precisely because a
    /// store that is shut is a state to report rather than a reason to give up on
    /// the backend.
    access: Mutex<Access>,
    /// Whether a key has ever actually been *stored* here.
    ///
    /// Until it has, a later probe must still answer the storage question: a
    /// machine whose keychain was locked at startup would otherwise never find out
    /// that its deployment is wrong, and would keep reporting a store that looks
    /// open but can never keep a key.
    storage_proven: AtomicBool,
}

impl SecureEnclaveBackend {
    /// Open the store and probe the enclave.
    ///
    /// Neither a locked keychain nor a wrong deployment is an opening *error*: both
    /// are reported through the store status, so the registry can choose another
    /// backend or serve this one and answer `closed`, instead of the daemon failing
    /// to start at all. What is an error is the shared store itself not opening.
    pub async fn open(state_dir: &Path) -> Result<Self, BackendError> {
        let db = tpmd_store::open(state_dir).await?;

        // The full probe: generating a key proves the enclave answers this
        // process; *storing* one proves this deployment can keep anything.
        let access = on_security_thread(enclave::probe_storage).await?;
        if let Access::Closed(refusal) | Access::Gone(refusal) = &access {
            tracing::info!(
                code = refusal.code(),
                reason = refusal.message(),
                "the Secure Enclave store cannot serve yet"
            );
        }
        let storage_proven = matches!(access, Access::Open);

        Ok(Self {
            db,
            db_path: tpmd_store::database_path(state_dir),
            access: Mutex::new(access),
            storage_proven: AtomicBool::new(storage_proven),
        })
    }

    /// The database path, for diagnostics.
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// The current verdict.
    fn access(&self) -> Access {
        self.access
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Replace the cached verdict.
    fn observe(&self, access: Access) {
        let mut guard = self
            .access
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = access;
    }

    async fn row(&self, owner: &Owner, key_id: &KeyId) -> Result<se_keys::Model, BackendError> {
        se_keys::Entity::find_by_id(row_id(owner, key_id))
            .one(&self.db)
            .await
            .map_err(|error| map_db_error("querying Secure Enclave key", error))?
            .ok_or(BackendError::UnknownKey)
    }
}

/// Run a blocking Security.framework call off the async runtime.
///
/// The framework is synchronous and can block for as long as the keychain takes,
/// and the daemon serves connections concurrently — so a call parked on a runtime
/// worker would stall everyone else. A plain OS thread keeps the runtime free, and
/// the process-wide lock keeps the calls themselves ordered.
///
/// This is about latency, not about the panic AGENTS.md warns of elsewhere: the
/// framework does not spin up a runtime of its own the way the OS credential
/// stores do.
async fn on_security_thread<T, F>(call: F) -> Result<T, BackendError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (sender, receiver) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let _guard = SECURITY_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // A send failure means the awaiting side went away, which is fine: the
        // call has already happened and its effect stands either way.
        let _ = sender.send(call());
    });
    receiver
        .await
        .map_err(|_| BackendError::Internal("the security thread went away".into()))
}

/// The store status a verdict maps to.
fn status_of(access: &Access) -> StoreStatus {
    match access {
        Access::Open => StoreStatus::Open,
        Access::Closed(refusal) => StoreStatus::Closed(refusal.message().to_owned()),
        Access::Gone(refusal) => StoreStatus::Gone(refusal.message().to_owned()),
    }
}

/// The composite primary key of a key row.
fn row_id(owner: &Owner, key_id: &KeyId) -> (String, String, Vec<u8>) {
    (
        owner.principal.as_str().to_owned(),
        owner.namespace.clone(),
        key_id.as_bytes().to_vec(),
    )
}

/// Map a refusal while creating a key.
///
/// A locked keychain, a wrong deployment and an absent enclave are all "not now,
/// and not something this process can fix": the daemon reports the store's state
/// separately, and the caller gets the platform's own words.
fn map_create(refusal: Refusal) -> BackendError {
    BackendError::Unavailable(refusal.message().to_owned())
}

/// Map a refusal while using a stored key.
///
/// A row whose keychain item is gone is **key loss** — the caller must re-pair —
/// while a keychain that will not answer is transient unavailability. The protocol
/// keeps the two apart on purpose, and the difference is entirely in the code.
fn map_use(refusal: Refusal) -> BackendError {
    if refusal.is_missing() {
        BackendError::KeyLoss(format!(
            "the stored Secure Enclave key is gone: {}",
            refusal.message()
        ))
    } else {
        BackendError::Unavailable(refusal.message().to_owned())
    }
}

#[async_trait]
impl Backend for SecureEnclaveBackend {
    fn name(&self) -> &'static str {
        "macos-se"
    }

    fn algorithms(&self) -> &'static [Algorithm] {
        ALGORITHMS
    }

    fn levels(&self) -> &'static [SecurityLevel] {
        LEVELS
    }

    /// A merely *closed* store is usable: a rung whose keychain is locked is a
    /// candidate, never a skip (WVR-152), because skipping it would silently move
    /// the machine's custody — and its identity — to a plainer store. Only a
    /// deployment this process can never satisfy makes it unusable.
    fn can_be_used(&self) -> bool {
        !matches!(self.access(), Access::Gone(_))
    }

    fn store_status(&self) -> StoreStatus {
        status_of(&self.access())
    }

    async fn probe_store(&self) -> StoreStatus {
        // A refusal no user action can change is not re-asked. The process cannot
        // sign itself differently while it runs, so the answer would only ever be
        // the same one, at the cost of a keychain call every interval.
        if let Access::Gone(refusal) = self.access()
            && refusal.is_deployment()
        {
            return StoreStatus::Gone(refusal.message().to_owned());
        }

        // While nothing has ever been stored, the storage question still has to be
        // asked: the enclave answering is not the keychain accepting.
        let prove_storage = !self.storage_proven.load(Ordering::Relaxed);
        let observed = on_security_thread(move || {
            if prove_storage {
                enclave::probe_storage()
            } else {
                enclave::probe_enclave()
            }
        })
        .await
        .unwrap_or_else(|error| Access::Gone(Refusal::internal(error.to_string())));

        if prove_storage && matches!(observed, Access::Open) {
            self.storage_proven.store(true, Ordering::Relaxed);
        }
        let status = status_of(&observed);
        self.observe(observed);
        status
    }

    fn store_mechanism(&self) -> Option<&'static str> {
        Some("secure-enclave")
    }

    /// macOS offers no signal for "the keychain was unlocked", so [`Backend::unlock_hints`]
    /// is left at its default: the daemon's own interval is the safety net, and a
    /// provider that could never fire would be worse than none.
    ///
    /// Forcing this backend is honoured though, so an operator asking *why* the
    /// enclave is unreachable is told rather than refused a start.
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
        if level != SecurityLevel::Hardware {
            // The daemon only ever passes a level this backend advertised, so
            // reaching here is a genuine mismatch: refuse rather than silently
            // weaken the policy.
            return Err(BackendError::IncompatiblePolicy {
                required: level,
                available: SecurityLevel::Hardware,
            });
        }

        let label = enclave::new_label();
        let created_unix = now_unix();

        let (compressed, public_blob) = {
            let for_thread = label.clone();
            on_security_thread(move || enclave::create_permanent(&for_thread))
                .await?
                .map_err(map_create)?
        };
        // The compressed point *is* the fingerprint, which is how a key is
        // addressed everywhere else in this workspace.
        let key_id = KeyId::P256(compressed);

        let (principal, namespace, id) = row_id(owner, &key_id);
        let inserted = se_keys::ActiveModel {
            principal: Set(principal),
            namespace: Set(namespace),
            key_id: Set(id),
            algorithm: Set(algorithm_index(algorithm)),
            level: Set(level_index(level)),
            key_name: Set(label.clone()),
            public_blob: Set(public_blob),
            created_unix: Set(created_unix),
        }
        .insert(&self.db)
        .await;

        if let Err(error) = inserted {
            // A key without its row is an orphan the caller can never address
            // again, so take it back out rather than leave it behind.
            let for_thread = label.clone();
            let _ = on_security_thread(move || {
                let _ = enclave::delete(&for_thread);
            })
            .await;
            return Err(map_db_error("inserting Secure Enclave key", error));
        }

        // Storing a key is the fact the probe was waiting for.
        self.storage_proven.store(true, Ordering::Relaxed);

        Ok(KeyInfo {
            key_id,
            algorithm,
            security_level: level,
            created_unix,
        })
    }

    async fn identify(&self, owner: &Owner, key_id: &KeyId) -> Result<KeyInfo, BackendError> {
        let row = self.row(owner, key_id).await?;
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
        let row = self.row(owner, key_id).await?;

        // The digest signed for the transcript. The enclave is asked for a *digest*
        // signature, so this is the only hash over the message: exactly one, as
        // protocol §10 requires.
        let digest: [u8; 32] = Sha256::digest(message).into();
        let label = row.key_name.clone();

        let raw = on_security_thread(move || enclave::sign(&label, &digest))
            .await?
            .map_err(map_use)?;

        Ok(Signature::P256(raw))
    }

    async fn destroy(&self, owner: &Owner, key_id: &KeyId) -> Result<(), BackendError> {
        let row = self.row(owner, key_id).await?;

        // Remove the key first: a row without its key is key loss the caller can
        // act on, while a key without its row is an orphan nobody can address again.
        let label = row.key_name.clone();
        on_security_thread(move || enclave::delete(&label))
            .await?
            .map_err(map_use)?;

        let result = se_keys::Entity::delete_by_id(row_id(owner, key_id))
            .exec(&self.db)
            .await
            .map_err(|error| map_db_error("deleting Secure Enclave key", error))?;
        if result.rows_affected == 0 {
            return Err(BackendError::UnknownKey);
        }
        Ok(())
    }
}

/// Wire enum indices, persisted as integers; coupled to `tpmd-proto`'s order.
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
        .map(|since| since.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_are_hardware_only() {
        // macOS has no `sealed` rung; WVR-154 owns that design question.
        assert_eq!(LEVELS, &[SecurityLevel::Hardware]);
    }

    /// The digest signed for the documented Tunnel Weaver transcript: the same
    /// value the macOS, Windows-CNG and Linux TPM runs produced.
    #[test]
    fn the_documented_transcript_hashes_to_the_shared_digest() {
        let mut transcript = b"weaver-mux-v1".to_vec();
        transcript.extend(std::iter::repeat_n(1u8, 32));
        transcript.extend(std::iter::repeat_n(2u8, 32));
        transcript.extend_from_slice(b"example.com");
        assert_eq!(
            hex::encode(Sha256::digest(&transcript)),
            "258a08d914a68d453682a14fc6cdd60e5ae7e1dca124106e42d86fe160da21c0"
        );
    }

    #[test]
    fn a_missing_key_is_key_loss_and_a_refusal_is_unavailability() {
        assert!(matches!(
            map_use(Refusal::from_status(-25300)),
            BackendError::KeyLoss(_)
        ));
        assert!(matches!(
            map_create(Refusal::from_status(-34018)),
            BackendError::Unavailable(_)
        ));
        assert!(matches!(
            map_use(Refusal::from_status(-25308)),
            BackendError::Unavailable(_)
        ));
    }

    #[test]
    fn a_shut_store_reads_as_closed_and_a_wrong_deployment_as_gone() {
        assert!(matches!(status_of(&Access::Open), StoreStatus::Open));
        assert!(matches!(
            status_of(&Access::Closed(Refusal::from_status(-25308))),
            StoreStatus::Closed(_)
        ));
        assert!(matches!(
            status_of(&Access::Gone(Refusal::from_status(-34018))),
            StoreStatus::Gone(_)
        ));
    }
}
