//! The dummy backend: software P-256 keys in the shared SQLite store.
//!
//! This is the first, universal rung of the security ladder. It reports
//! security level [`SecurityLevel::File`] and nothing stronger: the private
//! scalar sits in an ordinary SQLite file protected only by filesystem
//! permissions. It is not encrypted and not hardware-backed.
//!
//! Two rules from the architecture document are enforced here:
//!
//! * **Ownership.** Every key is addressed by `(principal, namespace,
//!   key_id)`, all three of which are part of the primary key. A lookup under
//!   the wrong principal or namespace is indistinguishable from a key that
//!   does not exist ([`BackendError::UnknownKey`]).
//! * **Never weaken silently.** A request to provision at any level other
//!   than `file` is refused rather than downgraded.
//!
//! The storage itself (schema, migrations, connection, file protection) lives
//! in `tpmd-store`, because the TPM backend shares the same file.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer as _;
use p256::elliptic_curve::sec1::ToSec1Point as _;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, Set};
use tpmd_backend::{Backend, BackendError, Owner};
use tpmd_proto::{Algorithm, KeyId, KeyInfo, SecurityLevel, Signature};
use tpmd_store::entities::keys;
use tpmd_store::map_db_error;

/// The only security level this backend can achieve.
const LEVELS: &[SecurityLevel] = &[SecurityLevel::File];

/// The only algorithm this backend can offer.
const ALGORITHMS: &[Algorithm] = &[Algorithm::EcdsaP256Sha256];

/// A software P-256 store backed by the shared SQLite database.
///
/// A `DatabaseConnection` is `Clone + Send + Sync`, so — unlike the raw
/// connection it replaced — it needs no mutex and the backend is trivially
/// shareable across the daemon's connection tasks.
pub struct DummyBackend {
    db: DatabaseConnection,
    db_path: PathBuf,
}

impl DummyBackend {
    /// Open (creating and migrating if needed) the shared store under
    /// `state_dir`.
    ///
    /// The directory is created `0700` and the database file forced `0600` (a
    /// protected owner-only DACL on Windows).
    pub async fn open(state_dir: &Path) -> Result<Self, BackendError> {
        let db = tpmd_store::open(state_dir).await?;
        Ok(Self {
            db,
            db_path: tpmd_store::database_path(state_dir),
        })
    }

    /// The database path, for diagnostics.
    pub fn db_path(&self) -> &Path {
        &self.db_path
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

#[async_trait]
impl Backend for DummyBackend {
    fn name(&self) -> &'static str {
        "dummy"
    }

    fn algorithms(&self) -> &'static [Algorithm] {
        ALGORITHMS
    }

    fn levels(&self) -> &'static [SecurityLevel] {
        LEVELS
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
        if level != SecurityLevel::File {
            // The daemon only ever passes a level this backend advertised, so
            // reaching here means a genuine mismatch. Refuse rather than
            // silently weaken.
            return Err(BackendError::IncompatiblePolicy {
                required: level,
                available: SecurityLevel::File,
            });
        }

        let (secret, key_id) = generate_key()?;
        let created_unix = now_unix();
        let (principal, namespace, id) = row_id(owner, &key_id);

        keys::ActiveModel {
            principal: Set(principal),
            namespace: Set(namespace),
            key_id: Set(id),
            algorithm: Set(algorithm_index(algorithm)),
            level: Set(level_index(level)),
            secret: Set(secret.to_vec()),
            created_unix: Set(created_unix),
        }
        .insert(&self.db)
        .await
        .map_err(|e| map_db_error("inserting key", e))?;

        Ok(KeyInfo {
            key_id,
            algorithm,
            security_level: level,
            created_unix,
        })
    }

    async fn identify(&self, owner: &Owner, key_id: &KeyId) -> Result<KeyInfo, BackendError> {
        let row = keys::Entity::find_by_id(row_id(owner, key_id))
            .one(&self.db)
            .await
            .map_err(|e| map_db_error("querying key", e))?
            .ok_or(BackendError::UnknownKey)?;

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
        let row = keys::Entity::find_by_id(row_id(owner, key_id))
            .one(&self.db)
            .await
            .map_err(|e| map_db_error("querying key", e))?
            .ok_or(BackendError::UnknownKey)?;

        let mut secret = row.secret;
        let signing_key = SigningKey::from_slice(&secret)
            .map_err(|e| BackendError::KeyLoss(format!("stored scalar is invalid: {e}")))?;
        // `Signer::sign` applies SHA-256 to `message` internally, which is
        // exactly the contract weaver_mux::auth::verify expects.
        let signature: p256::ecdsa::Signature = signing_key.sign(message);
        // The scalar was only in memory for the duration of the signature.
        zeroize_secret(&mut secret);

        let mut out = [0u8; 64];
        out.copy_from_slice(&signature.to_bytes());
        Ok(Signature::P256(out))
    }

    async fn destroy(&self, owner: &Owner, key_id: &KeyId) -> Result<(), BackendError> {
        let result = keys::Entity::delete_by_id(row_id(owner, key_id))
            .exec(&self.db)
            .await
            .map_err(|e| map_db_error("deleting key", e))?;
        if result.rows_affected == 0 {
            return Err(BackendError::UnknownKey);
        }
        Ok(())
    }
}

/// Overwrite a scalar in place. The dummy keeps software keys regardless, so
/// this is hygiene rather than a control, but leaving a scalar lying in a
/// freed allocation costs nothing to avoid.
fn zeroize_secret(secret: &mut [u8]) {
    secret.fill(0);
}

/// Draw a fresh P-256 secret scalar and derive its compressed public key.
///
/// A random 32-byte string is a valid P-256 scalar except with negligible
/// probability; the loop retries in that case.
fn generate_key() -> Result<([u8; 32], KeyId), BackendError> {
    for _ in 0..16 {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret)
            .map_err(|e| BackendError::Internal(format!("drawing randomness: {e}")))?;
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
        .map(|d| d.as_secs() as i64)
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

    async fn backend() -> (tempfile::TempDir, DummyBackend) {
        let dir = tempfile::tempdir().unwrap();
        let backend = DummyBackend::open(dir.path()).await.unwrap();
        (dir, backend)
    }

    #[tokio::test]
    async fn provision_reports_file_level_and_a_33_byte_fingerprint() {
        let (_dir, backend) = backend().await;
        let info = backend
            .provision(
                &owner("uid:1000", "app"),
                Algorithm::EcdsaP256Sha256,
                SecurityLevel::File,
            )
            .await
            .unwrap();
        assert_eq!(info.security_level, SecurityLevel::File);
        assert_eq!(info.key_id.as_bytes().len(), 33);
    }

    #[tokio::test]
    async fn provision_refuses_a_stronger_level() {
        let (_dir, backend) = backend().await;
        let err = backend
            .provision(
                &owner("uid:1000", "app"),
                Algorithm::EcdsaP256Sha256,
                SecurityLevel::Sealed,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, BackendError::IncompatiblePolicy { .. }));
    }

    #[tokio::test]
    async fn signatures_verify_independently() {
        let (_dir, backend) = backend().await;
        let info = backend
            .provision(
                &owner("uid:1000", "app"),
                Algorithm::EcdsaP256Sha256,
                SecurityLevel::File,
            )
            .await
            .unwrap();
        let message = b"weaver-mux-v1 transcript bytes";
        let signature = backend
            .sign(&owner("uid:1000", "app"), &info.key_id, message)
            .await
            .unwrap();

        // Verify with the p256 crate directly, not with tpmd's own code path.
        let verifying = VerifyingKey::from_sec1_bytes(info.key_id.as_bytes()).unwrap();
        let sig = p256::ecdsa::Signature::from_slice(signature.as_bytes()).unwrap();
        verifying.verify(message, &sig).unwrap();

        // A mutated message must fail.
        assert!(verifying.verify(b"different transcript", &sig).is_err());
    }

    #[tokio::test]
    async fn keys_are_scoped_to_principal_and_namespace() {
        let (_dir, backend) = backend().await;
        let info = backend
            .provision(
                &owner("uid:1000", "app"),
                Algorithm::EcdsaP256Sha256,
                SecurityLevel::File,
            )
            .await
            .unwrap();

        // Same key id, different principal: unknown.
        assert!(matches!(
            backend
                .identify(&owner("uid:2000", "app"), &info.key_id)
                .await,
            Err(BackendError::UnknownKey)
        ));
        // Different namespace: unknown.
        assert!(matches!(
            backend
                .identify(&owner("uid:1000", "other"), &info.key_id)
                .await,
            Err(BackendError::UnknownKey)
        ));
        // Signing under the wrong owner is refused too.
        assert!(matches!(
            backend
                .sign(&owner("uid:2000", "app"), &info.key_id, b"x")
                .await,
            Err(BackendError::UnknownKey)
        ));
    }

    #[tokio::test]
    async fn keys_survive_reopening_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let info = {
            let backend = DummyBackend::open(dir.path()).await.unwrap();
            backend
                .provision(
                    &owner("uid:1000", "app"),
                    Algorithm::EcdsaP256Sha256,
                    SecurityLevel::File,
                )
                .await
                .unwrap()
        };

        let reopened = DummyBackend::open(dir.path()).await.unwrap();
        let found = reopened
            .identify(&owner("uid:1000", "app"), &info.key_id)
            .await
            .unwrap();
        assert_eq!(found.key_id, info.key_id);
    }

    #[tokio::test]
    async fn destroy_removes_and_then_reports_unknown() {
        let (_dir, backend) = backend().await;
        let info = backend
            .provision(
                &owner("uid:1000", "app"),
                Algorithm::EcdsaP256Sha256,
                SecurityLevel::File,
            )
            .await
            .unwrap();
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

    /// Durability under concurrency depends on WAL: with the old rollback
    /// journal a reader could block the writer.
    #[tokio::test]
    async fn store_uses_wal_journaling() {
        let (_dir, backend) = backend().await;
        let mode: String = sea_orm::sqlx::query_scalar("PRAGMA journal_mode;")
            .fetch_one(backend.db.get_sqlite_connection_pool())
            .await
            .unwrap();
        assert_eq!(mode.to_ascii_lowercase(), "wal");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn database_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, backend) = backend().await;
        let db_mode = std::fs::metadata(backend.db_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(db_mode, 0o600);
        let dir_mode = std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
    }
}
