//! The dummy backend: a SQLite database holding software P-256 keys.
//!
//! This is the first, universal rung of the security ladder. It reports
//! security level [`SecurityLevel::File`] and nothing stronger: the private
//! scalar sits in an ordinary SQLite file protected only by filesystem
//! permissions. It is not encrypted and not hardware-backed.
//!
//! Two rules from the architecture document are enforced here:
//!
//! * **Ownership.** Every key is addressed by `(principal, namespace,
//!   key_id)`, all three of which are part of the table's primary key. A
//!   lookup under the wrong principal or namespace is indistinguishable from
//!   a key that does not exist ([`BackendError::UnknownKey`]).
//! * **Never weaken silently.** A request to provision at any level other
//!   than `file` is refused rather than downgraded.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer as _;
use p256::elliptic_curve::sec1::ToSec1Point as _;
use rusqlite::{Connection, OptionalExtension, params};
use tpmd_backend::{Backend, BackendError, Owner};
use tpmd_proto::{Algorithm, KeyId, KeyInfo, SecurityLevel, Signature};

/// File name of the SQLite database inside the state directory.
pub const DATABASE_FILE_NAME: &str = "keys.sqlite";

/// The only security level this backend can achieve.
const LEVELS: &[SecurityLevel] = &[SecurityLevel::File];

/// The only algorithm this backend can offer.
const ALGORITHMS: &[Algorithm] = &[Algorithm::EcdsaP256Sha256];

/// `journal_mode=TRUNCATE` keeps the rollback journal short-lived (unlike WAL,
/// whose `-wal`/`-shm` sidecars persist), so there is less to protect on disk.
/// The containing directory is `0700`, so any sidecar is owner-only anyway.
const SCHEMA: &str = "
PRAGMA journal_mode = TRUNCATE;
CREATE TABLE IF NOT EXISTS keys (
    principal    TEXT    NOT NULL,
    namespace    TEXT    NOT NULL,
    key_id       BLOB    NOT NULL,
    algorithm    INTEGER NOT NULL,
    level        INTEGER NOT NULL,
    secret       BLOB    NOT NULL,
    created_unix INTEGER NOT NULL,
    PRIMARY KEY (principal, namespace, key_id)
) WITHOUT ROWID;
";

/// A software P-256 store backed by SQLite.
///
/// Access is serialised behind a mutex: SQLite connections are not
/// `Sync`, and signing operations are microseconds long.
pub struct DummyBackend {
    conn: Mutex<Connection>,
    db_path: PathBuf,
}

impl DummyBackend {
    /// Open (creating if needed) the store under `state_dir`.
    ///
    /// The directory is created `0700` and the database file forced `0600` (a
    /// protected owner-only DACL on Windows).
    pub fn open(state_dir: &Path) -> Result<Self, BackendError> {
        tpmd_ipc::secure_fs::ensure_dir(state_dir)
            .map_err(|e| BackendError::Unavailable(format!("creating state dir: {e}")))?;

        let db_path = state_dir.join(DATABASE_FILE_NAME);
        let conn = Connection::open(&db_path).map_err(|e| {
            BackendError::Unavailable(format!("opening {}: {e}", db_path.display()))
        })?;

        // Restrict the database file itself. The directory is already 0700, so
        // SQLite's transient journal sidecars are covered too.
        tpmd_ipc::secure_fs::restrict_file(&db_path).map_err(|e| {
            BackendError::Unavailable(format!("restricting {}: {e}", db_path.display()))
        })?;

        conn.execute_batch(SCHEMA)
            .map_err(|e| BackendError::Unavailable(format!("initialising schema: {e}")))?;

        Ok(Self {
            conn: Mutex::new(conn),
            db_path,
        })
    }

    /// The database path, for diagnostics.
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>, BackendError> {
        self.conn
            .lock()
            .map_err(|_| BackendError::Internal("key store mutex was poisoned".into()))
    }
}

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

    fn provision(
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
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO keys (principal, namespace, key_id, algorithm, level, secret, created_unix)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                owner.principal.as_str(),
                owner.namespace,
                key_id.as_bytes(),
                algorithm_index(algorithm),
                level_index(level),
                secret.as_slice(),
                created_unix,
            ],
        )
        .map_err(|e| BackendError::Internal(format!("inserting key: {e}")))?;

        Ok(KeyInfo {
            key_id,
            algorithm,
            security_level: level,
            created_unix,
        })
    }

    fn identify(&self, owner: &Owner, key_id: &KeyId) -> Result<KeyInfo, BackendError> {
        let conn = self.lock()?;
        let row = conn
            .query_row(
                "SELECT algorithm, level, created_unix FROM keys
                 WHERE principal = ?1 AND namespace = ?2 AND key_id = ?3",
                params![owner.principal.as_str(), owner.namespace, key_id.as_bytes()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| BackendError::Internal(format!("querying key: {e}")))?;

        let (algorithm, level, created_unix) = row.ok_or(BackendError::UnknownKey)?;
        Ok(KeyInfo {
            key_id: *key_id,
            algorithm: algorithm_from_index(algorithm)?,
            security_level: level_from_index(level)?,
            created_unix,
        })
    }

    fn sign(
        &self,
        owner: &Owner,
        key_id: &KeyId,
        message: &[u8],
    ) -> Result<Signature, BackendError> {
        let sec1 = key_id_bytes(key_id)?;
        let secret: Vec<u8> = {
            let conn = self.lock()?;
            conn.query_row(
                "SELECT secret FROM keys
                 WHERE principal = ?1 AND namespace = ?2 AND key_id = ?3",
                params![owner.principal.as_str(), owner.namespace, sec1],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| BackendError::Internal(format!("querying key: {e}")))?
            .ok_or(BackendError::UnknownKey)?
        };

        let signing_key = SigningKey::from_slice(&secret)
            .map_err(|e| BackendError::KeyLoss(format!("stored scalar is invalid: {e}")))?;
        // `Signer::sign` applies SHA-256 to `message` internally, which is
        // exactly the contract weaver_mux::auth::verify expects.
        let signature: p256::ecdsa::Signature = signing_key.sign(message);
        let mut out = [0u8; 64];
        out.copy_from_slice(&signature.to_bytes());
        Ok(Signature::P256(out))
    }

    fn destroy(&self, owner: &Owner, key_id: &KeyId) -> Result<(), BackendError> {
        let conn = self.lock()?;
        let removed = conn
            .execute(
                "DELETE FROM keys WHERE principal = ?1 AND namespace = ?2 AND key_id = ?3",
                params![owner.principal.as_str(), owner.namespace, key_id.as_bytes()],
            )
            .map_err(|e| BackendError::Internal(format!("deleting key: {e}")))?;
        if removed == 0 {
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

fn key_id_bytes(key_id: &KeyId) -> Result<&[u8], BackendError> {
    match key_id {
        KeyId::P256(bytes) => Ok(bytes),
    }
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

    fn backend() -> (tempfile::TempDir, DummyBackend) {
        let dir = tempfile::tempdir().unwrap();
        let backend = DummyBackend::open(dir.path()).unwrap();
        (dir, backend)
    }

    #[test]
    fn provision_reports_file_level_and_a_33_byte_fingerprint() {
        let (_dir, backend) = backend();
        let info = backend
            .provision(
                &owner("uid:1000", "app"),
                Algorithm::EcdsaP256Sha256,
                SecurityLevel::File,
            )
            .unwrap();
        assert_eq!(info.security_level, SecurityLevel::File);
        assert_eq!(info.key_id.as_bytes().len(), 33);
    }

    #[test]
    fn provision_refuses_a_stronger_level() {
        let (_dir, backend) = backend();
        let err = backend
            .provision(
                &owner("uid:1000", "app"),
                Algorithm::EcdsaP256Sha256,
                SecurityLevel::Sealed,
            )
            .unwrap_err();
        assert!(matches!(err, BackendError::IncompatiblePolicy { .. }));
    }

    #[test]
    fn signatures_verify_independently() {
        let (_dir, backend) = backend();
        let info = backend
            .provision(
                &owner("uid:1000", "app"),
                Algorithm::EcdsaP256Sha256,
                SecurityLevel::File,
            )
            .unwrap();
        let message = b"weaver-mux-v1 transcript bytes";
        let signature = backend
            .sign(&owner("uid:1000", "app"), &info.key_id, message)
            .unwrap();

        // Verify with the p256 crate directly, not with tpmd's own code path.
        let verifying = VerifyingKey::from_sec1_bytes(info.key_id.as_bytes()).unwrap();
        let sig = p256::ecdsa::Signature::from_slice(signature.as_bytes()).unwrap();
        verifying.verify(message, &sig).unwrap();

        // A mutated message must fail.
        assert!(verifying.verify(b"different transcript", &sig).is_err());
    }

    #[test]
    fn keys_are_scoped_to_principal_and_namespace() {
        let (_dir, backend) = backend();
        let info = backend
            .provision(
                &owner("uid:1000", "app"),
                Algorithm::EcdsaP256Sha256,
                SecurityLevel::File,
            )
            .unwrap();

        // Same key id, different principal: unknown.
        assert!(matches!(
            backend.identify(&owner("uid:2000", "app"), &info.key_id),
            Err(BackendError::UnknownKey)
        ));
        // Different namespace: unknown.
        assert!(matches!(
            backend.identify(&owner("uid:1000", "other"), &info.key_id),
            Err(BackendError::UnknownKey)
        ));
        // Signing under the wrong owner is refused too.
        assert!(matches!(
            backend.sign(&owner("uid:2000", "app"), &info.key_id, b"x"),
            Err(BackendError::UnknownKey)
        ));
    }

    #[test]
    fn keys_survive_reopening_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let info = {
            let backend = DummyBackend::open(dir.path()).unwrap();
            backend
                .provision(
                    &owner("uid:1000", "app"),
                    Algorithm::EcdsaP256Sha256,
                    SecurityLevel::File,
                )
                .unwrap()
        };

        let reopened = DummyBackend::open(dir.path()).unwrap();
        let found = reopened
            .identify(&owner("uid:1000", "app"), &info.key_id)
            .unwrap();
        assert_eq!(found.key_id, info.key_id);
    }

    #[test]
    fn destroy_removes_and_then_reports_unknown() {
        let (_dir, backend) = backend();
        let info = backend
            .provision(
                &owner("uid:1000", "app"),
                Algorithm::EcdsaP256Sha256,
                SecurityLevel::File,
            )
            .unwrap();
        backend
            .destroy(&owner("uid:1000", "app"), &info.key_id)
            .unwrap();
        assert!(matches!(
            backend.destroy(&owner("uid:1000", "app"), &info.key_id),
            Err(BackendError::UnknownKey)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn database_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, backend) = backend();
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
