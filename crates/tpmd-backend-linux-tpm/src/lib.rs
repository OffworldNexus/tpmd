use std::path::{Path, PathBuf};
use std::sync::Mutex;

use async_trait::async_trait;
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer as _;
use p256::elliptic_curve::sec1::ToSec1Point as _;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, Set};
use sha2::{Digest as _, Sha256};
use tpmd_backend::{Backend, BackendError, Owner};
use tpmd_proto::{Algorithm, KeyId, KeyInfo, SecurityLevel, Signature};
use tpmd_store::entities::tpm_keys;
use tpmd_store::map_db_error;
use zeroize::Zeroize as _;

use crate::tpm2::{Tpm, TpmError};

mod tcti;
mod tpm2;

pub use tcti::DEVICE_ENV;

/// The levels this backend can reach: a scalar wrapped by the TPM (`sealed`)
/// and a scalar that never leaves it (`hardware`).
///
/// Both are advertised because both are reachable; the daemon's floor logic
/// then prefers `hardware`, which is strictly stronger. `sealed` is the
/// fallback for a TPM that can wrap objects but not create ECC signing keys.
const LEVELS: &[SecurityLevel] = &[SecurityLevel::Sealed, SecurityLevel::Hardware];

/// The only algorithm this backend offers.
const ALGORITHMS: &[Algorithm] = &[Algorithm::EcdsaP256Sha256];

/// A TPM 2.0 backend: `hardware` and `sealed` P-256 keys.
///
/// * **hardware** — a non-exportable, non-duplicable ECDSA child key under a
///   storage parent; signing happens inside the TPM.
/// * **sealed** — a software scalar sealed by the TPM at rest; it is released
///   only to sign, in this process, and is zeroized afterwards.
///
/// Only the wrapped blobs are persisted (in the shared `tpm_keys` table); the
/// storage parent is recreated deterministically on each run, which is what
/// lets a key survive a restart without a persistent TPM object.
pub struct LinuxTpmBackend {
    db: DatabaseConnection,
    db_path: PathBuf,
    /// The device that was opened, if any, for diagnostics.
    device_path: Option<PathBuf>,
    /// The open device, or `None` when there is no usable TPM here. Behind a
    /// mutex because a TPM command sequence is stateful and must not interleave.
    device: Mutex<Option<Tpm>>,
}

impl LinuxTpmBackend {
    /// Open the store and try to open the TPM device.
    ///
    /// A missing or inaccessible device is **not** an error here: it is
    /// reported through [`Backend::can_be_used`] so the registry can skip this
    /// backend and pick another, rather than failing the daemon.
    pub async fn open(state_dir: &Path) -> Result<Self, BackendError> {
        let db = tpmd_store::open(state_dir).await?;
        let (device_path, device) = match tcti::open_usable() {
            Ok((path, transport)) => {
                tracing::info!(device = %path.display(), "opened a TPM device");
                (Some(path), Some(Tpm::from_tcti(transport)))
            }
            Err(reason) => {
                tracing::info!(%reason, "linux-tpm backend is unusable here");
                (None, None)
            }
        };
        Ok(Self {
            db,
            db_path: tpmd_store::database_path(state_dir),
            device_path,
            device: Mutex::new(device),
        })
    }

    /// The database path, for diagnostics.
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Run one TPM operation under the device lock.
    ///
    /// A stale-handle answer means the cached parent was invalidated (a TPM
    /// reset, for instance); the parent is forgotten and the operation is
    /// retried once, which succeeds while the hierarchy seed is unchanged.
    fn run_tpm<R>(
        &self,
        reloading: bool,
        op: impl Fn(&mut Tpm) -> Result<R, TpmError>,
    ) -> Result<R, BackendError> {
        let mut guard = self
            .device
            .lock()
            .map_err(|_| BackendError::Internal("TPM device mutex was poisoned".into()))?;
        let tpm = guard.as_mut().ok_or_else(|| {
            BackendError::Unavailable(match &self.device_path {
                Some(path) => format!("the TPM device {} is not open", path.display()),
                None => "no TPM device is available on this host".to_owned(),
            })
        })?;

        match op(tpm) {
            Ok(value) => Ok(value),
            Err(TpmError::Handle(_)) => {
                tpm.forget_parent();
                op(tpm).map_err(|error| map_tpm_error(error, reloading))
            }
            Err(error) => Err(map_tpm_error(error, reloading)),
        }
    }

    async fn provision_hardware(
        &self,
        owner: &Owner,
        algorithm: Algorithm,
    ) -> Result<KeyInfo, BackendError> {
        let created = self.run_tpm(false, |tpm| {
            let parent = tpm.storage_parent()?;
            tpm.create_signing_child(parent)
        })?;
        let key_id = key_id_from_public(&created.public)?;
        self.insert(
            owner,
            algorithm,
            SecurityLevel::Hardware,
            &created.private,
            &created.public,
            &key_id,
        )
        .await
    }

    async fn provision_sealed(
        &self,
        owner: &Owner,
        algorithm: Algorithm,
    ) -> Result<KeyInfo, BackendError> {
        // The scalar is drawn locally and only ever exists sealed inside the
        // TPM at rest; this process sees it just long enough to seal it.
        let (mut scalar, key_id) = generate_software_key()?;
        let created = self.run_tpm(false, |tpm| {
            let parent = tpm.storage_parent()?;
            tpm.create_sealed_object(parent, &scalar)
        });
        scalar.zeroize();
        let created = created?;

        // Both blobs come straight from the TPM: the sealed object's public
        // half carries the digest of the sealed data, so a rebuilt template
        // would fail the load's integrity check. The fingerprint is the
        // software key's own public key, computed before sealing.
        self.insert(
            owner,
            algorithm,
            SecurityLevel::Sealed,
            &created.private,
            &created.public,
            &key_id,
        )
        .await
    }

    async fn insert(
        &self,
        owner: &Owner,
        algorithm: Algorithm,
        level: SecurityLevel,
        private: &[u8],
        public: &[u8],
        key_id: &KeyId,
    ) -> Result<KeyInfo, BackendError> {
        let created_unix = now_unix();
        let (principal, namespace, id) = row_id(owner, key_id);
        tpm_keys::ActiveModel {
            principal: Set(principal),
            namespace: Set(namespace),
            key_id: Set(id),
            algorithm: Set(algorithm_index(algorithm)),
            level: Set(level_index(level)),
            private_blob: Set(private.to_vec()),
            public_blob: Set(public.to_vec()),
            created_unix: Set(created_unix),
        }
        .insert(&self.db)
        .await
        .map_err(|e| map_db_error("inserting TPM key", e))?;
        Ok(KeyInfo {
            key_id: *key_id,
            algorithm,
            security_level: level,
            created_unix,
        })
    }

    async fn row(&self, owner: &Owner, key_id: &KeyId) -> Result<tpm_keys::Model, BackendError> {
        tpm_keys::Entity::find_by_id(row_id(owner, key_id))
            .one(&self.db)
            .await
            .map_err(|e| map_db_error("querying TPM key", e))?
            .ok_or(BackendError::UnknownKey)
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
impl Backend for LinuxTpmBackend {
    fn name(&self) -> &'static str {
        "linux-tpm"
    }

    fn algorithms(&self) -> &'static [Algorithm] {
        ALGORITHMS
    }

    fn levels(&self) -> &'static [SecurityLevel] {
        LEVELS
    }

    /// Usable exactly when the TPM device could be opened.
    fn can_be_used(&self) -> bool {
        self.device
            .lock()
            .map(|guard| guard.is_some())
            .unwrap_or(false)
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
        match level {
            SecurityLevel::Hardware => self.provision_hardware(owner, algorithm).await,
            SecurityLevel::Sealed => self.provision_sealed(owner, algorithm).await,
            // The daemon only ever passes a level this backend advertised;
            // reaching here is a genuine mismatch, so refuse rather than
            // silently weaken the policy.
            other => Err(BackendError::IncompatiblePolicy {
                required: other,
                available: SecurityLevel::Hardware,
            }),
        }
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
        let level = level_from_index(row.level)?;
        let mut out = [0u8; 64];

        match level {
            SecurityLevel::Hardware => {
                let digest = Sha256::digest(message);
                let signature = self.run_tpm(true, |tpm| {
                    load_sign_flush(tpm, &row.private_blob, &row.public_blob, &digest)
                })?;
                out.copy_from_slice(&signature);
            }
            SecurityLevel::Sealed => {
                let mut scalar = self.run_tpm(true, |tpm| {
                    load_unseal_flush(tpm, &row.private_blob, &row.public_blob)
                })?;
                let signing_key = SigningKey::from_slice(&scalar)
                    .map_err(|e| BackendError::KeyLoss(format!("unsealed scalar is invalid: {e}")));
                scalar.zeroize();
                let signing_key = signing_key?;
                let signature: p256::ecdsa::Signature = signing_key.sign(message);
                out.copy_from_slice(&signature.to_bytes());
            }
            other => {
                return Err(BackendError::Internal(format!(
                    "stored key claims the unsupported level {other}"
                )));
            }
        }

        Ok(Signature::P256(out))
    }

    async fn destroy(&self, owner: &Owner, key_id: &KeyId) -> Result<(), BackendError> {
        let result = tpm_keys::Entity::delete_by_id(row_id(owner, key_id))
            .exec(&self.db)
            .await
            .map_err(|e| map_db_error("deleting TPM key", e))?;
        if result.rows_affected == 0 {
            return Err(BackendError::UnknownKey);
        }
        Ok(())
    }
}

/// Load, sign, and always flush the child handle — the firmware TPM has only a
/// handful of transient slots.
fn load_sign_flush(
    tpm: &mut Tpm,
    private: &[u8],
    public: &[u8],
    digest: &[u8],
) -> Result<[u8; 64], TpmError> {
    let parent = tpm.storage_parent()?;
    let handle = tpm.load(parent, private, public)?;
    sign_and_flush(tpm, handle, digest)
}

fn sign_and_flush(tpm: &mut Tpm, handle: u32, digest: &[u8]) -> Result<[u8; 64], TpmError> {
    let signature = tpm.sign_digest(handle, digest);
    // Release the slot even if signing failed; the handle is worthless after.
    let _ = tpm.flush_context(handle);
    signature
}

/// Load a sealed object, unseal it, and flush the handle.
fn load_unseal_flush(tpm: &mut Tpm, private: &[u8], public: &[u8]) -> Result<Vec<u8>, TpmError> {
    let parent = tpm.storage_parent()?;
    let handle = tpm.load(parent, private, public)?;
    let data = tpm.unseal(handle);
    let _ = tpm.flush_context(handle);
    data
}

/// Derive the fingerprint (33-byte SEC1 compressed) from a TPM `TPMT_PUBLIC`.
fn key_id_from_public(public: &[u8]) -> Result<KeyId, BackendError> {
    let (x, y) =
        tpm2::ecc_public_point(public).map_err(|e| BackendError::Internal(e.to_string()))?;
    if x.len() > 32 || y.len() > 32 {
        return Err(BackendError::Internal(
            "the TPM returned an over-wide ECC coordinate".into(),
        ));
    }
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[33 - x.len()..33].copy_from_slice(&x);
    sec1[65 - y.len()..].copy_from_slice(&y);
    let verifying = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|e| BackendError::Internal(format!("TPM public key is not on P-256: {e}")))?;
    let point = verifying.as_affine().to_sec1_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(point.as_bytes());
    Ok(KeyId::P256(out))
}

/// Draw a software P-256 scalar and derive its compressed public key.
fn generate_software_key() -> Result<([u8; 32], KeyId), BackendError> {
    for _ in 0..16 {
        let mut scalar = [0u8; 32];
        getrandom::fill(&mut scalar)
            .map_err(|e| BackendError::Internal(format!("drawing randomness: {e}")))?;
        if let Ok(signing_key) = SigningKey::from_slice(&scalar) {
            let point = signing_key.verifying_key().as_affine().to_sec1_point(true);
            let mut pubkey = [0u8; 33];
            pubkey.copy_from_slice(point.as_bytes());
            return Ok((scalar, KeyId::P256(pubkey)));
        }
    }
    Err(BackendError::Internal(
        "failed to draw a valid P-256 scalar in 16 attempts".into(),
    ))
}

/// Map a TPM failure whose cause may be a *stored* key into the taxonomy.
///
/// While reloading an existing key, an integrity or handle failure means the
/// wrapped blob no longer matches the (recreated) parent: the key is lost and
/// the caller must re-pair. During provisioning the same codes are bugs.
fn map_tpm_error(error: TpmError, reloading: bool) -> BackendError {
    match error {
        TpmError::Unavailable(message) => BackendError::Unavailable(message),
        TpmError::Integrity(message) | TpmError::Handle(message) if reloading => {
            BackendError::KeyLoss(message)
        }
        other => BackendError::Internal(other.to_string()),
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
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The digest the daemon must sign for the documented Tunnel Weaver
    /// transcript. It is the same value the macOS and Windows backends signed
    /// (protocol §10: hash the message exactly once, then sign the digest).
    #[test]
    fn the_documented_transcript_hashes_to_the_shared_digest() {
        let mut transcript = b"weaver-mux-v1".to_vec();
        transcript.extend(std::iter::repeat_n(1u8, 32));
        transcript.extend(std::iter::repeat_n(2u8, 32));
        transcript.extend_from_slice(b"example.com");
        assert_eq!(transcript.len(), 88);
        let digest = Sha256::digest(&transcript);
        assert_eq!(
            hex::encode(digest),
            "258a08d914a68d453682a14fc6cdd60e5ae7e1dca124106e42d86fe160da21c0"
        );
    }
}
