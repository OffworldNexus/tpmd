//! The Windows CNG backend: P-256 keys held by the TPM through the Microsoft
//! Platform Crypto Provider, at security level `hardware`.
//!
//! There is deliberately no `sealed` rung here. The only honest hardware claim
//! Windows gives us is a non-exportable, TPM-backed Platform Crypto Provider
//! key; a DPAPI-protected software key is *not* sealing, so it is never
//! reported as one. The provider is asked what actually backs a key and that
//! answer decides the level — never the provider's name.
//!
//! Keys are **per-user**, and the agent runs in the owning user's interactive
//! session — the same shape as the macOS LaunchAgent and the Linux user mode.
//! The ticket's evidence shows why this has to be verified and not assumed:
//! opening the provider succeeds over a network logon (WinRM) while *creating*
//! a user key there is refused, so [`cng::Platform::probe`] exercises a whole
//! create-sign-delete cycle at startup.
//!
//! The whole crate compiles to nothing off Windows, so a Linux or macOS build
//! never links a byte of it.

#![cfg(target_os = "windows")]
#![deny(unsafe_code)]
#![warn(missing_docs)]

mod cng;
mod ffi;

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use async_trait::async_trait;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, Set};
use sha2::{Digest as _, Sha256};
use tpmd_backend::{Backend, BackendError, Owner};
use tpmd_proto::{Algorithm, KeyId, KeyInfo, SecurityLevel, Signature};
use tpmd_store::entities::cng_keys;
use tpmd_store::map_db_error;

use crate::cng::{CustodyError, Platform};
use crate::ffi::CngError;

/// The only security level this backend can reach.
const LEVELS: &[SecurityLevel] = &[SecurityLevel::Hardware];

/// The only algorithm this backend offers.
const ALGORITHMS: &[Algorithm] = &[Algorithm::EcdsaP256Sha256];

/// A user's private P-256 keys, held by the TPM through CNG.
///
/// The provider handle is opened once and used behind a mutex: CNG handles are
/// not safe to use concurrently.
pub struct WindowsCngBackend {
    db: DatabaseConnection,
    db_path: PathBuf,
    /// `None` when this host has no Platform Crypto Provider at all. Kept
    /// alongside `usable` because a provider can be present yet unusable for
    /// this user or logon type.
    platform: Mutex<Option<Platform>>,
    /// Whether the startup probe proved ordinary-user key custody works here.
    usable: bool,
}

impl WindowsCngBackend {
    /// Open the store and probe the provider.
    ///
    /// Neither a missing provider nor a failed probe is an opening *error*:
    /// usability is reported through [`Backend::can_be_used`] so the registry
    /// can select another backend instead of the daemon failing to start.
    pub async fn open(state_dir: &Path) -> Result<Self, BackendError> {
        let db = tpmd_store::open(state_dir).await?;

        let (platform, usable) = match Platform::open() {
            Ok(opened) => {
                let usable = opened.probe();
                if !usable {
                    tracing::info!(
                        "the Platform Crypto Provider cannot create a user key here \
                         (an interactive session and a live TPM 2.0 are required)"
                    );
                }
                (Some(opened), usable)
            }
            Err(error) => {
                tracing::info!(%error, "no Platform Crypto Provider on this host");
                (None, false)
            }
        };

        Ok(Self {
            db,
            db_path: tpmd_store::database_path(state_dir),
            platform: Mutex::new(platform),
            usable,
        })
    }

    /// The database path, for diagnostics.
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    fn lock(&self) -> Result<MutexGuard<'_, Option<Platform>>, BackendError> {
        self.platform
            .lock()
            .map_err(|_| BackendError::Internal("CNG provider mutex was poisoned".into()))
    }

    /// Best-effort removal of a native key, used when provisioning has to be
    /// rolled back.
    fn destroy_native(&self, name: &str) {
        if let Ok(guard) = self.lock()
            && let Some(platform) = guard.as_ref()
            && let Ok(key) = platform.open_key(name)
            && let Err(error) = platform.delete(key)
        {
            tracing::warn!(%error, name, "could not roll back a native key");
        }
    }

    async fn row(&self, owner: &Owner, key_id: &KeyId) -> Result<cng_keys::Model, BackendError> {
        cng_keys::Entity::find_by_id(row_id(owner, key_id))
            .one(&self.db)
            .await
            .map_err(|e| map_db_error("querying CNG key", e))?
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

/// Derive the fingerprint from an `EccPublicBlob`, validating the point.
fn derive_key_id(blob: &[u8]) -> Result<KeyId, BackendError> {
    let sec1 = cng::sec1_from_ecc_public_blob(blob)
        .map_err(|error| BackendError::Internal(error.to_string()))?;
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).map_err(|error| {
        BackendError::Internal(format!(
            "CNG returned a public key that is not on P-256: {error}"
        ))
    })?;
    Ok(KeyId::P256(sec1))
}

/// A non-custodial key is not a policy mismatch: the caller asked for hardware
/// and there simply is none here. The key has already been destroyed.
fn map_custody(error: CustodyError) -> BackendError {
    BackendError::Unavailable(format!("{error}"))
}

/// Map a CNG failure while creating a key.
fn map_create(error: CngError) -> BackendError {
    if error.is_access_denied() || error.code() == ffi::nte::DEVICE_NOT_READY {
        BackendError::Unavailable(format!("{error}"))
    } else {
        BackendError::Internal(format!("{error}"))
    }
}

/// Map a CNG failure while using a stored key.
///
/// A row whose native key has vanished is **key loss** (the caller must
/// re-pair), while a refusal by the session or the device is a transient
/// unavailability — the protocol keeps the two apart on purpose.
fn map_key_op(error: CngError) -> BackendError {
    if error.is_missing() {
        BackendError::KeyLoss(format!("the stored CNG key is gone: {error}"))
    } else if error.is_access_denied() {
        BackendError::Unavailable(format!("{error}"))
    } else {
        BackendError::Internal(format!("{error}"))
    }
}

#[async_trait]
impl Backend for WindowsCngBackend {
    fn name(&self) -> &'static str {
        "windows-cng"
    }

    fn algorithms(&self) -> &'static [Algorithm] {
        ALGORITHMS
    }

    fn levels(&self) -> &'static [SecurityLevel] {
        LEVELS
    }

    fn can_be_used(&self) -> bool {
        self.usable
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
            // The daemon only ever passes a level this backend advertised;
            // reaching here is a genuine mismatch, so refuse rather than
            // silently weaken the policy.
            return Err(BackendError::IncompatiblePolicy {
                required: level,
                available: SecurityLevel::Hardware,
            });
        }

        let name = cng::new_key_name().map_err(map_create)?;
        let created_unix = now_unix();

        // Create, verify custody and read the public half under one lock; the
        // handle is released afterwards (the key itself stays in the store).
        let (key_id, public_blob, private_export_refused) = {
            let guard = self.lock()?;
            let platform = guard.as_ref().ok_or_else(|| {
                BackendError::Unavailable("no Platform Crypto Provider on this host".into())
            })?;
            let key = platform.create_custodial_key(&name).map_err(map_custody)?;
            let refused = cng::private_export_is_refused(key.raw());
            let blob = platform.public_blob(key.raw()).map_err(map_key_op)?;
            let key_id = derive_key_id(&blob)?;
            drop(key);
            (key_id, blob, refused)
        };

        if !private_export_refused {
            // The custody we advertise did not hold. Take the key back out and
            // refuse, rather than hand out a fingerprint we cannot back.
            self.destroy_native(&name);
            return Err(BackendError::Unavailable(
                "the Platform Crypto Provider exported a private key; refusing to call it hardware"
                    .into(),
            ));
        }

        let (principal, namespace, id) = row_id(owner, &key_id);
        cng_keys::ActiveModel {
            principal: Set(principal),
            namespace: Set(namespace),
            key_id: Set(id),
            algorithm: Set(algorithm_index(algorithm)),
            level: Set(level_index(level)),
            key_name: Set(name),
            public_blob: Set(public_blob),
            created_unix: Set(created_unix),
        }
        .insert(&self.db)
        .await
        .map_err(|e| map_db_error("inserting CNG key", e))?;

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
        let digest = Sha256::digest(message);

        let signature = {
            let guard = self.lock()?;
            let platform = guard.as_ref().ok_or_else(|| {
                BackendError::Unavailable("no Platform Crypto Provider on this host".into())
            })?;
            let key = platform.open_key(&row.key_name).map_err(map_key_op)?;
            platform.sign(key.raw(), &digest).map_err(map_key_op)?
        };

        Ok(Signature::P256(signature))
    }

    async fn destroy(&self, owner: &Owner, key_id: &KeyId) -> Result<(), BackendError> {
        let row = self.row(owner, key_id).await?;
        // Remove the native key first: a row without its key is key loss, but a
        // key without its row is an orphan the caller can never address again.
        self.destroy_native(&row.key_name);

        let result = cng_keys::Entity::delete_by_id(row_id(owner, key_id))
            .exec(&self.db)
            .await
            .map_err(|e| map_db_error("deleting CNG key", e))?;
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
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_are_hardware_only() {
        assert_eq!(LEVELS, &[SecurityLevel::Hardware]);
    }

    /// The digest signed for the documented Tunnel Weaver transcript: the same
    /// value the macOS, Windows-CNG-probe and Linux TPM runs produced.
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
    fn a_missing_key_maps_to_key_loss_and_denial_to_unavailable() {
        assert!(matches!(
            map_key_op(CngError::Status {
                operation: "NCryptOpenKey",
                code: ffi::nte::BAD_KEYSET
            }),
            BackendError::KeyLoss(_)
        ));
        assert!(matches!(
            map_key_op(CngError::Status {
                operation: "NCryptOpenKey",
                code: ffi::nte::PERM
            }),
            BackendError::Unavailable(_)
        ));
    }
}
