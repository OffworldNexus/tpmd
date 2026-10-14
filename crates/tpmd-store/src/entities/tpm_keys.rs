//! The `tpm_keys` table: TPM-backed keys owned by the Linux TPM backend.
//!
//! Unlike `keys`, no plaintext private material is ever written here. The
//! `private_blob` is a TPM-wrapped object: for the `hardware` level it is the
//! duplicable-nowhere child private blob, and for the `sealed` level it is the
//! blob sealing a software scalar. `public_blob` holds what the backend needs
//! to reconstruct the public key (the TPM2B_PUBLIC, or the SEC1 bytes).

use sea_orm::entity::prelude::*;

/// One stored TPM-backed key.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "tpm_keys")]
pub struct Model {
    /// Authenticated OS principal, e.g. `uid:1000`.
    #[sea_orm(primary_key, auto_increment = false)]
    pub principal: String,
    /// Application namespace declared in `HELLO`.
    #[sea_orm(primary_key, auto_increment = false)]
    pub namespace: String,
    /// The 33-byte SEC1-compressed public key, i.e. the fingerprint.
    #[sea_orm(primary_key, auto_increment = false)]
    pub key_id: Vec<u8>,
    /// Wire index of the [`tpmd_proto::Algorithm`].
    pub algorithm: i64,
    /// Wire index of the [`tpmd_proto::SecurityLevel`] actually achieved.
    pub level: i64,
    /// TPM-wrapped private blob (never a plaintext scalar).
    pub private_blob: Vec<u8>,
    /// Backend-specific public material needed to reload the key.
    pub public_blob: Vec<u8>,
    /// Creation time, seconds since the Unix epoch.
    pub created_unix: i64,
}

/// No foreign keys: keys are addressed directly, never enumerated.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
