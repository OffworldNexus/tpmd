//! The `cng_keys` table: TPM-backed keys owned by the Windows CNG backend.
//!
//! No plaintext private material is ever written here. The private key lives in
//! the TPM via the Platform Crypto Provider; this row records the CNG key name
//! that maps to the fingerprint.

use sea_orm::entity::prelude::*;

/// One stored Windows CNG-backed key.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "cng_keys")]
pub struct Model {
    /// Authenticated OS principal, e.g. `sid:S-1-5-...`.
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
    /// CNG key name that identifies the TPM-resident private key.
    pub key_name: String,
    /// Backend-specific public material needed to reload the key.
    pub public_blob: Vec<u8>,
    /// Creation time, seconds since the Unix epoch.
    pub created_unix: i64,
}

/// No foreign keys: keys are addressed directly, never enumerated.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
