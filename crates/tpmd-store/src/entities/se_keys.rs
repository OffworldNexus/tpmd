//! The `se_keys` table: Secure Enclave keys owned by the macOS backend.
//!
//! No private material is ever written here — it never leaves the enclave, and
//! there is no operation that could copy it out. This row records the keychain
//! label that maps a fingerprint back to the key, so a restarted agent can find
//! the key again.

use sea_orm::entity::prelude::*;

/// One stored Secure Enclave key.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "se_keys")]
pub struct Model {
    /// Authenticated OS principal, e.g. `uid:501`.
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
    /// Keychain label identifying the enclave-resident private key.
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
