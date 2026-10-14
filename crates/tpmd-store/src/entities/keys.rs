//! The `keys` table: software P-256 keys owned by the dummy backend.
//!
//! The private scalar lives in `secret` in the clear; the row is protected
//! only by the container's filesystem permissions. This is the `file` level.

use sea_orm::entity::prelude::*;

/// One stored software key.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "keys")]
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
    /// The raw 32-byte P-256 private scalar.
    pub secret: Vec<u8>,
    /// Creation time, seconds since the Unix epoch.
    pub created_unix: i64,
}

/// No foreign keys: keys are addressed directly, never enumerated.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
