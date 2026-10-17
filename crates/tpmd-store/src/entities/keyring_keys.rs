//! The `keyring_keys` table: keys held by the OS credential store backend.
//!
//! No private material is ever written here. The scalar lives in the platform
//! credential store (Secret Service, the login keychain or the Credential
//! Manager); this row records the entry address that maps the fingerprint to
//! it, plus the metadata the protocol reports.

use sea_orm::entity::prelude::*;

/// One stored OS-credential-store key.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "keyring_keys")]
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
    /// The credential store entry this key's scalar lives in.
    ///
    /// Recorded rather than recomputed on read, so keys written by an older
    /// build survive a change to the addressing scheme — and so destroying a
    /// key cannot miss the credential.
    pub key_name: String,
    /// Creation time, seconds since the Unix epoch.
    pub created_unix: i64,
}

/// No foreign keys: keys are addressed directly, never enumerated.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
