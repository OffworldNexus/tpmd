//! The `settings` table: small, structured values the daemon keeps for itself.
//!
//! Stored in the same SQLite file as every key, so it inherits the same
//! protection (`0700` directory, `0600` file) and the same single migration set —
//! there is one store, and it holds both the keys and the notes about them. The
//! value is a blob because callers may hand it something structured; see
//! [`crate::settings`] for the accessors.

use sea_orm::entity::prelude::*;

/// One setting.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "settings")]
pub struct Model {
    /// The setting's name, e.g. `"backend.selection"`.
    #[sea_orm(primary_key, auto_increment = false)]
    pub key: String,
    /// The setting's value, opaque to this crate.
    pub value: Vec<u8>,
}

/// No foreign keys: a setting stands alone.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
