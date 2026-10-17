//! The SeaORM migration set that owns the shared store's schema.
//!
//! Migrations are the *only* thing that creates tables, so the schema has one
//! versioned home. Each migration uses raw SQL rather than the schema builder
//! because SQLite's `WITHOUT ROWID` (a real space and lookup win for these
//! narrow, composite-primary-key tables) cannot be expressed by the builder.

pub mod m20260101_000001_create_keys;
pub mod m20260101_000002_create_tpm_keys;
pub mod m20260101_000003_create_cng_keys;
pub mod m20260101_000004_create_keyring_keys;
pub mod m20260101_000005_create_settings;
pub mod m20260101_000006_create_se_keys;

use sea_orm_migration::prelude::*;

/// The migrator the backends run on open.
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260101_000001_create_keys::Migration),
            Box::new(m20260101_000002_create_tpm_keys::Migration),
            Box::new(m20260101_000003_create_cng_keys::Migration),
            Box::new(m20260101_000004_create_keyring_keys::Migration),
            Box::new(m20260101_000005_create_settings::Migration),
            Box::new(m20260101_000006_create_se_keys::Migration),
        ]
    }
}
