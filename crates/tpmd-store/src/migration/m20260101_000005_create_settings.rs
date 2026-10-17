//! Creates the `settings` table: the daemon's own small key/value store.
//!
//! Deliberately generic. The schema knows about *keys* and *values*, not about
//! what a value means: the daemon records its backend selection here, and nothing
//! in this crate needs to know that, which keeps the store a catalogue of
//! mechanisms rather than a home for policy.

use sea_orm_migration::prelude::*;

/// The migration.
pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260101_000005_create_settings"
    }
}

/// One row per setting. The value is a blob because a setting may be structured
/// (the selection record is `postcard`-encoded): a text column would have forced
/// the daemon to invent an escaping scheme.
const UP: &str = "
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT NOT NULL PRIMARY KEY,
    value BLOB NOT NULL
) WITHOUT ROWID;
";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared(UP).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS settings;")
            .await?;
        Ok(())
    }
}
