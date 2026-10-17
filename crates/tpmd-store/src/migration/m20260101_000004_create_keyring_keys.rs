//! Creates the `keyring_keys` table used by the OS credential store backend.

use sea_orm_migration::prelude::*;

/// The migration.
pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260101_000004_create_keyring_keys"
    }
}

/// Same addressing as `keys`, but the private scalar stays in the operating
/// system's credential store, and `key_name` maps the fingerprint to it.
const UP: &str = "
CREATE TABLE IF NOT EXISTS keyring_keys (
    principal    TEXT    NOT NULL,
    namespace    TEXT    NOT NULL,
    key_id       BLOB    NOT NULL,
    algorithm    INTEGER NOT NULL,
    level        INTEGER NOT NULL,
    key_name     TEXT    NOT NULL,
    created_unix INTEGER NOT NULL,
    PRIMARY KEY (principal, namespace, key_id)
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
            .execute_unprepared("DROP TABLE IF EXISTS keyring_keys;")
            .await?;
        Ok(())
    }
}
