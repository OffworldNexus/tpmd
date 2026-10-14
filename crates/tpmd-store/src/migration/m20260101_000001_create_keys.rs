//! Creates the `keys` table used by the dummy (`file`) backend.

use sea_orm_migration::prelude::*;

/// The migration.
pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260101_000001_create_keys"
    }
}

/// `IF NOT EXISTS` is deliberate: stores created by the pre-SeaORM daemon
/// already contain this exact table but carry no `seaql_migrations` row, so
/// this migration must be a no-op for them while still being recorded.
const UP: &str = "
CREATE TABLE IF NOT EXISTS keys (
    principal    TEXT    NOT NULL,
    namespace    TEXT    NOT NULL,
    key_id       BLOB    NOT NULL,
    algorithm    INTEGER NOT NULL,
    level        INTEGER NOT NULL,
    secret       BLOB    NOT NULL,
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
            .execute_unprepared("DROP TABLE IF EXISTS keys;")
            .await?;
        Ok(())
    }
}
