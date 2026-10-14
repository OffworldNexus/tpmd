//! Creates the `cng_keys` table used by the Windows CNG backend.

use sea_orm_migration::prelude::*;

/// The migration.
pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260101_000003_create_cng_keys"
    }
}

/// Same addressing as `keys`, but the private key remains in the TPM through
/// the Platform Crypto Provider, and `key_name` maps the fingerprint to it.
const UP: &str = "
CREATE TABLE IF NOT EXISTS cng_keys (
    principal    TEXT    NOT NULL,
    namespace    TEXT    NOT NULL,
    key_id       BLOB    NOT NULL,
    algorithm    INTEGER NOT NULL,
    level        INTEGER NOT NULL,
    key_name     TEXT    NOT NULL,
    public_blob  BLOB    NOT NULL,
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
            .execute_unprepared("DROP TABLE IF EXISTS cng_keys;")
            .await?;
        Ok(())
    }
}
