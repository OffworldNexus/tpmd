//! Creates the `tpm_keys` table used by the Linux TPM backend.

use sea_orm_migration::prelude::*;

/// The migration.
pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260101_000002_create_tpm_keys"
    }
}

/// Same addressing as `keys`, but `secret` is split into a wrapped
/// `private_blob` (a TPM object, never a plaintext scalar) and a
/// backend-defined `public_blob`.
const UP: &str = "
CREATE TABLE IF NOT EXISTS tpm_keys (
    principal    TEXT    NOT NULL,
    namespace    TEXT    NOT NULL,
    key_id       BLOB    NOT NULL,
    algorithm    INTEGER NOT NULL,
    level        INTEGER NOT NULL,
    private_blob BLOB    NOT NULL,
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
            .execute_unprepared("DROP TABLE IF EXISTS tpm_keys;")
            .await?;
        Ok(())
    }
}
