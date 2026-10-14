//! The shared SQLite store: one file, one migration set, one table per backend.
//!
//! Earlier revisions let each backend own its own database and its own raw
//! `rusqlite` handle. That did not scale: a device has several backends
//! available and the daemon selects one at runtime, so the schema needs a
//! single versioned home and the connections need to be cheap to clone. SeaORM
//! gives both — a `DatabaseConnection` is `Clone + Send + Sync`, and the
//! [`migration::Migrator`] is the only writer of DDL.
//!
//! Two properties are load-bearing and asserted by tests:
//!
//! * **Ownership.** Keys are addressed by `(principal, namespace, key_id)` in
//!   every table, so a lookup under the wrong owner is indistinguishable from
//!   a key that does not exist.
//! * **Protection.** The directory is `0700` and the database file `0600` (a
//!   protected owner-only DACL on Windows). WAL mode keeps a `-wal` and a
//!   `-shm` sidecar next to the database while it is open; both live in that
//!   `0700` directory, so they are protected by the same rule.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::{Path, PathBuf};

use sea_orm::sqlx::sqlite::SqliteJournalMode;
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use sea_orm_migration::MigratorTrait as _;
use tpmd_backend::BackendError;
use tpmd_ipc::secure_fs;

pub mod entities;
pub mod migration;

/// File name of the single SQLite database inside the state directory.
pub const DATABASE_FILE_NAME: &str = "keys.sqlite";

/// Path of the shared database inside `state_dir`.
#[must_use]
pub fn database_path(state_dir: &Path) -> PathBuf {
    state_dir.join(DATABASE_FILE_NAME)
}

/// Open (creating, protecting and migrating as needed) the shared store.
///
/// Safe to call from several backends in the same process: SQLite tolerates
/// multiple connections, and in WAL mode readers do not block the writer.
pub async fn open(state_dir: &Path) -> Result<DatabaseConnection, BackendError> {
    secure_fs::ensure_dir(state_dir)
        .map_err(|e| BackendError::Unavailable(format!("creating state dir: {e}")))?;

    let db_path = database_path(state_dir);
    // `?mode=rwc` makes sqlx create the file; `map_sqlx_sqlite_opts` is the
    // only supported seam for WAL, which cannot be requested through the URL
    // alone in a way we want to depend on.
    let mut options = ConnectOptions::new(format!("sqlite://{}?mode=rwc", db_path.display()));
    options.max_connections(5).map_sqlx_sqlite_opts(|sqlite| {
        sqlite
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
    });

    let db = Database::connect(options)
        .await
        .map_err(|e| map_db_error("opening the store", e))?;

    migration::Migrator::up(&db, None)
        .await
        .map_err(|e| map_db_error("migrating the store", e))?;

    // The file exists once connected; restrict it, and the WAL sidecars if
    // they already exist, before any key is written. The `0700` directory
    // covers them anyway, but matching modes costs nothing.
    secure_fs::restrict_file(&db_path).map_err(|e| {
        BackendError::Unavailable(format!("restricting {}: {e}", db_path.display()))
    })?;
    for suffix in ["-wal", "-shm"] {
        let mut name = db_path.clone().into_os_string();
        name.push(suffix);
        let sidecar = PathBuf::from(name);
        if sidecar.exists() {
            secure_fs::restrict_file(&sidecar).map_err(|e| {
                BackendError::Unavailable(format!("restricting {}: {e}", sidecar.display()))
            })?;
        }
    }

    Ok(db)
}

/// Map a SeaORM failure onto the backend's error taxonomy.
///
/// A busy/locked database is a *transient* condition the caller can retry, not
/// a corrupt store, so it must not be reported as an internal error: the
/// protocol keeps `store_locked` distinct from `internal` on purpose.
#[must_use]
pub fn map_db_error(context: &str, error: sea_orm::DbErr) -> BackendError {
    let message = error.to_string();
    let lowered = message.to_ascii_lowercase();
    if lowered.contains("database is locked") || lowered.contains("table is locked") {
        BackendError::StoreLocked(format!("{context}: {message}"))
    } else {
        BackendError::Internal(format!("{context}: {message}"))
    }
}
