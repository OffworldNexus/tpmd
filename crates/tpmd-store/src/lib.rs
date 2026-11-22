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

use sea_orm::sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sea_orm::{DatabaseConnection, SqlxSqliteConnector};
use sea_orm_migration::MigratorTrait as _;
use tpmd_backend::BackendError;
use tpmd_ipc::secure_fs;

pub mod entities;
pub mod migration;
pub mod settings;

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
    // The store knows its own path, so it hands SQLite the path itself rather
    // than a `sqlite://` URL built from it: a URL round-trip cannot represent
    // every filesystem path faithfully, and `url` 2.5.9 now rejects a Windows
    // path's backslashes (`sqlite://C:\...`) as an invalid port. With
    // `SqliteConnectOptions` there is no percent-encoding, no parser and no
    // failed parse to route around, on any platform.
    let sqlite = SqliteConnectOptions::new()
        .filename(&db_path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal);
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(sqlite)
        .await
        .map_err(|e| map_db_error("opening the store", e))?;
    let db = SqlxSqliteConnector::from_sqlx_sqlite_pool(pool);

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

/// Map a store failure onto the backend's error taxonomy.
///
/// A busy/locked database is a *transient* condition the caller can retry, not
/// a corrupt store, so it must not be reported as an internal error: the
/// protocol keeps `store_locked` distinct from `internal` on purpose.
///
/// Takes any error that can render itself because the store's failures arrive
/// in two shapes: SeaORM's `DbErr` from queries and migrations, and sqlx's
/// `Error` from opening the pool before a `DbErr` exists.
#[must_use]
pub fn map_db_error(context: &str, error: impl std::fmt::Display) -> BackendError {
    let message = error.to_string();
    let lowered = message.to_ascii_lowercase();
    if lowered.contains("database is locked") || lowered.contains("table is locked") {
        BackendError::StoreLocked(format!("{context}: {message}"))
    } else {
        BackendError::Internal(format!("{context}: {message}"))
    }
}
