//! Reading and writing the `settings` table.
//!
//! Small on purpose: a setting is a name and an opaque blob. What the blob
//! *means* belongs to whoever wrote it — today, the daemon's backend selection —
//! so this crate stays a catalogue of storage mechanisms rather than a home for
//! policy.

use sea_orm::{DatabaseConnection, EntityTrait, Set};

use crate::entities::settings;
use crate::map_db_error;

/// Read a setting, if it has ever been written.
///
/// # Errors
///
/// Any store failure, as `store_locked` or `internal` per [`map_db_error`].
pub async fn get(
    db: &DatabaseConnection,
    key: &str,
) -> Result<Option<Vec<u8>>, tpmd_backend::BackendError> {
    let row = settings::Entity::find_by_id(key.to_owned())
        .one(db)
        .await
        .map_err(|error| map_db_error("reading a setting", error))?;
    Ok(row.map(|row| row.value))
}

/// Write a setting, replacing any value it already had.
///
/// One statement, so a reader never sees a half-written setting: the row is
/// either the old value or the new one. `INSERT OR REPLACE` is what makes that
/// true without a transaction around a delete and an insert.
///
/// # Errors
///
/// Any store failure, as `store_locked` or `internal` per [`map_db_error`].
pub async fn put(
    db: &DatabaseConnection,
    key: &str,
    value: &[u8],
) -> Result<(), tpmd_backend::BackendError> {
    use sea_orm::sea_query::OnConflict;

    settings::Entity::insert(settings::ActiveModel {
        key: Set(key.to_owned()),
        value: Set(value.to_vec()),
    })
    .on_conflict(
        OnConflict::column(settings::Column::Key)
            .update_column(settings::Column::Value)
            .to_owned(),
    )
    .exec(db)
    .await
    .map_err(|error| map_db_error("writing a setting", error))?;
    Ok(())
}

/// Remove a setting, if it is there.
///
/// Absent is success: "forget this" is satisfied by its absence.
///
/// # Errors
///
/// Any store failure, as `store_locked` or `internal` per [`map_db_error`].
pub async fn remove(db: &DatabaseConnection, key: &str) -> Result<(), tpmd_backend::BackendError> {
    settings::Entity::delete_by_id(key.to_owned())
        .exec(db)
        .await
        .map_err(|error| map_db_error("removing a setting", error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn store() -> (tempfile::TempDir, DatabaseConnection) {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::open(dir.path()).await.unwrap();
        (dir, db)
    }

    #[tokio::test]
    async fn a_setting_round_trips() {
        let (_dir, db) = store().await;
        assert_eq!(get(&db, "nothing.here").await.unwrap(), None);

        put(&db, "backend.selection", b"\x01\x02opaque")
            .await
            .unwrap();
        assert_eq!(
            get(&db, "backend.selection").await.unwrap().as_deref(),
            Some(b"\x01\x02opaque".as_slice()),
            "the value is opaque: this crate must not interpret it"
        );
    }

    /// Rewriting is the common case (the selection is reconsidered by an
    /// administrator), so it must replace rather than collide on the primary key.
    #[tokio::test]
    async fn writing_twice_replaces_the_value() {
        let (_dir, db) = store().await;
        put(&db, "k", b"first").await.unwrap();
        put(&db, "k", b"second").await.unwrap();
        assert_eq!(
            get(&db, "k").await.unwrap().as_deref(),
            Some(b"second".as_slice())
        );
        assert_eq!(
            settings::Entity::find().all(&db).await.unwrap().len(),
            1,
            "replacing a setting must not leave the old row behind"
        );
    }

    #[tokio::test]
    async fn removing_a_setting_forgets_it() {
        let (_dir, db) = store().await;
        put(&db, "k", b"v").await.unwrap();
        remove(&db, "k").await.unwrap();
        assert_eq!(get(&db, "k").await.unwrap(), None);
        // Removing what is not there is success, not an error.
        remove(&db, "k").await.unwrap();
    }
}
