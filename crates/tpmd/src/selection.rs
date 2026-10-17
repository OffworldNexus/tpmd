//! Remembering which backend this machine chose — and never changing it by itself.
//!
//! The daemon used to re-run the backend ladder on **every** start, so the store
//! serving a device could change without anyone deciding it should. That is a
//! custody change, and it can be an *identity* change: a different store means a
//! different key, which means pairing again. Today it can happen because a
//! keychain happened to be locked when the daemon started.
//!
//! So the choice is made once, written to the shared store, and left alone. A
//! store that closes produces the non-fatal `closed` answer; a dependency that
//! disappears produces `backend_unavailable` — both on the *remembered* backend.
//! Only an administrator changes it, deliberately, and the verb that does so says
//! what it costs.
//!
//! Two subtleties are load-bearing:
//!
//! * **A closed rung is a candidate, not a skip.** Otherwise the first start —
//!   which usually happens at logon, before the user has unlocked anything —
//!   would permanently commit a plaintext store as this machine's identity.
//! * **The choice is committed on first successful *use*, not at open.** Opening a
//!   backend only proves it can be probed; committing then would record a choice
//!   at a moment nothing had actually served.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize};
use tpmd_backend::BackendError;
use tracing::warn;

/// The name the record lives under in the `settings` table.
pub(crate) const RECORD_KEY: &str = "backend.selection";

/// What was chosen, and enough context to understand it later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectionRecord {
    /// The backend's name, as used by `--backend` and `status`.
    pub backend: String,
    /// When it was chosen, Unix seconds.
    pub chosen_unix: i64,
    /// Why: who chose it, and what won.
    pub reason: String,
    /// What was passed over at that moment, and why — the ladder's own account of
    /// itself, kept because "why this backend?" is a question an administrator
    /// asks long after the fact.
    pub skipped: Vec<(String, String)>,
}

impl SelectionRecord {
    /// Encode for the settings table.
    ///
    /// `postcard` and the daemon already share this vocabulary, and a record with
    /// prose in it would be misery to store as text: the reasons contain colons,
    /// commas and whatever the platform told us.
    pub(crate) fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("a selection record always encodes")
    }

    /// Decode what was written by a previous run.
    ///
    /// A record we cannot read is not a reason to refuse to serve: it is reported,
    /// and the admin is told, because silently choosing something else is exactly
    /// the behaviour this module exists to stop.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, BackendError> {
        postcard::from_bytes(bytes).map_err(|error| {
            BackendError::Internal(format!(
                "the recorded backend selection is unreadable: {error}"
            ))
        })
    }
}

/// The record, as it is read, written and forgotten.
#[derive(Clone)]
pub struct SelectionStore {
    db: DatabaseConnection,
}

impl SelectionStore {
    /// Use the shared store.
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// What this machine chose, if it has ever chosen.
    ///
    /// # Errors
    ///
    /// A store that cannot be read. An unreadable *record* is reported too, rather
    /// than papered over: quietly choosing something else is the behaviour this
    /// module exists to stop.
    pub async fn read(&self) -> Result<Option<SelectionRecord>, BackendError> {
        match tpmd_store::settings::get(&self.db, RECORD_KEY).await? {
            Some(bytes) => SelectionRecord::decode(&bytes).map(Some),
            None => Ok(None),
        }
    }

    /// Remember a choice.
    ///
    /// # Errors
    ///
    /// A store that cannot be written.
    pub async fn write(&self, record: &SelectionRecord) -> Result<(), BackendError> {
        tpmd_store::settings::put(&self.db, RECORD_KEY, &record.encode()).await
    }

    /// Forget it, returning the next start to the ladder.
    ///
    /// # Errors
    ///
    /// A store that cannot be written.
    pub async fn clear(&self) -> Result<(), BackendError> {
        tpmd_store::settings::remove(&self.db, RECORD_KEY).await
    }
}

/// Commits the choice made at startup, the first time the store actually serves.
pub(crate) struct SelectionRecorder {
    store: SelectionStore,
    inner: Mutex<Inner>,
}

/// The two halves of a choice's life.
#[derive(Default)]
struct Inner {
    /// The choice to commit, until something serves.
    pending: Option<SelectionRecord>,
    /// The choice once it is committed.
    committed: Option<SelectionRecord>,
}

impl SelectionRecorder {
    /// A choice that will be committed on first successful use.
    pub(crate) fn pending(store: SelectionStore, record: SelectionRecord) -> Self {
        Self {
            store,
            inner: Mutex::new(Inner {
                pending: Some(record),
                committed: None,
            }),
        }
    }

    /// The machine has already chosen: there is nothing to decide, and nothing to
    /// write. Kept so `status` can report the choice without reading the store on
    /// every request.
    pub(crate) fn settled(store: SelectionStore, record: SelectionRecord) -> Self {
        Self {
            store,
            inner: Mutex::new(Inner {
                pending: None,
                committed: Some(record),
            }),
        }
    }

    /// The committed choice, if there is one.
    pub(crate) fn committed(&self) -> Option<SelectionRecord> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .committed
            .clone()
    }

    /// Commit the pending choice, if there is one.
    ///
    /// Idempotent, and free after the first call. A store that fails here is not a
    /// reason to fail the operation that just succeeded — the key exists — but it
    /// does mean the choice is not remembered, so it is logged rather than
    /// swallowed: the next start will choose again, which the administrator should
    /// know about.
    pub(crate) async fn commit(&self) {
        let record = {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            inner.pending.take()
        };
        let Some(record) = record else {
            return;
        };
        match self.store.write(&record).await {
            Ok(()) => {
                self.inner
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .committed = Some(record);
            }
            Err(error) => warn!(
                backend = record.backend.as_str(),
                %error,
                "could not remember the backend selection; the next start will choose again"
            ),
        }
    }
}

/// Now, in the units the record uses.
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn store() -> (tempfile::TempDir, SelectionStore) {
        let dir = tempfile::tempdir().unwrap();
        let db = tpmd_store::open(dir.path()).await.unwrap();
        (dir, SelectionStore::new(db))
    }

    fn record(backend: &str) -> SelectionRecord {
        SelectionRecord {
            backend: backend.to_owned(),
            chosen_unix: 1_700_000_000,
            reason: "selected at first start: the strongest candidate".to_owned(),
            skipped: vec![("dummy".to_owned(), "a weaker store".to_owned())],
        }
    }

    #[tokio::test]
    async fn a_record_round_trips_through_the_store() {
        let (_dir, store) = store().await;
        assert_eq!(
            store.read().await.unwrap(),
            None,
            "a fresh machine has chosen nothing"
        );

        store.write(&record("keyring")).await.unwrap();
        assert_eq!(store.read().await.unwrap(), Some(record("keyring")));

        store.clear().await.unwrap();
        assert_eq!(store.read().await.unwrap(), None);
    }

    /// A record with prose in it must survive: the reasons carry whatever the
    /// platform said, colons and all.
    #[tokio::test]
    async fn a_reason_full_of_punctuation_survives() {
        let (_dir, store) = store().await;
        let awkward = SelectionRecord {
            backend: "keyring".to_owned(),
            chosen_unix: 1,
            reason: "chosen by administrator: \"keyring\", because linux-tpm: no device; see a=b"
                .to_owned(),
            skipped: vec![(
                "linux-tpm".to_owned(),
                "/dev/tpmrm0: Permission denied (os error 13)".to_owned(),
            )],
        };
        store.write(&awkward).await.unwrap();
        assert_eq!(store.read().await.unwrap(), Some(awkward));
    }

    /// The point of the recorder: opening a backend must not settle anything.
    #[tokio::test]
    async fn a_pending_choice_is_not_committed_until_something_serves() {
        let (_dir, store) = store().await;
        let recorder = SelectionRecorder::pending(store.clone(), record("dummy"));
        assert_eq!(
            store.read().await.unwrap(),
            None,
            "nothing may be committed merely because the daemon started"
        );

        recorder.commit().await;
        assert_eq!(store.read().await.unwrap(), Some(record("dummy")));

        // Idempotent: a second commit changes nothing.
        recorder.commit().await;
        assert_eq!(store.read().await.unwrap(), Some(record("dummy")));
    }

    /// A machine that has already chosen never commits again by itself, even if a
    /// pending choice were offered by mistake.
    #[tokio::test]
    async fn a_settled_recorder_commits_nothing() {
        let (_dir, store) = store().await;
        let settled_on = record("keyring");
        store.write(&settled_on).await.unwrap();
        SelectionRecorder::settled(store.clone(), settled_on.clone())
            .commit()
            .await;
        assert_eq!(
            store.read().await.unwrap(),
            Some(settled_on),
            "the record must be left exactly as it was"
        );
    }
}
