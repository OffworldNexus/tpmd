//! The daemon's view of its backend's store, shared by every connection.
//!
//! A store that a client is waiting on is *the* reason this exists: the daemon
//! has to notice a keychain unlocking or a collection coming back, and it has to
//! do that without asking the client to poll and without one probe loop per
//! parked connection.
//!
//! Two rules shape it:
//!
//! * **One watcher per backend.** Ten parked clients must not mean ten detectors,
//!   so the detector is a single task per process, started on demand.
//! * **No probing when nobody is waiting.** The detector stops as soon as it has
//!   nothing to tell and no listeners; a daemon with no parked clients polls
//!   nothing at all.
//!
//! Only a [`StoreStatus::Closed`] store is ever waited on. A store that is `Open`
//! answers immediately, and one that is `Gone` is answered with a failure — the
//! whole point of the distinction being that nothing anyone does brings a gone
//! dependency back, so parking on it would be a hang dressed up as patience.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::watch;
use tpmd_backend::{Backend, BackendError, StoreStatus};

/// How often to look again when a backend offers no hints of its own.
///
/// A backend that *does* offer hints is woken by its platform instead; this is
/// the floor for everything else, and it is a fallback rather than the mechanism.
const FALLBACK_INTERVAL: Duration = Duration::from_millis(500);

/// A shared, self-updating view of the store, and the detector that updates it.
pub(crate) struct StoreWatch {
    backend: Arc<dyn Backend>,
    status: watch::Sender<StoreStatus>,
    /// True while a detector task is running, so there is never more than one.
    detecting: Mutex<bool>,
}

impl StoreWatch {
    /// Begin watching `backend`, starting from what it already reports.
    pub(crate) fn new(backend: Arc<dyn Backend>) -> Arc<Self> {
        let status = backend.store_status();
        let (sender, _receiver) = watch::channel(status);
        Arc::new(Self {
            backend,
            status: sender,
            detecting: Mutex::new(false),
        })
    }

    /// What the store is doing, as last observed.
    pub(crate) fn status(&self) -> StoreStatus {
        self.status.borrow().clone()
    }

    /// Record an observation someone else already made — typically a backend
    /// that has just been refused by its store mid-operation, which is how the
    /// daemon learns the store closed without asking.
    pub(crate) fn note(&self, status: StoreStatus) {
        // A send failure only means nobody is subscribed; the value is kept for
        // whoever comes next.
        let _ = self.status.send(status);
    }

    /// Resolve once the store can serve, or once it is clear it never will.
    ///
    /// Returns immediately when the store is open (there is nothing to wait for)
    /// and when it is gone (there is nothing to wait *for* — see the module
    /// docs); it parks only on a closed store, which is the one state the user can
    /// change.
    pub(crate) async fn wait_until_open(self: &Arc<Self>) -> StoreStatus {
        if !self.status().is_waitable() {
            return self.status();
        }
        self.ensure_detecting();

        let mut receiver = self.status.subscribe();
        loop {
            if !receiver.borrow().is_waitable() {
                return receiver.borrow().clone();
            }
            if receiver.changed().await.is_err() {
                // Every sender is gone, which cannot happen while we hold one.
                // Answer with what we know rather than spin.
                return self.status();
            }
        }
    }

    /// Start the detector unless one is already running.
    fn ensure_detecting(self: &Arc<Self>) {
        {
            let mut detecting = self
                .detecting
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if *detecting {
                return;
            }
            *detecting = true;
        }

        let watch = Arc::clone(self);
        tokio::spawn(async move {
            // The platform's own hint source where it has one; an interval where
            // it does not. Either way the daemon *probes* after every hint: a hint
            // is an opportunity to check, never a promise.
            let hints = watch.backend.unlock_hints();
            loop {
                match &hints {
                    Some(hints) => hints.next_hint().await,
                    None => tokio::time::sleep(FALLBACK_INTERVAL).await,
                }

                let observed = watch.backend.probe_store().await;
                let settling = observed.is_waitable();
                watch.note(observed);

                // Open (tell everyone) or gone (tell everyone, once): either way
                // there is nothing left to watch for.
                if !settling {
                    break;
                }
                // Nobody is listening any more — a new waiter will start a new
                // detector, so stopping is free.
                if watch.status.receiver_count() == 0 {
                    break;
                }
            }
            *watch
                .detecting
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = false;
        });
    }
}

/// Map an observed store status onto the error a client is owed.
///
/// The two failure classes are deliberately different, because a client can
/// retry one and cannot meaningfully retry the other.
pub(crate) fn store_error(status: &StoreStatus) -> BackendError {
    match status {
        StoreStatus::Open => {
            BackendError::Internal("asked for the error of an open store".to_owned())
        }
        StoreStatus::Closed(reason) => BackendError::StoreLocked(reason.clone()),
        StoreStatus::Gone(reason) => BackendError::Unavailable(reason.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tpmd_backend::{Owner, UnlockHints};
    use tpmd_proto::{Algorithm, KeyId, KeyInfo, SecurityLevel, Signature};

    /// A backend whose store state the test drives by hand.
    struct ScriptedStore {
        status: Mutex<StoreStatus>,
        /// What the next probe should find.
        next: Mutex<StoreStatus>,
        probes: Arc<AtomicUsize>,
    }

    impl ScriptedStore {
        fn new(status: StoreStatus, next: StoreStatus, probes: Arc<AtomicUsize>) -> Self {
            Self {
                status: Mutex::new(status),
                next: Mutex::new(next),
                probes,
            }
        }
    }

    #[async_trait]
    impl Backend for ScriptedStore {
        fn name(&self) -> &'static str {
            "scripted"
        }
        fn algorithms(&self) -> &'static [Algorithm] {
            &[Algorithm::EcdsaP256Sha256]
        }
        fn levels(&self) -> &'static [SecurityLevel] {
            &[SecurityLevel::File]
        }
        fn store_status(&self) -> StoreStatus {
            self.status
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
        async fn probe_store(&self) -> StoreStatus {
            self.probes.fetch_add(1, Ordering::Relaxed);
            let next = self
                .next
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            *self
                .status
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = next.clone();
            next
        }
        fn unlock_hints(&self) -> Option<Arc<dyn UnlockHints>> {
            /// Resolves immediately, so a test never waits on time.
            struct Immediately;
            #[async_trait]
            impl UnlockHints for Immediately {
                async fn next_hint(&self) {}
            }
            Some(Arc::new(Immediately))
        }
        async fn provision(
            &self,
            _owner: &Owner,
            _algorithm: Algorithm,
            _level: SecurityLevel,
        ) -> Result<KeyInfo, BackendError> {
            unimplemented!()
        }
        async fn identify(&self, _owner: &Owner, _key_id: &KeyId) -> Result<KeyInfo, BackendError> {
            unimplemented!()
        }
        async fn sign(
            &self,
            _owner: &Owner,
            _key_id: &KeyId,
            _message: &[u8],
        ) -> Result<Signature, BackendError> {
            unimplemented!()
        }
        async fn destroy(&self, _owner: &Owner, _key_id: &KeyId) -> Result<(), BackendError> {
            unimplemented!()
        }
    }

    fn scripted(current: StoreStatus, next: StoreStatus) -> (Arc<StoreWatch>, Arc<AtomicUsize>) {
        let probes = Arc::new(AtomicUsize::new(0));
        let backend: Arc<dyn Backend> =
            Arc::new(ScriptedStore::new(current, next, Arc::clone(&probes)));
        (StoreWatch::new(backend), probes)
    }

    /// The common case has to be free: an open store answers at once, and a
    /// watcher must not start a detector it does not need.
    #[tokio::test]
    async fn an_open_store_is_answered_without_waiting() {
        let (watch, probes) = scripted(StoreStatus::Open, StoreStatus::Open);
        assert_eq!(watch.wait_until_open().await, StoreStatus::Open);
        assert_eq!(probes.load(Ordering::Relaxed), 0, "no probe was needed");
    }

    /// The case this exists for: a closed store, woken by the platform's hint.
    #[tokio::test]
    async fn a_closed_store_is_waited_on_until_it_opens() {
        let (watch, probes) = scripted(StoreStatus::Closed("locked".into()), StoreStatus::Open);
        assert_eq!(watch.wait_until_open().await, StoreStatus::Open);
        assert!(
            probes.load(Ordering::Relaxed) >= 1,
            "the store was asked again"
        );
    }

    /// A dependency that is gone must never park anybody: waiting could not help,
    /// and a hang dressed up as patience is the failure this distinction exists to
    /// prevent.
    #[tokio::test]
    async fn a_gone_store_is_never_waited_on() {
        let (watch, probes) = scripted(StoreStatus::Gone("no bus".into()), StoreStatus::Open);
        assert!(matches!(
            watch.wait_until_open().await,
            StoreStatus::Gone(_)
        ));
        assert_eq!(probes.load(Ordering::Relaxed), 0, "nothing to check");
    }

    /// A store that closes *while* a client waits, and then turns out to be gone,
    /// must release the waiter rather than leave it parked for ever.
    #[tokio::test]
    async fn a_waiter_is_released_when_the_store_turns_out_to_be_gone() {
        let (watch, _probes) = scripted(
            StoreStatus::Closed("locked".into()),
            StoreStatus::Gone("the provider went away".into()),
        );
        assert!(matches!(
            watch.wait_until_open().await,
            StoreStatus::Gone(_)
        ));
    }

    /// What a client is told must let it decide whether to try again.
    #[test]
    fn the_two_failure_classes_are_different_errors() {
        assert!(matches!(
            store_error(&StoreStatus::Closed("locked".into())),
            BackendError::StoreLocked(_)
        ));
        assert!(matches!(
            store_error(&StoreStatus::Gone("no bus".into())),
            BackendError::Unavailable(_)
        ));
    }
}
