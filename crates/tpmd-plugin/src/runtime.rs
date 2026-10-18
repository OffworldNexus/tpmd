//! A backend that runs on a runtime of its own.
//!
//! A plugin is a `cdylib`, and a `cdylib` links its own copies of its
//! dependencies: in one process there are then two `tokio`s, two `sqlx`es and two
//! `sea-orm`s, and neither half knows the other is there. A runtime context is a
//! thread-local **of the crate that set it**, so a daemon thread standing in the
//! daemon's runtime is, to the plugin's copy of `tokio`, a thread with no runtime
//! at all. `sqlx` refuses exactly that — from inside a `cdylib` frame, where the
//! refusal stops being a catchable panic and becomes an abort of the whole
//! daemon:
//!
//! ```text
//! panicked at sqlx-core/src/pool/inner.rs: this functionality requires a Tokio context
//! fatal runtime error: Rust cannot catch foreign exceptions, aborting
//! ```
//!
//! So no plugin code is ever driven by the daemon's threads. Each plugin gives
//! itself a runtime, every call the daemon makes is *spawned* on it, and the
//! answer comes back through a channel: the daemon's thread only waits on the
//! channel, and the plugin's own `tokio` sees a runtime of its own kind around
//! every line it runs. [`own`] is that wrapper, and `export_backend!` installs it,
//! so a shim still reads as the one line it always was.
//!
//! The alternative — the daemon owning the store and a plugin owning only the
//! mechanism — was not taken: the store is not a detail this boundary can hide.
//! `keyring` and `linux-tpm` both read *and write* the shared SQLite file, so
//! moving it out would rewrite both backends and the trait they implement, to
//! solve a problem that is really about which thread a future is polled on.
//!
//! A plugin nobody asks anything of builds no runtime: it is made on the first
//! call, once, and shared by every backend that plugin opens.

use std::future::Future;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::oneshot;
use tpmd_backend::{Backend, BackendError, BackendFactory, Owner, StoreStatus, UnlockHints};
use tpmd_proto::{Algorithm, KeyId, KeyInfo, SecurityLevel, Signature};

/// The runtime a plugin's own code is driven on.
#[derive(Default)]
struct Own {
    /// `Err` is a host that cannot start a thread at all. Kept rather than
    /// retried because it cannot change while this process lives.
    runtime: OnceLock<Result<Arc<Runtime>, String>>,
}

impl Own {
    fn get(&self) -> Result<Arc<Runtime>, BackendError> {
        match self.runtime.get_or_init(build) {
            Ok(runtime) => Ok(Arc::clone(runtime)),
            Err(why) => Err(BackendError::Internal(format!(
                "the backend's own runtime could not be started: {why}"
            ))),
        }
    }
}

/// Build the plugin's runtime, on a thread of its own.
///
/// Building it beside a runtime the daemon is standing in would put the plugin's
/// worker threads in the world of a thread that is already somebody else's; a
/// thread that is nobody's costs one spawn and removes the question.
///
/// The default number of worker threads, not one: plugin code spawns tasks of its
/// own and then waits for them (the keyring's unlock hints spawn a bus watcher and
/// wait for what it says), and a single worker would deadlock on that.
fn build() -> Result<Arc<Runtime>, String> {
    std::thread::spawn(|| {
        Builder::new_multi_thread()
            .enable_all()
            .thread_name("tpmd-plugin")
            .build()
            .map(Arc::new)
            .map_err(|error| error.to_string())
    })
    .join()
    .unwrap_or_else(|_| Err("the thread building it did not finish".to_owned()))
}

/// Run one operation on the plugin's runtime, and bring the answer back.
async fn on<T, F>(runtime: &Arc<Runtime>, work: F) -> Result<T, BackendError>
where
    T: Send + 'static,
    F: Future<Output = Result<T, BackendError>> + Send + 'static,
{
    let (sender, receiver) = oneshot::channel();
    runtime.spawn(async move {
        // A receiver that has gone away means the daemon stopped waiting. The
        // answer has nowhere to go, and losing it is not worth panicking over
        // from inside a `cdylib`.
        let _ = sender.send(work.await);
    });
    match receiver.await {
        Ok(answer) => answer,
        Err(_) => Err(BackendError::Internal(
            "the backend's own runtime dropped the operation".to_owned(),
        )),
    }
}

/// Ask the plugin's runtime a question whose answer is not a `Result`.
async fn on_status<F>(runtime: &Arc<Runtime>, work: F) -> StoreStatus
where
    F: Future<Output = StoreStatus> + Send + 'static,
{
    let (sender, receiver) = oneshot::channel();
    runtime.spawn(async move {
        let _ = sender.send(work.await);
    });
    match receiver.await {
        Ok(status) => status,
        // If the plugin's own runtime cannot answer, nothing about the store is
        // knowable — the backend is unreachable, which is not the same as locked.
        Err(_) => StoreStatus::Gone("the backend's own runtime dropped the probe".to_owned()),
    }
}

/// A plugin's factory, wrapped so that what it opens is driven on the plugin's
/// own runtime. This is what `export_backend!` installs.
pub struct OwnedFactory<F> {
    inner: Arc<F>,
    own: Arc<Own>,
}

/// Wrap `factory` so that everything it produces runs on this plugin's runtime.
pub fn own<F>(factory: F) -> OwnedFactory<F>
where
    F: BackendFactory + 'static,
{
    OwnedFactory {
        inner: Arc::new(factory),
        own: Arc::new(Own::default()),
    }
}

#[async_trait]
impl<F> BackendFactory for OwnedFactory<F>
where
    F: BackendFactory + 'static,
{
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    async fn open(&self, state_dir: &Path) -> Result<Box<dyn Backend>, BackendError> {
        let runtime = self.own.get()?;
        let factory = Arc::clone(&self.inner);
        let dir = state_dir.to_owned();
        let backend = on(&runtime, async move { factory.open(&dir).await }).await?;
        Ok(Box::new(OwnedBackend {
            inner: Arc::from(backend),
            runtime,
        }))
    }
}

/// A backend that belongs to the plugin, and is only ever reached on the
/// plugin's runtime.
struct OwnedBackend {
    inner: Arc<dyn Backend>,
    runtime: Arc<Runtime>,
}

#[async_trait]
impl Backend for OwnedBackend {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn algorithms(&self) -> &'static [Algorithm] {
        self.inner.algorithms()
    }

    fn levels(&self) -> &'static [SecurityLevel] {
        self.inner.levels()
    }

    fn can_be_used(&self) -> bool {
        self.inner.can_be_used()
    }

    fn store_status(&self) -> StoreStatus {
        self.inner.store_status()
    }

    async fn probe_store(&self) -> StoreStatus {
        let backend = Arc::clone(&self.inner);
        on_status(&self.runtime, async move { backend.probe_store().await }).await
    }

    fn unlock_hints(&self) -> Option<Arc<dyn UnlockHints>> {
        Some(Arc::new(OwnedHints {
            inner: self.inner.unlock_hints()?,
            runtime: Arc::clone(&self.runtime),
        }))
    }

    fn default_level(&self) -> SecurityLevel {
        self.inner.default_level()
    }

    fn store_mechanism(&self) -> Option<&'static str> {
        self.inner.store_mechanism()
    }

    fn forced_when_unusable(&self) -> bool {
        self.inner.forced_when_unusable()
    }

    async fn provision(
        &self,
        owner: &Owner,
        algorithm: Algorithm,
        level: SecurityLevel,
    ) -> Result<KeyInfo, BackendError> {
        let backend = Arc::clone(&self.inner);
        let owner = owner.clone();
        on(&self.runtime, async move {
            backend.provision(&owner, algorithm, level).await
        })
        .await
    }

    async fn identify(&self, owner: &Owner, key_id: &KeyId) -> Result<KeyInfo, BackendError> {
        let backend = Arc::clone(&self.inner);
        let owner = owner.clone();
        let key_id = *key_id;
        on(&self.runtime, async move {
            backend.identify(&owner, &key_id).await
        })
        .await
    }

    async fn sign(
        &self,
        owner: &Owner,
        key_id: &KeyId,
        message: &[u8],
    ) -> Result<Signature, BackendError> {
        let backend = Arc::clone(&self.inner);
        let owner = owner.clone();
        let key_id = *key_id;
        let message = message.to_vec();
        on(&self.runtime, async move {
            backend.sign(&owner, &key_id, &message).await
        })
        .await
    }

    async fn destroy(&self, owner: &Owner, key_id: &KeyId) -> Result<(), BackendError> {
        let backend = Arc::clone(&self.inner);
        let owner = owner.clone();
        let key_id = *key_id;
        on(&self.runtime, async move {
            backend.destroy(&owner, &key_id).await
        })
        .await
    }
}

/// The plugin's own unlock-hint provider, waited for on the plugin's runtime.
struct OwnedHints {
    inner: Arc<dyn UnlockHints>,
    runtime: Arc<Runtime>,
}

#[async_trait]
impl UnlockHints for OwnedHints {
    async fn next_hint(&self) {
        let inner = Arc::clone(&self.inner);
        let (sender, receiver) = oneshot::channel();
        self.runtime.spawn(async move {
            inner.next_hint().await;
            let _ = sender.send(());
        });
        // A dropped answer needs no error to carry: the only thing a hint says is
        // "look again", and the daemon looks again on its own interval anyway.
        let _ = receiver.await;
    }
}
