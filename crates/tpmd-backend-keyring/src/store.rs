//! The platform seam: which credential store this build talks to.
//!
//! Exactly one store is compiled into any given build, chosen by target OS, so
//! the rest of the backend is written once against [`CredentialStore`]. This
//! module is the only place that knows a platform exists.
//!
//! The three stores are the ones the [`crate`] documentation promises:
//!
//! | OS      | Store                             | Credential store   |
//! | ------- | --------------------------------- | ------------------ |
//! | Linux   | Secret Service over the session bus | login collection   |
//! | macOS   | login keychain                    | Aqua session       |
//! | Windows | Credential Manager                | loaded user profile |
//!
//! The Linux *kernel* keyring is deliberately not among them: it dies with
//! logout and reboot, which is the storage class this security level exists to
//! rule out.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use keyring_core::{CredentialStore, Error as KeyringError};
use tpmd_backend::{StoreStatus, UnlockHints};

/// The service every tpmd credential is filed under.
///
/// The distinguishing half of a key's address is the *user*, which carries the
/// whole `(principal, namespace, key_id)` triple (see [`crate::address`]).
pub(crate) const SERVICE: &str = "tpmd";

/// The user an availability probe reads under.
///
/// A probe only ever *reads*, and a read of a credential that does not exist is
/// the ordinary answer on every store, so probing can never create, modify or
/// lock anything.
const PROBE_USER: &str = "tpmd.probe";

/// Store-specific modifiers to use when creating an entry.
///
/// Windows needs one. Its Credential Manager defaults to **Enterprise**
/// persistence, which roams with a roaming profile — and a device identity must
/// not roam, because it identifies *this* machine. So the one thing this backend
/// asks for is **Local** persistence: per-machine, non-roaming.
///
/// **There is no fallback, deliberately.** A logon session with no profile-backed
/// credential manager answers `ERROR_NO_SUCH_LOGON_SESSION` to durable
/// persistence, and taking `Session` instead would silently change what the
/// `keyring` level promises: the key would evaporate at logoff, the device would
/// return as a stranger needing re-pairing, and nothing but a line in a
/// background service's log would say so. A refusal is reported instead — and it
/// is [`StoreStatus::Gone`], not `Closed`, because nothing the user does inside
/// that session changes it (see [`refusal_status`]).
///
/// The Secret Service and Apple stores take no modifiers.
pub(crate) const fn entry_modifiers() -> &'static [(&'static str, &'static str)] {
    #[cfg(target_os = "windows")]
    {
        &[("persistence", "Local")]
    }
    #[cfg(not(target_os = "windows"))]
    {
        &[]
    }
}

/// What the write context calls the custody being asked for, so a refusal names
/// it and an operator can search the reason rather than guess at it.
pub(crate) const fn write_context() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "writing the credential with local persistence"
    }
    #[cfg(not(target_os = "windows"))]
    {
        "writing the credential"
    }
}

/// The hint provider for a store there is nothing to subscribe to.
///
/// Honest about what it is: an interval, not an event. macOS and Windows offer no
/// notification for a keychain or a profile becoming usable, so the only way to
/// notice is to ask again — and the daemon asks after *every* hint regardless, so
/// a missed hint costs latency, never correctness.
///
/// The interval backs off, because a user who has walked away should not cost a
/// probe every half second for an hour, and it stays capped so somebody who has
/// just come back is noticed promptly.
#[cfg(not(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
)))]
mod interval {
    use super::*;
    use std::sync::Mutex;

    /// The interval-backed provider, for platforms with nothing to watch.
    pub(crate) struct IntervalHints {
        next: Mutex<Duration>,
    }
    impl IntervalHints {
        /// First check after half a second: long enough not to hammer a store that
        /// is locked while the screen is still locked, short enough to feel
        /// immediate once it is not.
        const FIRST: Duration = Duration::from_millis(500);

        /// Ten seconds, so a daemon parked for a long time costs almost nothing.
        const CAP: Duration = Duration::from_secs(10);
    }

    impl Default for IntervalHints {
        fn default() -> Self {
            Self {
                next: Mutex::new(Self::FIRST),
            }
        }
    }

    #[async_trait]
    impl UnlockHints for IntervalHints {
        async fn next_hint(&self) {
            let wait = {
                let mut next = self
                    .next
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let wait = *next;
                *next = (*next * 2).min(Self::CAP);
                wait
            };
            tokio::time::sleep(wait).await;
        }
    }
}

#[cfg(not(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
)))]
pub(crate) use interval::IntervalHints;

/// The underlying store's name, as reported in `tpmd status` and the logs.
pub(crate) fn mechanism() -> &'static str {
    #[cfg(all(
        unix,
        not(any(target_os = "macos", target_os = "ios", target_os = "android"))
    ))]
    {
        "secret-service"
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        "login-keychain"
    }
    #[cfg(target_os = "windows")]
    {
        "credential-manager"
    }
    #[cfg(not(any(
        all(
            unix,
            not(any(target_os = "macos", target_os = "ios", target_os = "android"))
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "windows",
    )))]
    {
        "none"
    }
}

/// Build the credential store for this platform.
///
/// **Blocking.** On Linux this opens a connection to the session bus, so it
/// must be called from a blocking context, never from an async executor thread.
pub(crate) fn platform_store() -> Result<Arc<CredentialStore>, StoreStatus> {
    #[cfg(all(
        unix,
        not(any(target_os = "macos", target_os = "ios", target_os = "android"))
    ))]
    {
        let store: Arc<CredentialStore> =
            zbus_secret_service_keyring_store::Store::new().map_err(unreachable_status)?;
        Ok(store)
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        let store: Arc<CredentialStore> =
            apple_native_keyring_store::keychain::Store::new().map_err(unreachable_status)?;
        Ok(store)
    }
    #[cfg(target_os = "windows")]
    {
        let store: Arc<CredentialStore> =
            windows_native_keyring_store::Store::new().map_err(unreachable_status)?;
        Ok(store)
    }
    #[cfg(not(any(
        all(
            unix,
            not(any(target_os = "macos", target_os = "ios", target_os = "android"))
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "windows",
    )))]
    Err(StoreStatus::Gone(format!(
        "no {} credential store is implemented for this platform",
        mechanism()
    )))
}

/// Ask the store a single read-only question, and classify the answer.
///
/// **Blocking** for the same reason as [`platform_store`].
///
/// Read-only on purpose: this is asked whenever a client is waiting, and a probe
/// that created, modified or deleted anything would be a side effect on a store
/// that may not even be ours.
///
/// The classification is the whole point, because it decides whether a client is
/// parked on this store or told to give up:
///
/// * **Answers at all** — including "no such credential", which is the ordinary
///   state before a key exists — is [`StoreStatus::Open`].
/// * **`NoStorageAccess`** is [`StoreStatus::Closed`]: the store is there and
///   locked, and unlocking it is something the *user* can do.
/// * **Anything else** is classified by [`refusal_status`], which differs per
///   platform because the remedies do.
pub(crate) fn probe_status(store: &CredentialStore) -> StoreStatus {
    let Ok(entry) = store.build(SERVICE, PROBE_USER, None) else {
        return StoreStatus::Gone(format!(
            "the {} store refused to name a credential",
            mechanism()
        ));
    };
    match entry.get_secret() {
        Ok(_) | Err(KeyringError::NoEntry) => StoreStatus::Open,
        Err(KeyringError::NoStorageAccess(_)) => {
            StoreStatus::Closed("the store is locked".to_owned())
        }
        Err(other) => refusal_status(&other.to_string()),
    }
}

/// What a refusal means for waiting, which is a per-platform question because the
/// remedies are.
///
/// macOS and Linux refuse a locked keychain or collection with an authorization
/// error, and the *user* unlocking either is a normal thing that happens — so a
/// refusal there is worth waiting for, and is [`StoreStatus::Closed`].
///
/// Windows is the odd one, and the reason this is not a single global rule: a
/// refused credential write there means the logon session has no profile-backed
/// credential manager. Nothing the user does *inside this session* changes that,
/// so it is [`StoreStatus::Gone`] — the store is reachable, but it will never
/// hold this key while this daemon lives. WVR-149 owns the fix, which is starting
/// the agent in a session that can.
pub(crate) fn refusal_status(reason: &str) -> StoreStatus {
    #[cfg(target_os = "windows")]
    {
        StoreStatus::Gone(reason.to_owned())
    }
    #[cfg(not(target_os = "windows"))]
    {
        StoreStatus::Closed(reason.to_owned())
    }
}

/// The store could not be built at all, so its dependency is not there.
///
/// [`StoreStatus::Gone`], not `Closed`: on Linux this is "no session bus to talk
/// to", on Windows "no provider to open", and neither is something the user
/// changes from inside a running session. A *locked* store does not come through
/// here — building one succeeds; only the probe finds it shut.
pub(crate) fn unreachable_status(error: KeyringError) -> StoreStatus {
    StoreStatus::Gone(format!("the {} store is unreachable: {error}", mechanism()))
}

/// The platform's way of noticing the store *might* have opened.
///
/// Linux gets a real event; the others get an interval (see [`IntervalHints`]).
pub(crate) fn unlock_hints() -> Arc<dyn UnlockHints> {
    #[cfg(all(
        unix,
        not(any(target_os = "macos", target_os = "ios", target_os = "android"))
    ))]
    {
        Arc::new(SecretServiceHints::default())
    }
    #[cfg(not(all(
        unix,
        not(any(target_os = "macos", target_os = "ios", target_os = "android"))
    )))]
    {
        Arc::new(IntervalHints::default())
    }
}

/// The Secret Service, watched through the session bus.
///
/// Two real events are worth waking on, and neither needs the signal's contents:
///
/// * **The service appearing or disappearing** — `NameOwnerChanged` for
///   `org.freedesktop.secrets`, which is what a keyring daemon starting or dying
///   looks like.
/// * **A collection changing** — `PropertiesChanged` on the default collection,
///   which is what an unlock looks like. Any property change counts, because a
///   hint is only an opportunity to look again and the daemon probes afterwards;
///   parsing the payload would buy nothing.
///
/// There is also a **safety net**: the bus can be quiet in ways we did not
/// anticipate (a missed signal, a collection we could not resolve, a daemon that
/// reports unlocking some other way), and a hint provider that never fires would
/// park a client for ever. So a timer wakes us too, and it is short enough to
/// bound the latency of the case we care about most.
#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
))]
#[derive(Default)]
pub(crate) struct SecretServiceHints {
    /// The signal stream, built on first use and kept: re-subscribing on every
    /// hint would leave a window in which an unlock could be missed.
    wakeups: tokio::sync::Mutex<Option<tokio::sync::mpsc::Receiver<()>>>,
}

#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
))]
impl SecretServiceHints {
    /// How long to wait before looking anyway.
    ///
    /// A last resort, not the mechanism: the bus signal should fire in
    /// milliseconds, and this bounds how long a *missed* one can cost.
    const SAFETY_NET: Duration = Duration::from_secs(5);

    /// The bus watcher, started once.
    async fn receiver(&self) -> tokio::sync::mpsc::Receiver<()> {
        let mut slot = self.wakeups.lock().await;
        if slot.is_none() {
            *slot = Some(spawn_bus_watcher().await);
        }
        slot.take().expect("just filled")
    }

    /// Put the receiver back so the next wait reuses the same subscription.
    async fn keep(&self, receiver: tokio::sync::mpsc::Receiver<()>) {
        *self.wakeups.lock().await = Some(receiver);
    }
}

#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
))]
#[async_trait]
impl UnlockHints for SecretServiceHints {
    async fn next_hint(&self) {
        let mut receiver = self.receiver().await;
        // Either the bus tells us something, or we look anyway.
        let _ = tokio::time::timeout(Self::SAFETY_NET, receiver.recv()).await;
        self.keep(receiver).await;
    }
}

/// Subscribe to the two bus signals, and forward each to a channel.
///
/// If the bus cannot be reached at all, the watcher degrades to a slow tick: the
/// store is gone anyway in that case, so the hint only has to keep the daemon
/// curious rather than prompt.
#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
))]
async fn spawn_bus_watcher() -> tokio::sync::mpsc::Receiver<()> {
    use futures_util::StreamExt as _;

    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        // Nothing to subscribe to if there is no bus: tick slowly instead, so the
        // daemon still looks on its own. (The store is `Gone` in that case, so a
        // prompt hint buys nothing — only the promise that we keep looking.)
        let Ok(connection) = zbus::Connection::session().await else {
            while sender.send(()).await.is_ok() {
                tokio::time::sleep(SLOW_TICK).await;
            }
            return;
        };

        let mut streams: Vec<zbus::proxy::SignalStream<'static>> = Vec::new();

        // The service appearing or going away. Asked for by name so the bus does
        // the filtering — otherwise every name change on the session would wake us
        // for a probe we did not need.
        if let Ok(bus) = zbus::Proxy::new(
            &connection,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
        )
        .await
            && let Ok(names) = bus
                .receive_signal_with_args("NameOwnerChanged", &[(0, SECRETS_SERVICE)])
                .await
        {
            streams.push(names);
        }

        // A collection changing, which is what an unlock looks like. Best effort:
        // without it we still have the service signal and the safety net.
        if let Some(path) = default_collection(&connection).await
            && let Ok(proxy) = zbus::Proxy::new(
                &connection,
                SECRETS_SERVICE,
                path.as_str(),
                "org.freedesktop.Secret.Collection",
            )
            .await
        {
            // Anything that changes the collection's state — including `Locked`,
            // which is the unlock we are really after — comes through as a
            // property change.
            if let Ok(properties) = proxy.receive_signal("PropertiesChanged").await {
                streams.push(properties);
            }
            // …and anything that changes its contents. Not a re-opening as such,
            // but it is a change to the store, and a hint costs one cheap read:
            // waking too often is affordable, sleeping through a real change is
            // not.
            for signal in ["ItemCreated", "ItemDeleted"] {
                if let Ok(changes) = proxy.receive_signal(signal).await {
                    streams.push(changes);
                }
            }
        }

        if streams.is_empty() {
            while sender.send(()).await.is_ok() {
                tokio::time::sleep(SLOW_TICK).await;
            }
            return;
        }

        // One stream out of however many we managed to subscribe to.
        let mut signals = futures_util::stream::select_all(streams);
        while signals.next().await.is_some() {
            if sender.send(()).await.is_err() {
                return;
            }
        }
    });
    receiver
}

/// How long to wait between hints when there is no bus to watch.
#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
))]
const SLOW_TICK: Duration = Duration::from_secs(30);

/// The path of the default collection, if the Secret Service will name it.
#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
))]
async fn default_collection(
    connection: &zbus::Connection,
) -> Option<zbus::zvariant::OwnedObjectPath> {
    let proxy = zbus::Proxy::new(
        connection,
        SECRETS_SERVICE,
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await
    .ok()?;
    proxy
        .call::<_, _, zbus::zvariant::OwnedObjectPath>("ReadAlias", &("default",))
        .await
        .ok()
}

/// The well-known name of the Secret Service on the session bus.
#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
))]
const SECRETS_SERVICE: &str = "org.freedesktop.secrets";
