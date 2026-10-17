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

use keyring_core::{CredentialStore, Error as KeyringError};
use tpmd_backend::BackendError;

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

/// Store-specific modifiers for creating an entry, where the platform needs any.
///
/// Windows needs one. Its Credential Manager defaults to **Enterprise**
/// persistence, which roams with a roaming profile — and a device identity must
/// not roam, because it identifies *this* machine. So the one thing this backend
/// asks for is **Local** persistence: per-machine, non-roaming.
///
/// What happens when a host will not grant it is deliberately *not* handled by
/// asking for something weaker. A logon session with no profile-backed credential
/// manager — a Task Scheduler- or service-started process, which is how the
/// Windows agent runs — answers `ERROR_NO_SUCH_LOGON_SESSION` to durable
/// persistence, and taking `Session` instead would silently change the promise
/// the `keyring` level makes: the key would evaporate at logoff and the device
/// would come back as a stranger, needing re-pairing, with nothing but a log line
/// to explain it. So the refusal is reported to the caller as `store_locked` and
/// the operator fixes *how the agent is started*.
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
pub(crate) fn platform_store() -> Result<Arc<CredentialStore>, BackendError> {
    #[cfg(all(
        unix,
        not(any(target_os = "macos", target_os = "ios", target_os = "android"))
    ))]
    {
        let store: Arc<CredentialStore> =
            zbus_secret_service_keyring_store::Store::new().map_err(unreachable)?;
        Ok(store)
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        let store: Arc<CredentialStore> =
            apple_native_keyring_store::keychain::Store::new().map_err(unreachable)?;
        Ok(store)
    }
    #[cfg(target_os = "windows")]
    {
        let store: Arc<CredentialStore> =
            windows_native_keyring_store::Store::new().map_err(unreachable)?;
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
    Err(BackendError::StoreLocked(format!(
        "no {} credential store is implemented for this platform",
        mechanism()
    )))
}

/// Ask the store a single read-only question: can it answer at all here?
///
/// **Blocking** for the same reason as [`platform_store`].
///
/// A store that answers "no such credential" is *usable*: the credential being
/// absent is the normal state before a key exists. Only a store that cannot
/// answer at all — no session bus, no reachable keychain, no loaded profile —
/// makes the backend unusable, so selection falls to the next rung instead of
/// serving a backend whose every operation would fail.
///
/// A store that is *locked* answers `NoStorageAccess`; that counts as usable
/// here, because the protocol has a dedicated class for it (`store_locked`) and
/// reporting it is more useful than silently dropping to a weaker store.
pub(crate) fn probe(store: &CredentialStore) -> bool {
    let Ok(entry) = store.build(SERVICE, PROBE_USER, None) else {
        return false;
    };
    match entry.get_secret() {
        Ok(_) | Err(KeyringError::NoEntry) | Err(KeyringError::NoStorageAccess(_)) => true,
        Err(_) => false,
    }
}

/// The store could not be opened, so it is locked for our purposes.
///
/// `store_locked` — not `unavailable` — because the condition is "the storage
/// that holds the keys exists but cannot be reached right now", which is
/// exactly the distinction the protocol draws, and which callers may retry.
fn unreachable(error: KeyringError) -> BackendError {
    BackendError::StoreLocked(format!("the {} store is unreachable: {error}", mechanism()))
}
