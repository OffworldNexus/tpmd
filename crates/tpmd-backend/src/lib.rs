//! The storage-backend abstraction shared by the daemon and every backend.
//!
//! A backend is the *only* holder of private key material. The daemon selects
//! one backend at build time (per-mechanism crates, feature-gated) and drives
//! it through the object-safe [`Backend`] trait. This crate therefore has to
//! be a dependency of both the daemon and the backend crates, while the
//! backends must not depend on the daemon — hence a small dedicated crate
//! rather than putting the trait in the daemon.
//!
//! Backends are **async**: a backend call may touch a local store (via an
//! async ORM) or a hardware device, and the daemon already runs on Tokio. The
//! trait is object-safe through `async-trait` so the daemon can hold an
//! `Arc<dyn Backend>` regardless of which mechanism was selected.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;
use tpmd_proto::{Algorithm, KeyId, KeyInfo, SecurityLevel, Signature};

/// The OS principal the daemon authenticated for a connection.
///
/// On Unix this is derived from `SO_PEERCRED` (`"uid:1000"`); on Windows from
/// the named-pipe client's token SID (`"sid:S-1-5-..."`). The daemon fabricates
/// it; a client can never supply it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Principal(pub String);

impl Principal {
    /// The principal as a string, for logging and protocol messages.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for Principal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The full ownership of a stored key: which principal, in which namespace.
///
/// A backend must treat `(principal, namespace, key_id)` as the key's address,
/// and must not reveal whether a foreign key exists.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Owner {
    /// The authenticated OS principal.
    pub principal: Principal,
    /// The application namespace declared in `HELLO`.
    pub namespace: String,
}

impl Owner {
    /// Build an owner from a principal and namespace.
    pub fn new(principal: Principal, namespace: impl Into<String>) -> Self {
        Self {
            principal,
            namespace: namespace.into(),
        }
    }
}

/// What a backend can say about the store behind it.
///
/// A backend learns this **by being refused**, never by asking in advance: none
/// of the platforms we serve offers a change event we can rely on, so a status is
/// a cached observation, refreshed by a probe — or woken by an [`UnlockHints`]
/// provider where the platform has one.
///
/// The daemon maps these onto the wire: [`StoreStatus::Closed`] becomes the
/// non-fatal `closed` answer (worth waiting for), [`StoreStatus::Gone`] becomes a
/// fatal `reject` naming the backend unavailable. The distinction is who can
/// change it — the user, or nobody.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreStatus {
    /// The store answers; operations may proceed.
    Open,
    /// The store exists but will not answer yet. Something the *user* does can
    /// change that — unlocking a keychain, logging in — so it is worth waiting
    /// for rather than failing.
    Closed(String),
    /// The store's dependency is gone: no device to open, nothing to talk to.
    /// Nothing in this process's lifetime brings it back, and choosing another
    /// backend is an administrator's decision, never an automatic one.
    Gone(String),
}

impl StoreStatus {
    /// Whether operations may proceed right now.
    #[must_use]
    pub fn is_open(&self) -> bool {
        matches!(self, Self::Open)
    }

    /// Whether waiting could change anything. Only a *closed* store is waitable;
    /// a gone one is exactly the case a client must not be parked on.
    #[must_use]
    pub fn is_waitable(&self) -> bool {
        matches!(self, Self::Closed(_))
    }

    /// The reason, for logs and for the wire.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Open => None,
            Self::Closed(reason) | Self::Gone(reason) => Some(reason),
        }
    }
}

/// Something that can tell the daemon the store *might* be usable again.
///
/// Hints only, and never a substitute for probing: the daemon asks the store
/// after every hint, because a hint is an opportunity to check, not a promise.
/// The Linux Secret Service can raise a real one (a collection unlocking, or the
/// service reappearing on the bus); macOS and Windows have nothing to subscribe
/// to, so their implementations resolve after their own interval.
#[async_trait]
pub trait UnlockHints: Send + Sync {
    /// Resolve when the store may have become usable.
    async fn next_hint(&self);
}

/// A backend failure, mapped by the daemon onto the wire error taxonomy.
#[derive(Debug, Error)]
pub enum BackendError {
    /// The key does not exist, or is not owned by the caller. Deliberately a
    /// single variant so existence never leaks.
    #[error("unknown key")]
    UnknownKey,
    /// The requested algorithm is not supported by this backend.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(Algorithm),
    /// The requested security floor cannot be met by this backend.
    #[error("incompatible policy: required {required}, available {available}")]
    IncompatiblePolicy {
        /// The floor the caller requested.
        required: SecurityLevel,
        /// The strongest level the backend can actually offer.
        available: SecurityLevel,
    },
    /// The store exists but cannot be opened right now (locked, permissions).
    #[error("store locked: {0}")]
    StoreLocked(String),
    /// Key material was found but is unusable or lost.
    #[error("key loss: {0}")]
    KeyLoss(String),
    /// The backend could not be initialised or has disappeared.
    #[error("backend unavailable: {0}")]
    Unavailable(String),
    /// The request was semantically invalid.
    #[error("invalid request: {0}")]
    Invalid(String),
    /// Anything unexpected.
    #[error("internal backend error: {0}")]
    Internal(String),
}

/// A private-key store plus signing, addressed by principal and namespace.
///
/// The trait is object-safe so the daemon can select a mechanism at run time
/// and still drive it through one `Arc<dyn Backend>`.
#[async_trait]
pub trait Backend: Send + Sync {
    /// The backend's short name, e.g. `"dummy"`.
    fn name(&self) -> &'static str;

    /// Algorithms this backend can offer.
    fn algorithms(&self) -> &'static [Algorithm];

    /// Security levels this backend can achieve, weakest first.
    fn levels(&self) -> &'static [SecurityLevel];

    /// Whether this backend can actually be used on this machine right now.
    ///
    /// Selection needs to tell "compiled in" from "usable": a TPM backend is
    /// built on every Linux host but only works where a TPM device can be
    /// opened. Each backend proves this its own way; the default is a backend
    /// with no external dependency, which is usable wherever it builds.
    fn can_be_used(&self) -> bool {
        true
    }

    /// What the store behind this backend can do right now, from what the
    /// backend has already observed.
    ///
    /// Cheap and side-effect free: it must not touch the store. A backend with no
    /// store of its own — a file, a device — answers [`StoreStatus::Open`] and lets
    /// a failed operation say otherwise; one whose store can shut under it (a
    /// keychain, a credential store) records that here as it is refused.
    fn store_status(&self) -> StoreStatus {
        StoreStatus::Open
    }

    /// Ask the store whether it can serve, and remember the answer.
    ///
    /// **Read-only.** A backend must never create, modify or delete anything to
    /// answer this: the question is asked while a client is waiting, and a probe
    /// that wrote would be a side effect on a store that may not even be ours.
    /// Defaults to the cached answer, for a backend with nothing to ask.
    async fn probe_store(&self) -> StoreStatus {
        self.store_status()
    }

    /// The platform's way of telling us the store *might* have opened, where it
    /// has one.
    ///
    /// `None` means the only way to notice is to ask again, which the daemon does
    /// on its own interval — so a backend that implements nothing here is slower
    /// to notice a reopened store, never unable to.
    fn unlock_hints(&self) -> Option<Arc<dyn UnlockHints>> {
        None
    }

    /// The strongest level this backend achieves right now.
    ///
    /// Defaults to the last entry of [`Backend::levels`]. A backend whose
    /// level can vary at runtime (e.g. a machine that lost its TPM) overrides
    /// this to report the truth.
    fn default_level(&self) -> SecurityLevel {
        self.levels()
            .last()
            .copied()
            .expect("every backend offers at least one security level")
    }

    /// The underlying store this backend talks to, where that is a meaningful
    /// thing to name (e.g. `"secret-service"`, `"login-keychain"`).
    ///
    /// Diagnostics only. `tpmd status` renders it beside the backend name so a
    /// user can tell *which* store is actually serving them, without the wire
    /// protocol growing a field that only one backend would ever fill.
    fn store_mechanism(&self) -> Option<&'static str> {
        None
    }

    /// Whether `--backend <name>` should construct this backend even when it
    /// reports it cannot be used here.
    ///
    /// Normally forcing an unusable backend is refused distinctly, because a
    /// backend that cannot run has nothing useful to say. A backend that is
    /// merely *unreachable* is different: it exists, it knows why it cannot
    /// answer, and saying so is exactly what an operator forcing it wants.
    fn forced_when_unusable(&self) -> bool {
        false
    }

    /// Mint a key owned by `owner` at exactly `level`.
    ///
    /// The daemon has already chosen `level` via [`select_level`]; the backend
    /// must still refuse a level it cannot provide rather than downgrading.
    async fn provision(
        &self,
        owner: &Owner,
        algorithm: Algorithm,
        level: SecurityLevel,
    ) -> Result<KeyInfo, BackendError>;

    /// Look up the metadata of a key owned by `owner`.
    async fn identify(&self, owner: &Owner, key_id: &KeyId) -> Result<KeyInfo, BackendError>;

    /// Sign `message` with the key named by `key_id`.
    ///
    /// The contract (protocol §10): the backend SHA-256-hashes `message` and
    /// ECDSA-signs the digest, returning raw `r ‖ s`.
    async fn sign(
        &self,
        owner: &Owner,
        key_id: &KeyId,
        message: &[u8],
    ) -> Result<Signature, BackendError>;

    /// Destroy a key owned by `owner`.
    async fn destroy(&self, owner: &Owner, key_id: &KeyId) -> Result<(), BackendError>;
}

/// A backend this build knows how to construct.
///
/// The daemon never names a concrete backend type: it holds a factory per
/// mechanism and asks each to [`open`](BackendFactory::open) itself. That is
/// what lets the same selection code drive a backend compiled into the daemon
/// and one loaded from a plugin at run time — the two differ only in where the
/// factory came from.
///
/// The trait lives here, beside [`Backend`], rather than in the daemon because
/// both sides of that boundary need it: a backend crate implements it so the
/// daemon can be told how to build the backend, and the daemon consumes it. A
/// backend must never depend on the daemon.
#[async_trait]
pub trait BackendFactory: Send + Sync {
    /// The backend's name, as used by `--backend`, `status` and logs.
    fn name(&self) -> &'static str;

    /// Construct the backend, opening its store if it has one.
    ///
    /// Failing here means "unavailable on this host": the registry records the
    /// reason and moves on rather than aborting the daemon.
    async fn open(&self, state_dir: &Path) -> Result<Box<dyn Backend>, BackendError>;
}

/// Choose the level to provision at, honouring the caller's floor.
///
/// Returns the **strongest** available level that is at least `floor`. If no
/// level meets the floor, returns the strongest available level when
/// `allow_below_floor` is set, otherwise [`BackendError::IncompatiblePolicy`].
///
/// This is the single place the "never silently weaken policy" rule is
/// implemented, so it is shared rather than re-derived per backend.
pub fn select_level(
    levels: &[SecurityLevel],
    floor: SecurityLevel,
    allow_below_floor: bool,
) -> Result<SecurityLevel, BackendError> {
    let strongest =
        levels.iter().copied().max().ok_or_else(|| {
            BackendError::Unavailable("backend advertises no security levels".into())
        })?;

    if let Some(meeting) = levels.iter().copied().filter(|&l| l >= floor).max() {
        return Ok(meeting);
    }
    if allow_below_floor {
        return Ok(strongest);
    }
    Err(BackendError::IncompatiblePolicy {
        required: floor,
        available: strongest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A backend with no store of its own — a file, a device — which is what most
    /// backends are. The defaults must say so, because the daemon parks a client
    /// on a *closed* store and on nothing else.
    struct StorelessBackend;

    #[async_trait]
    impl Backend for StorelessBackend {
        fn name(&self) -> &'static str {
            "storeless"
        }
        fn algorithms(&self) -> &'static [Algorithm] {
            &[Algorithm::EcdsaP256Sha256]
        }
        fn levels(&self) -> &'static [SecurityLevel] {
            &[SecurityLevel::File]
        }
        async fn provision(
            &self,
            _owner: &Owner,
            _algorithm: Algorithm,
            _level: SecurityLevel,
        ) -> Result<KeyInfo, BackendError> {
            unimplemented!("the defaults under test never touch a key")
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

    #[test]
    fn a_backend_without_a_store_is_open_and_has_nothing_to_wait_for() {
        let backend = StorelessBackend;
        assert_eq!(backend.store_status(), StoreStatus::Open);
        assert!(backend.store_status().is_open());
        assert!(!backend.store_status().is_waitable());
        assert!(
            backend.unlock_hints().is_none(),
            "nothing to wait for means nothing to hint about"
        );
    }

    #[tokio::test]
    async fn probing_a_storeless_backend_agrees_with_its_cached_status() {
        assert_eq!(StorelessBackend.probe_store().await, StoreStatus::Open);
    }

    /// The distinction the daemon's whole closed/gone policy rests on: waiting
    /// only ever makes sense for a store the *user* can change.
    #[test]
    fn only_a_closed_store_is_waitable() {
        assert!(StoreStatus::Closed("locked".into()).is_waitable());
        assert!(!StoreStatus::Gone("no device".into()).is_waitable());
        assert!(!StoreStatus::Open.is_waitable());
        assert_eq!(
            StoreStatus::Closed("locked".into()).reason(),
            Some("locked")
        );
        assert_eq!(
            StoreStatus::Gone("no device".into()).reason(),
            Some("no device")
        );
        assert_eq!(StoreStatus::Open.reason(), None);
    }

    const DUMMY_LEVELS: &[SecurityLevel] = &[SecurityLevel::File];

    #[test]
    fn a_lower_floor_is_met_by_the_strongest_level_above_it() {
        let levels = &[
            SecurityLevel::File,
            SecurityLevel::Keyring,
            SecurityLevel::Sealed,
        ];
        assert_eq!(
            select_level(levels, SecurityLevel::Keyring, false).unwrap(),
            SecurityLevel::Sealed
        );
    }

    #[test]
    fn an_unmet_floor_is_refused_without_consent() {
        let err = select_level(DUMMY_LEVELS, SecurityLevel::Sealed, false).unwrap_err();
        match err {
            BackendError::IncompatiblePolicy {
                required,
                available,
            } => {
                assert_eq!(required, SecurityLevel::Sealed);
                assert_eq!(available, SecurityLevel::File);
            }
            other => panic!("expected IncompatiblePolicy, got {other:?}"),
        }
    }

    #[test]
    fn an_unmet_floor_is_honoured_with_consent() {
        assert_eq!(
            select_level(DUMMY_LEVELS, SecurityLevel::Sealed, true).unwrap(),
            SecurityLevel::File
        );
    }
}
