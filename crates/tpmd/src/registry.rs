//! Backend inclusion and selection.
//!
//! Two decisions are separated on purpose:
//!
//! * **What is built** is a compile-time property: the workspace member list
//!   and the target-gated dependencies decide which backends exist in this
//!   binary. A Windows build never contains the Linux TPM code.
//! * **What is used** is a run-time property: a backend that is compiled in
//!   may still be unusable on the host it runs on (no TPM device, unsupported
//!   kernel), so selection asks each candidate [`Backend::can_be_used`] and
//!   keeps the strongest that answers yes.
//!
//! The dummy (`file`) backend is always built and always usable, so selection
//! can never come up empty — it is the floor of the ladder. The keyring backend
//! is also always built, but may not be usable, in which case selection passes
//! over it for the dummy.

use std::cmp::Reverse;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use tpmd_backend::{Backend, BackendError};

/// A backend this binary knows how to construct.
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

/// Every backend compiled into this binary for this operating system.
#[must_use]
pub fn builtin_factories() -> Vec<Box<dyn BackendFactory>> {
    // Two backends are unconditional: the dummy, because it is the guaranteed
    // fallback, and the keyring, because it serves every platform (whether it
    // can actually be used there is a run-time question, not a build-time one).
    // The `mut` is only exercised where a hardware backend exists, i.e. not on
    // macOS or any other platform without one.
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "windows")),
        allow(unused_mut)
    )]
    let mut factories: Vec<Box<dyn BackendFactory>> =
        vec![Box::new(DummyFactory), Box::new(KeyringFactory)];
    #[cfg(target_os = "linux")]
    factories.push(Box::new(LinuxTpmFactory));
    #[cfg(target_os = "windows")]
    factories.push(Box::new(WindowsCngFactory));
    factories
}

/// The names of every built backend, in selection order.
#[must_use]
pub fn built_names(factories: &[Box<dyn BackendFactory>]) -> String {
    factories
        .iter()
        .map(|f| f.name())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Why backend selection could not produce a backend.
#[derive(Debug, thiserror::Error)]
pub enum SelectionError {
    /// `--backend` named something this build does not contain.
    #[error("backend {name:?} is not built for this platform (built backends: {built})")]
    NotBuilt {
        /// The requested name.
        name: String,
        /// The names that are available.
        built: String,
    },
    /// The requested backend is built but cannot run here.
    #[error("backend {name:?} is not usable here: {reason}")]
    Unusable {
        /// The requested name.
        name: String,
        /// Why it could not be used.
        reason: String,
    },
}

/// A chosen backend plus what was passed over, for logging.
pub struct Selection {
    /// The selected backend.
    pub backend: Arc<dyn Backend>,
    /// Backends that were built but not used, with the reason.
    pub skipped: Vec<(&'static str, String)>,
}

impl core::fmt::Debug for Selection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Selection")
            .field("backend", &self.backend.name())
            .field("skipped", &self.skipped)
            .finish()
    }
}

/// Choose the backend to serve with.
///
/// With `forced`, the named backend must be built **and** usable, otherwise a
/// clear error naming the alternatives is returned — unless the backend asks to
/// be honoured anyway ([`Backend::forced_when_unusable`]), which a backend that
/// can explain its own unreachability does. Without `forced`, every factory is
/// opened, unusable ones are skipped, and the one with the highest
/// [`Backend::default_level`] wins.
pub async fn select(
    factories: &[Box<dyn BackendFactory>],
    state_dir: &Path,
    forced: Option<&str>,
) -> Result<Selection, SelectionError> {
    if let Some(name) = forced {
        let factory = factories.iter().find(|f| f.name() == name).ok_or_else(|| {
            SelectionError::NotBuilt {
                name: name.to_owned(),
                built: built_names(factories),
            }
        })?;

        let backend = factory
            .open(state_dir)
            .await
            .map_err(|error| SelectionError::Unusable {
                name: name.to_owned(),
                reason: error.to_string(),
            })?;
        // Forcing a backend whose store is *closed* is honoured: the caller asked
        // for it, and every operation will say `store_locked` — which is more
        // useful than a refusal to start. Forcing one that is *gone* is refused
        // unless the backend asks to be honoured anyway.
        let status = backend.store_status();
        if !status.is_open() && !status.is_waitable() && !backend.forced_when_unusable() {
            return Err(SelectionError::Unusable {
                name: name.to_owned(),
                reason: status
                    .reason()
                    .unwrap_or("the backend reports it cannot be used on this host")
                    .to_owned(),
            });
        }
        return Ok(Selection {
            backend: Arc::from(backend),
            skipped: Vec::new(),
        });
    }

    let mut usable: Vec<Box<dyn Backend>> = Vec::new();
    let mut skipped: Vec<(&'static str, String)> = Vec::new();
    for factory in factories {
        match factory.open(state_dir).await {
            Ok(backend) => {
                let status = backend.store_status();
                // A **closed** store is a candidate, not a skip: a locked keychain
                // is a state the user changes, and the daemon answers it with the
                // non-fatal `closed` reply while the client waits. Only a *gone*
                // dependency is passed over, because nothing brings it back —
                // serving a weaker store instead would be a silent custody change.
                if status.is_open() || status.is_waitable() {
                    usable.push(backend);
                } else {
                    skipped.push((
                        factory.name(),
                        status
                            .reason()
                            .unwrap_or("the backend reports it cannot be used on this host")
                            .to_owned(),
                    ));
                }
            }
            Err(error) => skipped.push((factory.name(), error.to_string())),
        }
    }

    // Strongest first. The dummy is always present, so this cannot be empty
    // unless the dummy itself failed to open — which is a real error worth
    // reporting rather than papering over.
    usable.sort_by_key(|backend| Reverse(backend.default_level()));
    let backend = usable
        .into_iter()
        .next()
        .ok_or_else(|| SelectionError::NotBuilt {
            name: "<any>".to_owned(),
            built: built_names(factories),
        })?;

    Ok(Selection {
        backend: backend.into(),
        skipped,
    })
}

/// The universal `file`-level backend.
struct DummyFactory;

#[async_trait]
impl BackendFactory for DummyFactory {
    fn name(&self) -> &'static str {
        "dummy"
    }

    async fn open(&self, state_dir: &Path) -> Result<Box<dyn Backend>, BackendError> {
        Ok(Box::new(
            tpmd_backend_dummy::DummyBackend::open(state_dir).await?,
        ))
    }
}

/// The universal `keyring`-level backend: the operating system's own credential
/// store.
///
/// Built everywhere, unlike the hardware backends, because all three platforms
/// have such a store. Whether this host's store is reachable is a run-time
/// question the backend answers through [`Backend::can_be_used`].
struct KeyringFactory;

#[async_trait]
impl BackendFactory for KeyringFactory {
    fn name(&self) -> &'static str {
        "keyring"
    }

    async fn open(&self, state_dir: &Path) -> Result<Box<dyn Backend>, BackendError> {
        Ok(Box::new(
            tpmd_backend_keyring::KeyringBackend::open(state_dir).await?,
        ))
    }
}

/// The Linux TPM 2.0 backend: `sealed` and `hardware`.
#[cfg(target_os = "linux")]
struct LinuxTpmFactory;

#[cfg(target_os = "linux")]
#[async_trait]
impl BackendFactory for LinuxTpmFactory {
    fn name(&self) -> &'static str {
        "linux-tpm"
    }

    async fn open(&self, state_dir: &Path) -> Result<Box<dyn Backend>, BackendError> {
        Ok(Box::new(
            tpmd_backend_linux_tpm::LinuxTpmBackend::open(state_dir).await?,
        ))
    }
}

/// The Windows CNG backend: `hardware`, via the Platform Crypto Provider.
#[cfg(target_os = "windows")]
struct WindowsCngFactory;

#[cfg(target_os = "windows")]
#[async_trait]
impl BackendFactory for WindowsCngFactory {
    fn name(&self) -> &'static str {
        "windows-cng"
    }

    async fn open(&self, state_dir: &Path) -> Result<Box<dyn Backend>, BackendError> {
        Ok(Box::new(
            tpmd_backend_windows_cng::WindowsCngBackend::open(state_dir).await?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpmd_backend::{Owner, StoreStatus};
    use tpmd_proto::{Algorithm, KeyId, KeyInfo, SecurityLevel, Signature};

    /// A backend whose only interesting properties are its level and what its
    /// store is doing.
    struct FakeBackend {
        name: &'static str,
        level: SecurityLevel,
        status: StoreStatus,
        forced: bool,
    }

    #[async_trait]
    impl Backend for FakeBackend {
        fn name(&self) -> &'static str {
            self.name
        }
        fn algorithms(&self) -> &'static [Algorithm] {
            &[Algorithm::EcdsaP256Sha256]
        }
        fn levels(&self) -> &'static [SecurityLevel] {
            &[SecurityLevel::File]
        }
        fn can_be_used(&self) -> bool {
            self.status.is_open()
        }
        fn store_status(&self) -> StoreStatus {
            self.status.clone()
        }
        fn forced_when_unusable(&self) -> bool {
            self.forced
        }
        fn default_level(&self) -> SecurityLevel {
            self.level
        }
        async fn provision(
            &self,
            _owner: &Owner,
            _algorithm: Algorithm,
            _level: SecurityLevel,
        ) -> Result<KeyInfo, BackendError> {
            unimplemented!("the registry never provisions")
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

    struct FakeFactory {
        name: &'static str,
        level: SecurityLevel,
        status: StoreStatus,
        opens: bool,
        forced: bool,
    }

    #[async_trait]
    impl BackendFactory for FakeFactory {
        fn name(&self) -> &'static str {
            self.name
        }
        async fn open(&self, _state_dir: &Path) -> Result<Box<dyn Backend>, BackendError> {
            if !self.opens {
                return Err(BackendError::Unavailable("no device on this host".into()));
            }
            Ok(Box::new(FakeBackend {
                name: self.name,
                level: self.level,
                status: self.status.clone(),
                forced: self.forced,
            }))
        }
    }

    /// Build a fake backend factory; spelled out once so each test case reads as
    /// the property it is about.
    fn fake(
        name: &'static str,
        level: SecurityLevel,
        status: StoreStatus,
        opens: bool,
        forced: bool,
    ) -> Box<dyn BackendFactory> {
        Box::new(FakeFactory {
            name,
            level,
            status,
            opens,
            forced,
        })
    }

    /// An open store — the ordinary case.
    fn open() -> StoreStatus {
        StoreStatus::Open
    }

    fn factories() -> Vec<Box<dyn BackendFactory>> {
        vec![
            fake("file", SecurityLevel::File, open(), true, false),
            fake("hw", SecurityLevel::Hardware, open(), true, false),
            fake("broken", SecurityLevel::Hardware, open(), false, false),
            fake(
                "gone",
                SecurityLevel::Hardware,
                StoreStatus::Gone("no device on this host".into()),
                true,
                false,
            ),
        ]
    }

    fn dir() -> &'static Path {
        Path::new("/nonexistent-registry-test")
    }

    #[tokio::test]
    async fn the_strongest_usable_backend_wins() {
        let selection = select(&factories(), dir(), None).await.unwrap();
        assert_eq!(selection.backend.name(), "hw");
        // The passed-over ones are reported with a reason.
        let skipped: Vec<&str> = selection.skipped.iter().map(|(n, _)| *n).collect();
        assert!(skipped.contains(&"broken"));
        assert!(skipped.contains(&"gone"));
        assert!(!skipped.contains(&"file"));
        // …and the reason says what was actually wrong, not a generic shrug.
        let (_, reason) = selection
            .skipped
            .iter()
            .find(|(name, _)| *name == "gone")
            .unwrap();
        assert!(reason.contains("no device"), "{reason}");
    }

    #[tokio::test]
    async fn a_failing_or_gone_backend_is_skipped_for_a_weaker_one() {
        let only_weak = vec![
            fake("broken", SecurityLevel::Hardware, open(), false, false),
            fake(
                "gone",
                SecurityLevel::Hardware,
                StoreStatus::Gone("no device".into()),
                true,
                false,
            ),
            fake("file", SecurityLevel::File, open(), true, false),
        ];
        let selection = select(&only_weak, dir(), None).await.unwrap();
        assert_eq!(selection.backend.name(), "file");
    }

    /// The rule that makes a locked keychain usable rather than a demotion: a
    /// **closed** store is a candidate, and it outranks the weaker store beneath
    /// it. Serving the weaker one instead would be a silent custody change, which
    /// is exactly what the `closed` answer exists to avoid.
    #[tokio::test]
    async fn a_closed_store_is_a_candidate_and_outranks_a_weaker_open_one() {
        let candidates = vec![
            fake(
                "closed-but-strong",
                SecurityLevel::Keyring,
                StoreStatus::Closed("the keychain is locked".into()),
                true,
                false,
            ),
            fake("file", SecurityLevel::File, open(), true, false),
        ];
        let selection = select(&candidates, dir(), None).await.unwrap();
        assert_eq!(
            selection.backend.name(),
            "closed-but-strong",
            "a closed rung must be chosen over a weaker open one"
        );
        assert!(selection.skipped.is_empty(), "nothing was skipped");
    }

    #[tokio::test]
    async fn forcing_a_built_backend_selects_it_even_if_weaker() {
        let selection = select(&factories(), dir(), Some("file")).await.unwrap();
        assert_eq!(selection.backend.name(), "file");
        assert!(selection.skipped.is_empty());
    }

    #[tokio::test]
    async fn forcing_an_unbuilt_backend_names_the_alternatives() {
        let error = select(&factories(), dir(), Some("nope")).await.unwrap_err();
        let message = error.to_string();
        assert!(message.contains("nope"), "{message}");
        assert!(
            message.contains("dummy") || message.contains("hw"),
            "{message}"
        );
    }

    #[tokio::test]
    async fn forcing_a_gone_or_failing_backend_is_refused_distinctly() {
        let error = select(&factories(), dir(), Some("gone")).await.unwrap_err();
        assert!(matches!(error, SelectionError::Unusable { .. }));

        let error = select(&factories(), dir(), Some("broken"))
            .await
            .unwrap_err();
        assert!(matches!(error, SelectionError::Unusable { .. }));
    }

    /// Forcing a backend whose store is merely *closed* is honoured: the caller
    /// asked for it, and every operation will say `store_locked` — which is more
    /// useful than refusing to start.
    #[tokio::test]
    async fn forcing_a_closed_backend_is_honoured() {
        let candidates = vec![fake(
            "closed",
            SecurityLevel::Keyring,
            StoreStatus::Closed("the keychain is locked".into()),
            true,
            false,
        )];
        let selection = select(&candidates, dir(), Some("closed")).await.unwrap();
        assert_eq!(selection.backend.name(), "closed");
    }

    /// A backend that can explain its own unreachability is honoured when
    /// forced, so `--backend keyring` on a host with no store reports the store's
    /// problem instead of refusing to start.
    #[tokio::test]
    async fn forcing_a_self_explaining_backend_is_honoured() {
        let candidates = vec![
            fake("file", SecurityLevel::File, open(), true, false),
            fake(
                "self-explaining",
                SecurityLevel::Keyring,
                StoreStatus::Gone("no session bus".into()),
                true,
                true,
            ),
        ];
        let selection = select(&candidates, dir(), Some("self-explaining"))
            .await
            .unwrap();
        assert_eq!(selection.backend.name(), "self-explaining");
        // It is still passed over when nothing forces it.
        let auto = select(&candidates, dir(), None).await.unwrap();
        assert_eq!(auto.backend.name(), "file");
    }
}
