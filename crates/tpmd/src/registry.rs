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
//!
//! # Where a factory comes from
//!
//! The Debian split (`loadable-backends`) moves *one* thing: the keyring and
//! Linux TPM factories stop being compiled in and are instead asked of a shared
//! object in `/usr/lib/tpmd/backends`. Nothing downstream changes — the survey,
//! the ladder, the sticky record and the floor logic all see an ordinary
//! `Box<dyn BackendFactory>` either way, and a plugin that is absent is simply a
//! shorter ladder. The dummy never moves: it is the guaranteed rung, and a floor
//! that could be uninstalled is not a floor.

use std::cmp::Reverse;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use tpmd_backend::{Backend, BackendError};
#[cfg(feature = "loadable-backends")]
use tracing::error;

/// A backend this build knows how to construct.
///
/// Re-exported from [`tpmd_backend`], which is where it has to live: the plugin
/// boundary hands back one of these, and a backend crate implements it without
/// knowing whether it is linked into the daemon or loaded beside it.
pub use tpmd_backend::BackendFactory;

#[cfg(all(feature = "builtin-backends", feature = "loadable-backends"))]
compile_error!(
    "`builtin-backends` and `loadable-backends` are mutually exclusive: one links every \
     backend into the daemon, the other loads them from plugins, and both together would \
     offer every rung twice — including the ones the survey is supposed to weigh"
);

#[cfg(not(any(feature = "builtin-backends", feature = "loadable-backends")))]
compile_error!(
    "one of `builtin-backends` (the default) or `loadable-backends` must be enabled: the \
     daemon has to be told how it comes by a backend other than the dummy"
);

#[cfg(all(feature = "loadable-backends", not(target_os = "linux")))]
compile_error!(
    "`loadable-backends` is a Linux-only build mode: the Windows and macOS backends stay \
     linked into their agent (and are not shipped by the Debian packages this mode exists \
     for) until their installers grow the same split"
);

/// Every backend this build can offer, plus whatever must stay mapped for them.
///
/// Held for the daemon's whole run: under `loadable-backends` the factories (and
/// the vtable of every backend opened through one) point into shared objects,
/// and a plugin must not be unmapped while something may still call into it.
#[must_use]
pub struct Backends {
    factories: Vec<Box<dyn BackendFactory>>,
    /// Declared after the factories so it drops after them, which is the order
    /// the mapping requires.
    #[cfg(feature = "loadable-backends")]
    _mapped: tpmd_plugin::host::Mapped,
}

impl Backends {
    /// The factories to survey, in ladder-agnostic order (the survey sorts).
    #[must_use]
    pub fn factories(&self) -> &[Box<dyn BackendFactory>] {
        &self.factories
    }
}

/// Every backend this build can offer.
///
/// What is *built* is this function's business; what is *used* is the survey's.
#[cfg(feature = "builtin-backends")]
pub fn backends() -> Backends {
    // The dummy is unconditional, because it is the guaranteed fallback. The
    // keyring serves every platform (whether it can actually be used there is a
    // run-time question, not a build-time one). The `mut` is only exercised
    // where a hardware backend exists, i.e. not on macOS or any other platform
    // without one.
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "windows", target_os = "macos")),
        allow(unused_mut)
    )]
    let mut factories: Vec<Box<dyn BackendFactory>> = vec![
        Box::new(DummyFactory),
        Box::new(tpmd_backend_keyring::KeyringFactory),
    ];
    #[cfg(target_os = "linux")]
    factories.push(Box::new(tpmd_backend_linux_tpm::LinuxTpmFactory));
    #[cfg(target_os = "windows")]
    factories.push(Box::new(WindowsCngFactory));
    #[cfg(target_os = "macos")]
    factories.push(Box::new(SecureEnclaveFactory));
    Backends { factories }
}

/// Every backend this machine has *installed*: the dummy, plus one plugin per
/// backend package.
///
/// A plugin that is present but cannot be loaded is an **error in the journal**,
/// never a silent omission: an installed rung that quietly is not offered is how
/// a machine ends up on a weaker store without anyone deciding that. It does not
/// stop the daemon — a broken optional package must not brick the agent — but it
/// does mean the ladder below it can be chosen, which is why it is said loudly
/// rather than logged at a level nobody reads.
#[cfg(feature = "loadable-backends")]
pub fn backends() -> Backends {
    let plugins = tpmd_plugin::host::load(&tpmd_plugin::host::directory());
    for (path, reason) in plugins.failures() {
        error!(
            plugin = %path.display(),
            %reason,
            "an installed backend plugin was not loaded, so its rung is not offered"
        );
    }
    let (loaded, mapped) = plugins.into_factories();
    let mut factories: Vec<Box<dyn BackendFactory>> = vec![Box::new(DummyFactory)];
    factories.extend(loaded);
    Backends {
        factories,
        _mapped: mapped,
    }
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

impl Selection {
    /// What was passed over, owned — for a record that outlives this selection.
    #[must_use]
    pub fn skipped_owned(&self) -> Vec<(String, String)> {
        self.skipped
            .iter()
            .map(|(name, reason)| ((*name).to_owned(), reason.clone()))
            .collect()
    }
}

impl core::fmt::Debug for Selection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Selection")
            .field("backend", &self.backend.name())
            .field("skipped", &self.skipped)
            .finish()
    }
}

/// What every candidate backend is doing, without choosing anything.
///
/// Opens each factory exactly once and reports what it found. The same survey
/// answers both questions the daemon has — "which backend should this fresh
/// machine use?" and, when a record already exists, "would anything stronger win
/// now?" — the second being **information for an administrator, never an
/// action**.
pub struct Survey {
    /// Backends that could serve, strongest first. A backend whose store is
    /// merely *closed* is a candidate: a locked keychain is not a reason to fall
    /// to a plainer store, which would be a silent custody change.
    pub candidates: Vec<Box<dyn Backend>>,
    /// What was passed over, and why.
    pub skipped: Vec<(&'static str, String)>,
}

/// Open one named backend, whether or not it can serve right now.
///
/// Used once a machine has chosen: a remembered backend is opened even if its
/// store is *closed* (the daemon then answers `closed` and a client may wait) or
/// its dependency is *gone* (the daemon answers `backend_unavailable`). It is
/// never quietly swapped for something else, because that would change custody —
/// and could change the identity a caller sees.
pub async fn open_named(
    factories: &[Box<dyn BackendFactory>],
    name: &str,
    state_dir: &Path,
) -> Result<Box<dyn Backend>, SelectionError> {
    let factory = factories
        .iter()
        .find(|factory| factory.name() == name)
        .ok_or_else(|| SelectionError::NotBuilt {
            name: name.to_owned(),
            built: built_names(factories),
        })?;
    factory
        .open(state_dir)
        .await
        .map_err(|error| SelectionError::Unusable {
            name: name.to_owned(),
            reason: error.to_string(),
        })
}

/// Look at every built backend and report what it can do.
pub async fn survey(factories: &[Box<dyn BackendFactory>], state_dir: &Path) -> Survey {
    let mut candidates: Vec<Box<dyn Backend>> = Vec::new();
    let mut skipped: Vec<(&'static str, String)> = Vec::new();

    for factory in factories {
        match factory.open(state_dir).await {
            Ok(backend) => {
                let status = backend.store_status();
                if status.is_open() || status.is_waitable() {
                    candidates.push(backend);
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

    candidates.sort_by_key(|backend| Reverse(backend.default_level()));
    Survey {
        candidates,
        skipped,
    }
}

impl Survey {
    /// The backend a fresh machine should use: the strongest candidate, or the
    /// one an administrator named.
    ///
    /// `named` is how `--backend` is honoured on a first start: it restricts the
    /// ladder rather than bypassing it, so naming a backend that is not built — or
    /// whose dependency is gone — is refused with the reason, exactly as an
    /// automatic choice would be.
    pub fn pick(&mut self, named: Option<&str>) -> Result<Box<dyn Backend>, SelectionError> {
        let Some(named) = named else {
            if self.candidates.is_empty() {
                return Err(SelectionError::NotBuilt {
                    name: "<any>".to_owned(),
                    built: built_names_of(self),
                });
            }
            return Ok(self.candidates.remove(0));
        };

        if let Some(index) = self
            .candidates
            .iter()
            .position(|backend| backend.name() == named)
        {
            return Ok(self.candidates.remove(index));
        }

        match self.skipped.iter().find(|(name, _)| *name == named) {
            // Built, but it cannot serve here: say why rather than choosing
            // something else, which is the whole point of naming it.
            Some((_, reason)) => Err(SelectionError::Unusable {
                name: named.to_owned(),
                reason: reason.clone(),
            }),
            None => Err(SelectionError::NotBuilt {
                name: named.to_owned(),
                built: built_names_of(self),
            }),
        }
    }

    /// The strongest candidate, if any could serve.
    pub fn strongest(&self) -> Option<&dyn Backend> {
        self.candidates.first().map(|backend| backend.as_ref())
    }

    /// What was passed over, owned — for a record that outlives this survey.
    pub fn skipped_owned(&self) -> Vec<(String, String)> {
        self.skipped
            .iter()
            .map(|(name, reason)| ((*name).to_owned(), reason.clone()))
            .collect()
    }
}

/// The names this survey saw, for an error that should name the alternatives.
fn built_names_of(survey: &Survey) -> String {
    let mut names: Vec<&str> = survey
        .candidates
        .iter()
        .map(|backend| backend.name())
        .collect();
    names.extend(survey.skipped.iter().map(|(name, _)| *name));
    names.join(", ")
}

/// Choose the backend for a machine that has **not** chosen yet.
///
/// The ladder: every candidate is surveyed, the strongest wins, and `named` —
/// which is how `--backend` is honoured on a first start — restricts the choice
/// to one rung rather than bypassing the survey's reasons.
///
/// A named backend whose store is **gone** is refused, unless it asks to be
/// honoured anyway ([`Backend::forced_when_unusable`]): an operator asking "what
/// is wrong with my keyring?" should be told `store_locked`, not refused a start.
pub async fn select(
    factories: &[Box<dyn BackendFactory>],
    state_dir: &Path,
    named: Option<&str>,
) -> Result<Selection, SelectionError> {
    let mut survey = survey(factories, state_dir).await;
    let backend = match survey.pick(named) {
        Ok(backend) => backend,
        Err(error) => {
            // Only a backend the caller *named* may be honoured despite being
            // unable to serve; an automatic choice has no one to ask.
            if named.is_none() {
                return Err(error);
            }
            let SelectionError::Unusable { name, .. } = &error else {
                return Err(error);
            };
            let name = name.clone();
            let opened = open_named(factories, &name, state_dir).await?;
            if opened.forced_when_unusable() {
                opened
            } else {
                return Err(error);
            }
        }
    };
    Ok(Selection {
        backend: Arc::from(backend),
        skipped: survey.skipped,
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

/// The macOS Secure Enclave backend: `hardware`, via the login keychain's
/// enclave-held keys.
///
/// Built only on macOS, and — unlike the other hardware backends — only *usable*
/// from a signed bundle in the Aqua session. The probe in `open()` is what
/// decides, and it stores a key rather than merely generating one, because
/// generating succeeds in places where keeping a key is refused.
#[cfg(target_os = "macos")]
struct SecureEnclaveFactory;

#[cfg(target_os = "macos")]
#[async_trait]
impl BackendFactory for SecureEnclaveFactory {
    fn name(&self) -> &'static str {
        "macos-se"
    }

    async fn open(&self, state_dir: &Path) -> Result<Box<dyn Backend>, BackendError> {
        Ok(Box::new(
            tpmd_backend_macos_se::SecureEnclaveBackend::open(state_dir).await?,
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
        assert_eq!(
            selection.backend.name(),
            "file",
            "a named backend wins even though a stronger one stands on the ladder"
        );
        // `skipped` means "could not serve", not "was not chosen": the backends
        // the survey could not use are the ones reported here, with their reasons.
        let skipped: Vec<&str> = selection.skipped.iter().map(|(name, _)| *name).collect();
        assert!(skipped.contains(&"broken"), "{skipped:?}");
        assert!(skipped.contains(&"gone"), "{skipped:?}");
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

    /// The survey is what an administrator's "would anything stronger win now?"
    /// is built on, so its ordering has to be the ladder's own: strongest first,
    /// with a merely-closed rung still counting.
    #[tokio::test]
    async fn the_survey_reports_candidates_strongest_first() {
        let candidates = vec![
            fake("file", SecurityLevel::File, open(), true, false),
            fake(
                "hardware-but-closed",
                SecurityLevel::Hardware,
                StoreStatus::Closed("the device is busy".into()),
                true,
                false,
            ),
            fake(
                "hardware-but-gone",
                SecurityLevel::Hardware,
                StoreStatus::Gone("no device".into()),
                true,
                false,
            ),
        ];
        let survey = survey(&candidates, dir()).await;
        let strongest = survey.strongest().expect("something can serve");
        assert_eq!(
            strongest.name(),
            "hardware-but-closed",
            "a closed rung outranks a weaker open one"
        );
        assert_eq!(
            survey.skipped_owned().len(),
            1,
            "only the gone one is passed over"
        );
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
