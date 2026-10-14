//! The storage-backend abstraction shared by the daemon and every backend.
//!
//! A backend is the *only* holder of private key material. The daemon selects
//! one backend at build time (per-mechanism crates, feature-gated) and drives
//! it through the object-safe [`Backend`] trait. This crate therefore has to
//! be a dependency of both the daemon and the backend crates, while the
//! backends must not depend on the daemon — hence a small dedicated crate
//! rather than putting the trait in the daemon.
//!
//! Backends are **synchronous**: a backend call touches a local store and (for
//! the dummy) does a little ECDSA arithmetic, neither of which warrants an
//! async runtime inside the backend. The daemon decides how to schedule calls.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

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
pub trait Backend: Send + Sync {
    /// The backend's short name, e.g. `"dummy"`.
    fn name(&self) -> &'static str;

    /// Algorithms this backend can offer.
    fn algorithms(&self) -> &'static [Algorithm];

    /// Security levels this backend can achieve, weakest first.
    fn levels(&self) -> &'static [SecurityLevel];

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

    /// Mint a key owned by `owner` at exactly `level`.
    ///
    /// The daemon has already chosen `level` via [`select_level`]; the backend
    /// must still refuse a level it cannot provide rather than downgrading.
    fn provision(
        &self,
        owner: &Owner,
        algorithm: Algorithm,
        level: SecurityLevel,
    ) -> Result<KeyInfo, BackendError>;

    /// Look up the metadata of a key owned by `owner`.
    fn identify(&self, owner: &Owner, key_id: &KeyId) -> Result<KeyInfo, BackendError>;

    /// Sign `message` with the key named by `key_id`.
    ///
    /// The contract (protocol §10): the backend SHA-256-hashes `message` and
    /// ECDSA-signs the digest, returning raw `r ‖ s`.
    fn sign(
        &self,
        owner: &Owner,
        key_id: &KeyId,
        message: &[u8],
    ) -> Result<Signature, BackendError>;

    /// Destroy a key owned by `owner`.
    fn destroy(&self, owner: &Owner, key_id: &KeyId) -> Result<(), BackendError>;
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
