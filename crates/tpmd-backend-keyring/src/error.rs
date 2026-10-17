//! The credential store's error taxonomy, mapped onto the backend's.
//!
//! The two vocabularies overlap but are not the same, and the protocol makes
//! distinctions the store does not. In particular `store_locked` and
//! `key_loss` and `unknown_key` are three different wire codes, and the daemon
//! refuses to leak "this key exists but you may not have it":
//!
//! * **Ownership is decided before the store is consulted.** A request under
//!   the wrong principal, or for a key that was never minted, never reaches
//!   this module: the `keyring_keys` row is looked up first and a miss is
//!   [`BackendError::UnknownKey`]. So "unknown key" is never a store error here.
//! * **`NoEntry` therefore means the key is on record but its credential is
//!   gone**, which is key *loss*, not an unknown key.
//! * **Anything that stops the store answering** — locked, unreachable, no
//!   session bus, no loaded profile — is `store_locked`, its own class, never
//!   "key missing".

use keyring_core::Error as KeyringError;
use tpmd_backend::BackendError;

/// Map a store failure onto the backend's error taxonomy.
///
/// `keyring_core::Error` is `#[non_exhaustive]`, so the final arm is
/// deliberately a catch-all: a store that grows a new failure mode must not
/// turn into a panic, and `internal` is the honest answer for one we do not
/// understand.
pub(crate) fn map_store_error(context: &str, error: KeyringError) -> BackendError {
    match error {
        // The credential is on record but the store no longer holds it.
        KeyringError::NoEntry => {
            BackendError::KeyLoss(format!("{context}: the credential is gone from the store"))
        }
        // Reachable in principle, not answering now: locked keychain, no
        // session bus, no loaded profile.
        KeyringError::NoStorageAccess(error) | KeyringError::PlatformFailure(error) => {
            BackendError::StoreLocked(format!("{context}: {error}"))
        }
        // No store was configured at all: a deployment problem, not a retry.
        KeyringError::NoDefaultStore => {
            BackendError::Unavailable(format!("{context}: no credential store is configured"))
        }
        // The store does not implement what we asked of it.
        KeyringError::NotSupportedByStore(why) => {
            BackendError::Unavailable(format!("{context}: {why}"))
        }
        // Our address is supposed to be unique, so several matches is a bug on
        // our side rather than a condition to interpret.
        KeyringError::Ambiguous(matches) => BackendError::Internal(format!(
            "{context}: {} credentials match this key",
            matches.len()
        )),
        KeyringError::Invalid(what, why) => {
            BackendError::Internal(format!("{context}: {what} is not acceptable: {why}"))
        }
        KeyringError::TooLong(attribute, limit) => BackendError::Internal(format!(
            "{context}: {attribute} exceeds the store's limit of {limit}"
        )),
        KeyringError::BadStoreFormat(why) => {
            BackendError::Internal(format!("{context}: the store is malformed: {why}"))
        }
        // We wrote a hex scalar; anything else in the entry is corruption or a
        // foreign credential, and either way the key is lost — never silently
        // replaced by a fresh one.
        KeyringError::BadEncoding(_) | KeyringError::BadDataFormat(_, _) => BackendError::KeyLoss(
            format!("{context}: the stored credential is not a tpmd key"),
        ),
        other => BackendError::Internal(format!("{context}: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn platform(message: &str) -> Box<dyn std::error::Error + Send + Sync> {
        Box::from(message)
    }

    #[test]
    fn an_absent_credential_is_key_loss_not_an_unknown_key() {
        assert!(matches!(
            map_store_error("reading", KeyringError::NoEntry),
            BackendError::KeyLoss(_)
        ));
    }

    #[test]
    fn a_store_that_cannot_answer_is_store_locked() {
        for error in [
            KeyringError::NoStorageAccess(platform("the keychain is locked")),
            KeyringError::PlatformFailure(platform("no session bus")),
        ] {
            assert!(
                matches!(
                    map_store_error("reading", error),
                    BackendError::StoreLocked(_)
                ),
                "a store that cannot answer must be store_locked"
            );
        }
    }

    #[test]
    fn corruption_and_ambiguity_are_never_reported_as_missing_keys() {
        assert!(matches!(
            map_store_error("reading", KeyringError::BadEncoding(vec![0xff])),
            BackendError::KeyLoss(_)
        ));
        assert!(matches!(
            map_store_error(
                "reading",
                KeyringError::BadDataFormat(vec![], platform("x"))
            ),
            BackendError::KeyLoss(_)
        ));
        assert!(matches!(
            map_store_error("reading", KeyringError::Ambiguous(Vec::new())),
            BackendError::Internal(_)
        ));
        assert!(matches!(
            map_store_error(
                "reading",
                KeyringError::Invalid("user".into(), "bad".into())
            ),
            BackendError::Internal(_)
        ));
    }

    #[test]
    fn a_missing_store_is_reported_as_unavailable() {
        assert!(matches!(
            map_store_error("reading", KeyringError::NoDefaultStore),
            BackendError::Unavailable(_)
        ));
    }

    /// The operator's only clue is the message, so the store's own words have
    /// to survive the mapping.
    #[test]
    fn the_platform_error_is_kept_in_the_message() {
        let error = map_store_error(
            "reading",
            KeyringError::PlatformFailure(platform("bus gone")),
        );
        assert!(error.to_string().contains("bus gone"), "{error}");
    }
}
