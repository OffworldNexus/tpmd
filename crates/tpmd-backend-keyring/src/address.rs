//! Where a key lives inside the OS credential store.
//!
//! The store is a flat namespace of `(service, user)` pairs, so the whole
//! `(principal, namespace, key_id)` address has to be folded into the *user*
//! half. That folding has to be injective: two different keys sharing one entry
//! would let one principal read another's scalar, and the whole ownership model
//! rests on keys being addressed exactly.
//!
//! Plain concatenation would not do. A namespace may contain any character
//! (only its length is bounded), so `("a", "b:c")` and `("a:b", "c")` would
//! collide. Prefixing each variable-length part with its own length removes the
//! ambiguity without escaping, so the address stays readable in the OS store's
//! UI, which is worth a lot when a user is asked to inspect or delete a
//! credential by hand.
//!
//! The result is bounded by `4 + 60 + 4 + 255 + 1 + 66`, i.e. under the 513
//! characters Windows allows for a credential's target name; the namespace is
//! capped by the protocol at [`tpmd_proto::MAX_NAMESPACE_LEN`].

use tpmd_backend::Owner;
use tpmd_proto::{KeyId, MAX_NAMESPACE_LEN};

/// The address of `key_id` for `owner`, as it is stored in the OS credential
/// store.
///
/// Deterministic: the same key always maps to the same entry, across daemon
/// restarts and machines, with no lookup and no allocation of identities.
///
/// The result is also persisted verbatim in the `keyring_keys` table, so a
/// future change to this scheme cannot orphan keys written by an older build.
pub(crate) fn entry_address(owner: &Owner, key_id: &KeyId) -> String {
    let principal = owner.principal.as_str();
    let namespace = owner.namespace.as_str();
    debug_assert!(namespace.len() <= MAX_NAMESPACE_LEN as usize);
    format!(
        "{:04x}:{}:{:04x}:{}:{}",
        principal.len(),
        principal,
        namespace.len(),
        namespace,
        hex::encode(key_id.as_bytes()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpmd_backend::Principal;

    fn owner(principal: &str, namespace: &str) -> Owner {
        Owner::new(Principal(principal.into()), namespace)
    }

    fn key(byte: u8) -> KeyId {
        KeyId::P256([byte; 33])
    }

    #[test]
    fn the_address_is_stable_and_names_the_principal() {
        let address = entry_address(&owner("uid:1000", "app"), &key(1));
        assert!(address.contains("uid:1000"), "{address}");
        assert_eq!(address, entry_address(&owner("uid:1000", "app"), &key(1)));
    }

    #[test]
    fn different_keys_never_share_an_address() {
        let a = entry_address(&owner("uid:1000", "app"), &key(1));
        assert_ne!(a, entry_address(&owner("uid:1000", "app"), &key(2)));
        assert_ne!(a, entry_address(&owner("uid:2000", "app"), &key(1)));
        assert_ne!(a, entry_address(&owner("uid:1000", "other"), &key(1)));
    }

    /// The reason the parts are length-prefixed: a colon inside a namespace
    /// must not let two different owners slide into each other's entry.
    #[test]
    fn a_delimiter_in_a_namespace_cannot_shift_the_boundaries() {
        let left = entry_address(&owner("uid:1", "a:b"), &key(1));
        let right = entry_address(&owner("uid:1:a", "b"), &key(1));
        assert_ne!(left, right);
    }

    #[test]
    fn the_address_fits_a_windows_credential_name() {
        let long_principal = "sid:".to_owned() + &"9".repeat(56);
        let long_namespace = "n".repeat(MAX_NAMESPACE_LEN as usize);
        let address = entry_address(&owner(&long_principal, &long_namespace), &key(0xff));
        assert!(address.len() < 513, "address is {} chars", address.len());
    }
}
