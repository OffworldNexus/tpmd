//! The Secure Enclave, through `security-framework`'s safe wrappers.
//!
//! Everything platform-shaped lives here: `lib.rs` never sees a `CFType`, asks
//! for bytes and gets bytes or a [`Refusal`]. That line is worth keeping because
//! the refusals are not all the same thing — the backend's classification of a
//! shut store rests entirely on them.
//!
//! Four platform facts shape this module. Each was measured on the M1 rig, with
//! the evidence recorded in `docs/macos.md`:
//!
//! * **An ephemeral enclave key needs no keychain at all.** It is therefore the
//!   cheapest honest proof that the enclave answers *this process*, it works from
//!   any session (even one launchd would call Background), and it leaves nothing
//!   behind — which is what makes it safe to repeat while a client waits.
//! * **A persistent key is *stored*, and storage is where a wrongly deployed
//!   process is refused** — with `errSecMissingEntitlement`, whose name suggests a
//!   signing problem and is one: the bundle's identifier must be an App ID the
//!   team has provisioned, or the keychain will not take a key from it. Every
//!   operation on such a process fails, so usability has to be probed by *storing*
//!   something, not merely by generating.
//! * **A locked keychain and a wrong deployment both refuse**, with different
//!   codes, and only the first is the user's to fix. Those codes are the whole
//!   basis of `Closed` versus `Gone`.
//! * **The enclave signs a digest and returns DER.** The wire wants raw `r ‖ s`,
//!   so the conversion happens here, at the boundary, as the protocol requires;
//!   and it must not hash the message again — the enclave is asked to sign the
//!   SHA-256 we computed, so exactly one hash covers the transcript.

use core_foundation::error::CFError;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::base::Error as SecurityError;
use security_framework::item::{
    ItemClass, ItemSearchOptions, KeyClass, Location, Reference, SearchResult,
};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework_sys::access_control::kSecAccessControlPrivateKeyUsage;
use security_framework_sys::base::errSecItemNotFound;

/// `errSecInteractionNotAllowed`: the keychain is present but will not interact.
/// On macOS that is what a **locked** login keychain says, and unlocking it is
/// the user's own doing — hence `Closed` rather than `Gone`.
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;

/// `errSecAuthFailed`: the keychain refused the attempt to authorise it. The
/// same "fixable by the user" class as the code above.
const ERR_SEC_AUTH_FAILED: i32 = -25293;

/// `errSecMissingEntitlement`: the keychain refused the **process**, not the item.
///
/// This is the code a bundle gets when its identifier is not one the team's
/// provisioned identity covers; no amount of unlocking or retrying changes it,
/// which is exactly why it must not be reported as a closed store. (There is no
/// constant for it in `security-framework-sys`; the value is Apple's.)
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34018;

/// Why the platform said no.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Refusal {
    /// The `OSStatus` behind it, which is the only part that classifies. `i32`
    /// because that is what `OSStatus` is, and naming a foreign alias for it buys
    /// nothing at this boundary.
    code: i32,
    message: String,
}

impl Refusal {
    /// From a `CFError`, which is what the key APIs return.
    fn from_cf(error: &CFError) -> Self {
        let message = error.description().to_string();
        Self {
            code: error.code() as i32,
            message,
        }
    }

    /// From a raw status, for the item APIs, which have no `CFError`.
    pub(crate) fn from_status(code: i32) -> Self {
        let message = SecurityError::from_code(code)
            .message()
            .unwrap_or_else(|| format!("OSStatus {code}"));
        Self { code, message }
    }

    /// A failure on our side of the boundary, which is not the platform refusing
    /// anything.
    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self {
            code: 0,
            message: message.into(),
        }
    }

    /// The status behind the refusal.
    pub(crate) fn code(&self) -> i32 {
        self.code
    }

    /// The platform's own words, for the error the caller eventually sees.
    pub(crate) fn message(&self) -> &str {
        &self.message
    }

    /// Something the user can change: the keychain is locked.
    pub(crate) fn is_locked(&self) -> bool {
        matches!(
            self.code,
            ERR_SEC_INTERACTION_NOT_ALLOWED | ERR_SEC_AUTH_FAILED
        )
    }

    /// Something only a different deployment can change.
    pub(crate) fn is_deployment(&self) -> bool {
        self.code == ERR_SEC_MISSING_ENTITLEMENT
    }

    /// The item this key names is not in the keychain any more.
    pub(crate) fn is_missing(&self) -> bool {
        self.code == errSecItemNotFound
    }
}

/// What the process found the last time it asked.
#[derive(Clone)]
pub(crate) enum Access {
    /// The enclave made a key *and* the keychain stored it.
    Open,
    /// Shut for now; the user can open it (a locked keychain).
    Closed(Refusal),
    /// Unreachable as this process is deployed; nobody inside it can change that.
    Gone(Refusal),
}

impl Access {
    /// Sort a refusal into "the user can fix this" and "they cannot".
    ///
    /// Only two codes mean the former, and both are about interaction with the
    /// keychain. Everything else — a missing entitlement, an unknown host, no
    /// enclave at all — is a deployment problem, and calling it closed would park
    /// a client on a store that can never open.
    fn classify(refusal: Refusal) -> Self {
        if refusal.is_locked() {
            Self::Closed(refusal)
        } else {
            Self::Gone(refusal)
        }
    }
}

/// The access control a background agent needs: usable whenever the keychain is
/// unlocked, and **no** user presence.
///
/// The ticket is explicit that no presence policy is imposed, and the reason is
/// concrete: a biometric or passcode prompt on an unattended daemon is a hang,
/// not a security win. Whatever protects the login keychain still applies.
fn access_control() -> Result<SecAccessControl, Refusal> {
    SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
        kSecAccessControlPrivateKeyUsage,
    )
    .map_err(|error| Refusal::internal(format!("could not build an access control: {error}")))
}

/// The options an enclave key is generated with.
///
/// `label` is the handle the store records and finds the key again by; setting a
/// `location` is also what makes the key *permanent*. Secure Enclave keys live in
/// the data protection keychain — the crate's own documentation is explicit that
/// they must, and it is the one the rig proved.
fn options(label: &str, permanent: bool) -> Result<GenerateKeyOptions, Refusal> {
    let mut options = GenerateKeyOptions::default();
    options
        .set_key_type(KeyType::ec_sec_prime_random())
        .set_size_in_bits(256)
        .set_token(Token::SecureEnclave)
        .set_access_control(access_control()?);
    if permanent {
        options
            .set_label(label)
            .set_location(Location::DataProtectionKeychain);
    }
    Ok(options)
}

/// A fresh, unambiguous keychain label for one key.
///
/// Random rather than derived from the fingerprint, because the key has to be
/// labelled *before* it exists — the label is part of the request that creates it.
pub(crate) fn new_label() -> String {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).expect("the OS always has randomness");
    let mut label = String::from("nexus.offworld.tpmd.se.");
    for byte in random {
        label.push_str(&format!("{byte:02x}"));
    }
    label
}

/// Ask whether the enclave answers this process at all.
///
/// Generates an ephemeral key and drops it: nothing is stored, so this is the
/// probe that is safe to repeat. It answers "is the enclave reachable", which is
/// a *different* question from "will the keychain keep a key" — see
/// [`probe_storage`].
pub(crate) fn probe_enclave() -> Access {
    let Ok(options) = options("", false) else {
        return Access::Gone(Refusal::internal("could not build key options"));
    };
    match SecKey::new(&options) {
        Ok(_ephemeral) => Access::Open,
        Err(error) => Access::classify(Refusal::from_cf(&error)),
    }
}

/// Ask whether the keychain will *store* a key from this process.
///
/// This is the question that catches the expensive deployment mistake: a bundle
/// whose identifier the team has not provisioned can generate keys happily and be
/// refused the moment one has to persist. The probe key is deleted before
/// returning, so a successful probe leaves the keychain exactly as it found it.
pub(crate) fn probe_storage() -> Access {
    let label = new_label();
    let Ok(options) = options(&label, true) else {
        return Access::Gone(Refusal::internal("could not build key options"));
    };
    match SecKey::new(&options) {
        Ok(_probe) => {
            // Best effort: a probe that cannot clean up after itself is still a
            // probe that answered.
            let _ = delete(&label);
            Access::Open
        }
        Err(error) => Access::classify(Refusal::from_cf(&error)),
    }
}

/// Create a permanent enclave key, returning the fingerprint and its public half.
pub(crate) fn create_permanent(label: &str) -> Result<([u8; 33], Vec<u8>), Refusal> {
    let options = options(label, true)?;
    let key = SecKey::new(&options).map_err(|error| Refusal::from_cf(&error))?;

    // The custody this level advertises is *non-exportability*. If the platform
    // hands out the private half then what was created is not an enclave key, and
    // saying it is would be the silent weakening AGENTS.md forbids: take it back
    // out and refuse rather than tag a fingerprint we cannot back.
    if key.external_representation().is_some() {
        let _ = delete(label);
        return Err(Refusal::internal(
            "the platform exported a private key; this is not an enclave key",
        ));
    }

    let compressed = public_sec1(&key)?;
    Ok((compressed, compressed.to_vec()))
}

/// Find a stored key by its label.
pub(crate) fn find(label: &str) -> Result<SecKey, Refusal> {
    let mut search = ItemSearchOptions::new();
    search
        .class(ItemClass::key())
        .key_class(KeyClass::private())
        .label(label)
        .load_refs(true)
        // The data protection keychain is invisible to a default search, and it
        // is where enclave keys live.
        .ignore_legacy_keychains();

    let results = search
        .search()
        .map_err(|error| Refusal::from_status(error.code()))?;

    results
        .into_iter()
        .find_map(|result| match result {
            SearchResult::Ref(Reference::Key(key)) => Some(key),
            _ => None,
        })
        .ok_or_else(|| Refusal::from_status(errSecItemNotFound))
}

/// Sign a SHA-256 digest, returning raw big-endian `r ‖ s`.
///
/// The enclave is asked for a *digest* signature, so the one hash over the
/// transcript is the one the caller computed. The DER it returns is converted
/// here: the wire speaks raw `r ‖ s`, and the protocol says platform encodings are
/// normalised at the backend boundary.
pub(crate) fn sign(label: &str, digest: &[u8; 32]) -> Result<[u8; 64], Refusal> {
    let key = find(label)?;
    let der = key
        .create_signature(Algorithm::ECDSASignatureDigestX962SHA256, digest)
        .map_err(|error| Refusal::from_cf(&error))?;
    der_to_raw(&der).ok_or_else(|| {
        Refusal::internal("the platform returned a signature that is not a DER ECDSA pair")
    })
}

/// Remove a stored key. Absent is success: the caller asked for it to be gone.
pub(crate) fn delete(label: &str) -> Result<(), Refusal> {
    let mut delete = ItemSearchOptions::new();
    delete
        .class(ItemClass::key())
        .key_class(KeyClass::private())
        .label(label)
        .ignore_legacy_keychains();

    match delete.delete() {
        Ok(()) => Ok(()),
        // Nothing there is the outcome the caller wanted.
        Err(error) if error.code() == errSecItemNotFound => Ok(()),
        Err(error) => Err(Refusal::from_status(error.code())),
    }
}

/// The key's public half as SEC1 compressed, which is the fingerprint format.
fn public_sec1(key: &SecKey) -> Result<[u8; 33], Refusal> {
    let raw = key
        .public_key()
        .and_then(|public| public.external_representation())
        .ok_or_else(|| Refusal::internal("the enclave would not export a public key"))?;
    sec1_compressed(&raw).ok_or_else(|| {
        Refusal::internal(
            "the enclave returned a public key that is not an uncompressed P-256 point",
        )
    })
}

/// X9.63 uncompressed (65 bytes) to SEC1 compressed (33 bytes).
fn sec1_compressed(raw: &[u8]) -> Option<[u8; 33]> {
    if raw.len() != 65 || raw[0] != 0x04 {
        return None;
    }
    let mut compressed = [0u8; 33];
    // The prefix is the parity of the y coordinate, which is the last byte of the
    // uncompressed form.
    compressed[0] = if raw[64] & 1 == 0 { 0x02 } else { 0x03 };
    compressed[1..].copy_from_slice(&raw[1..33]);
    Some(compressed)
}

/// DER `SEQUENCE { INTEGER r, INTEGER s }` to raw big-endian `r ‖ s`.
///
/// Both integers lose DER's sign padding and are left-padded to 32 bytes; a value
/// that does not fit is a refusal rather than a silently truncated signature.
fn der_to_raw(der: &[u8]) -> Option<[u8; 64]> {
    if der.len() < 8 || der[0] != 0x30 {
        return None;
    }
    // The SEQUENCE length is one byte, or a long form (0x81/0x82) that has to be
    // skipped whole.
    let mut index = if der[1] & 0x80 == 0 {
        2
    } else {
        2 + usize::from(der[1] & 0x7f)
    };

    let mut integers = [[0u8; 32]; 2];
    for slot in &mut integers {
        if index + 2 > der.len() || der[index] != 0x02 {
            return None;
        }
        let length = usize::from(der[index + 1]);
        let body = der.get(index + 2..index + 2 + length)?;
        index += 2 + length;

        let body = match body {
            [0, rest @ ..] if rest.len() >= 32 => rest,
            rest => rest,
        };
        if body.len() > 32 {
            return None;
        }
        slot[32 - body.len()..].copy_from_slice(body);
    }

    let mut raw = [0u8; 64];
    raw[..32].copy_from_slice(&integers[0]);
    raw[32..].copy_from_slice(&integers[1]);
    Some(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_der_pair_becomes_the_raw_wire_form() {
        // A real 71-byte signature from the rig, with the leading 0x00 DER adds to
        // keep `s` positive — the case the padding rule exists for.
        let der = hex_bytes(
            "3045022057d7caf9f810451697b842d7e185e524b9c07ec88590781cbd9d2010cb68f361\
             0221008d558146730e3009299d133e5b52e48a8f4f3dd58dd913066009af6a0bbea5a0",
        );
        let raw = der_to_raw(&der).expect("a DER pair");
        assert_eq!(
            hex(&raw),
            "57d7caf9f810451697b842d7e185e524b9c07ec88590781cbd9d2010cb68f361\
             8d558146730e3009299d133e5b52e48a8f4f3dd58dd913066009af6a0bbea5a0"
        );
        // Both halves are exactly 32 bytes, whatever DER's own length was.
        assert_eq!(raw.len(), 64);
    }

    #[test]
    fn a_short_der_pair_is_padded_not_truncated() {
        // r = 0x01, s = 0x02: the smallest legal pair.
        let der = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let raw = der_to_raw(&der).expect("a DER pair");
        assert_eq!(raw[31], 0x01);
        assert_eq!(raw[63], 0x02);
        assert_eq!(raw[..31], [0u8; 31]);
    }

    #[test]
    fn something_that_is_not_a_der_pair_is_refused() {
        assert_eq!(der_to_raw(&[]), None);
        assert_eq!(
            der_to_raw(&[0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]),
            None
        );
        // A value that cannot fit in 32 bytes is refused rather than cut down.
        let mut oversized = vec![0x30, 0x45, 0x02, 0x21, 0x01];
        oversized.extend_from_slice(&[0xff; 32]);
        oversized.extend_from_slice(&[0x02, 0x01, 0x02]);
        assert_eq!(der_to_raw(&oversized), None);
    }

    #[test]
    fn the_public_key_compresses_by_parity() {
        let mut uncompressed = vec![0x04];
        uncompressed.extend_from_slice(&[0x11; 32]); // x
        uncompressed.extend_from_slice(&[0x22; 31]); // y …
        uncompressed.push(0x22); // … which is even
        let even = sec1_compressed(&uncompressed).expect("a point");
        assert_eq!(even[0], 0x02);
        assert_eq!(&even[1..], &[0x11; 32]);

        let mut odd = uncompressed.clone();
        odd[64] = 0x23;
        assert_eq!(sec1_compressed(&odd).expect("a point")[0], 0x03);
    }

    #[test]
    fn a_compressed_or_wrong_length_key_is_not_recompressed() {
        assert_eq!(sec1_compressed(&[0x02; 33]), None);
        assert_eq!(sec1_compressed(&[0x04; 64]), None);
    }

    #[test]
    fn the_classification_splits_what_the_user_can_fix() {
        assert!(matches!(
            Access::classify(Refusal::from_status(ERR_SEC_INTERACTION_NOT_ALLOWED)),
            Access::Closed(_)
        ));
        assert!(matches!(
            Access::classify(Refusal::from_status(ERR_SEC_AUTH_FAILED)),
            Access::Closed(_)
        ));
        // A keychain that will not hear of this process is nobody's to unlock.
        assert!(matches!(
            Access::classify(Refusal::from_status(ERR_SEC_MISSING_ENTITLEMENT)),
            Access::Gone(_)
        ));
        assert!(Refusal::from_status(ERR_SEC_MISSING_ENTITLEMENT).is_deployment());
        assert!(Refusal::from_status(errSecItemNotFound).is_missing());
    }

    #[test]
    fn labels_are_unique_and_namespaced() {
        let first = new_label();
        let second = new_label();
        assert_ne!(first, second);
        assert!(first.starts_with("nexus.offworld.tpmd.se."));
        assert_eq!(first.len(), "nexus.offworld.tpmd.se.".len() + 32);
    }

    /// `hex::decode` is a dev-dependency; this keeps the test's intent visible.
    fn hex_bytes(text: &str) -> Vec<u8> {
        hex::decode(text.replace(['\n', ' '], "")).expect("hex")
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
