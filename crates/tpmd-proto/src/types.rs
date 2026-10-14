//! Core value types shared across the protocol: algorithms, security levels,
//! key identifiers and signatures.
//!
//! These types are intentionally algorithm-aware: [`Algorithm`], [`KeyId`]
//! and [`Signature`] are enums whose variants are named after the algorithm,
//! so a future Ed25519 backend is a new variant rather than a change to every
//! message. In protocol v1 only ECDSA P-256 / SHA-256 exists.

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// A signing algorithm the daemon can offer.
///
/// The wire encoding is the variant index (Postcard varint), so **new variants
/// must be appended**, never inserted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Algorithm {
    /// ECDSA over NIST P-256 with SHA-256.
    EcdsaP256Sha256,
}

impl Algorithm {
    /// The length, in bytes, of a [`KeyId`] for this algorithm.
    pub const fn key_id_len(self) -> usize {
        match self {
            Algorithm::EcdsaP256Sha256 => 33,
        }
    }

    /// The length, in bytes, of a [`Signature`] for this algorithm.
    pub const fn signature_len(self) -> usize {
        match self {
            Algorithm::EcdsaP256Sha256 => 64,
        }
    }

    /// The public-key encoding documented in `docs/protocol.md`.
    pub const fn key_id_encoding(self) -> &'static str {
        match self {
            Algorithm::EcdsaP256Sha256 => "sec1-compressed",
        }
    }

    /// The signature encoding documented in `docs/protocol.md`.
    pub const fn signature_encoding(self) -> &'static str {
        match self {
            Algorithm::EcdsaP256Sha256 => "raw-r-s",
        }
    }
}

impl core::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Algorithm::EcdsaP256Sha256 => f.write_str("ecdsa-p256-sha256"),
        }
    }
}

/// The achieved protection of a key, ordered weakest to strongest.
///
/// `Ord` follows the variant order, so `file < keyring < sealed < hardware`.
/// A backend "meets the floor" when its level is `>= floor`. The wire encoding
/// is the variant index, so **new variants must be appended**.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// Software key in permission-protected storage. No hardware or
    /// credential-store protection. This is all the dummy backend offers.
    File,
    /// Software key protected by the OS credential store. Does not by itself
    /// prove hardware backing.
    Keyring,
    /// Software signing key hardware-wrapped at rest. Plaintext private
    /// material necessarily exists while signing.
    Sealed,
    /// Private key generated and retained in hardware; signing inside
    /// hardware; no private-key export.
    Hardware,
}

impl SecurityLevel {
    /// A stable, lowercase name suitable for logs and CLI output.
    pub const fn as_str(self) -> &'static str {
        match self {
            SecurityLevel::File => "file",
            SecurityLevel::Keyring => "keyring",
            SecurityLevel::Sealed => "sealed",
            SecurityLevel::Hardware => "hardware",
        }
    }

    /// Parse a level from its [`SecurityLevel::as_str`] spelling (case
    /// insensitive). Used by the CLI's `--min-key-security`.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "file" => Some(SecurityLevel::File),
            "keyring" => Some(SecurityLevel::Keyring),
            "sealed" => Some(SecurityLevel::Sealed),
            "hardware" => Some(SecurityLevel::Hardware),
            _ => None,
        }
    }
}

impl core::fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A key's identity: **its fingerprint**, which is exactly the public key in
/// the algorithm's compact encoding.
///
/// For P-256 this is the 33-byte SEC1-compressed point (`0x02`/`0x03` + X),
/// which is also the value Tunnel Weaver uses as its handshake `KeyId`. There
/// is no separate "id" concept, and keys are never listed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyId {
    /// ECDSA P-256 public key, SEC1 compressed (33 bytes).
    P256(#[serde(with = "BigArray")] [u8; 33]),
}

impl KeyId {
    /// The algorithm this key belongs to.
    pub const fn algorithm(self) -> Algorithm {
        match self {
            KeyId::P256(_) => Algorithm::EcdsaP256Sha256,
        }
    }

    /// The raw public-key bytes (SEC1 compressed for P-256).
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            KeyId::P256(bytes) => bytes.as_slice(),
        }
    }

    /// Lowercase hex of the fingerprint, for logs and golden-frame fixtures.
    pub fn to_hex(&self) -> String {
        hex_encode(self.as_bytes())
    }
}

impl core::fmt::Display for KeyId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// A signature in the algorithm's fixed encoding.
///
/// For P-256 this is the 64-byte big-endian `r ‖ s`, each integer left-padded
/// to 32 bytes — the encoding `weaver_mux::auth::verify` expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Signature {
    /// ECDSA P-256 signature, fixed-width `r ‖ s` (64 bytes).
    P256(#[serde(with = "BigArray")] [u8; 64]),
}

impl Signature {
    /// The algorithm this signature belongs to.
    pub const fn algorithm(self) -> Algorithm {
        match self {
            Signature::P256(_) => Algorithm::EcdsaP256Sha256,
        }
    }

    /// The raw signature bytes (`r ‖ s` for P-256).
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Signature::P256(bytes) => bytes.as_slice(),
        }
    }

    /// Lowercase hex of the signature, for logs and golden-frame fixtures.
    pub fn to_hex(&self) -> String {
        hex_encode(self.as_bytes())
    }
}

impl core::fmt::Display for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Minimal lowercase hex encoder.
///
/// Hand-rolled to keep `tpmd-proto` free of the `hex` crate at runtime; the
/// crate is only a dev-dependency for tests. Public keys and signatures are at
/// most 64 bytes, so a table-free encoder is plenty fast.
fn hex_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(TABLE[(b >> 4) as usize] as char);
        out.push(TABLE[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_level_orders_weakest_to_strongest() {
        assert!(SecurityLevel::File < SecurityLevel::Keyring);
        assert!(SecurityLevel::Keyring < SecurityLevel::Sealed);
        assert!(SecurityLevel::Sealed < SecurityLevel::Hardware);
    }

    #[test]
    fn security_level_round_trips_through_parse() {
        for level in [
            SecurityLevel::File,
            SecurityLevel::Keyring,
            SecurityLevel::Sealed,
            SecurityLevel::Hardware,
        ] {
            assert_eq!(SecurityLevel::parse(level.as_str()), Some(level));
        }
        assert_eq!(SecurityLevel::parse("SEALED"), Some(SecurityLevel::Sealed));
        assert_eq!(SecurityLevel::parse("nonsense"), None);
    }

    #[test]
    fn key_id_hex_is_the_fingerprint() {
        let id = KeyId::P256([0xab; 33]);
        assert_eq!(id.as_bytes().len(), 33);
        assert_eq!(id.to_hex(), "ab".repeat(33));
        assert_eq!(id.algorithm(), Algorithm::EcdsaP256Sha256);
    }
}
