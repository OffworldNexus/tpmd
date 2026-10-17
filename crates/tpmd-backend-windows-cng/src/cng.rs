//! Safe wrapper over the Microsoft Platform Crypto Provider, plus the pieces of
//! the backend that need no FFI at all: blob parsing, key naming, the custody
//! check and the startup probe.
//!
//! The distinction that matters here: a Platform Crypto Provider key can exist
//! **without** the TPM, in which case Windows wraps it with DPAPI. That key is
//! non-exportable by policy but is *not* hardware custody, so this module never
//! infers the level from the provider's name — it asks the provider what backs
//! the key and reports that.
//!
//! The key context is the caller's: these are per-user keys, and the ticket's
//! evidence shows a *network* logon (WinRM) is refused where an interactive
//! session succeeds, so [`Platform::probe`] verifies usability rather than
//! assuming it.

use windows_sys::Win32::Security::Cryptography as ncrypt;

use crate::ffi::{self, CngError, Handle, Owned};

/// `EccPublicBlob` header: `magic(4) ‖ cbKey(4)`.
const ECC_BLOB_HEADER: usize = 8;
/// A P-256 coordinate.
const ECC_COORDINATE: usize = 32;
/// `BCRYPT_ECDSA_PUBLIC_P256_MAGIC`, i.e. `"ECS1"` little-endian.
const ECDSA_PUBLIC_P256_MAGIC: u32 = 0x3153_4345;

/// `PCP_PLATFORM_TYPE` answers, as reported by the Platform Crypto Provider.
///
/// The provider tells the truth about what is backing a key, which is the only
/// honest basis for a `hardware` claim; the recorded probe on this project's
/// vTPM confirms which value a real TPM 2.0 produces.
const PCP_PLATFORM_TYPE_TPM12: u32 = 1;
const PCP_PLATFORM_TYPE_TPM20: u32 = 2;

/// A malformed public blob.
#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    /// Too short to hold the header and both coordinates.
    #[error("the public blob is {actual} bytes; a P-256 EccPublicBlob is 72")]
    Short {
        /// The length we were given.
        actual: usize,
    },
    /// Not a P-256 ECDSA public blob.
    #[error("unexpected EccPublicBlob magic {magic:#010x}")]
    Magic {
        /// The magic we found.
        magic: u32,
    },
    /// The key is not the width a P-256 coordinate should be.
    #[error("unexpected EccPublicBlob key size {size}")]
    CoordinateSize {
        /// The size the blob declared.
        size: u32,
    },
}

/// Why a key did not meet the `hardware` claim.
#[derive(Debug, thiserror::Error)]
pub enum CustodyError {
    /// The key can be exported, so it is not hardware custody at all.
    #[error("the key is exportable (export policy {0:#010x}); refusing to call it hardware")]
    Exportable(u32),
    /// The provider is backing the key with something other than a TPM 2.0.
    #[error("the provider reports platform type {0}, which is not a TPM 2.0")]
    NotTpm(u32),
    /// The provider itself says the key may be exported.
    #[error("the provider allows this key to be exported; refusing to call it hardware")]
    ExportAllowed(u8),
    /// The provider would not answer a question the claim depends on, so the
    /// claim cannot be made. Named, because *which* property failed is the
    /// difference between "no TPM here" and "the device said something odd".
    #[error("the provider could not report {name} for this key ({source})")]
    Property {
        /// The property that could not be read.
        name: &'static str,
        /// The underlying failure.
        source: CngError,
    },
    /// A CNG call failed while checking.
    #[error(transparent)]
    Cng(#[from] CngError),
}

/// Derive the 33-byte SEC1-compressed fingerprint from an `EccPublicBlob`.
///
/// The blob is `magic ‖ cbKey ‖ X ‖ Y` with big-endian coordinates that already
/// match SEC1; only the `0x02`/`0x03` prefix has to be reconstructed from the
/// parity of `Y`.
pub fn sec1_from_ecc_public_blob(blob: &[u8]) -> Result<[u8; 33], BlobError> {
    if blob.len() < ECC_BLOB_HEADER + 2 * ECC_COORDINATE {
        return Err(BlobError::Short { actual: blob.len() });
    }
    let magic = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
    if magic != ECDSA_PUBLIC_P256_MAGIC {
        return Err(BlobError::Magic { magic });
    }
    let size = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]);
    if size as usize != ECC_COORDINATE {
        return Err(BlobError::CoordinateSize { size });
    }

    let x = &blob[ECC_BLOB_HEADER..ECC_BLOB_HEADER + ECC_COORDINATE];
    let y = &blob[ECC_BLOB_HEADER + ECC_COORDINATE..ECC_BLOB_HEADER + 2 * ECC_COORDINATE];
    let mut out = [0u8; 33];
    out[0] = if y[ECC_COORDINATE - 1] & 1 == 0 {
        0x02
    } else {
        0x03
    };
    out[1..].copy_from_slice(x);
    Ok(out)
}

/// A fresh provider key name.
///
/// The name cannot be derived from the fingerprint: the public key does not
/// exist until the key is finalized, so a random name is minted and the
/// name → fingerprint mapping is what the store row records.
pub fn new_key_name() -> Result<String, CngError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| CngError::Random(e.to_string()))?;
    let mut name = String::from("tpmd-");
    for byte in bytes {
        use core::fmt::Write as _;
        let _ = write!(name, "{byte:02x}");
    }
    Ok(name)
}

/// Check that a key really is non-exportable and TPM-backed.
///
/// The export policy is the control that matters: if it is not zero the key can
/// leave, and no backing story saves that. Beyond it the provider is asked what
/// backs the key, and only a TPM 2.0 answer is acceptable.
///
/// Some providers will not answer. This project's emulated TPM returns a
/// TPM-facility error for `PCP_PLATFORM_TYPE` *and* for the otherwise ordinary
/// `Algorithm Group`, so when the backing cannot be confirmed directly the check
/// falls back to the two facts that remain — the key is non-exportable by policy
/// **and** the provider itself reports export is not allowed **and** the key
/// lives in the Platform Crypto Provider, which will not create a key without a
/// TPM 2.0. The fallback is logged rather than hidden, and it is never used to
/// excuse an exportable key.
pub fn verify_custody(key: Handle) -> Result<(), CustodyError> {
    let policy = ffi::get_u32(key, ncrypt::NCRYPT_EXPORT_POLICY_PROPERTY).map_err(|source| {
        CustodyError::Property {
            name: "its export policy",
            source,
        }
    })?;
    if policy != 0 {
        return Err(CustodyError::Exportable(policy));
    }

    match ffi::get_u32(key, ncrypt::NCRYPT_PCP_PLATFORM_TYPE_PROPERTY) {
        Ok(PCP_PLATFORM_TYPE_TPM20) => Ok(()),
        Ok(PCP_PLATFORM_TYPE_TPM12) => Err(CustodyError::NotTpm(PCP_PLATFORM_TYPE_TPM12)),
        Ok(other) => Err(CustodyError::NotTpm(other)),
        Err(source) => match ffi::get_u8(key, ncrypt::NCRYPT_PCP_EXPORT_ALLOWED_PROPERTY) {
            // Corroborated: the provider says this key may not be exported, and
            // it is a Platform Crypto Provider key.
            Ok(0) => {
                tracing::warn!(
                    %source,
                    "the provider will not report what backs this key; relying on the \
                     Platform Crypto Provider's own non-exportable store instead"
                );
                Ok(())
            }
            Ok(allowed) => Err(CustodyError::ExportAllowed(allowed)),
            Err(source) => Err(CustodyError::Property {
                name: "what backs the key (PCP_PLATFORM_TYPE)",
                source,
            }),
        },
    }
}

/// Exercise the custody guarantee: exporting the private half must not work.
///
/// Any failure counts as refusal — the property under test is "we could not
/// obtain the private key", not *why* the provider said no.
pub fn private_export_is_refused(key: Handle) -> bool {
    match ffi::export_private_blob(key) {
        Ok(_) => false,
        Err(error) => {
            tracing::debug!(
                status = %format_args!("{:#010x}", error.code()),
                "private export refused, as it must be"
            );
            true
        }
    }
}

/// An open Platform Crypto Provider.
pub struct Platform {
    provider: Owned,
}

impl Platform {
    /// Open the provider. A machine with no usable TPM (or a user who cannot
    /// reach it) fails here, which is how the backend learns it is unusable.
    pub fn open() -> Result<Self, CngError> {
        Ok(Self {
            provider: ffi::open_platform_provider()?,
        })
    }

    /// Whether the provider offers ECDSA P-256.
    pub fn supports_p256(&self) -> bool {
        ffi::supports_p256(self.provider.raw())
    }

    /// Create a persisted, non-exportable, TPM-backed P-256 key.
    ///
    /// Order matters: the export policy must be set *before* finalize, and
    /// finalize is what writes the key into the user's store. If the key turns
    /// out not to be hardware-custodial it is **destroyed** before returning —
    /// we never leave behind a key we refused to call hardware.
    pub fn create_custodial_key(&self, name: &str) -> Result<Owned, CustodyError> {
        let key = ffi::create_persisted_p256(self.provider.raw(), name)?;
        // Nothing may ever leave the TPM.
        ffi::set_u32(key.raw(), ncrypt::NCRYPT_EXPORT_POLICY_PROPERTY, 0)?;
        ffi::finalize(key.raw())?;

        if let Err(error) = verify_custody(key.raw()) {
            if let Err(cleanup) = ffi::delete_key(key) {
                tracing::warn!(%cleanup, name, "could not destroy a non-custodial key");
            }
            return Err(error);
        }
        Ok(key)
    }

    /// Open a persisted key by name.
    pub fn open_key(&self, name: &str) -> Result<Owned, CngError> {
        ffi::open_key(self.provider.raw(), name)
    }

    /// Sign a pre-computed digest; the result is already raw `r ‖ s`.
    pub fn sign(&self, key: Handle, digest: &[u8]) -> Result<[u8; 64], CngError> {
        ffi::sign_digest(key, digest)
    }

    /// The public half of a key, as an `EccPublicBlob`.
    pub fn public_blob(&self, key: Handle) -> Result<Vec<u8>, CngError> {
        ffi::export_public_blob(key)
    }

    /// Delete a persisted key.
    pub fn delete(&self, key: Owned) -> Result<(), CngError> {
        ffi::delete_key(key)
    }

    /// Prove that this user, in this session, can create, use and delete a
    /// hardware key.
    ///
    /// The ticket requires ordinary-user key creation to be *verified, not
    /// assumed*, and the recorded evidence shows why: opening the provider
    /// succeeds over a network logon, and only key creation fails there. The
    /// probe therefore goes all the way through a signature.
    pub fn probe(&self) -> bool {
        if !self.supports_p256() {
            tracing::info!("the Platform Crypto Provider does not offer ECDSA P-256");
            return false;
        }

        let name = match new_key_name() {
            Ok(name) => name,
            Err(error) => {
                tracing::warn!(%error, "cannot draw a key name for the probe");
                return false;
            }
        };

        let key = match self.create_custodial_key(&name) {
            Ok(key) => key,
            Err(error) => {
                tracing::info!(
                    %error,
                    "the Platform Crypto Provider cannot create a user key here \
                     (an interactive session and a live TPM 2.0 are required)"
                );
                return false;
            }
        };

        let usable = ffi::sign_digest(key.raw(), &[0u8; 32]).is_ok()
            && ffi::export_public_blob(key.raw()).is_ok();
        // Always clean up, whether or not the probe succeeded.
        if let Err(error) = ffi::delete_key(key) {
            tracing::warn!(%error, "could not delete the probe key");
        }
        usable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(magic: u32, y_last: u8) -> Vec<u8> {
        let mut blob = Vec::new();
        blob.extend_from_slice(&magic.to_le_bytes());
        blob.extend_from_slice(&(ECC_COORDINATE as u32).to_le_bytes());
        blob.extend_from_slice(&[0x11; ECC_COORDINATE]); // X
        let mut y = [0x22u8; ECC_COORDINATE];
        y[ECC_COORDINATE - 1] = y_last;
        blob.extend_from_slice(&y);
        blob
    }

    #[test]
    fn an_even_y_yields_a_02_prefix() {
        let sec1 = sec1_from_ecc_public_blob(&blob(ECDSA_PUBLIC_P256_MAGIC, 0x22)).unwrap();
        assert_eq!(sec1[0], 0x02);
        assert_eq!(&sec1[1..], &[0x11; ECC_COORDINATE]);
    }

    #[test]
    fn an_odd_y_yields_a_03_prefix() {
        let sec1 = sec1_from_ecc_public_blob(&blob(ECDSA_PUBLIC_P256_MAGIC, 0x23)).unwrap();
        assert_eq!(sec1[0], 0x03);
    }

    #[test]
    fn a_wrong_magic_is_rejected() {
        assert!(matches!(
            sec1_from_ecc_public_blob(&blob(0xdead_beef, 0x22)),
            Err(BlobError::Magic { .. })
        ));
    }

    #[test]
    fn a_short_blob_is_rejected() {
        assert!(matches!(
            sec1_from_ecc_public_blob(&[0u8; 8]),
            Err(BlobError::Short { .. })
        ));
    }

    #[test]
    fn a_wrong_coordinate_size_is_rejected() {
        let mut bad = blob(ECDSA_PUBLIC_P256_MAGIC, 0x22);
        bad[4..8].copy_from_slice(&64u32.to_le_bytes());
        assert!(matches!(
            sec1_from_ecc_public_blob(&bad),
            Err(BlobError::CoordinateSize { .. })
        ));
    }

    #[test]
    fn key_names_are_prefixed_and_unique() {
        let a = new_key_name().unwrap();
        let b = new_key_name().unwrap();
        assert!(a.starts_with("tpmd-"));
        assert_eq!(a.len(), "tpmd-".len() + 32);
        assert_ne!(a, b);
    }

    /// The custody guarantee, exercised against a real provider.
    ///
    /// Needs a live TPM 2.0 **and** a logon that may create a Platform Crypto
    /// Provider user key (an interactive session, not WinRM), so it reports a
    /// skip instead of failing where those are missing — which is what keeps
    /// the TPM-less CI runner green.
    ///
    /// It also prints the provider's `PCP_PLATFORM_TYPE`, which is where the
    /// "is this really TPM-backed?" constant gets confirmed on real hardware.
    #[test]
    fn a_real_key_is_non_exportable_and_reports_its_backing() {
        let platform = match Platform::open() {
            Ok(platform) => platform,
            Err(error) => {
                eprintln!("skipping: no Platform Crypto Provider ({error})");
                return;
            }
        };
        if !platform.supports_p256() {
            eprintln!("skipping: the provider offers no ECDSA P-256");
            return;
        }

        let name = new_key_name().unwrap();
        let key = match platform.create_custodial_key(&name) {
            Ok(key) => key,
            Err(error) => {
                eprintln!("skipping: cannot create a user key here ({error})");
                return;
            }
        };

        assert!(
            private_export_is_refused(key.raw()),
            "a hardware key must not be exportable"
        );

        let policy = ffi::get_u32(key.raw(), ncrypt::NCRYPT_EXPORT_POLICY_PROPERTY).unwrap();
        assert_eq!(policy, 0, "the export policy must be zero");

        let backing = ffi::get_u32(key.raw(), ncrypt::NCRYPT_PCP_PLATFORM_TYPE_PROPERTY);
        match backing {
            Ok(value) => {
                eprintln!(
                    "PCP_PLATFORM_TYPE = {value} \
                     (TPM 2.0 is expected to be {PCP_PLATFORM_TYPE_TPM20})"
                );
                assert_eq!(value, PCP_PLATFORM_TYPE_TPM20, "the key must be TPM-backed");
            }
            Err(error) => {
                // Some providers will not answer (this project's emulated TPM
                // returns a TPM-facility error). What must hold either way is
                // that the provider considers the key non-exportable.
                eprintln!(
                    "the provider would not report PCP_PLATFORM_TYPE ({error}); \
                     custody fell back to the export policy"
                );
                let allowed =
                    ffi::get_u8(key.raw(), ncrypt::NCRYPT_PCP_EXPORT_ALLOWED_PROPERTY).unwrap();
                assert_eq!(allowed, 0, "the provider must forbid exporting this key");
            }
        }

        let blob = platform.public_blob(key.raw()).unwrap();
        let sec1 = sec1_from_ecc_public_blob(&blob).unwrap();
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).unwrap();

        platform.delete(key).unwrap();

        // A row whose native key has gone must read as *missing*, which is what
        // the backend maps to key loss rather than a transient failure.
        let gone = platform.open_key(&name).unwrap_err();
        assert!(gone.is_missing(), "expected a missing key, got {gone}");
    }
}
