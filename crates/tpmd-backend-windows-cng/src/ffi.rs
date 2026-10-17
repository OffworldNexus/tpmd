//! The only module in this crate permitted `unsafe`: the CNG (NCrypt) calls,
//! handle ownership and status-code handling.
//!
//! The declarations themselves come from `windows-sys`; what this module adds
//! is the three things a raw binding should not be used without:
//!
//! * **RAII handles.** Every `NCrypt*` object is wrapped in [`Owned`], which
//!   calls `NCryptFreeObject` on drop, so a failing call cannot leak one.
//! * **Wide strings.** `PCWSTR` needs a NUL-terminated UTF-16 buffer, built by
//!   [`wide`] for the duration of each call.
//! * **A typed failure.** A negative `HRESULT` becomes a [`CngError`] carrying
//!   the operation and the status, which the layer above maps onto the
//!   backend's error taxonomy.
//!
//! Everything here is a thin, mechanical wrapper; the interesting decisions
//! (which properties to check, what counts as hardware custody) live in
//! [`crate::cng`], which is safe code.
#![allow(unsafe_code)]

use core::ffi::c_void;
use core::mem::ManuallyDrop;
use std::ptr;

use windows_sys::Win32::Security::Cryptography as ncrypt;

/// A CNG object handle (provider, key or generic).
pub type Handle = ncrypt::NCRYPT_HANDLE;

/// The status codes this crate reasons about, from `winerror.h`/`ntstatus.h`.
///
/// Declared locally rather than imported so the meaning of each branch is
/// visible where it is used.
pub mod nte {
    /// The key set could not be opened: no such key for this user.
    pub const BAD_KEYSET: i32 = 0x8009_0016u32 as i32;
    /// The object was not found.
    pub const NOT_FOUND: i32 = 0x8009_0011u32 as i32;
    /// Access was denied (permissions, or a logon type that cannot use the key).
    pub const PERM: i32 = 0x8009_0010u32 as i32;
    /// The handle is not valid.
    pub const INVALID_HANDLE: i32 = 0x8009_0026u32 as i32;
    /// The backing device (the TPM) is not ready or not present.
    pub const DEVICE_NOT_READY: i32 = 0x8009_0015u32 as i32;
    /// A generic CNG failure.
    pub const FAIL: i32 = 0x8009_0029u32 as i32;
}

/// A CNG failure.
#[derive(Debug, thiserror::Error)]
pub enum CngError {
    /// The call returned a negative status.
    #[error("{operation} failed with CNG status {code:#010x}")]
    Status {
        /// The `NCrypt*` call that failed.
        operation: &'static str,
        /// The raw `HRESULT`.
        code: i32,
    },
    /// The call succeeded but returned something the caller cannot use.
    #[error("{operation} returned {actual} bytes where {expected} were expected")]
    Shape {
        /// The `NCrypt*` call that misbehaved.
        operation: &'static str,
        /// The size the contract promises.
        expected: u32,
        /// The size we actually got.
        actual: u32,
    },
    /// The operating system could not supply randomness for a key name.
    #[error("could not draw randomness: {0}")]
    Random(String),
}

impl CngError {
    /// The raw status, for classification by the caller.
    pub fn code(&self) -> i32 {
        match self {
            CngError::Status { code, .. } => *code,
            // Neither of these is a device answer; classify as a generic
            // failure rather than pretending to know better.
            CngError::Shape { .. } | CngError::Random(_) => nte::FAIL,
        }
    }

    /// True when the key simply is not there (as opposed to being unusable).
    pub fn is_missing(&self) -> bool {
        matches!(
            self.code(),
            nte::BAD_KEYSET | nte::NOT_FOUND | nte::INVALID_HANDLE
        )
    }

    /// True when the failure is about access rather than existence — typically
    /// a logon type (e.g. a network logon) that cannot use this user's keys.
    pub fn is_access_denied(&self) -> bool {
        self.code() == nte::PERM
    }
}

/// A NUL-terminated UTF-16 buffer for a `PCWSTR` argument.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(core::iter::once(0)).collect()
}

/// Turn a negative `HRESULT` into an error.
fn check(operation: &'static str, status: i32) -> Result<(), CngError> {
    if status >= 0 {
        Ok(())
    } else {
        Err(CngError::Status {
            operation,
            code: status,
        })
    }
}

/// Owns a CNG object and releases it on drop.
pub struct Owned(Handle);

impl Owned {
    /// The raw handle, for passing to further calls.
    pub fn raw(&self) -> Handle {
        self.0
    }

    /// Relinquish ownership: the caller takes over releasing the handle.
    ///
    /// Used where a call frees the handle itself (`NCryptDeleteKey`), so the
    /// drop guard does not double-free. Leaking one handle is always safer
    /// than freeing twice.
    pub fn into_raw(self) -> Handle {
        ManuallyDrop::new(self).0
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from a successful `NCrypt*` open/create call
        // and has not been handed to `into_raw`, so it is ours to release.
        unsafe {
            ncrypt::NCryptFreeObject(self.0);
        }
    }
}

impl core::fmt::Debug for Owned {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // A raw handle is not secret, but it is not useful either; print it for
        // diagnostics without implying anything about the key.
        f.debug_tuple("CngObject").field(&self.0).finish()
    }
}

/// Open the Microsoft Platform Crypto Provider.
///
/// This is the only provider that puts keys in the TPM; a machine without one
/// fails here (which is how `can_be_used` finds out).
pub fn open_platform_provider() -> Result<Owned, CngError> {
    let mut provider: ncrypt::NCRYPT_PROV_HANDLE = 0;
    // SAFETY: `provider` is a valid out-parameter and the provider name is a
    // static NUL-terminated wide string supplied by `windows-sys`.
    let status = unsafe {
        ncrypt::NCryptOpenStorageProvider(&mut provider, ncrypt::MS_PLATFORM_CRYPTO_PROVIDER, 0)
    };
    check("NCryptOpenStorageProvider", status)?;
    Ok(Owned(provider))
}

/// Whether the provider offers ECDSA P-256.
pub fn supports_p256(provider: Handle) -> bool {
    // SAFETY: `provider` is an open provider handle owned by the caller.
    unsafe { ncrypt::NCryptIsAlgSupported(provider, ncrypt::NCRYPT_ECDSA_P256_ALGORITHM, 0) == 0 }
}

/// Begin creating a persisted P-256 key. The key is not usable until
/// [`finalize`] runs, which is what makes the export policy stick.
pub fn create_persisted_p256(provider: Handle, name: &str) -> Result<Owned, CngError> {
    let name = wide(name);
    let mut key: ncrypt::NCRYPT_KEY_HANDLE = 0;
    // SAFETY: `key` is a valid out-parameter; both algorithm and name are
    // NUL-terminated wide strings that outlive the call.
    let status = unsafe {
        ncrypt::NCryptCreatePersistedKey(
            provider,
            &mut key,
            ncrypt::NCRYPT_ECDSA_P256_ALGORITHM,
            name.as_ptr(),
            0,
            0,
        )
    };
    check("NCryptCreatePersistedKey", status)?;
    Ok(Owned(key))
}

/// Set a `DWORD` property on a key and persist it with the key.
pub fn set_u32(key: Handle, property: *const u16, value: u32) -> Result<(), CngError> {
    let bytes = value.to_le_bytes();
    // SAFETY: the property name and the 4-byte value are both valid for the
    // duration of the call; `key` is an open key handle.
    let status = unsafe {
        ncrypt::NCryptSetProperty(
            key,
            property,
            bytes.as_ptr(),
            bytes.len() as u32,
            ncrypt::NCRYPT_PERSIST_FLAG,
        )
    };
    check("NCryptSetProperty", status)
}

/// Read a `DWORD` property from a key.
pub fn get_u32(key: Handle, property: *const u16) -> Result<u32, CngError> {
    let mut buffer = [0u8; 4];
    let mut written = 0u32;
    // SAFETY: the output buffer is 4 bytes and `written` is a valid
    // out-parameter, so the call cannot write past `buffer`.
    let status = unsafe {
        ncrypt::NCryptGetProperty(
            key,
            property,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            &mut written,
            0,
        )
    };
    check("NCryptGetProperty", status)?;
    if written != buffer.len() as u32 {
        return Err(CngError::Shape {
            operation: "NCryptGetProperty",
            expected: buffer.len() as u32,
            actual: written,
        });
    }
    Ok(u32::from_le_bytes(buffer))
}

/// Read a single-byte property from a key.
pub fn get_u8(key: Handle, property: *const u16) -> Result<u8, CngError> {
    let mut buffer = [0u8; 1];
    let mut written = 0u32;
    // SAFETY: the output buffer is 1 byte and `written` is a valid
    // out-parameter, so the call cannot write past `buffer`.
    let status = unsafe {
        ncrypt::NCryptGetProperty(key, property, buffer.as_mut_ptr(), 1, &mut written, 0)
    };
    check("NCryptGetProperty", status)?;
    if written != 1 {
        return Err(CngError::Shape {
            operation: "NCryptGetProperty",
            expected: 1,
            actual: written,
        });
    }
    Ok(buffer[0])
}

/// Promote a key into the user's store, silently (no UI).
pub fn finalize(key: Handle) -> Result<(), CngError> {
    // SAFETY: `key` is an open, not-yet-finalized key handle.
    let status = unsafe { ncrypt::NCryptFinalizeKey(key, ncrypt::NCRYPT_SILENT_FLAG) };
    check("NCryptFinalizeKey", status)
}

/// Export a key blob of the given type.
fn export(key: Handle, blob_type: *const u16) -> Result<Vec<u8>, CngError> {
    let mut needed = 0u32;
    // SAFETY: a size query passes a null buffer with zero length, which the
    // API documents as "tell me how much you need".
    let status = unsafe {
        ncrypt::NCryptExportKey(
            key,
            0,
            blob_type,
            ptr::null(),
            ptr::null_mut(),
            0,
            &mut needed,
            0,
        )
    };
    check("NCryptExportKey(size)", status)?;

    let mut buffer = vec![0u8; needed as usize];
    let mut written = 0u32;
    // SAFETY: `buffer` has exactly `needed` bytes, which is what the size
    // query asked for, and `written` is a valid out-parameter.
    let status = unsafe {
        ncrypt::NCryptExportKey(
            key,
            0,
            blob_type,
            ptr::null(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            &mut written,
            0,
        )
    };
    check("NCryptExportKey", status)?;
    buffer.truncate(written as usize);
    Ok(buffer)
}

/// The public half of a key: `EccPublicBlob` (`ECS1 ‖ cbKey ‖ X ‖ Y`).
pub fn export_public_blob(key: Handle) -> Result<Vec<u8>, CngError> {
    export(key, ncrypt::BCRYPT_ECCPUBLIC_BLOB)
}

/// The private half of a key. For a `hardware` key this **must fail**: that
/// refusal is the custody guarantee, so the backend asserts it at provision.
pub fn export_private_blob(key: Handle) -> Result<Vec<u8>, CngError> {
    export(key, ncrypt::BCRYPT_ECCPRIVATE_BLOB)
}

/// Sign a pre-computed digest, returning the provider's raw signature.
///
/// CNG already returns `r ‖ s` (no DER), which is the wire contract.
pub fn sign_digest(key: Handle, digest: &[u8]) -> Result<[u8; 64], CngError> {
    let mut signature = [0u8; 64];
    let mut written = 0u32;
    // SAFETY: the digest and the signature buffer are both live for the call;
    // `written` is a valid out-parameter and a null padding struct is correct
    // for ECDSA (no padding scheme applies).
    let status = unsafe {
        ncrypt::NCryptSignHash(
            key,
            ptr::null::<c_void>(),
            digest.as_ptr(),
            digest.len() as u32,
            signature.as_mut_ptr(),
            signature.len() as u32,
            &mut written,
            0,
        )
    };
    check("NCryptSignHash", status)?;
    if written != signature.len() as u32 {
        return Err(CngError::Shape {
            operation: "NCryptSignHash",
            expected: signature.len() as u32,
            actual: written,
        });
    }
    Ok(signature)
}

/// Open a persisted key by name.
pub fn open_key(provider: Handle, name: &str) -> Result<Owned, CngError> {
    let name = wide(name);
    let mut key: ncrypt::NCRYPT_KEY_HANDLE = 0;
    // SAFETY: `key` is a valid out-parameter and `name` outlives the call.
    let status = unsafe { ncrypt::NCryptOpenKey(provider, &mut key, name.as_ptr(), 0, 0) };
    check("NCryptOpenKey", status)?;
    Ok(Owned(key))
}

/// Delete a persisted key.
///
/// `NCryptDeleteKey` frees the handle it is given, so ownership is released
/// first and the drop guard must not run afterwards.
pub fn delete_key(key: Owned) -> Result<(), CngError> {
    let raw = key.into_raw();
    // SAFETY: `raw` is a live key handle that we no longer own, and the API
    // consumes it.
    let status = unsafe { ncrypt::NCryptDeleteKey(raw, 0) };
    check("NCryptDeleteKey", status)
}
