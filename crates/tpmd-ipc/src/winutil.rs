//! Windows platform primitives: token SIDs and owner-only DACLs.
//!
//! Everything here is `unsafe` Win32 interop, kept in one module so it can be
//! reviewed as a unit. The rest of the crate stays safe Rust.

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use std::slice;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT,
    SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACL, CopySid, DACL_SECURITY_INFORMATION, GetLengthSid, GetTokenInformation,
    InitializeSecurityDescriptor, IsValidSid, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
    SetSecurityDescriptorDacl, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// `SUB_CONTAINERS_AND_OBJECTS_INHERIT`: children of a directory inherit the
/// owning user's ACE (so SQLite sidecars stay owner-only too).
const INHERIT_SUB_CONTAINERS_AND_OBJECTS: u32 = 0x0000_0003;
/// `SECURITY_DESCRIPTOR_REVISION`.
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

fn last_error() -> io::Error {
    io::Error::last_os_error()
}

/// The raw SID bytes of the calling process's user.
pub fn current_user_sid() -> io::Result<Vec<u8>> {
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle that must not be
    // closed; `OpenProcessToken` only borrows it.
    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(last_error());
        }
        let sid = token_user_sid(token);
        CloseHandle(token);
        sid
    }
}

/// The raw SID bytes of the process on the other end of a named pipe.
pub fn client_process_sid(pipe: HANDLE) -> io::Result<Vec<u8>> {
    // SAFETY: `pipe` is a live pipe handle; the process handle and token are
    // closed on every path.
    unsafe {
        let mut pid: u32 = 0;
        if GetNamedPipeClientProcessId(pipe, &mut pid) == 0 {
            return Err(last_error());
        }
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            return Err(last_error());
        }
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
            let err = last_error();
            CloseHandle(process);
            return Err(err);
        }
        let sid = token_user_sid(token);
        CloseHandle(token);
        CloseHandle(process);
        sid
    }
}

/// Read the `TokenUser` SID out of an open token as owned bytes.
unsafe fn token_user_sid(token: HANDLE) -> io::Result<Vec<u8>> {
    // First call sizes the buffer; it is expected to fail.
    let mut len: u32 = 0;
    // SAFETY: null buffer with length 0 is the documented sizing call.
    unsafe {
        GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut len);
    }
    if len == 0 {
        return Err(last_error());
    }
    // `TOKEN_USER` embeds a pointer, so the buffer must be pointer-aligned.
    let words = len.div_ceil(8) as usize;
    let mut buf = vec![0u64; words];
    // SAFETY: buffer is large enough for `len` bytes per the sizing call.
    unsafe {
        if GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr() as *mut c_void,
            len,
            &mut len,
        ) == 0
        {
            return Err(last_error());
        }
        let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
        let sid: PSID = token_user.User.Sid;
        if IsValidSid(sid) == 0 {
            return Err(io::Error::other("token returned an invalid SID"));
        }
        let sid_len = GetLengthSid(sid) as usize;
        let mut out = vec![0u8; sid_len];
        if CopySid(sid_len as u32, out.as_mut_ptr() as PSID, sid) == 0 {
            return Err(last_error());
        }
        Ok(out)
    }
}

/// Convert raw SID bytes to the familiar `S-1-5-...` string form.
pub fn sid_to_string(sid: &[u8]) -> io::Result<String> {
    // SAFETY: `sid` is a valid, self-contained SID copied from a token.
    unsafe {
        let mut pw: *mut u16 = ptr::null_mut();
        if ConvertSidToStringSidW(sid.as_ptr() as PSID, &mut pw) == 0 {
            return Err(last_error());
        }
        let mut n = 0isize;
        while *pw.offset(n) != 0 {
            n += 1;
        }
        let wide = slice::from_raw_parts(pw, n as usize);
        let s = String::from_utf16_lossy(wide);
        LocalFree(pw as HLOCAL);
        Ok(s)
    }
}

/// Build an owner-only ACL (a `GRANT_ACCESS` ACE for `sid`) allocated by the
/// system; free it with `LocalFree`.
///
/// # Safety
/// `sid` must point at a valid SID. The returned ACL is owned by the caller.
unsafe fn owner_only_acl(sid: PSID, inheritance: u32) -> io::Result<*mut ACL> {
    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: FILE_ALL_ACCESS,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: inheritance,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: sid as *mut u16,
        },
    };
    let mut acl: *mut ACL = ptr::null_mut();
    // SAFETY: one fully-initialised EXPLICIT_ACCESS_W, no old ACL.
    let rc = unsafe { SetEntriesInAclW(1, &entry, ptr::null(), &mut acl) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    Ok(acl)
}

/// Apply a protected, owner-only DACL to a file or directory.
pub fn set_owner_only(path: &Path) -> io::Result<()> {
    let sid = current_user_sid()?;
    let is_dir = std::fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false);
    let inheritance = if is_dir {
        INHERIT_SUB_CONTAINERS_AND_OBJECTS
    } else {
        0
    };
    // SAFETY: `sid` is valid for the duration of the call.
    let acl = unsafe { owner_only_acl(sid.as_ptr() as PSID, inheritance)? };

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `wide` is a NUL-terminated wide string; `acl` is a valid ACL.
    let rc = unsafe {
        SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            acl,
            ptr::null(),
        )
    };
    // SAFETY: `acl` came from SetEntriesInAclW and is ours to free.
    unsafe { LocalFree(acl as HLOCAL) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    Ok(())
}

/// A `SECURITY_ATTRIBUTES` restricting a named pipe to the owning user.
///
/// Keeps the security descriptor and ACL alive for as long as the pipe is
/// being created, then frees the ACL.
pub struct PipeSecurity {
    descriptor: Box<SECURITY_DESCRIPTOR>,
    acl: *mut ACL,
}

impl PipeSecurity {
    /// Build a restrictive security descriptor granting only `sid`.
    pub fn new(sid: &[u8]) -> io::Result<Self> {
        // SAFETY: building an ACL from a valid SID.
        let acl = unsafe { owner_only_acl(sid.as_ptr() as PSID, 0)? };
        let mut descriptor = Box::new(SECURITY_DESCRIPTOR::default());
        let sd_ptr = descriptor.as_mut() as *mut SECURITY_DESCRIPTOR as PSECURITY_DESCRIPTOR;
        // SAFETY: `descriptor` is a valid, writable SECURITY_DESCRIPTOR.
        unsafe {
            if InitializeSecurityDescriptor(sd_ptr, SECURITY_DESCRIPTOR_REVISION) == 0 {
                LocalFree(acl as HLOCAL);
                return Err(last_error());
            }
            if SetSecurityDescriptorDacl(sd_ptr, 1, acl, 0) == 0 {
                LocalFree(acl as HLOCAL);
                return Err(last_error());
            }
        }
        Ok(Self { descriptor, acl })
    }

    /// The `SECURITY_ATTRIBUTES` to pass to pipe creation.
    ///
    /// The descriptor must outlive the creation call; `self` does.
    pub fn attributes(&mut self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.descriptor.as_mut() as *mut SECURITY_DESCRIPTOR
                as *mut c_void,
            bInheritHandle: 0,
        }
    }
}

impl Drop for PipeSecurity {
    fn drop(&mut self) {
        // SAFETY: `acl` was allocated by SetEntriesInAclW.
        unsafe { LocalFree(self.acl as HLOCAL) };
    }
}
