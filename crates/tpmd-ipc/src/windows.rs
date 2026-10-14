//! Windows named-pipe endpoints.
//!
//! The pipe is created with a restrictive security descriptor granting only
//! the owning user, so a second user cannot even connect. The caller's SID is
//! additionally read from the connected client's token, so the daemon reports
//! and scopes by the real principal rather than trusting the pipe name.

use std::io;
use std::time::{Duration, Instant};

use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, PipeMode, ServerOptions,
};

use crate::winutil;

/// `ERROR_PIPE_BUSY`: every instance of the pipe currently has a client.
const ERROR_PIPE_BUSY: i32 = 231;

/// How long a client waits for a free pipe instance before giving up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Delay between connection attempts while the pipe is busy.
const CONNECT_RETRY: Duration = Duration::from_millis(10);

/// The per-user pipe name: `\\.\pipe\tpmd-<fnv1a-hex-of-SID>`.
///
/// Hashing the SID keeps the endpoint short and avoids spelling a user's SID
/// into a world-readable pipe name.
pub fn user_pipe_name() -> io::Result<String> {
    let sid = winutil::current_user_sid()?;
    let sid_string = winutil::sid_to_string(&sid)?;
    Ok(format!(
        r"\\.\pipe\tpmd-{:016x}",
        fnv1a64(sid_string.as_bytes())
    ))
}

/// Create the next server instance, restricted to the owning user.
pub fn create_instance(name: &str) -> io::Result<NamedPipeServer> {
    let sid = winutil::current_user_sid()?;
    let mut security = winutil::PipeSecurity::new(&sid)?;
    let mut options = ServerOptions::new();
    options.first_pipe_instance(false);
    options.reject_remote_clients(true);
    options.pipe_mode(PipeMode::Byte);
    // Allow several simultaneous connections; a burst beyond this is handled
    // by the client's `ERROR_PIPE_BUSY` retry below.
    options.max_instances(64);
    let mut attrs = security.attributes();
    // SAFETY: `attrs` points at `security`, which outlives this call, and is a
    // valid SECURITY_ATTRIBUTES for the duration of pipe creation.
    unsafe {
        options.create_with_security_attributes_raw(
            name,
            &mut attrs as *mut _ as *mut std::ffi::c_void,
        )
    }
}

/// Connect to the pipe as a client.
///
/// Windows returns `ERROR_PIPE_BUSY` when every instance is momentarily in
/// use. The idiomatic handling (what `WaitNamedPipe` does) is to wait and
/// retry, so this loop does exactly that for a bounded time.
pub async fn connect(name: &str) -> io::Result<NamedPipeClient> {
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    loop {
        match ClientOptions::new().open(name) {
            Ok(client) => return Ok(client),
            Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                if Instant::now() >= deadline {
                    return Err(error);
                }
                tokio::time::sleep(CONNECT_RETRY).await;
            }
            Err(error) => return Err(error),
        }
    }
}

/// The principal of the process on the other end of an accepted pipe.
pub fn client_principal(handle: std::os::windows::io::RawHandle) -> io::Result<String> {
    let sid = winutil::client_process_sid(handle as windows_sys::Win32::Foundation::HANDLE)?;
    let sid_string = winutil::sid_to_string(&sid)?;
    Ok(format!("sid:{sid_string}"))
}

/// FNV-1a 64-bit, used only to make a short, stable pipe name from a SID.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}
