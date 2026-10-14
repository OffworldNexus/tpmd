//! Unix domain socket endpoints (Linux and macOS).

use std::io;
use std::path::{Path, PathBuf};

use tokio::net::{UnixListener, UnixStream};

use crate::secure_fs;

/// The per-user directory that holds the socket.
///
/// `$XDG_RUNTIME_DIR/tpmd` where set (Linux), else `$TMPDIR/tpmd` (macOS),
/// else `<temp>/tpmd`. The directory is created `0700`.
pub fn user_runtime_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(dir).join("tpmd");
    }
    if let Some(dir) = std::env::var_os("TMPDIR") {
        return PathBuf::from(dir).join("tpmd");
    }
    std::env::temp_dir().join("tpmd")
}

/// Full path of the per-user socket.
pub fn user_socket_path() -> PathBuf {
    user_runtime_dir().join(crate::SOCKET_FILE_NAME)
}

/// Bind a Unix socket, creating its directory and handling a stale file.
///
/// A leftover socket file is unlinked only if nothing answers on it; a live
/// listener is surfaced as [`io::ErrorKind::AlreadyExists`] so a second daemon
/// refuses to start rather than stealing the endpoint.
pub async fn bind(path: &Path) -> io::Result<UnixListener> {
    if let Some(dir) = path.parent() {
        secure_fs::ensure_dir(dir)?;
    }
    if path.exists() {
        match UnixStream::connect(path).await {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("another tpmd is already listening on {}", path.display()),
                ));
            }
            Err(_) => {
                // Stale socket from a crashed daemon: safe to remove.
                let _ = std::fs::remove_file(path);
            }
        }
    }
    let listener = UnixListener::bind(path)?;
    secure_fs::restrict_socket(path)?;
    Ok(listener)
}

/// Connect to a Unix socket.
pub async fn connect(path: &Path) -> io::Result<UnixStream> {
    UnixStream::connect(path).await
}

/// Derive the caller principal from the kernel's peer credentials.
///
/// Uses `SO_PEERCRED` (Linux) / `LOCAL_PEERCRED` (macOS) via Tokio; the value
/// is authoritative and cannot be spoofed by the client.
pub fn peer_principal(stream: &UnixStream) -> io::Result<String> {
    let cred = stream.peer_cred()?;
    Ok(format!("uid:{}", cred.uid()))
}
