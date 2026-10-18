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

/// A listener handed over by the service manager, if there is one.
///
/// systemd socket activation (`ListenStream=` in a `.socket` unit, `Sockets=`
/// in the service) is how the packaged agent gets its endpoint: the manager
/// binds it before the daemon exists, so a client reaching a cold machine is
/// queued rather than refused, and the socket's mode and ownership stay the
/// manager's decision rather than the daemon's.
///
/// `listenfd` reads the handover, which keeps the `from_raw_fd` this needs out
/// of this file: the crate wraps it in a safe API, so nothing here reaches for
/// `unsafe` to obtain a socket someone else opened.
#[cfg(target_os = "linux")]
pub fn inherited_listener() -> io::Result<Option<UnixListener>> {
    let mut inherited = listenfd::ListenFd::from_env();
    match inherited.take_unix_listener(0)? {
        Some(listener) => adopt(listener).map(Some),
        None => Ok(None),
    }
}

/// Hand a listener someone else opened to tokio.
///
/// systemd passes its sockets in *blocking* mode, and `from_std` does not
/// change that: it is the caller's job. Left blocking, the first accept after
/// a connection does not return `WouldBlock`; it sleeps in `accept4` until the
/// next client arrives, holding the task that also waits for SIGTERM, so a stop
/// waits for a stranger to connect or for systemd's timeout.
#[cfg(target_os = "linux")]
fn adopt(listener: std::os::unix::net::UnixListener) -> io::Result<UnixListener> {
    listener.set_nonblocking(true)?;
    UnixListener::from_std(listener)
}

/// No service manager hands sockets over on this platform — a macOS agent binds
/// its own path, as the per-user agent does everywhere — so there is nothing to
/// inherit.
#[cfg(not(target_os = "linux"))]
pub fn inherited_listener() -> io::Result<Option<UnixListener>> {
    Ok(None)
}

/// Bind a Unix socket, creating its directory and handling a stale file.
///
/// A leftover socket file is unlinked only if nothing answers on it; a live
/// listener is surfaced as [`io::ErrorKind::AlreadyExists`] so a second daemon
/// refuses to start rather than stealing the endpoint.
///
/// The containing directory is only created (and forced `0700`) for an
/// owner-only socket. A system socket lives in a directory the *deployment*
/// owns — `/run` is `root:root 0755` — so the daemon must not rewrite its
/// mode; if that directory does not exist, binding fails loudly instead.
pub async fn bind(path: &Path, access: crate::SocketAccess) -> io::Result<UnixListener> {
    if access == crate::SocketAccess::Owner
        && let Some(dir) = path.parent()
    {
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
    secure_fs::restrict_socket(path, access)?;
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

/// The process's effective UID where the platform exposes it.
///
/// Read from `/proc/self`'s ownership rather than a `geteuid()` syscall: on
/// Linux `proc(5)` guarantees the directory is owned by the effective UID of
/// the process, so this is exact and needs no `unsafe`. macOS has no `/proc`,
/// so this returns `None` there — callers treat that as "not root", which is
/// the safe direction.
pub fn effective_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata("/proc/self").ok().map(|meta| meta.uid())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::time::Duration;

    /// A blocking listener, as systemd hands one over, must not wedge the
    /// accept loop once its first client has been served. The run happens on
    /// a thread of its own so a regression fails the test instead of hanging it.
    #[test]
    fn an_adopted_listener_does_not_block_after_a_connection() {
        let dir = std::env::temp_dir().join(format!("tpmd-adopt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s.sock");
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(false).unwrap();

        let (done, finished) = std::sync::mpsc::channel();
        let client_path = path.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let idle = runtime.block_on(async move {
                let listener = super::adopt(listener).unwrap();
                let _client = tokio::net::UnixStream::connect(&client_path).await.unwrap();
                listener.accept().await.unwrap();
                tokio::time::timeout(Duration::from_millis(200), listener.accept())
                    .await
                    .is_err()
            });
            let _ = done.send(idle);
        });

        let outcome = finished.recv_timeout(Duration::from_secs(5));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            outcome,
            Ok(true),
            "the second accept should time out, not block the thread"
        );
    }
}
