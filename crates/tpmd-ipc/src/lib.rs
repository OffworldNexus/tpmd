//! The platform layer of tpmd: local endpoints, native caller
//! authentication, framed I/O and secure filesystem helpers.
//!
//! Everything here is OS-specific by nature, so it is isolated from the
//! protocol (`tpmd-proto`), the storage backends and the daemon logic. The
//! daemon and the client both use it, which is why it is a crate rather than
//! living inside either.
//!
//! * **Endpoints** — a Unix domain socket on Linux/macOS, a named pipe on
//!   Windows. No TCP listener exists.
//! * **Caller authentication** — the peer's identity comes from the kernel
//!   (`SO_PEERCRED` / `LOCAL_PEERCRED`) or from the named-pipe client's token
//!   SID, never from a value the client sends.
//! * **Secure filesystem** — owner-only directories and files (Unix modes
//!   `0700`/`0600`; a protected owner-only DACL on Windows).
//! * **Framed I/O** — length-prefixed Postcard frames over any async stream.

#![deny(unsafe_code)]
#![warn(missing_docs)]
// The Windows implementation is the only place that needs `unsafe`; it is
// confined to `winutil` and the pipe/DACL setup and reviewed as a unit.
#![cfg_attr(windows, allow(unsafe_code))]

use std::io;
use std::path::PathBuf;

use tpmd_proto::{FrameError, MAX_FRAME_LEN, Message};

pub mod secure_fs;
mod stream;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
mod winutil;

#[cfg(windows)]
use std::os::windows::io::AsRawHandle;

pub use stream::LocalStream;

/// File name of the per-user Unix socket inside its `tpmd` directory.
pub const SOCKET_FILE_NAME: &str = "tpmd.sock";

/// Path of the Linux system-wide socket used by a shared daemon.
pub const SYSTEM_SOCKET_PATH: &str = "/run/tpmd.sock";

/// How reachable a bound local socket is to other local users.
///
/// Reachability is **not** authorization: whichever mode is chosen, every
/// operation is scoped to the caller's kernel-authenticated principal. The
/// mode only decides whether a foreign user can open the socket and be told
/// `unknown_key` versus being refused the connection outright.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketAccess {
    /// Owner-only: the per-user daemon's socket (`0600` on Unix).
    Owner,
    /// Any local user may connect: a shared system daemon's socket (`0666` on
    /// Unix, where `/run` is world-traversable and the daemon runs as `tss`).
    LocalUsers,
}

impl SocketAccess {
    /// The Unix mode this access level maps to.
    #[cfg(unix)]
    pub const fn socket_mode(self) -> u32 {
        match self {
            SocketAccess::Owner => 0o600,
            SocketAccess::LocalUsers => 0o666,
        }
    }
}

/// The process's effective UID, where the platform exposes it.
///
/// Only the daemon's system-mode auto-detection uses this (root ⇒ shared
/// daemon). `None` means "not determinable" and is treated as non-root.
pub fn effective_uid() -> Option<u32> {
    #[cfg(unix)]
    {
        unix::effective_uid()
    }
    #[cfg(windows)]
    {
        None
    }
}

/// Where a client or daemon connects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// A Unix domain socket at this path (Linux and macOS).
    UnixSocket(PathBuf),
    /// A Windows named pipe with this name, e.g. `\\.\pipe\tpmd-1a2b`.
    NamedPipe(String),
}

impl Endpoint {
    /// The per-user endpoint.
    ///
    /// * Unix: `$XDG_RUNTIME_DIR/tpmd/tpmd.sock` (Linux) or
    ///   `$TMPDIR/tpmd/tpmd.sock` (macOS), falling back to the temp dir.
    /// * Windows: `\\.\pipe\tpmd-<hash-of-SID>`, so two users never collide.
    pub fn user() -> io::Result<Endpoint> {
        #[cfg(unix)]
        {
            Ok(Endpoint::UnixSocket(unix::user_socket_path()))
        }
        #[cfg(windows)]
        {
            Ok(Endpoint::NamedPipe(windows::user_pipe_name()?))
        }
    }

    /// The system-wide endpoint, if the platform has one.
    ///
    /// Linux has `/run/tpmd.sock` for a shared daemon. Windows and macOS
    /// (per-user only) return `None`.
    pub fn system() -> Option<Endpoint> {
        #[cfg(unix)]
        {
            // Only Linux is documented to run a shared system daemon.
            if cfg!(target_os = "linux") {
                return Some(Endpoint::UnixSocket(PathBuf::from(SYSTEM_SOCKET_PATH)));
            }
            None
        }
        #[cfg(windows)]
        {
            let _ = SYSTEM_SOCKET_PATH;
            None
        }
    }

    /// The endpoints a client should try, in order: user-scoped first, then
    /// the system endpoint.
    pub fn client_candidates() -> io::Result<Vec<Endpoint>> {
        let mut out = vec![Endpoint::user()?];
        if let Some(system) = Endpoint::system() {
            out.push(system);
        }
        Ok(out)
    }

    /// Build an explicit Unix-socket endpoint (used by tests and `--socket`).
    pub fn unix_socket(path: impl Into<PathBuf>) -> Endpoint {
        Endpoint::UnixSocket(path.into())
    }

    /// Human-readable form for logs and error messages.
    pub fn display(&self) -> String {
        match self {
            Endpoint::UnixSocket(path) => path.display().to_string(),
            Endpoint::NamedPipe(name) => name.clone(),
        }
    }
}

/// An accepted (server side) or connected (client side) local stream together
/// with the authenticated peer principal.
pub struct Connection {
    /// The byte stream.
    pub stream: LocalStream,
    /// The authenticated caller principal, e.g. `"uid:1000"` or `"sid:S-…"`.
    pub peer: String,
}

/// A bound server endpoint.
pub enum Listener {
    /// A Unix domain socket listener.
    #[cfg(unix)]
    Unix {
        /// The Tokio listener.
        listener: tokio::net::UnixListener,
        /// The socket path, kept for diagnostics.
        path: PathBuf,
    },
    /// A Windows named-pipe listener with one pending instance.
    #[cfg(windows)]
    Pipe {
        /// The pipe name.
        name: String,
        /// The next instance to accept on; replaced after each accept.
        pending: Option<tokio::net::windows::named_pipe::NamedPipeServer>,
    },
}

impl Listener {
    /// Bind the endpoint, creating its directory securely and clearing a
    /// stale socket if one is left behind.
    ///
    /// # Errors
    /// Returns `AlreadyExists` when another daemon is already listening on
    /// the endpoint.
    pub async fn bind(endpoint: Endpoint, access: SocketAccess) -> io::Result<Listener> {
        // On Windows the access policy is carried by the pipe's own DACL at
        // creation, not by a mode, so the parameter is intentionally unused.
        #[cfg(windows)]
        let _ = access;

        match endpoint {
            #[cfg(unix)]
            Endpoint::UnixSocket(path) => {
                let listener = unix::bind(&path, access).await?;
                Ok(Listener::Unix { listener, path })
            }
            #[cfg(windows)]
            Endpoint::NamedPipe(name) => {
                let pending = windows::create_instance(&name)?;
                Ok(Listener::Pipe {
                    name,
                    pending: Some(pending),
                })
            }
            #[allow(unreachable_patterns)]
            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "endpoint not supported on this platform: {}",
                    other.display()
                ),
            )),
        }
    }

    /// The endpoint this listener is bound to.
    pub fn endpoint(&self) -> Endpoint {
        match self {
            #[cfg(unix)]
            Listener::Unix { path, .. } => Endpoint::UnixSocket(path.clone()),
            #[cfg(windows)]
            Listener::Pipe { name, .. } => Endpoint::NamedPipe(name.clone()),
        }
    }

    /// Accept the next caller, authenticating its principal.
    pub async fn accept(&mut self) -> io::Result<Connection> {
        match self {
            #[cfg(unix)]
            Listener::Unix { listener, .. } => {
                let (stream, _addr) = listener.accept().await?;
                let peer = unix::peer_principal(&stream)?;
                Ok(Connection {
                    stream: LocalStream::Unix(stream),
                    peer,
                })
            }
            #[cfg(windows)]
            Listener::Pipe { name, pending } => {
                let server = pending.take().ok_or_else(|| {
                    io::Error::other("named pipe listener has no pending instance")
                })?;
                // Create the next instance *before* waiting for this client, so
                // a second caller can connect while we serve the first.
                *pending = Some(windows::create_instance(name)?);
                server.connect().await?;
                let peer = windows::client_principal(server.as_raw_handle())?;
                Ok(Connection {
                    stream: LocalStream::Server(server),
                    peer,
                })
            }
        }
    }
}

/// Connect to an endpoint as a client.
pub async fn connect(endpoint: &Endpoint) -> io::Result<LocalStream> {
    match endpoint {
        #[cfg(unix)]
        Endpoint::UnixSocket(path) => Ok(LocalStream::Unix(unix::connect(path).await?)),
        #[cfg(windows)]
        Endpoint::NamedPipe(name) => Ok(LocalStream::Client(windows::connect(name).await?)),
        #[allow(unreachable_patterns)]
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "endpoint not supported on this platform: {}",
                other.display()
            ),
        )),
    }
}

/// A framed-I/O failure.
#[derive(Debug, thiserror::Error)]
pub enum FrameIoError {
    /// The underlying stream failed.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    /// A frame was structurally invalid. Fatal for the connection.
    #[error("frame error: {0}")]
    Frame(#[from] FrameError),
}

/// Read exactly one framed [`Message`] from a stream.
///
/// A clean end-of-stream before any byte of the length prefix is reported as
/// [`io::ErrorKind::UnexpectedEof`], which callers treat as a normal close.
pub async fn read_message<S>(stream: &mut S) -> Result<Message, FrameIoError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    let len = tpmd_proto::parse_frame_len(header)?;
    debug_assert!((len as u32) <= MAX_FRAME_LEN);
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;
    let (message, _rest) =
        postcard::take_from_bytes::<Message>(&payload).map_err(FrameError::Decode)?;
    Ok(message)
}

/// Write one framed [`Message`] to a stream.
pub async fn write_message<S>(stream: &mut S, message: &Message) -> Result<(), FrameIoError>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let framed = tpmd_proto::encode_frame(message);
    stream.write_all(&framed).await?;
    stream.flush().await?;
    Ok(())
}
