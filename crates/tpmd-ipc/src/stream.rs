//! A connected local byte stream, uniform across platforms.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A connected local stream — a Unix socket or a Windows named pipe.
///
/// Both are byte streams, so framed I/O is identical on every platform. The
/// variants are cfg-gated: on Unix only [`LocalStream::Unix`] exists, on
/// Windows only the two pipe variants (server-side and client-side).
pub enum LocalStream {
    /// A Unix domain socket stream (Linux and macOS).
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    /// An accepted Windows named-pipe instance.
    #[cfg(windows)]
    Server(tokio::net::windows::named_pipe::NamedPipeServer),
    /// A connected Windows named pipe.
    #[cfg(windows)]
    Client(tokio::net::windows::named_pipe::NamedPipeClient),
}

impl core::fmt::Debug for LocalStream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LocalStream")
    }
}

impl AsyncRead for LocalStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            LocalStream::Unix(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(windows)]
            LocalStream::Server(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(windows)]
            LocalStream::Client(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for LocalStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            #[cfg(unix)]
            LocalStream::Unix(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(windows)]
            LocalStream::Server(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(windows)]
            LocalStream::Client(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            LocalStream::Unix(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(windows)]
            LocalStream::Server(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(windows)]
            LocalStream::Client(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            LocalStream::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(windows)]
            LocalStream::Server(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(windows)]
            LocalStream::Client(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}
