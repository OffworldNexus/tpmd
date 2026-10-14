//! Wire types and framing for the `tpmd` local key agent.
//!
//! This crate defines *what* travels between a `tpmd-client` and the `tpmd`
//! daemon, and *how it is framed on the stream*. It is deliberately free of
//! OS and storage dependencies: it knows nothing about sockets, files, TPMs
//! or signers. The daemon, client and backend crates all depend on it, so it
//! must stay small.
//!
//! # The contract at a glance
//!
//! * The first message the client sends is [`Message::Hello`]; the daemon
//!   answers [`Message::Welcome`] or [`Message::Reject`].
//! * Afterwards, every exchange is a [`Request`] / [`Response`] pair matched
//!   by an opaque `id`.
//! * Messages are Postcard-encoded and framed as a `u32` big-endian length
//!   followed by that many payload bytes.
//! * Keys are addressed only by their [`KeyId`], which *is* the 33-byte
//!   SEC1-compressed public key. There is no key enumeration.
//!
//! See `docs/protocol.md` in the repository for the full narrative.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod frame;
mod types;
mod wire;

pub use frame::{FRAME_LEN_BYTES, FrameError, decode_frame, encode_frame, parse_frame_len};
pub use types::{Algorithm, KeyId, SecurityLevel, Signature};
pub use wire::{
    Capabilities, ErrorCode, ErrorDetail, ErrorReply, Hello, KeyInfo, KeyOutcome, KeyRequest,
    Limits, Message, Op, ProvisionRequest, Reject, RejectCode, Reply, Request, Response, Status,
    Welcome,
};

/// Lowest protocol version this build accepts.
pub const MIN_PROTOCOL_VERSION: u16 = 1;

/// Highest protocol version this build speaks.
pub const PROTOCOL_VERSION: u16 = 1;

/// Largest permitted frame payload, in bytes (64 KiB).
///
/// A frame advertising more than this, a zero length, or a truncated frame is
/// a fatal framing error and the daemon closes the connection.
pub const MAX_FRAME_LEN: u32 = 64 * 1024;

/// Largest `sign` message input accepted, in bytes (1 MiB).
pub const MAX_MESSAGE_LEN: u32 = 1024 * 1024;

/// Largest accepted application namespace, in bytes.
pub const MAX_NAMESPACE_LEN: u16 = 255;

/// Default idle timeout, in milliseconds, after which the daemon closes a
/// connection that has sent nothing.
pub const DEFAULT_IDLE_TIMEOUT_MS: u64 = 30_000;

/// Human-readable daemon version string used in [`Capabilities::daemon`].
pub const DAEMON_VERSION: &str = concat!("tpmd ", env!("CARGO_PKG_VERSION"));

/// The limits announced in [`Welcome`] and enforced by both sides.
///
/// Returns the values this build ships; the daemon may announce smaller ones.
pub const fn default_limits() -> Limits {
    Limits {
        max_frame_len: MAX_FRAME_LEN,
        max_message_len: MAX_MESSAGE_LEN,
        max_namespace_len: MAX_NAMESPACE_LEN,
        idle_timeout_ms: DEFAULT_IDLE_TIMEOUT_MS,
    }
}
