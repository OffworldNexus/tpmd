//! The byte-level frame codec.
//!
//! A frame is a 4-byte big-endian length followed by that many Postcard
//! payload bytes. This module is deliberately slice-based and free of any I/O:
//! the async stream reader/writer lives in `tpmd-ipc`, so this crate keeps
//! knowing nothing about sockets or runtimes.

use thiserror::Error;

use crate::MAX_FRAME_LEN;
use crate::wire::Message;

/// Number of bytes in the length prefix (`u32`, big-endian).
pub const FRAME_LEN_BYTES: usize = 4;

/// A frame could not be parsed. All of these are **fatal** on a live
/// connection: the daemon closes rather than trying to resynchronise.
#[derive(Debug, Error)]
pub enum FrameError {
    /// The advertised length is larger than [`MAX_FRAME_LEN`].
    #[error("frame length {0} exceeds the maximum of {max}", max = MAX_FRAME_LEN)]
    TooLarge(u32),
    /// A zero-length frame can never be a valid message.
    #[error("zero-length frame is not a valid message")]
    ZeroLength,
    /// Fewer bytes were present than the header advertised.
    #[error("truncated frame: header advertises {expected} payload bytes, {got} present")]
    Truncated {
        /// Payload bytes the header claims.
        expected: usize,
        /// Payload bytes actually available.
        got: usize,
    },
    /// The payload did not decode as a [`Message`].
    #[error("message payload could not be decoded: {0}")]
    Decode(#[from] postcard::Error),
}

/// Validate a 4-byte length header and return the payload length in bytes.
///
/// Rejects a zero length and anything above [`MAX_FRAME_LEN`].
pub fn parse_frame_len(header: [u8; FRAME_LEN_BYTES]) -> Result<usize, FrameError> {
    let len = u32::from_be_bytes(header);
    if len == 0 {
        return Err(FrameError::ZeroLength);
    }
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    Ok(len as usize)
}

/// Encode a message as one frame (length prefix + Postcard payload).
///
/// Serialisation of the protocol types cannot fail — they are plain data with
/// no fallible custom serialisers — so this returns a `Vec` rather than a
/// `Result`.
pub fn encode_frame(message: &Message) -> Vec<u8> {
    let payload =
        postcard::to_allocvec(message).expect("protocol messages are infallible to serialise");
    let mut out = Vec::with_capacity(FRAME_LEN_BYTES + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    out
}

/// Decode one frame from a complete buffer.
///
/// The buffer must contain the length prefix and at least that many payload
/// bytes. Trailing bytes after the frame are ignored, so this is convenient
/// for golden-frame fixtures; the streaming reader in `tpmd-ipc` reads exactly
/// one frame at a time instead.
pub fn decode_frame(bytes: &[u8]) -> Result<Message, FrameError> {
    if bytes.len() < FRAME_LEN_BYTES {
        return Err(FrameError::Truncated {
            expected: FRAME_LEN_BYTES,
            got: bytes.len(),
        });
    }
    let len = parse_frame_len([bytes[0], bytes[1], bytes[2], bytes[3]])?;
    let payload = &bytes[FRAME_LEN_BYTES..];
    if payload.len() < len {
        return Err(FrameError::Truncated {
            expected: len,
            got: payload.len(),
        });
    }
    // `take_from_bytes` returns the unread remainder; a decoder for an older
    // layout thus tolerates appended fields.
    let (message, _rest) = postcard::take_from_bytes::<Message>(&payload[..len])?;
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Request;

    #[test]
    fn frame_round_trips() {
        let message = Message::Request(Request {
            id: 7,
            op: crate::Op::Status,
        });
        let framed = encode_frame(&message);
        assert_eq!(
            u32::from_be_bytes([framed[0], framed[1], framed[2], framed[3]]) as usize,
            framed.len() - FRAME_LEN_BYTES
        );
        assert_eq!(decode_frame(&framed).unwrap(), message);
    }

    #[test]
    fn zero_length_is_rejected() {
        assert!(matches!(
            parse_frame_len([0, 0, 0, 0]),
            Err(FrameError::ZeroLength)
        ));
    }

    #[test]
    fn oversized_length_is_rejected() {
        let too_big = (MAX_FRAME_LEN + 1).to_be_bytes();
        assert!(matches!(
            parse_frame_len(too_big),
            Err(FrameError::TooLarge(_))
        ));
    }

    #[test]
    fn truncated_payload_is_rejected() {
        // Claims 100 bytes but carries 2.
        let mut bytes = vec![0, 0, 0, 100, 0xaa, 0xbb];
        assert!(matches!(
            decode_frame(&bytes),
            Err(FrameError::Truncated {
                expected: 100,
                got: 2
            })
        ));
        bytes.truncate(2);
        assert!(matches!(
            decode_frame(&bytes),
            Err(FrameError::Truncated {
                expected: 4,
                got: 2
            })
        ));
    }

    #[test]
    fn garbage_payload_is_a_decode_error() {
        // Header says 2 bytes, then bytes that are not a valid Message enum.
        let bytes = vec![0, 0, 0, 2, 0xff, 0xff];
        assert!(matches!(decode_frame(&bytes), Err(FrameError::Decode(_))));
    }
}
