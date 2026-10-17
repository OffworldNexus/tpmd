//! The protocol messages.
//!
//! Postcard is positional, so **field order is the schema**. Appending a
//! struct field or an enum variant is backward compatible (an older decoder
//! ignores trailing bytes / rejects unknown indices); reordering, removing or
//! changing the meaning of a field requires bumping
//! [`PROTOCOL_VERSION`](crate::PROTOCOL_VERSION).

use serde::{Deserialize, Serialize};

use crate::types::{Algorithm, KeyId, SecurityLevel, Signature};

/// Anything that can appear as a framed message on the wire.
///
/// Variants are **appended, never inserted**: Postcard encodes the variant index,
/// so reordering would silently reinterpret existing frames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Message {
    /// First client message: declares versions, namespace and the key request.
    Hello(Hello),
    /// Daemon's answer to a valid [`Hello`].
    Welcome(Welcome),
    /// Daemon's refusal, after which the connection is closed.
    Reject(Reject),
    /// A request on an established connection.
    Request(Request),
    /// The answer to a [`Request`], matched by `id`.
    Response(Response),
    /// The store is closed: the daemon cannot serve yet, but the connection
    /// stays open and the client may wait for it (see [`Op::Await`]).
    Closed(Closed),
}

/// Client → daemon, first frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// Lowest protocol version the client accepts.
    pub min_version: u16,
    /// Highest protocol version the client speaks.
    pub max_version: u16,
    /// The application namespace all keys on this connection are scoped to.
    /// Namespacing only — not proof of executable identity.
    pub namespace: String,
    /// What the connection wants to do about a key.
    pub key: KeyRequest,
}

/// What the client wants from the handshake regarding a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyRequest {
    /// Liveness/capability probe: "are you tpmd?". No key is involved.
    None,
    /// Mint a fresh key.
    Create(ProvisionRequest),
    /// Atomic get-or-create: resume `key_id` if the daemon still has it,
    /// otherwise mint a new key per `provision`.
    ResumeOrCreate {
        /// The fingerprint the client believes it owns.
        key_id: KeyId,
        /// How to mint a replacement if the key is gone.
        provision: ProvisionRequest,
    },
}

/// Parameters for minting a key, shared by the handshake and the
/// [`Op::Provision`](crate::Op::Provision) operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisionRequest {
    /// The algorithm to use.
    pub algorithm: Algorithm,
    /// The caller's security floor.
    pub min_security: SecurityLevel,
    /// Explicit, auditable consent to provision below `min_security` when the
    /// backend cannot meet it. Without this the daemon refuses rather than
    /// silently weakening the key.
    pub allow_below_floor: bool,
}

/// Daemon → client, answer to [`Hello`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Welcome {
    /// The negotiated protocol version; every later message uses it.
    pub version: u16,
    /// Who the daemon authenticated: `"uid:1000"`, `"sid:S-1-5-..."`.
    pub principal: String,
    /// The capability announce.
    pub capabilities: Capabilities,
    /// The limits in force for this connection.
    pub limits: Limits,
    /// The result of the handshake's [`KeyRequest`].
    pub key: KeyOutcome,
}

/// What the daemon actually has regarding the handshake's key request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyOutcome {
    /// No key was requested (probe handshake).
    None,
    /// A key was minted. If the client asked to resume, this is a **new
    /// identity** and the client must re-pair.
    Created(KeyInfo),
    /// The requested key was found and is usable.
    Resumed(KeyInfo),
}

/// Metadata about a usable key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyInfo {
    /// The fingerprint, which is the SEC1-compressed public key.
    pub key_id: KeyId,
    /// The algorithm this key uses.
    pub algorithm: Algorithm,
    /// The achieved protection level.
    pub security_level: SecurityLevel,
    /// Creation time, Unix seconds.
    pub created_unix: i64,
}

/// The daemon's self-description: the "announce".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    /// Human-readable daemon version, e.g. `"tpmd 0.1.0"`.
    pub daemon: String,
    /// The active backend's name, e.g. `"dummy"`.
    pub backend: String,
    /// Algorithms the daemon can offer.
    pub algorithms: Vec<Algorithm>,
    /// Security levels the active backend can achieve.
    pub levels: Vec<SecurityLevel>,
    /// The level the active backend achieves right now.
    pub default_level: SecurityLevel,
    /// Public-key encoding, e.g. `"sec1-compressed"`.
    pub key_id_encoding: String,
    /// Signature encoding, e.g. `"raw-r-s"`.
    pub signature_encoding: String,
    /// Whether the store can serve right now. Appended last, because Postcard is
    /// positional: new fields go at the end or they change every existing frame.
    pub store: StoreState,
}

/// Connection limits, enforced by both sides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    /// Largest frame payload accepted, in bytes.
    pub max_frame_len: u32,
    /// Largest `sign` message accepted, in bytes.
    pub max_message_len: u32,
    /// Largest application namespace accepted, in bytes.
    pub max_namespace_len: u16,
    /// Idle timeout after which the daemon closes the connection, in ms.
    pub idle_timeout_ms: u64,
}

/// Daemon → client refusal, after which the connection closes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reject {
    /// The reason class.
    pub code: RejectCode,
    /// Human-readable detail.
    pub message: String,
    /// Structured detail, e.g. the floor mismatch for
    /// [`RejectCode::IncompatiblePolicy`].
    pub detail: Option<ErrorDetail>,
}

/// Why a handshake was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RejectCode {
    /// No protocol version in common.
    UnsupportedVersion,
    /// The first frame was not a well-formed `HELLO`.
    BadHandshake,
    /// The declared namespace exceeds `max_namespace_len`.
    NamespaceTooLong,
    /// The daemon is shutting down.
    ShuttingDown,
    /// Key establishment in the handshake was refused by policy (the floor
    /// cannot be met). Carries [`ErrorDetail::Floor`].
    IncompatiblePolicy,
    /// Key establishment failed for another reason.
    KeyError,
    /// The backend's own dependency is gone: no device to open, no session bus,
    /// nothing to talk to. **Fatal and not waitable** — nothing in this daemon's
    /// lifetime will bring it back, and choosing another backend is an
    /// administrator's decision, never an automatic one.
    BackendUnavailable,
}

/// Daemon → client: the store is closed, and this is *not* fatal.
///
/// The only refusal that leaves the connection open, and deliberately distinct
/// from [`Reject`]: a user-session store is *normally* shut whenever the screen
/// is locked, so a client must be able to tell "come back later" from "you spoke
/// nonsense" without knowing anything about our implementation.
///
/// It is never [`ErrorCode::UnknownKey`], [`ErrorCode::KeyLoss`] or
/// [`ErrorCode::PermissionDenied`]; it never means the connection is over; and a
/// client may wait for the store to open (see [`Op::Await`]) rather than guess
/// when to retry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Closed {
    /// The reason class: [`ErrorCode::StoreLocked`].
    pub code: ErrorCode,
    /// Human-readable detail.
    pub message: String,
    /// Structured detail, mirroring [`Reject`] and [`ErrorReply`].
    pub detail: Option<ErrorDetail>,
}

/// Whether the daemon's store can serve right now.
///
/// Announced in [`Capabilities`] and [`Status`] so a client can tell "is it
/// running?" from "can it sign right now?" without attempting an operation, and
/// so an operator has a window on a daemon whose store is shut. It carries the
/// same report as the [`Closed`] message, so a client parses one shape, not two.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StoreState {
    /// The store answers.
    Open,
    /// The store exists but will not answer yet.
    Closed(Closed),
}

/// A request on an established connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// Client-chosen correlation id, echoed in the [`Response`].
    pub id: u64,
    /// The operation.
    pub op: Op,
}

/// The operations a client may invoke.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    /// Describe the daemon and this connection.
    Status,
    /// Mint an extra key (e.g. for rotation) without reconnecting.
    Provision(ProvisionRequest),
    /// Metadata for a key owned by the caller's principal and namespace.
    Describe {
        /// The fingerprint to look up.
        key_id: KeyId,
    },
    /// Sign a message with the named key.
    Sign {
        /// The fingerprint to sign with — the handle, not the private key.
        key_id: KeyId,
        /// The message; the daemon hashes it with SHA-256 then signs.
        message: Vec<u8>,
    },
    /// Destroy a key permanently.
    Destroy {
        /// The fingerprint to destroy.
        key_id: KeyId,
    },
    /// Ask to be told when the store can serve, rather than guessing when to
    /// come back. Deliberately carries **no timing**: noticing that the store
    /// has opened is the daemon's business — it is the component that knows what
    /// its dependency is — and asking a client for an interval would only
    /// invite it to poll.
    Await,
}

/// The answer to a [`Request`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    /// Echoes [`Request::id`].
    pub id: u64,
    /// The reply, or an error.
    pub result: Result<Reply, ErrorReply>,
}

/// A successful reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reply {
    /// Answer to [`Op::Status`].
    Status(Status),
    /// Answer to [`Op::Provision`]: the new fingerprint.
    KeyId(KeyId),
    /// Answer to [`Op::Describe`].
    KeyInfo(KeyInfo),
    /// Answer to [`Op::Sign`].
    Signature(Signature),
    /// Answer to [`Op::Destroy`].
    Destroyed,
    /// Answer to [`Op::Await`]: the store is usable again. Capabilities are
    /// re-announced because the achieved level can differ from the one announced
    /// before the store closed.
    Opened(Capabilities),
}

/// The daemon/connection description returned by [`Op::Status`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    /// Human-readable daemon version.
    pub daemon: String,
    /// Active backend name.
    pub backend: String,
    /// Authenticated principal.
    pub principal: String,
    /// The connection's namespace.
    pub namespace: String,
    /// Levels the active backend can achieve.
    pub levels: Vec<SecurityLevel>,
    /// The level achieved right now.
    pub default_level: SecurityLevel,
    /// The daemon's configured default floor.
    pub default_min_security: SecurityLevel,
    /// Whether the store can serve right now, so `tpmd status` answers "is it
    /// running, and can it sign?" without attempting an operation.
    pub store: StoreState,
}

/// A failed request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorReply {
    /// The error class.
    pub code: ErrorCode,
    /// Human-readable detail.
    pub message: String,
    /// Optional structured detail.
    pub detail: Option<ErrorDetail>,
}

/// The error classes, reported separately and never collapsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    /// Protocol version could not be negotiated (handshake only).
    UnsupportedVersion,
    /// A frame was malformed. Normally this is a fatal close instead.
    MalformedFrame,
    /// The peer is not permitted to talk to the daemon.
    PermissionDenied,
    /// The fingerprint is unknown, or not owned by the caller's principal
    /// and namespace. The two are deliberately indistinguishable.
    UnknownKey,
    /// The requested security floor cannot be met.
    IncompatiblePolicy,
    /// The backend failed to initialise or disappeared.
    BackendUnavailable,
    /// The store exists but is locked.
    StoreLocked,
    /// Key material was lost or invalidated.
    KeyLoss,
    /// The request was semantically invalid.
    InvalidRequest,
    /// Unexpected daemon failure.
    Internal,
}

/// Structured error detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorDetail {
    /// A security-floor mismatch.
    Floor {
        /// The floor the caller requested.
        required: SecurityLevel,
        /// The strongest level actually available.
        available: SecurityLevel,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_info() -> KeyInfo {
        KeyInfo {
            key_id: KeyId::P256([0x11; 33]),
            algorithm: Algorithm::EcdsaP256Sha256,
            security_level: SecurityLevel::File,
            created_unix: 1_700_000_000,
        }
    }

    fn round_trip(message: &Message) {
        let bytes = crate::encode_frame(message);
        let back = crate::decode_frame(&bytes).expect("decodes");
        assert_eq!(&back, message);
    }

    /// Canonical byte sequences, copied into `docs/protocol.md`. They pin the
    /// enum tags, Postcard varints and the big-endian length prefix. If this
    /// test changes, the wire format changed.
    #[test]
    fn golden_frames() {
        let hello = Message::Hello(Hello {
            min_version: 1,
            max_version: 1,
            namespace: "tpmd".into(),
            key: KeyRequest::None,
        });
        // length=9 | Hello(00) min=1 max=1 len=4 "tpmd" KeyRequest::None(00)
        assert_eq!(
            hex::encode(crate::encode_frame(&hello)),
            "000000090001010474706d6400"
        );

        let request = Message::Request(Request {
            id: 1,
            op: Op::Status,
        });
        // length=3 | Request(03) id=1 Status(00)
        assert_eq!(hex::encode(crate::encode_frame(&request)), "00000003030100");

        let response = Message::Response(Response {
            id: 1,
            result: Ok(Reply::Destroyed),
        });
        // length=4 | Response(04) id=1 Ok(00) Destroyed(04)
        assert_eq!(
            hex::encode(crate::encode_frame(&response)),
            "0000000404010004"
        );

        // The closed-store additions are *appends*, so nothing above moved: the
        // tags `Request` and `Response` were 03 and 04 before and still are.
        let closed = Message::Closed(Closed {
            code: ErrorCode::StoreLocked,
            message: "locked".into(),
            detail: None,
        });
        // length=10 | Closed(05) StoreLocked(06) len=6 "locked" None(00)
        assert_eq!(
            hex::encode(crate::encode_frame(&closed)),
            "0000000a0506066c6f636b656400"
        );

        let await_op = Message::Request(Request {
            id: 1,
            op: Op::Await,
        });
        // length=3 | Request(03) id=1 Await(05)
        assert_eq!(
            hex::encode(crate::encode_frame(&await_op)),
            "00000003030105"
        );
    }

    #[test]
    fn every_message_shape_round_trips() {
        round_trip(&Message::Hello(Hello {
            min_version: 1,
            max_version: 1,
            namespace: "tunnel-weaver".into(),
            key: KeyRequest::None,
        }));
        round_trip(&Message::Hello(Hello {
            min_version: 1,
            max_version: 2,
            namespace: "app".into(),
            key: KeyRequest::ResumeOrCreate {
                key_id: KeyId::P256([0x22; 33]),
                provision: ProvisionRequest {
                    algorithm: Algorithm::EcdsaP256Sha256,
                    min_security: SecurityLevel::Sealed,
                    allow_below_floor: true,
                },
            },
        }));
        round_trip(&Message::Welcome(Welcome {
            version: 1,
            principal: "uid:1000".into(),
            capabilities: Capabilities {
                daemon: crate::DAEMON_VERSION.into(),
                backend: "dummy".into(),
                algorithms: vec![Algorithm::EcdsaP256Sha256],
                levels: vec![SecurityLevel::File],
                default_level: SecurityLevel::File,
                key_id_encoding: "sec1-compressed".into(),
                signature_encoding: "raw-r-s".into(),
                store: StoreState::Open,
            },
            limits: crate::default_limits(),
            key: KeyOutcome::Created(sample_info()),
        }));
        round_trip(&Message::Closed(Closed {
            code: ErrorCode::StoreLocked,
            message: "the keychain is locked".into(),
            detail: None,
        }));
        round_trip(&Message::Reject(Reject {
            code: RejectCode::UnsupportedVersion,
            message: "no common version".into(),
            detail: None,
        }));
        round_trip(&Message::Reject(Reject {
            code: RejectCode::IncompatiblePolicy,
            message: "floor not met".into(),
            detail: Some(ErrorDetail::Floor {
                required: SecurityLevel::Sealed,
                available: SecurityLevel::File,
            }),
        }));
        round_trip(&Message::Request(Request {
            id: 42,
            op: Op::Sign {
                key_id: KeyId::P256([0x33; 33]),
                message: b"transcript".to_vec(),
            },
        }));
        round_trip(&Message::Response(Response {
            id: 42,
            result: Ok(Reply::Signature(Signature::P256([0x44; 64]))),
        }));
        round_trip(&Message::Response(Response {
            id: 43,
            result: Err(ErrorReply {
                code: ErrorCode::IncompatiblePolicy,
                message: "floor not met".into(),
                detail: Some(ErrorDetail::Floor {
                    required: SecurityLevel::Sealed,
                    available: SecurityLevel::File,
                }),
            }),
        }));
        round_trip(&Message::Response(Response {
            id: 44,
            result: Ok(Reply::Status(Status {
                daemon: crate::DAEMON_VERSION.into(),
                backend: "dummy".into(),
                principal: "uid:1000".into(),
                namespace: "app".into(),
                levels: vec![SecurityLevel::File],
                default_level: SecurityLevel::File,
                default_min_security: SecurityLevel::Sealed,
                store: StoreState::Closed(Closed {
                    code: ErrorCode::StoreLocked,
                    message: "the keychain is locked".into(),
                    detail: None,
                }),
            })),
        }));
        round_trip(&Message::Request(Request {
            id: 45,
            op: Op::Await,
        }));
        round_trip(&Message::Response(Response {
            id: 45,
            result: Ok(Reply::Opened(Capabilities {
                daemon: crate::DAEMON_VERSION.into(),
                backend: "keyring".into(),
                algorithms: vec![Algorithm::EcdsaP256Sha256],
                levels: vec![SecurityLevel::Keyring],
                default_level: SecurityLevel::Keyring,
                key_id_encoding: "sec1-compressed".into(),
                signature_encoding: "raw-r-s".into(),
                store: StoreState::Open,
            })),
        }));
    }

    #[test]
    fn version_is_the_first_hello_field() {
        // Postcard encodes the `Message` enum tag first (Hello = 0), then the
        // `Hello` fields. `min_version` is the first, encoded as a varint:
        // 0x1234 -> [0xb4, 0x24].
        let bytes = crate::encode_frame(&Message::Hello(Hello {
            min_version: 0x1234,
            max_version: 0,
            namespace: String::new(),
            key: KeyRequest::None,
        }));
        assert_eq!(bytes[crate::FRAME_LEN_BYTES], 0x00, "Hello variant tag");
        assert_eq!(
            &bytes[crate::FRAME_LEN_BYTES + 1..crate::FRAME_LEN_BYTES + 3],
            &[0xb4, 0x24]
        );
    }
}
