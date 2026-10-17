//! The consumer API for the tpmd local key agent.
//!
//! This is the crate applications link against. It hides the transport
//! (Unix socket or Windows named pipe), the framing and the handshake, and
//! exposes the handful of operations a consumer needs:
//!
//! ```no_run
//! # async fn run() -> Result<(), tpmd_client::ClientError> {
//! use tpmd_client::{Algorithm, Client, KeyId, KeyRequest, ProvisionRequest, SecurityLevel};
//!
//! // Handshake: resume our key if the agent still has it, else mint one.
//! let key_id = KeyId::P256([0; 33]); // remembered from last time
//! let mut client = Client::connect_user(
//!     "my-app",
//!     KeyRequest::ResumeOrCreate {
//!         key_id,
//!         provision: ProvisionRequest {
//!             algorithm: Algorithm::EcdsaP256Sha256,
//!             min_security: SecurityLevel::Sealed,
//!             allow_below_floor: false,
//!         },
//!     },
//! )
//! .await?;
//!
//! // Sign a message with a key the agent owns and we never see.
//! let signature = client.sign(key_id, b"some transcript").await?;
//! # let _ = signature;
//! # Ok(())
//! # }
//! ```
//!
//! The private key never leaves the daemon. The caller passes the key's
//! **fingerprint** ([`tpmd_proto::KeyId`]) instead of the key itself.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use tpmd_ipc::{Endpoint, LocalStream, read_message, write_message};

/// Consumer-facing protocol types, re-exported so applications depend only on
/// `tpmd-client`.
pub use tpmd_proto::{
    Algorithm, Capabilities, ErrorCode, ErrorDetail, KeyId, KeyInfo, KeyOutcome, KeyRequest,
    Limits, ProvisionRequest, RejectCode, SecurityLevel, Signature, Status, Welcome,
};
use tpmd_proto::{
    Closed, ErrorReply, Hello, MIN_PROTOCOL_VERSION, Message, Op, PROTOCOL_VERSION, Reject, Reply,
    Request, Response, StoreState,
};

/// Errors a client can encounter.
///
/// The variants distinguish the failure classes the protocol mandates keep
/// separate: the daemon being unreachable is a transport failure, a refused
/// handshake is a policy/version failure, and a failed request carries the
/// daemon's own error taxonomy.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The daemon could not be reached (no socket, connection refused, …).
    #[error("daemon unavailable at {endpoint}: {source}")]
    Unavailable {
        /// The endpoint that was tried.
        endpoint: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The daemon spoke something unexpected, or the connection broke
    /// mid-exchange.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// The daemon refused the handshake and closed.
    #[error("handshake rejected ({code:?}): {message}")]
    Rejected {
        /// Why the handshake was refused.
        code: RejectCode,
        /// Human-readable detail.
        message: String,
        /// Structured detail (e.g. the floor mismatch).
        detail: Option<ErrorDetail>,
    },
    /// The daemon answered a request with an error.
    #[error("request failed ({code:?}): {message}")]
    Request {
        /// The error class.
        code: ErrorCode,
        /// Human-readable detail.
        message: String,
        /// Structured detail.
        detail: Option<ErrorDetail>,
    },
    /// The daemon's store is shut, and it did not open within the time the caller
    /// was willing to wait.
    ///
    /// **Not a failure of the daemon** — a user-centric store is normally locked
    /// whenever the user is away — so this is the variant a caller should expect
    /// to *retry*, and the daemon's own message says why it is shut. Reaching it
    /// means either the wait budget ran out or the caller asked not to wait at
    /// all (`Duration::ZERO`).
    #[error("the store is closed ({code:?}): {message}")]
    StoreClosed {
        /// The reason class the daemon gave: `StoreLocked`.
        code: ErrorCode,
        /// Why the store is shut, in the daemon's words.
        message: String,
        /// Structured detail, if the daemon offered any.
        detail: Option<ErrorDetail>,
    },
    /// The backend's own dependency is **gone**, not merely shut.
    ///
    /// This is the one tpmd condition that retrying cannot fix: there is no
    /// device to open, no session bus, or nothing that will hold the key. It is
    /// given its own variant so an application cannot confuse it with a transport
    /// failure or with a waitable store — the honest response is to tell the user
    /// that tpmd needs an administrator, not to try again.
    #[error("tpmd cannot serve this machine: {message}")]
    BackendUnavailable {
        /// What is missing, in the daemon's words.
        message: String,
    },
}

/// How long a connection waits for a closed store before giving up.
///
/// A user-centric store is shut *normally* — the screen is locked, the user is at
/// lunch — so the default is to wait rather than to fail: an application that
/// gave up instantly would have to treat a non-error as an error. Thirty seconds
/// is long enough for "I just unlocked it" and short enough not to hold a UI.
pub const DEFAULT_STORE_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// A connection to the daemon.
///
/// Operations are sequential: the client sends one request and waits for its
/// response. This is all a consumer such as Tunnel Weaver needs, and it keeps
/// correlation trivial. Pipelining is possible at the protocol level and can
/// be added here without a wire change.
#[derive(Debug)]
pub struct Client {
    stream: LocalStream,
    welcome: Welcome,
    next_id: u64,
}

impl Client {
    /// Connect to a specific endpoint and perform the handshake, waiting for a
    /// closed store for up to [`DEFAULT_STORE_WAIT`].
    pub async fn connect(
        endpoint: &Endpoint,
        namespace: &str,
        key: KeyRequest,
    ) -> Result<Self, ClientError> {
        Self::connect_within(endpoint, namespace, key, DEFAULT_STORE_WAIT).await
    }

    /// Connect, waiting no longer than `budget` for a *closed* store to open.
    ///
    /// A closed store is not a failure: the daemon says so with a non-fatal
    /// `CLOSED`, this client asks to be told when it opens (`AWAIT` — one request,
    /// never a poll), and then re-issues the handshake. Establishment stays atomic
    /// and the daemon never resumes anything on its own.
    ///
    /// `budget` is the caller's patience, expressed once and enforced by this
    /// client: when it runs out — or when the store turns out to be *gone* — the
    /// socket is closed, which is also how an outstanding wait is cancelled.
    /// [`std::time::Duration::ZERO`] means "do not wait at all".
    pub async fn connect_within(
        endpoint: &Endpoint,
        namespace: &str,
        key: KeyRequest,
        budget: std::time::Duration,
    ) -> Result<Self, ClientError> {
        let mut stream =
            tpmd_ipc::connect(endpoint)
                .await
                .map_err(|source| ClientError::Unavailable {
                    endpoint: endpoint.display(),
                    source,
                })?;

        let deadline = std::time::Instant::now() + budget;
        let hello = || {
            Message::Hello(Hello {
                min_version: MIN_PROTOCOL_VERSION,
                max_version: PROTOCOL_VERSION,
                namespace: namespace.to_owned(),
                key: key.clone(),
            })
        };

        loop {
            write_message(&mut stream, &hello())
                .await
                .map_err(protocol)?;

            match read_message(&mut stream).await.map_err(protocol)? {
                Message::Welcome(welcome) => {
                    return Ok(Self {
                        stream,
                        welcome,
                        next_id: 0,
                    });
                }
                // Closed, not refused: wait for the daemon to say it is open, then
                // try the handshake again.
                Message::Closed(closed) => {
                    wait_for_open(&mut stream, deadline, closed).await?;
                }
                Message::Reject(reject) => return Err(rejected(reject)),
                other => {
                    return Err(ClientError::Protocol(format!(
                        "expected WELCOME, got {other:?}"
                    )));
                }
            }
        }
    }

    /// Connect to the per-user endpoint for this process.
    pub async fn connect_user(namespace: &str, key: KeyRequest) -> Result<Self, ClientError> {
        let endpoint = Endpoint::user().map_err(|source| ClientError::Unavailable {
            endpoint: "<user endpoint>".into(),
            source,
        })?;
        Self::connect(&endpoint, namespace, key).await
    }

    /// Try the per-user endpoint first, then the system endpoint.
    ///
    /// This is the normal entry point: a client should not care whether the
    /// daemon runs per-user or as a shared system service.
    pub async fn connect_candidates(namespace: &str, key: KeyRequest) -> Result<Self, ClientError> {
        let candidates =
            Endpoint::client_candidates().map_err(|source| ClientError::Unavailable {
                endpoint: "<user endpoint>".into(),
                source,
            })?;
        if candidates.is_empty() {
            return Err(ClientError::Protocol(
                "no client endpoints available".into(),
            ));
        }

        let mut last_error = None;
        for endpoint in &candidates {
            match Self::connect(endpoint, namespace, key.clone()).await {
                Ok(client) => return Ok(client),
                // A refused handshake is authoritative: do not try the next
                // endpoint, the daemon answered.
                Err(err @ ClientError::Rejected { .. }) => return Err(err),
                Err(err) => last_error = Some(err),
            }
        }
        Err(last_error.expect("at least one candidate was tried"))
    }

    /// The handshake's `WELCOME`, including the capability announce.
    pub fn welcome(&self) -> &Welcome {
        &self.welcome
    }

    /// The authenticated principal, as the daemon sees it.
    pub fn principal(&self) -> &str {
        &self.welcome.principal
    }

    /// What the handshake did about the key request.
    pub fn key_outcome(&self) -> &KeyOutcome {
        &self.welcome.key
    }

    /// Describe the daemon and this connection.
    pub async fn status(&mut self) -> Result<Status, ClientError> {
        match self.request(Op::Status).await? {
            Reply::Status(status) => Ok(status),
            other => Err(unexpected("STATUS", &other)),
        }
    }

    /// Mint an additional key, returning its fingerprint.
    pub async fn provision(&mut self, request: ProvisionRequest) -> Result<KeyId, ClientError> {
        match self.request(Op::Provision(request)).await? {
            Reply::KeyId(key_id) => Ok(key_id),
            other => Err(unexpected("PROVISION", &other)),
        }
    }

    /// Look up a key's metadata.
    pub async fn describe(&mut self, key_id: KeyId) -> Result<KeyInfo, ClientError> {
        match self.request(Op::Describe { key_id }).await? {
            Reply::KeyInfo(info) => Ok(info),
            other => Err(unexpected("DESCRIBE", &other)),
        }
    }

    /// Sign `message` with the named key.
    ///
    /// The daemon SHA-256-hashes `message` and ECDSA-signs the digest; the
    /// result is the raw 64-byte `r ‖ s` expected by
    /// `weaver_mux::auth::verify`.
    pub async fn sign(&mut self, key_id: KeyId, message: &[u8]) -> Result<Signature, ClientError> {
        match self
            .request(Op::Sign {
                key_id,
                message: message.to_vec(),
            })
            .await?
        {
            Reply::Signature(signature) => Ok(signature),
            other => Err(unexpected("SIGN", &other)),
        }
    }

    /// Destroy a key permanently.
    pub async fn destroy(&mut self, key_id: KeyId) -> Result<(), ClientError> {
        match self.request(Op::Destroy { key_id }).await? {
            Reply::Destroyed => Ok(()),
            other => Err(unexpected("DESTROY", &other)),
        }
    }

    /// Close the connection cleanly.
    pub async fn shutdown(mut self) -> Result<(), ClientError> {
        use tokio::io::AsyncWriteExt;
        self.stream.shutdown().await.map_err(protocol)
    }

    /// Wait for a store that shut mid-session to open again, up to `budget`.
    ///
    /// The recovery path for [`ClientError::StoreClosed`]: an operation came back
    /// saying the store is shut, the caller decided it is worth waiting, and this
    /// waits — one request, no polling — until the store opens or the budget runs
    /// out. On success the caller retries whatever it was doing; nothing is replayed
    /// for it, because silently re-running an operation is how surprises happen.
    ///
    /// Returns immediately if the store is open already.
    pub async fn await_store_open(
        &mut self,
        budget: std::time::Duration,
    ) -> Result<(), ClientError> {
        let status = self.status().await?;
        let closed = match status.store {
            // Nothing to wait for.
            StoreState::Open => return Ok(()),
            StoreState::Closed(closed) => closed,
        };
        let deadline = std::time::Instant::now() + budget;
        wait_for_open(&mut self.stream, deadline, closed).await
    }

    /// Whether the daemon last reported its store as able to serve.
    pub fn store_is_open(&self) -> bool {
        matches!(self.welcome.capabilities.store, StoreState::Open)
    }

    async fn request(&mut self, op: Op) -> Result<Reply, ClientError> {
        self.next_id += 1;
        let id = self.next_id;
        write_message(&mut self.stream, &Message::Request(Request { id, op }))
            .await
            .map_err(protocol)?;

        match read_message(&mut self.stream).await.map_err(protocol)? {
            Message::Response(Response {
                id: response_id,
                result,
            }) if response_id == id => result.map_err(request_error),
            Message::Response(Response {
                id: response_id, ..
            }) => Err(ClientError::Protocol(format!(
                "response id {response_id} does not match request {id}"
            ))),
            other => Err(ClientError::Protocol(format!(
                "expected RESPONSE, got {other:?}"
            ))),
        }
    }
}

fn protocol(error: impl std::fmt::Display) -> ClientError {
    ClientError::Protocol(error.to_string())
}

/// A refusal at the handshake, in the class the caller can act on.
fn rejected(reject: Reject) -> ClientError {
    match reject.code {
        // The one fatal refusal that has nothing to do with what the caller
        // asked: the backend's dependency is gone, and trying again cannot help.
        RejectCode::BackendUnavailable => ClientError::BackendUnavailable {
            message: reject.message,
        },
        code => ClientError::Rejected {
            code,
            message: reject.message,
            detail: reject.detail,
        },
    }
}

/// A failed request, in the class the caller can act on.
fn request_error(error: ErrorReply) -> ClientError {
    match error.code {
        // A store that shut mid-session is the same condition as one that was shut
        // at the handshake, so callers get one variant to retry on.
        ErrorCode::StoreLocked => ClientError::StoreClosed {
            code: error.code,
            message: error.message,
            detail: error.detail,
        },
        ErrorCode::BackendUnavailable => ClientError::BackendUnavailable {
            message: error.message,
        },
        _ => ClientError::Request {
            code: error.code,
            message: error.message,
            detail: error.detail,
        },
    }
}

/// The caller's view of a store that is shut.
fn closed_error(closed: Closed) -> ClientError {
    ClientError::StoreClosed {
        code: closed.code,
        message: closed.message,
        detail: closed.detail,
    }
}

/// Ask the daemon to say when its store opens, and wait for it, up to `deadline`.
///
/// **One request, one answer — never a poll.** The daemon owns detection, because
/// the daemon is the component that knows what its dependency is; a client that
/// polled would be guessing on behalf of something better informed.
///
/// The wait is bounded by the caller's own patience, and cancelling it is simply
/// dropping the connection: the daemon notices the peer go away and holds nothing
/// for it. That is also why running out of budget closes the socket rather than
/// leaving a request in flight.
async fn wait_for_open(
    stream: &mut LocalStream,
    deadline: std::time::Instant,
    closed: Closed,
) -> Result<(), ClientError> {
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    if remaining.is_zero() {
        return Err(closed_error(closed));
    }

    // Ids only have to be unique per connection, and nothing else is outstanding
    // while a handshake is unfinished or a wait has just been entered.
    const AWAIT_ID: u64 = 0;
    write_message(
        stream,
        &Message::Request(Request {
            id: AWAIT_ID,
            op: Op::Await,
        }),
    )
    .await
    .map_err(protocol)?;

    let answer = tokio::time::timeout(remaining, read_message(stream)).await;
    let Ok(read) = answer else {
        // The budget ran out while parked: the store is still shut as far as this
        // caller is concerned, and the connection goes with the answer.
        return Err(closed_error(closed));
    };

    match read.map_err(protocol)? {
        Message::Response(Response { id, result }) if id == AWAIT_ID => match result {
            Ok(Reply::Opened(_)) => Ok(()),
            Ok(other) => Err(unexpected("AWAIT", &other)),
            // A dependency that turned out to be *gone* while we waited: the one
            // case where waiting could never have helped.
            Err(error) => Err(request_error(error)),
        },
        other => Err(ClientError::Protocol(format!(
            "expected the answer to AWAIT, got {other:?}"
        ))),
    }
}

fn unexpected(op: &str, reply: &Reply) -> ClientError {
    ClientError::Protocol(format!("{op} got an unexpected reply: {reply:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error_reply(code: ErrorCode, message: &str) -> ErrorReply {
        ErrorReply {
            code,
            message: message.to_owned(),
            detail: None,
        }
    }

    /// A shut store is a *retryable* condition, whether the daemon said so at the
    /// handshake or in answer to an operation: callers should meet one variant.
    #[test]
    fn a_closed_store_is_its_own_retryable_variant() {
        assert!(matches!(
            request_error(error_reply(
                ErrorCode::StoreLocked,
                "the keychain is locked"
            )),
            ClientError::StoreClosed {
                code: ErrorCode::StoreLocked,
                ..
            }
        ));
    }

    /// A gone dependency must be impossible to confuse with a transport failure or
    /// with a store worth waiting for: retrying cannot help, and applications are
    /// told to say so to their user.
    #[test]
    fn a_gone_backend_is_its_own_unrecoverable_variant() {
        assert!(matches!(
            request_error(error_reply(ErrorCode::BackendUnavailable, "no session bus")),
            ClientError::BackendUnavailable { .. }
        ));
        assert!(matches!(
            rejected(Reject {
                code: RejectCode::BackendUnavailable,
                message: "no device".into(),
                detail: None,
            }),
            ClientError::BackendUnavailable { .. }
        ));
    }

    /// Everything else keeps the daemon's own taxonomy, unfiltered.
    #[test]
    fn other_failures_keep_the_daemons_taxonomy() {
        assert!(matches!(
            request_error(error_reply(ErrorCode::UnknownKey, "unknown key")),
            ClientError::Request {
                code: ErrorCode::UnknownKey,
                ..
            }
        ));
        assert!(matches!(
            rejected(Reject {
                code: RejectCode::UnsupportedVersion,
                message: "no common version".into(),
                detail: None,
            }),
            ClientError::Rejected {
                code: RejectCode::UnsupportedVersion,
                ..
            }
        ));
    }
}
