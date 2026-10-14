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
    Hello, MIN_PROTOCOL_VERSION, Message, Op, PROTOCOL_VERSION, Reply, Request, Response,
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
}

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
    /// Connect to a specific endpoint and perform the handshake.
    pub async fn connect(
        endpoint: &Endpoint,
        namespace: &str,
        key: KeyRequest,
    ) -> Result<Self, ClientError> {
        let mut stream =
            tpmd_ipc::connect(endpoint)
                .await
                .map_err(|source| ClientError::Unavailable {
                    endpoint: endpoint.display(),
                    source,
                })?;

        write_message(
            &mut stream,
            &Message::Hello(Hello {
                min_version: MIN_PROTOCOL_VERSION,
                max_version: PROTOCOL_VERSION,
                namespace: namespace.to_owned(),
                key,
            }),
        )
        .await
        .map_err(protocol)?;

        let welcome = match read_message(&mut stream).await.map_err(protocol)? {
            Message::Welcome(welcome) => welcome,
            Message::Reject(reject) => {
                return Err(ClientError::Rejected {
                    code: reject.code,
                    message: reject.message,
                    detail: reject.detail,
                });
            }
            other => {
                return Err(ClientError::Protocol(format!(
                    "expected WELCOME, got {other:?}"
                )));
            }
        };

        Ok(Self {
            stream,
            welcome,
            next_id: 0,
        })
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
            }) if response_id == id => result.map_err(|error| ClientError::Request {
                code: error.code,
                message: error.message,
                detail: error.detail,
            }),
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

fn unexpected(op: &str, reply: &Reply) -> ClientError {
    ClientError::Protocol(format!("{op} got an unexpected reply: {reply:?}"))
}
