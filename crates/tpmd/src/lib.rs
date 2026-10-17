//! The tpmd daemon.
//!
//! The daemon owns every private key. It binds a local endpoint, authenticates
//! each caller's OS principal, scopes keys to `(principal, namespace)`,
//! enforces the consumer's security floor and answers the operations in
//! `tpmd-proto`. It never exports a private key.
//!
//! Every backend compiled into this binary for the current OS is registered
//! with [`registry`]; the daemon selects one at run time — the strongest
//! usable, or the one named by `--backend` — and drives it through the
//! object-safe [`tpmd_backend::Backend`] trait as an `Arc<dyn Backend>`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tpmd_backend::{Backend, BackendError, Owner, Principal, select_level};
use tpmd_ipc::{
    Connection, Endpoint, FrameIoError, Listener, SocketAccess, read_message, write_message,
};
use tpmd_proto::{
    Capabilities, DAEMON_VERSION, ErrorCode, ErrorDetail, ErrorReply, KeyInfo, KeyOutcome,
    KeyRequest, MAX_NAMESPACE_LEN, Message, Op, Reject, RejectCode, Reply, Response, Status,
    Welcome, default_limits,
};
use tracing::{info, warn};

pub mod registry;

/// How long to wait for the `HELLO` before giving up on a connection.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Daemon configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// The local endpoint to bind.
    pub endpoint: Endpoint,
    /// Where the backends keep their state (one shared store).
    pub state_dir: PathBuf,
    /// The floor the daemon advertises as its default. Enforcement itself is
    /// driven by each caller's request, so a client must explicitly consent
    /// (`allow_below_floor`) to go lower.
    pub default_min_security: tpmd_proto::SecurityLevel,
    /// Force a specific backend by name. `None` selects the strongest usable
    /// backend automatically.
    pub backend: Option<String>,
    /// How reachable the bound socket is: owner-only for a per-user daemon, or
    /// any local user for a shared system daemon (authorization is still
    /// per-operation, from kernel peer credentials).
    pub socket_access: SocketAccess,
}

/// Errors that stop the daemon entirely.
#[derive(Debug, Error)]
pub enum DaemonError {
    /// No backend could be selected.
    #[error("backend selection: {0}")]
    Selection(#[from] registry::SelectionError),
    /// The endpoint could not be bound.
    #[error("binding endpoint: {0}")]
    Bind(#[source] std::io::Error),
}

/// The platform's default state directory.
///
/// `TPMD_STATE_DIR` overrides everything. Otherwise Linux uses
/// `$XDG_DATA_HOME/tpmd` (falling back to `~/.local/share/tpmd`), macOS
/// `~/Library/Application Support/tpmd`, and Windows `%LOCALAPPDATA%\tpmd`.
pub fn state_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("TPMD_STATE_DIR") {
        return PathBuf::from(dir);
    }

    #[cfg(windows)]
    {
        if let Some(dir) = std::env::var_os("LOCALAPPDATA") {
            return PathBuf::from(dir).join("tpmd");
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join("Library/Application Support/tpmd");
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(dir) = std::env::var_os("XDG_DATA_HOME") {
            return PathBuf::from(dir).join("tpmd");
        }
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(".local/share/tpmd");
        }
    }

    std::env::temp_dir().join("tpmd")
}

/// Run the daemon until interrupted.
pub async fn run(config: Config) -> Result<(), DaemonError> {
    let selection = registry::select(
        &registry::builtin_factories(),
        &config.state_dir,
        config.backend.as_deref(),
    )
    .await?;
    let backend = selection.backend;
    for (name, reason) in &selection.skipped {
        info!(backend = name, reason = %reason, "backend skipped");
    }
    info!(
        backend = backend.name(),
        store = backend.store_mechanism().unwrap_or("-"),
        "backend selected"
    );

    let mut listener = Listener::bind(config.endpoint.clone(), config.socket_access)
        .await
        .map_err(DaemonError::Bind)?;
    info!(endpoint = %listener.endpoint().display(), "tpmd listening");

    loop {
        tokio::select! {
            _ = shutdown_signal() => {
                info!("shutdown signal received");
                break;
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok(connection) => {
                        let backend = Arc::clone(&backend);
                        let default_min_security = config.default_min_security;
                        tokio::spawn(async move {
                            if let Err(error) =
                                handle_connection(connection, backend, default_min_security).await
                            {
                                warn!(error = %error, "connection ended with an error");
                            }
                        });
                    }
                    Err(error) => {
                        warn!(error = %error, "accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        }
    }

    Ok(())
}

async fn shutdown_signal() {
    // `ctrl_c` is available on all supported platforms.
    let _ = tokio::signal::ctrl_c().await;
}

/// Serve one connection: handshake, then the request loop.
async fn handle_connection(
    mut connection: Connection,
    backend: Arc<dyn Backend>,
    default_min_security: tpmd_proto::SecurityLevel,
) -> Result<(), FrameIoError> {
    let limits = default_limits();

    let hello =
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, read_message(&mut connection.stream)).await {
            Ok(Ok(Message::Hello(hello))) => hello,
            Ok(Ok(_other)) => {
                return reject(
                    &mut connection,
                    RejectCode::BadHandshake,
                    "first frame was not HELLO",
                    None,
                )
                .await;
            }
            // Client went away, sent garbage, or timed out: nothing to answer.
            Ok(Err(_)) | Err(_) => return Ok(()),
        };

    if hello.namespace.len() > MAX_NAMESPACE_LEN as usize {
        return reject(
            &mut connection,
            RejectCode::NamespaceTooLong,
            "namespace is too long",
            None,
        )
        .await;
    }

    let Some(version) = negotiate_version(hello.min_version, hello.max_version) else {
        return reject(
            &mut connection,
            RejectCode::UnsupportedVersion,
            "no protocol version in common",
            None,
        )
        .await;
    };

    let owner = Owner::new(Principal(connection.peer.clone()), hello.namespace.clone());
    let session = Session {
        owner,
        namespace: hello.namespace,
        default_min_security,
    };

    let key = match establish_key(backend.as_ref(), &session, hello.key).await {
        Ok(outcome) => outcome,
        Err(handshake_reject) => {
            return reject_message(&mut connection, handshake_reject).await;
        }
    };

    let welcome = Welcome {
        version,
        principal: connection.peer.clone(),
        capabilities: capabilities(backend.as_ref()),
        limits,
        key,
    };
    write_message(&mut connection.stream, &Message::Welcome(welcome)).await?;

    let idle = Duration::from_millis(limits.idle_timeout_ms);
    loop {
        match tokio::time::timeout(idle, read_message(&mut connection.stream)).await {
            Ok(Ok(Message::Request(request))) => {
                let result = dispatch(backend.as_ref(), &session, request.op).await;
                let response = Message::Response(Response {
                    id: request.id,
                    result,
                });
                write_message(&mut connection.stream, &response).await?;
            }
            // A well-formed but out-of-place message is a protocol violation.
            Ok(Ok(_)) => return Ok(()),
            // Client closed or the frame was malformed.
            Ok(Err(_)) | Err(_) => return Ok(()),
        }
    }
}

/// Per-connection state derived from the handshake.
struct Session {
    owner: Owner,
    namespace: String,
    default_min_security: tpmd_proto::SecurityLevel,
}

/// A handshake refusal carrying its structured detail.
struct HandshakeReject {
    code: RejectCode,
    message: String,
    detail: Option<ErrorDetail>,
}

fn negotiate_version(client_min: u16, client_max: u16) -> Option<u16> {
    let low = client_min.max(tpmd_proto::MIN_PROTOCOL_VERSION);
    let high = client_max.min(tpmd_proto::PROTOCOL_VERSION);
    (low <= high).then_some(high)
}

/// The backend's name for `tpmd status`, naming the underlying store when the
/// backend has one worth naming (e.g. `keyring (secret-service)`).
///
/// `Status.backend` is a free-form string, so this needs no protocol change;
/// the machine-readable `Capabilities.backend` keeps the bare name.
fn backend_display_name(backend: &dyn Backend) -> String {
    match backend.store_mechanism() {
        Some(mechanism) => format!("{} ({mechanism})", backend.name()),
        None => backend.name().to_owned(),
    }
}

fn capabilities(backend: &dyn Backend) -> Capabilities {
    let algorithms = backend.algorithms().to_vec();
    let (key_id_encoding, signature_encoding) = algorithms
        .first()
        .map(|a| {
            (
                a.key_id_encoding().to_owned(),
                a.signature_encoding().to_owned(),
            )
        })
        .unwrap_or_default();
    Capabilities {
        daemon: DAEMON_VERSION.to_owned(),
        backend: backend.name().to_owned(),
        algorithms,
        levels: backend.levels().to_vec(),
        default_level: backend.default_level(),
        key_id_encoding,
        signature_encoding,
    }
}

async fn establish_key(
    backend: &dyn Backend,
    session: &Session,
    request: KeyRequest,
) -> Result<KeyOutcome, HandshakeReject> {
    match request {
        KeyRequest::None => Ok(KeyOutcome::None),
        KeyRequest::Create(provision) => {
            let info = provision_key(backend, session, provision).await?;
            Ok(KeyOutcome::Created(info))
        }
        KeyRequest::ResumeOrCreate { key_id, provision } => {
            match backend.identify(&session.owner, &key_id).await {
                Ok(info) => Ok(KeyOutcome::Resumed(info)),
                // The key is gone (or not ours): mint a replacement, atomically.
                Err(BackendError::UnknownKey) => {
                    let info = provision_key(backend, session, provision).await?;
                    Ok(KeyOutcome::Created(info))
                }
                Err(error) => Err(handshake_reject_from(error)),
            }
        }
    }
}

async fn provision_key(
    backend: &dyn Backend,
    session: &Session,
    request: tpmd_proto::ProvisionRequest,
) -> Result<KeyInfo, HandshakeReject> {
    let level = select_level(
        backend.levels(),
        request.min_security,
        request.allow_below_floor,
    )
    .map_err(handshake_reject_from)?;
    backend
        .provision(&session.owner, request.algorithm, level)
        .await
        .map_err(handshake_reject_from)
}

async fn dispatch(backend: &dyn Backend, session: &Session, op: Op) -> Result<Reply, ErrorReply> {
    match op {
        Op::Status => Ok(Reply::Status(Status {
            daemon: DAEMON_VERSION.to_owned(),
            backend: backend_display_name(backend),
            principal: session.owner.principal.to_string(),
            namespace: session.namespace.clone(),
            levels: backend.levels().to_vec(),
            default_level: backend.default_level(),
            default_min_security: session.default_min_security,
        })),
        Op::Provision(request) => {
            let level = select_level(
                backend.levels(),
                request.min_security,
                request.allow_below_floor,
            )
            .map_err(reply_error_from)?;
            let info = backend
                .provision(&session.owner, request.algorithm, level)
                .await
                .map_err(reply_error_from)?;
            Ok(Reply::KeyId(info.key_id))
        }
        Op::Describe { key_id } => {
            let info = backend
                .identify(&session.owner, &key_id)
                .await
                .map_err(reply_error_from)?;
            Ok(Reply::KeyInfo(info))
        }
        Op::Sign { key_id, message } => {
            if message.len() as u32 > tpmd_proto::MAX_MESSAGE_LEN {
                return Err(ErrorReply {
                    code: ErrorCode::InvalidRequest,
                    message: format!(
                        "message exceeds the {} byte limit",
                        tpmd_proto::MAX_MESSAGE_LEN
                    ),
                    detail: None,
                });
            }
            let signature = backend
                .sign(&session.owner, &key_id, &message)
                .await
                .map_err(reply_error_from)?;
            Ok(Reply::Signature(signature))
        }
        Op::Destroy { key_id } => {
            backend
                .destroy(&session.owner, &key_id)
                .await
                .map_err(reply_error_from)?;
            Ok(Reply::Destroyed)
        }
    }
}

async fn reject(
    connection: &mut Connection,
    code: RejectCode,
    message: &str,
    detail: Option<ErrorDetail>,
) -> Result<(), FrameIoError> {
    reject_message(
        connection,
        HandshakeReject {
            code,
            message: message.to_owned(),
            detail,
        },
    )
    .await
}

async fn reject_message(
    connection: &mut Connection,
    reject: HandshakeReject,
) -> Result<(), FrameIoError> {
    write_message(
        &mut connection.stream,
        &Message::Reject(Reject {
            code: reject.code,
            message: reject.message,
            detail: reject.detail,
        }),
    )
    .await
}

fn handshake_reject_from(error: BackendError) -> HandshakeReject {
    let code = match error {
        BackendError::IncompatiblePolicy { .. } => RejectCode::IncompatiblePolicy,
        _ => RejectCode::KeyError,
    };
    HandshakeReject {
        code,
        message: error.to_string(),
        detail: error_detail(&error),
    }
}

fn reply_error_from(error: BackendError) -> ErrorReply {
    ErrorReply {
        code: reply_code(&error),
        message: error.to_string(),
        detail: error_detail(&error),
    }
}

fn reply_code(error: &BackendError) -> ErrorCode {
    match error {
        BackendError::UnknownKey => ErrorCode::UnknownKey,
        BackendError::IncompatiblePolicy { .. } => ErrorCode::IncompatiblePolicy,
        BackendError::UnsupportedAlgorithm(_) | BackendError::Invalid(_) => {
            ErrorCode::InvalidRequest
        }
        BackendError::StoreLocked(_) => ErrorCode::StoreLocked,
        BackendError::KeyLoss(_) => ErrorCode::KeyLoss,
        BackendError::Unavailable(_) => ErrorCode::BackendUnavailable,
        BackendError::Internal(_) => ErrorCode::Internal,
    }
}

fn error_detail(error: &BackendError) -> Option<ErrorDetail> {
    match error {
        BackendError::IncompatiblePolicy {
            required,
            available,
        } => Some(ErrorDetail::Floor {
            required: *required,
            available: *available,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpmd_proto::{MIN_PROTOCOL_VERSION, PROTOCOL_VERSION, SecurityLevel};

    #[test]
    fn version_negotiation_picks_the_highest_common() {
        assert_eq!(negotiate_version(1, 1), Some(1));
        assert_eq!(
            negotiate_version(MIN_PROTOCOL_VERSION, PROTOCOL_VERSION),
            Some(PROTOCOL_VERSION)
        );
        // Client too old.
        assert_eq!(negotiate_version(0, 0), None);
    }

    #[test]
    fn incompatible_policy_maps_to_floor_detail() {
        let error = BackendError::IncompatiblePolicy {
            required: SecurityLevel::Sealed,
            available: SecurityLevel::File,
        };
        assert!(matches!(
            error_detail(&error),
            Some(ErrorDetail::Floor { .. })
        ));
        assert_eq!(reply_code(&error), ErrorCode::IncompatiblePolicy);
    }
}
