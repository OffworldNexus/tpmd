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

mod store_watch;

use store_watch::{StoreWatch, store_error};

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tpmd_backend::{Backend, BackendError, Owner, Principal, StoreStatus, select_level};
use tpmd_ipc::{
    Connection, Endpoint, FrameIoError, Listener, SocketAccess, read_message, write_message,
};
use tpmd_proto::{
    Capabilities, Closed, DAEMON_VERSION, ErrorCode, ErrorDetail, ErrorReply, KeyInfo, KeyOutcome,
    KeyRequest, MAX_NAMESPACE_LEN, Message, Op, Reject, RejectCode, Reply, Response, Status,
    StoreState, Welcome, default_limits,
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
    // One watcher for the process, shared by every connection and every parked
    // client: the store's state is a property of the backend, not of a client.
    let store_watch = StoreWatch::new(Arc::clone(&backend));
    info!(
        backend = backend.name(),
        store = backend.store_mechanism().unwrap_or("-"),
        store_state = store_watch.status().reason().unwrap_or("open"),
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
                        let store_watch = Arc::clone(&store_watch);
                        let default_min_security = config.default_min_security;
                        tokio::spawn(async move {
                            if let Err(error) = handle_connection(
                                connection,
                                backend,
                                store_watch,
                                default_min_security,
                            )
                            .await
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
///
/// Two phases, and the first one can repeat. A store that is **closed** does not
/// end the connection: the client is told `CLOSED` (non-fatal — a locked keychain
/// is a normal state, not an error), and it may then wait with `AWAIT` or try
/// again with a fresh `HELLO`. Only a *fatal* refusal — bad handshake, no version
/// in common, a dependency that is gone — closes it.
async fn handle_connection(
    mut connection: Connection,
    backend: Arc<dyn Backend>,
    store_watch: Arc<StoreWatch>,
    default_min_security: tpmd_proto::SecurityLevel,
) -> Result<(), FrameIoError> {
    let limits = default_limits();
    let idle = Duration::from_millis(limits.idle_timeout_ms);
    let principal = connection.peer.clone();

    // ---- Phase 1: handshake, repeatable while the store is shut ----
    let session = loop {
        let hello =
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, read_message(&mut connection.stream))
                .await
            {
                Ok(Ok(Message::Hello(hello))) => hello,
                // An `AWAIT` before a successful handshake is legitimate: it is
                // exactly what a client does after being told `CLOSED`.
                Ok(Ok(Message::Request(request))) if matches!(request.op, Op::Await) => {
                    let reply = answer_await(&store_watch, backend.as_ref()).await;
                    write_message(
                        &mut connection.stream,
                        &Message::Response(Response {
                            id: request.id,
                            result: reply,
                        }),
                    )
                    .await?;
                    continue;
                }
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

        let owner = Owner::new(Principal(principal.clone()), hello.namespace.clone());
        let session = Session {
            owner,
            namespace: hello.namespace,
            default_min_security,
        };

        match establish_key(backend.as_ref(), &session, hello.key).await {
            Ok(key) => {
                let welcome = Welcome {
                    version,
                    principal: principal.clone(),
                    capabilities: capabilities(backend.as_ref(), store_watch.status()),
                    limits,
                    key,
                };
                write_message(&mut connection.stream, &Message::Welcome(welcome)).await?;
                break session;
            }
            // Closed, not fatal: tell the client, keep the socket, let it wait or
            // try again. This is the whole point of the `closed` message.
            Err(handshake_reject) if handshake_reject.closed => {
                info!(
                    reason = %handshake_reject.message,
                    "store is closed; answering closed and keeping the connection"
                );
                let closed = Closed {
                    code: ErrorCode::StoreLocked,
                    message: handshake_reject.message,
                    detail: handshake_reject.detail,
                };
                write_message(&mut connection.stream, &Message::Closed(closed)).await?;
            }
            Err(handshake_reject) => {
                return reject_message(&mut connection, handshake_reject).await;
            }
        }
    };

    // ---- Phase 2: requests ----
    //
    // The writer is its own task, because a parked `AWAIT` must not stop this
    // connection from answering anything else: the protocol lets a client pipeline
    // requests and lets the daemon answer out of order, and a client that is
    // waiting for the store should still be able to ask `STATUS`.
    let (mut reader, mut writer) = tokio::io::split(connection.stream);
    let (outbound, mut queue) = tokio::sync::mpsc::channel::<Message>(REQUEST_QUEUE);
    let writing = tokio::spawn(async move {
        while let Some(message) = queue.recv().await {
            if write_message(&mut writer, &message).await.is_err() {
                // The peer is gone; the reader will notice on its own.
                break;
            }
        }
    });

    loop {
        match tokio::time::timeout(idle, read_message(&mut reader)).await {
            Ok(Ok(Message::Request(request))) => {
                let watch = Arc::clone(&store_watch);
                let backend = Arc::clone(&backend);
                let session_owner = session.owner.clone();
                let namespace = session.namespace.clone();
                let default_min_security = session.default_min_security;
                let outbound = outbound.clone();
                // Answered by its own task so a wait on the store cannot stall the
                // connection.
                tokio::spawn(async move {
                    let session = Session {
                        owner: session_owner,
                        namespace,
                        default_min_security,
                    };
                    let result = dispatch(&watch, backend.as_ref(), &session, request.op).await;
                    // Whatever the operation did, the backend may have learned
                    // something about its store — a refusal is *how* the daemon
                    // finds out a keychain has been locked — so one cheap, cached
                    // read keeps the announce and `status` honest.
                    watch.note(backend.store_status());
                    let _ = outbound
                        .send(Message::Response(Response {
                            id: request.id,
                            result,
                        }))
                        .await;
                });
            }
            // A well-formed but out-of-place message is a protocol violation.
            Ok(Ok(_)) => break,
            // Client closed or the frame was malformed.
            Ok(Err(_)) | Err(_) => break,
        }
    }

    // Dropping our sender lets the writer finish whatever is queued, then stop.
    drop(outbound);
    let _ = writing.await;
    Ok(())
}

/// How many answers may be queued for a client before we stop reading.
///
/// A client that pipelines without reading is not something to buffer for: this
/// bounds the memory one connection can cost.
const REQUEST_QUEUE: usize = 16;

/// Answer `AWAIT`: now if the store is open, after a wait if it is closed, and a
/// failure if it turns out to be gone.
///
/// Only a *closed* store is waited on. A gone dependency is answered with a
/// failure, because nothing in this daemon's lifetime brings it back and parking
/// on it would be a hang dressed up as patience.
async fn answer_await(
    store_watch: &Arc<StoreWatch>,
    backend: &dyn Backend,
) -> Result<Reply, ErrorReply> {
    let status = store_watch.wait_until_open().await;
    if status.is_open() {
        return Ok(Reply::Opened(capabilities(backend, status)));
    }
    Err(reply_error_from(store_error(&status)))
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
    /// True when the store is merely *closed*: the daemon then answers `CLOSED`
    /// and keeps the connection instead of refusing it for good.
    closed: bool,
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

fn capabilities(backend: &dyn Backend, store: StoreStatus) -> Capabilities {
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
        // Reported rather than assumed: the daemon knows what its backend last
        // saw, and a client asking "can you sign?" deserves that answer even in a
        // liveness handshake that touches no store.
        store: wire_store_state(&store),
    }
}

/// How the announce and `status` describe the store.
///
/// A *gone* store is described here rather than omitted, because a client that
/// only probes liveness deserves to learn the daemon's dependency is missing — and
/// it is described with `BackendUnavailable` as the reason class so it cannot be
/// mistaken for the waitable kind.
fn wire_store_state(status: &StoreStatus) -> StoreState {
    match status {
        StoreStatus::Open => StoreState::Open,
        StoreStatus::Closed(reason) => StoreState::Closed(Closed {
            code: ErrorCode::StoreLocked,
            message: reason.clone(),
            detail: None,
        }),
        StoreStatus::Gone(reason) => StoreState::Closed(Closed {
            code: ErrorCode::BackendUnavailable,
            message: reason.clone(),
            detail: None,
        }),
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

async fn dispatch(
    store_watch: &Arc<StoreWatch>,
    backend: &dyn Backend,
    session: &Session,
    op: Op,
) -> Result<Reply, ErrorReply> {
    match op {
        // "Tell me when you can serve me."
        //
        // Open: answer now, with the capabilities that prove it. Closed: *park* —
        // the client asked not to have to guess when to come back, and the daemon
        // is the component that knows what its dependency is. Gone: fail, because
        // nothing in this daemon's lifetime brings a gone dependency back, so
        // parking would be a hang dressed up as patience.
        Op::Await => answer_await(store_watch, backend).await,
        Op::Status => Ok(Reply::Status(Status {
            daemon: DAEMON_VERSION.to_owned(),
            backend: backend_display_name(backend),
            principal: session.owner.principal.to_string(),
            namespace: session.namespace.clone(),
            levels: backend.levels().to_vec(),
            default_level: backend.default_level(),
            default_min_security: session.default_min_security,
            store: wire_store_state(&store_watch.status()),
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
            // The literal refusals below are all fatal ones.
            closed: false,
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
        // A dependency that is gone is named as such, because it is the one
        // refusal an operator has to act on rather than a client waiting out.
        BackendError::Unavailable(_) => RejectCode::BackendUnavailable,
        _ => RejectCode::KeyError,
    };
    HandshakeReject {
        code,
        // A closed store is *not* a fatal refusal: the daemon answers `CLOSED`
        // and keeps the connection, because a locked keychain is a normal state a
        // client may wait out.
        closed: matches!(error, BackendError::StoreLocked(_)),
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
