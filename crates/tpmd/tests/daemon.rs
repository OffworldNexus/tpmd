//! End-to-end tests for the daemon: handshake, life-cycle, restarts,
//! concurrency, persistence and protocol-level failures.
//!
//! The daemon runs in-process on a Tokio task against a per-test temporary
//! state directory and endpoint, so tests are isolated and parallel.

use std::path::Path;
use std::time::Duration;

use p256::ecdsa::VerifyingKey;
use p256::ecdsa::signature::Verifier as _;
use tpmd_client::{Client, ClientError, KeyRequest, ProvisionRequest};
use tpmd_ipc::{Endpoint, read_message, write_message};
use tpmd_proto::{
    Algorithm, ErrorCode, ErrorDetail, Hello, KeyId, KeyOutcome, MIN_PROTOCOL_VERSION, Message,
    PROTOCOL_VERSION, RejectCode, SecurityLevel,
};

/// The endpoint for a test, platform-appropriate.
fn test_endpoint(dir: &Path) -> Endpoint {
    #[cfg(unix)]
    {
        Endpoint::unix_socket(dir.join("tpmd.sock"))
    }
    #[cfg(windows)]
    {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        dir.hash(&mut hasher);
        Endpoint::NamedPipe(format!(r"\\.\pipe\tpmd-test-{:016x}", hasher.finish()))
    }
}

/// Start a daemon against `dir`, returning its endpoint and task handle.
async fn spawn_daemon(
    dir: &Path,
) -> (
    Endpoint,
    tokio::task::JoinHandle<Result<(), tpmd::DaemonError>>,
) {
    let endpoint = test_endpoint(dir);
    let config = tpmd::Config {
        endpoint: endpoint.clone(),
        state_dir: dir.to_path_buf(),
        default_min_security: SecurityLevel::Sealed,
    };
    let handle = tokio::spawn(tpmd::run(config));
    wait_ready(&endpoint).await;
    (endpoint, handle)
}

async fn wait_ready(endpoint: &Endpoint) {
    for _ in 0..200 {
        if Client::connect(endpoint, "readiness", KeyRequest::None)
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("daemon did not become ready at {}", endpoint.display());
}

fn file_floor() -> ProvisionRequest {
    ProvisionRequest {
        algorithm: Algorithm::EcdsaP256Sha256,
        min_security: SecurityLevel::File,
        allow_below_floor: true,
    }
}

fn verify(public_key: &KeyId, message: &[u8], signature: &tpmd_proto::Signature) -> bool {
    let Ok(verifying) = VerifyingKey::from_sec1_bytes(public_key.as_bytes()) else {
        return false;
    };
    let Ok(sig) = p256::ecdsa::Signature::from_slice(signature.as_bytes()) else {
        return false;
    };
    verifying.verify(message, &sig).is_ok()
}

#[tokio::test]
async fn probe_reports_capabilities_without_a_key() {
    let dir = tempfile::tempdir().unwrap();
    let (endpoint, _handle) = spawn_daemon(dir.path()).await;

    let client = Client::connect(&endpoint, "app", KeyRequest::None)
        .await
        .unwrap();
    assert_eq!(client.key_outcome(), &KeyOutcome::None);
    let capabilities = &client.welcome().capabilities;
    assert_eq!(capabilities.backend, "dummy");
    assert_eq!(capabilities.levels, vec![SecurityLevel::File]);
    assert_eq!(client.welcome().version, PROTOCOL_VERSION);
}

#[tokio::test]
async fn provision_sign_and_verify() {
    let dir = tempfile::tempdir().unwrap();
    let (endpoint, _handle) = spawn_daemon(dir.path()).await;

    let mut client = Client::connect(&endpoint, "app", KeyRequest::Create(file_floor()))
        .await
        .unwrap();
    let KeyOutcome::Created(info) = client.key_outcome().clone() else {
        panic!("expected a created key");
    };
    assert_eq!(info.security_level, SecurityLevel::File);

    let message = b"a transcript to sign";
    let signature = client.sign(info.key_id, message).await.unwrap();
    assert!(verify(&info.key_id, message, &signature));
    assert!(!verify(&info.key_id, b"a different transcript", &signature));
}

#[tokio::test]
async fn sealed_floor_is_refused_with_structured_detail() {
    let dir = tempfile::tempdir().unwrap();
    let (endpoint, _handle) = spawn_daemon(dir.path()).await;

    let error = Client::connect(
        &endpoint,
        "app",
        KeyRequest::Create(ProvisionRequest {
            algorithm: Algorithm::EcdsaP256Sha256,
            min_security: SecurityLevel::Sealed,
            allow_below_floor: false,
        }),
    )
    .await
    .unwrap_err();

    match error {
        ClientError::Rejected {
            code: RejectCode::IncompatiblePolicy,
            detail:
                Some(ErrorDetail::Floor {
                    required,
                    available,
                }),
            ..
        } => {
            assert_eq!(required, SecurityLevel::Sealed);
            assert_eq!(available, SecurityLevel::File);
        }
        other => panic!("expected a structured floor refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn identity_survives_a_daemon_restart() {
    let dir = tempfile::tempdir().unwrap();
    let (endpoint, handle) = spawn_daemon(dir.path()).await;

    let client = Client::connect(&endpoint, "app", KeyRequest::Create(file_floor()))
        .await
        .unwrap();
    let KeyOutcome::Created(info) = client.key_outcome().clone() else {
        panic!("expected a created key");
    };
    drop(client);

    // Stop the daemon and start a fresh one on the same state directory.
    handle.abort();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let (endpoint, _handle) = spawn_daemon(dir.path()).await;

    let mut client = Client::connect(
        &endpoint,
        "app",
        KeyRequest::ResumeOrCreate {
            key_id: info.key_id,
            provision: file_floor(),
        },
    )
    .await
    .unwrap();
    let KeyOutcome::Resumed(resumed) = client.key_outcome().clone() else {
        panic!(
            "expected the key to be resumed, got {:?}",
            client.key_outcome()
        );
    };
    assert_eq!(resumed.key_id, info.key_id);

    // And it still signs the same message the same way.
    let message = b"across a restart";
    let signature = client.sign(info.key_id, message).await.unwrap();
    assert!(verify(&info.key_id, message, &signature));
}

#[tokio::test]
async fn resume_of_a_missing_key_creates_a_new_identity() {
    let dir = tempfile::tempdir().unwrap();
    let (endpoint, _handle) = spawn_daemon(dir.path()).await;

    let unknown = KeyId::P256([0x5a; 33]);
    let client = Client::connect(
        &endpoint,
        "app",
        KeyRequest::ResumeOrCreate {
            key_id: unknown,
            provision: file_floor(),
        },
    )
    .await
    .unwrap();
    match client.key_outcome() {
        KeyOutcome::Created(info) => assert_ne!(info.key_id, unknown),
        other => panic!("expected a created key, got {other:?}"),
    }
}

#[tokio::test]
async fn keys_are_isolated_by_namespace() {
    let dir = tempfile::tempdir().unwrap();
    let (endpoint, _handle) = spawn_daemon(dir.path()).await;

    let app = Client::connect(&endpoint, "app", KeyRequest::Create(file_floor()))
        .await
        .unwrap();
    let KeyOutcome::Created(info) = app.key_outcome().clone() else {
        panic!("expected a created key");
    };

    // Another namespace knows the fingerprint but does not own the key.
    let mut other = Client::connect(&endpoint, "other", KeyRequest::None)
        .await
        .unwrap();
    let error = other.sign(info.key_id, b"x").await.unwrap_err();
    assert!(matches!(
        error,
        ClientError::Request {
            code: ErrorCode::UnknownKey,
            ..
        }
    ));
}

#[tokio::test]
async fn destroy_then_resume_yields_a_fresh_identity() {
    let dir = tempfile::tempdir().unwrap();
    let (endpoint, _handle) = spawn_daemon(dir.path()).await;

    let mut client = Client::connect(&endpoint, "app", KeyRequest::Create(file_floor()))
        .await
        .unwrap();
    let KeyOutcome::Created(info) = client.key_outcome().clone() else {
        panic!("expected a created key");
    };
    client.destroy(info.key_id).await.unwrap();
    drop(client);

    let client = Client::connect(
        &endpoint,
        "app",
        KeyRequest::ResumeOrCreate {
            key_id: info.key_id,
            provision: file_floor(),
        },
    )
    .await
    .unwrap();
    match client.key_outcome() {
        KeyOutcome::Created(fresh) => assert_ne!(fresh.key_id, info.key_id),
        other => panic!("expected a fresh key, got {other:?}"),
    }
}

#[tokio::test]
async fn concurrent_clients_can_sign() {
    let dir = tempfile::tempdir().unwrap();
    let (endpoint, _handle) = spawn_daemon(dir.path()).await;

    let setup = Client::connect(&endpoint, "app", KeyRequest::Create(file_floor()))
        .await
        .unwrap();
    let KeyOutcome::Created(info) = setup.key_outcome().clone() else {
        panic!("expected a created key");
    };
    drop(setup);

    let mut tasks = Vec::new();
    for i in 0..8u8 {
        let endpoint = endpoint.clone();
        let key_id = info.key_id;
        tasks.push(tokio::spawn(async move {
            let mut client = Client::connect(&endpoint, "app", KeyRequest::None)
                .await
                .unwrap();
            let message = [i; 16];
            let signature = client.sign(key_id, &message).await.unwrap();
            assert!(verify(&key_id, &message, &signature));
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
}

#[tokio::test]
async fn version_mismatch_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (endpoint, _handle) = spawn_daemon(dir.path()).await;

    let mut stream = tpmd_ipc::connect(&endpoint).await.unwrap();
    write_message(
        &mut stream,
        &Message::Hello(Hello {
            min_version: 99,
            max_version: 99,
            namespace: "app".into(),
            key: KeyRequest::None,
        }),
    )
    .await
    .unwrap();

    match read_message(&mut stream).await.unwrap() {
        Message::Reject(reject) => assert_eq!(reject.code, RejectCode::UnsupportedVersion),
        other => panic!("expected a version rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn a_non_hello_first_frame_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (endpoint, _handle) = spawn_daemon(dir.path()).await;

    let mut stream = tpmd_ipc::connect(&endpoint).await.unwrap();
    write_message(
        &mut stream,
        &Message::Request(tpmd_proto::Request {
            id: 1,
            op: tpmd_proto::Op::Status,
        }),
    )
    .await
    .unwrap();

    match read_message(&mut stream).await.unwrap() {
        Message::Reject(reject) => assert_eq!(reject.code, RejectCode::BadHandshake),
        other => panic!("expected a bad-handshake rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn an_oversized_namespace_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (endpoint, _handle) = spawn_daemon(dir.path()).await;

    let mut stream = tpmd_ipc::connect(&endpoint).await.unwrap();
    write_message(
        &mut stream,
        &Message::Hello(Hello {
            min_version: MIN_PROTOCOL_VERSION,
            max_version: PROTOCOL_VERSION,
            namespace: "x".repeat(300),
            key: KeyRequest::None,
        }),
    )
    .await
    .unwrap();

    match read_message(&mut stream).await.unwrap() {
        Message::Reject(reject) => assert_eq!(reject.code, RejectCode::NamespaceTooLong),
        other => panic!("expected a namespace rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn a_zero_length_frame_closes_the_connection() {
    let dir = tempfile::tempdir().unwrap();
    let (endpoint, _handle) = spawn_daemon(dir.path()).await;

    use tokio::io::AsyncWriteExt;
    let mut stream = tpmd_ipc::connect(&endpoint).await.unwrap();
    // A zero length header is a fatal framing error.
    stream.write_all(&[0, 0, 0, 0]).await.unwrap();
    stream.flush().await.unwrap();

    // The daemon closes; the next read sees end-of-stream.
    let error = read_message(&mut stream).await.unwrap_err();
    assert!(matches!(error, tpmd_ipc::FrameIoError::Io(_)));
}
