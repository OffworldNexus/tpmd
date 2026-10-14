//! Cross-user isolation, exercised with a real second OS account.
//!
//! The architecture document requires that one user cannot use another user's
//! keys. In single-user mode the strongest guarantee is that the second user
//! cannot even reach the socket; when it *can* connect (relaxed permissions,
//! as a system daemon would allow) the daemon must still refuse, because the
//! key belongs to a different principal.
//!
//! The test skips itself when no usable second account is available:
//! `TPMD_TEST_OTHER_USER` (default `tpmdtest`) must exist and `sudo -n` must
//! work.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use tpmd_client::{Client, KeyOutcome, KeyRequest, ProvisionRequest};
use tpmd_ipc::{Endpoint, SocketAccess};
use tpmd_proto::{Algorithm, SecurityLevel};

fn other_user() -> Option<String> {
    let user = std::env::var("TPMD_TEST_OTHER_USER").unwrap_or_else(|_| "tpmdtest".to_owned());
    if !Command::new("id")
        .arg("-u")
        .arg(&user)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return None;
    }
    if !Command::new("sudo")
        .args(["-n", "-u", &user, "true"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return None;
    }
    Some(user)
}

/// The built `tpmd-demo` binary, used here as a client CLI.
fn demo_binary() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let candidate = exe.parent()?.parent()?.join("tpmd-demo");
    candidate.exists().then_some(candidate)
}

async fn spawn_daemon(dir: &Path) -> Endpoint {
    let endpoint = Endpoint::unix_socket(dir.join("tpmd.sock"));
    let config = tpmd::Config {
        endpoint: endpoint.clone(),
        state_dir: dir.to_path_buf(),
        default_min_security: SecurityLevel::Sealed,
        // Pin the dummy: the isolation guarantee under test is backend-agnostic,
        // and this keeps the test independent of TPM availability.
        backend: Some("dummy".to_owned()),
        socket_access: SocketAccess::Owner,
    };
    let _handle = tokio::spawn(tpmd::run(config));
    // Leak the handle: the daemon should run until the test process ends.
    std::mem::forget(_handle);
    for _ in 0..200 {
        if Client::connect(&endpoint, "readiness", KeyRequest::None)
            .await
            .is_ok()
        {
            return endpoint;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("daemon did not become ready");
}

fn run_as(user: &str, demo: &Path, socket: &Path, fingerprint: &str) -> std::process::Output {
    Command::new("sudo")
        .args(["-n", "-u", user])
        .arg(demo)
        .arg("--socket")
        .arg(socket)
        .arg("--namespace")
        .arg("app")
        .arg("describe")
        .arg(fingerprint)
        .output()
        .expect("running the demo as the second user")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_user_cannot_reach_another_users_keys() {
    let Some(user) = other_user() else {
        eprintln!("skipping cross-user test: no second user with passwordless sudo");
        return;
    };
    let Some(demo) = demo_binary() else {
        eprintln!("skipping cross-user test: tpmd-demo binary not built");
        return;
    };

    // The daemon state lives in a private directory; the client binary is
    // copied to a world-traversable one so the second user can execute it.
    let state_dir = tempfile::tempdir().unwrap();
    let bin_dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(bin_dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let demo_copy = bin_dir.path().join("tpmd-demo");
    std::fs::copy(&demo, &demo_copy).unwrap();
    std::fs::set_permissions(&demo_copy, std::fs::Permissions::from_mode(0o755)).unwrap();

    let endpoint = spawn_daemon(state_dir.path()).await;
    let socket = state_dir.path().join("tpmd.sock");

    // Provision a key as the current user.
    let mut client = Client::connect(
        &endpoint,
        "app",
        KeyRequest::Create(ProvisionRequest {
            algorithm: Algorithm::EcdsaP256Sha256,
            min_security: SecurityLevel::File,
            allow_below_floor: true,
        }),
    )
    .await
    .unwrap();
    let KeyOutcome::Created(info) = client.key_outcome().clone() else {
        panic!("expected a created key");
    };
    let fingerprint = info.key_id.to_hex();

    // Control: the owning user can read the key.
    client.describe(info.key_id).await.unwrap();

    // Layer 1: with production permissions the second user cannot even reach
    // the socket (the state directory is 0700).
    let denied = run_as(&user, &demo_copy, &socket, &fingerprint);
    assert!(
        !denied.status.success(),
        "the second user unexpectedly reached the socket"
    );

    // Layer 2: relax the directory and socket so the second user *can*
    // connect; the daemon must still refuse, because the key belongs to a
    // different principal.
    std::fs::set_permissions(state_dir.path(), std::fs::Permissions::from_mode(0o711)).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666)).unwrap();

    let attempted = run_as(&user, &demo_copy, &socket, &fingerprint);
    let stderr = String::from_utf8_lossy(&attempted.stderr);
    assert!(
        !attempted.status.success(),
        "the second user read another user's key: {stderr}"
    );
    assert!(
        stderr.contains("UnknownKey"),
        "expected an unknown-key refusal, got: {stderr}"
    );
}
