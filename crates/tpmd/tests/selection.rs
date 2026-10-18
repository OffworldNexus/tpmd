//! Sticky backend selection: the choice is made once, kept, and changed only
//! deliberately.
//!
//! The daemon runs in-process against a per-test temporary state directory, so
//! these tests are isolated and parallel. Where a key has to be *made* the dummy
//! backend is pinned, because the point is when a choice is recorded — not which
//! store happens to work on the machine running the suite.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use tpmd_client::{Client, KeyRequest, ProvisionRequest};
use tpmd_ipc::{Endpoint, SocketAccess};
use tpmd_proto::{Algorithm, SecurityLevel};

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
        Endpoint::NamedPipe(format!(r"\\.\pipe\tpmd-sel-{:016x}", hasher.finish()))
    }
}

fn config(dir: &Path, backend: Option<&str>) -> tpmd::Config {
    tpmd::Config {
        endpoint: test_endpoint(dir),
        state_dir: dir.to_path_buf(),
        default_min_security: SecurityLevel::Sealed,
        // Nothing in this directory is a plugin, so the ladder is exactly the
        // backends this build has: what this machine has installed cannot change
        // what the test asserts on.
        plugin_dir: dir.to_path_buf(),
        backend: backend.map(str::to_owned),
        socket_access: SocketAccess::Owner,
    }
}

/// Start a daemon, and wait for its socket to answer.
async fn spawn(dir: &Path, backend: Option<&str>) -> Endpoint {
    let endpoint = test_endpoint(dir);
    // Leaked: the daemon runs until the test process ends, as in the other
    // end-to-end tests.
    std::mem::forget(tokio::spawn(tpmd::run(config(dir, backend))));

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

/// What this state directory records, if anything.
async fn record(dir: &Path) -> Option<tpmd::selection::SelectionRecord> {
    let db = tpmd_store::open(dir).await.unwrap();
    tpmd::selection::SelectionStore::new(db)
        .read()
        .await
        .unwrap()
}

/// Make a key, so the store has actually served.
async fn make_a_key(endpoint: &Endpoint) {
    let mut client = Client::connect(
        endpoint,
        "selection-test",
        KeyRequest::Create(ProvisionRequest {
            algorithm: Algorithm::EcdsaP256Sha256,
            min_security: SecurityLevel::File,
            allow_below_floor: true,
        }),
    )
    .await
    .unwrap();
    let key_id = match client.key_outcome() {
        tpmd_client::KeyOutcome::Created(info) => info.key_id,
        other => panic!("expected a created key, got {other:?}"),
    };
    client.destroy(key_id).await.unwrap();
}

/// A machine whose store has never served has chosen nothing — not even though
/// the daemon is up and answering liveness probes. This is what stops a store
/// that merely happened to be locked at startup from settling the machine on a
/// weaker one.
#[tokio::test]
async fn a_fresh_machine_records_nothing_until_the_store_serves() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = spawn(dir.path(), Some("dummy")).await;

    assert!(
        record(dir.path()).await.is_none(),
        "starting the daemon, and answering a probe, must not settle the choice"
    );

    make_a_key(&endpoint).await;

    let recorded = record(dir.path())
        .await
        .expect("a store that served is a machine that has chosen");
    assert_eq!(recorded.backend, "dummy");
    assert!(recorded.chosen_unix > 0, "the choice is dated");
    assert!(
        recorded.reason.contains("dummy"),
        "the record says why: {}",
        recorded.reason
    );
}

/// The whole point: once chosen, a stronger backend appearing does **not** change
/// it — because changing it re-keys the device.
#[tokio::test]
async fn the_choice_is_kept_even_when_a_stronger_backend_is_available() {
    let dir = tempfile::tempdir().unwrap();

    // Choose the dummy, deliberately, and let it serve.
    let endpoint = spawn(dir.path(), Some("dummy")).await;
    make_a_key(&endpoint).await;
    let chosen = record(dir.path()).await.unwrap();
    assert_eq!(chosen.backend, "dummy");

    // Now start again with nothing pinned. On a machine with a usable keychain a
    // fresh ladder *would* pick something stronger — and must not.
    let endpoint = spawn(dir.path(), None).await;
    let mut client = Client::connect(&endpoint, "selection-test", KeyRequest::None)
        .await
        .unwrap();
    let status = client.status().await.unwrap();

    assert!(
        status.backend.contains("dummy"),
        "the remembered backend must keep serving: {}",
        status.backend
    );
    assert_eq!(status.selection.backend, "dummy");
    assert!(
        status.selection.chosen_unix.is_some(),
        "the choice is reported as committed"
    );
    assert_eq!(
        record(dir.path()).await.unwrap(),
        chosen,
        "and the record is untouched"
    );
}

/// `--backend` may agree with the record, or be absent — it may never contradict
/// it, because that is the automatic change this exists to prevent wearing a
/// command-line coat.
#[tokio::test]
async fn a_backend_that_contradicts_the_record_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = spawn(dir.path(), Some("dummy")).await;
    make_a_key(&endpoint).await;

    // Something this build really has, but not what the machine chose.
    let error = tpmd::run(config(dir.path(), Some("keyring")))
        .await
        .unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains("keyring") && message.contains("dummy"),
        "the error must name both: {message}"
    );
    assert!(
        message.contains("tpmd backend set"),
        "and point at the verb that changes it: {message}"
    );

    // Naming the remembered backend is fine, and changes nothing.
    let endpoint = spawn(dir.path(), Some("dummy")).await;
    assert!(
        Client::connect(&endpoint, "selection-test", KeyRequest::None)
            .await
            .is_ok()
    );
}

/// On a fresh machine `--backend` is how the first choice is *expressed*: it
/// restricts the ladder, and the choice is then recorded like any other.
#[tokio::test]
async fn naming_a_backend_on_a_fresh_machine_seeds_the_choice() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = spawn(dir.path(), Some("dummy")).await;
    make_a_key(&endpoint).await;

    let recorded = record(dir.path()).await.unwrap();
    assert_eq!(recorded.backend, "dummy");
    assert!(
        recorded.reason.contains("command line"),
        "the record says the flag chose it: {}",
        recorded.reason
    );
}

/// A name this build does not have is refused *before* it can be recorded: a
/// record naming a missing backend would leave a machine whose agent will not
/// start.
#[tokio::test]
async fn an_unknown_backend_is_refused_before_it_is_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = spawn(dir.path(), Some("dummy")).await;
    make_a_key(&endpoint).await;

    let error = tpmd::run(config(dir.path(), Some("no-such-backend")))
        .await
        .unwrap_err();
    // The *record* is what refuses it here: the machine has chosen dummy, so
    // naming anything else is a contradiction before it is a missing backend.
    assert!(error.to_string().contains("no-such-backend"), "{error}");
    assert_eq!(
        record(dir.path()).await.expect("a choice was made").backend,
        "dummy"
    );
}

// ---- the administrator's verb ----

/// Run the installed binary's `backend` verb against a state directory.
fn cli(state_dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_tpmd"))
        // Not this machine's plugins: an install in the packaged
        // directory would change the ladder this test asserts on.
        .env(
            "TPMD_BACKEND_DIR",
            std::env::temp_dir().join("tpmd-e2e-no-backends"),
        )
        .arg("backend")
        .arg("--state-dir")
        .arg(state_dir)
        .args(args)
        .output()
        .expect("tpmd runs")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn the_verb_shows_a_fresh_machine_has_chosen_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let shown = cli(dir.path(), &[]);
    assert!(shown.status.success(), "{}", text(&shown.stderr));
    assert!(
        text(&shown.stdout).contains("none yet"),
        "{}",
        text(&shown.stdout)
    );
}

#[test]
fn changing_the_backend_needs_confirmation() {
    let dir = tempfile::tempdir().unwrap();

    // Without --yes: refused, and told why it matters.
    let refused = cli(dir.path(), &["set", "dummy"]);
    assert!(!refused.status.success());
    let stderr = text(&refused.stderr);
    assert!(stderr.contains("--yes"), "{stderr}");
    assert!(
        stderr.contains("identity") || stderr.contains("pair"),
        "the warning must say what it costs: {stderr}"
    );

    // With --yes: done, and visible afterwards.
    let accepted = cli(dir.path(), &["set", "dummy", "--yes"]);
    assert!(accepted.status.success(), "{}", text(&accepted.stderr));
    let shown = cli(dir.path(), &[]);
    let shown = text(&shown.stdout);
    assert!(shown.contains("backend   : dummy"), "{shown}");
    assert!(shown.contains("set by an administrator"), "{shown}");

    // And forgotten again on request.
    assert!(cli(dir.path(), &["clear"]).status.success());
    assert!(text(&cli(dir.path(), &[]).stdout).contains("none yet"));
}

#[test]
fn setting_a_backend_this_build_does_not_have_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let refused = cli(dir.path(), &["set", "no-such-backend", "--yes"]);
    assert!(!refused.status.success());
    let stderr = text(&refused.stderr);
    assert!(stderr.contains("not a backend this build has"), "{stderr}");
    assert!(
        stderr.contains("dummy"),
        "it should name what is built: {stderr}"
    );
}
