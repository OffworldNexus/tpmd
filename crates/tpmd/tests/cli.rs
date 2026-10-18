//! Command-line behaviour for backend selection.
//!
//! These run the real binary, so they cover the one thing unit tests cannot:
//! that a bad `--backend` fails loudly *before* the daemon tries to serve.

use std::process::Command;

#[test]
fn an_unbuilt_backend_is_rejected_and_the_alternatives_named() {
    let output = Command::new(env!("CARGO_BIN_EXE_tpmd"))
        // Not this machine's plugins: an install in the packaged
        // directory would change the ladder this test asserts on.
        .env(
            "TPMD_BACKEND_DIR",
            std::env::temp_dir().join("tpmd-e2e-no-backends"),
        )
        .args([
            "serve",
            "--backend",
            "nonsense",
            "--socket",
            "/tmp/tpmd-cli-unknown.sock",
            "--state-dir",
            "/tmp/tpmd-cli-unknown-state",
        ])
        .output()
        .expect("running tpmd");

    assert!(!output.status.success(), "a bogus backend must not start");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("nonsense"), "stderr was: {stderr}");
    assert!(
        stderr.contains("dummy"),
        "the error should list the built backends: {stderr}"
    );
}

#[test]
fn invalid_arguments_are_reported_without_starting() {
    let output = Command::new(env!("CARGO_BIN_EXE_tpmd"))
        // Not this machine's plugins: an install in the packaged
        // directory would change the ladder this test asserts on.
        .env(
            "TPMD_BACKEND_DIR",
            std::env::temp_dir().join("tpmd-e2e-no-backends"),
        )
        .args(["serve", "--min-key-security", "nonsense"])
        .output()
        .expect("running tpmd");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("min-key-security"), "stderr was: {stderr}");
}
