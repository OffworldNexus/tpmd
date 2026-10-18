//! The plugin loader, against a *real* shared object rather than a mock.
//!
//! The loader's whole job is to turn a file on disk into a trait object the rest
//! of the daemon cannot tell from a linked-in one, and the ways that can go
//! wrong — the symbol not being exported, the fat pointer not surviving the
//! handover, a plugin from another build being called anyway — are exactly the
//! ways a mock cannot reproduce. So this test builds the fixture crate twice, as
//! a `cdylib`, and loads both variants from a temporary directory.
//!
//! Not gated on the daemon's `loadable-backends`: the loader is reached through
//! the `tpmd-plugin` dev-dependency, so the coverage does not depend on which
//! build mode the surrounding `cargo test` happens to use.
//!
//! Building the artefact: `cargo rustc --crate-type cdylib` for the fixture,
//! into the same target directory this test was built into, so the fixture
//! reuses the dependency tree the test run already produced instead of compiling
//! a second one. It is a separate process because a `cdylib` cannot be produced
//! from inside the test's own binary; and the same target directory is safe
//! because cargo has already released its build lock by the time tests run.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::Command;

use tpmd_backend::StoreStatus;
use tpmd_proto::SecurityLevel;

/// The fixture's crate name, and so the base of the file it produces.
const FIXTURE: &str = "tpmd-plugin-fixture";

/// Where this test was built: `<target>/<profile>/deps/<test>-<hash>`, so the
/// target root is three levels up and the profile directory two.
fn target_dir() -> PathBuf {
    std::env::current_exe()
        .expect("the test binary knows where it is")
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .expect("the test binary lives in <target>/<profile>/deps")
        .to_owned()
}

/// Build the fixture, as a `cdylib`, and put it in `dir` under `name`.
fn build_fixture(dir: &Path, name: &str, features: &[&str]) {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let target = target_dir();

    let mut command = Command::new(cargo);
    command
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("rustc")
        .arg("--crate-type")
        .arg("cdylib")
        // Pinned to this test's own target directory and profile, so the
        // artefact is found below and the dependencies are not built a second
        // time.
        .arg("--target-dir")
        .arg(&target)
        .args(if cfg!(debug_assertions) {
            &["--profile", "dev"][..]
        } else {
            &["--release"][..]
        })
        .arg("-p")
        .arg(FIXTURE);
    if !features.is_empty() {
        command.arg("--features").arg(features.join(","));
    }

    let output = command.output().expect("cargo is what runs these tests");
    assert!(
        output.status.success(),
        "building the fixture plugin failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let built = target
        .join(profile)
        .join(format!("lib{}.so", FIXTURE.replace('-', "_")));
    std::fs::copy(&built, dir.join(name)).unwrap_or_else(|error| {
        panic!(
            "the fixture should have been built at {}: {error}",
            built.display()
        )
    });
}

/// A runtime to drive the loaded factory: the backend it returns is a future
/// that only exists in the plugin.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime")
        .block_on(future)
}

#[test]
fn a_real_plugin_loads_and_a_plugin_from_another_build_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    build_fixture(dir.path(), "libfixture.so", &[]);
    build_fixture(dir.path(), "libwrongabi.so", &["wrong-abi"]);

    let plugins = tpmd_plugin::host::load(dir.path());

    // The good plugin is loaded, and named.
    let names: Vec<&str> = plugins
        .factories()
        .iter()
        .map(|factory| factory.name())
        .collect();
    assert_eq!(names, ["fixture"], "the well-formed plugin must load");

    // The wrong-ABI one is refused, loudly, and named.
    let failures = plugins.failures();
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert!(
        failures[0].0.ends_with("libwrongabi.so"),
        "the refusal must name the file: {failures:?}"
    );
    let why = &failures[0].1;
    assert!(
        why.contains("ABI") && why.contains(tpmd_plugin::ABI_VERSION.to_string().as_str()),
        "the refusal must say which ABI it speaks: {why}"
    );

    // And the loaded factory is not merely constructed: a call reaches the
    // plugin's own code, and the backend it returns answers through the plugin's
    // vtable — which is the property the whole boundary rests on.
    let factory = &plugins.factories()[0];
    let backend = block_on(factory.open(dir.path())).expect("the fixture opens");
    assert_eq!(backend.name(), "fixture");
    assert_eq!(backend.levels(), [SecurityLevel::File]);

    // The other rule of this boundary, and the one that aborted a split build in
    // the field: the plugin's code had to run on a runtime of the plugin's own.
    // Opening the store above builds an `sqlx` pool; a probe reaches the plugin
    // again; and the hint provider waits for a timer. Each of those needs a
    // `tokio` runtime *of the plugin's own copy*, so each one is a place the
    // daemon dies if this wrapper is ever removed.
    assert_eq!(block_on(backend.probe_store()), StoreStatus::Open);
    let hints = backend
        .unlock_hints()
        .expect("the fixture offers a hint provider");
    block_on(hints.next_hint());
    let refused = block_on(backend.destroy(&owner(), &key_id()));
    assert!(
        matches!(
            &refused,
            Err(tpmd_plugin::BackendError::Unavailable(reason)) if reason.contains("holds no keys")
        ),
        "a call into the plugin must reach the plugin's own code and come back: {refused:?}"
    );
}

/// An owner and a key id, for calls the fixture only ever refuses.
fn owner() -> tpmd_backend::Owner {
    tpmd_backend::Owner::new(tpmd_backend::Principal("uid:1000".to_owned()), "fixture")
}

fn key_id() -> tpmd_proto::KeyId {
    tpmd_proto::KeyId::P256([0u8; 33])
}
