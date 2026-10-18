//! A *shipped* backend plugin, loaded and opened by the real loader.
//!
//! `plugin_loader.rs` proves the ABI against a fixture. This proves the other
//! half against the artifact the packaging split actually publishes, because the
//! fixture and the real thing failed differently: the fixture opened nothing, so
//! it was happy while every real backend aborted the daemon on startup. A plugin
//! above the dummy opens the shared SQLite store, and a store is a pool, and a
//! pool wants a `tokio` runtime — the one *its own copy* of `tokio` is inside.
//!
//! So this test asks for exactly that: load the shipped keyring shim, survey it,
//! and make one call that reaches the store. If the boundary ever goes back to
//! driving plugin code on the daemon's runtime, this test does not fail — it
//! *aborts*, inside the shared object, which is what the field saw and why a
//! refusal here would be a lie.
//!
//! Gated on `loadable-backends` because that is the mode the split ships, and CI
//! runs it. Gated on Linux for the same reason the daemon's own feature is.

#![cfg(all(target_os = "linux", feature = "loadable-backends"))]

use std::path::{Path, PathBuf};
use std::process::Command;

use tpmd_backend::{BackendError, Owner, Principal};
use tpmd_plugin::host;
use tpmd_proto::KeyId;

/// The shipped shim crate, and the file the dynamic loader looks for.
const PLUGIN: &str = "tpmd-backend-keyring-plugin";
const FILE: &str = "libtpmd_backend_keyring_plugin.so";

/// Where this test was built: `<target>/<profile>/deps/<test>-<hash>`, so the
/// target root is three levels up.
fn target_dir() -> PathBuf {
    std::env::current_exe()
        .expect("the test binary knows where it is")
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .expect("the test binary lives in <target>/<profile>/deps")
        .to_owned()
}

/// Build the keyring shim exactly as `debian/rules` does, into this run's target
/// directory so the dependency tree is not built twice.
fn build_plugin() -> PathBuf {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let target = target_dir();

    let output = Command::new(cargo)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["rustc", "--crate-type", "cdylib", "-p", PLUGIN])
        .arg("--target-dir")
        .arg(&target)
        .args(if cfg!(debug_assertions) {
            &["--profile", "dev"][..]
        } else {
            &["--release"][..]
        })
        .output()
        .expect("cargo is what runs these tests");
    assert!(
        output.status.success(),
        "building {PLUGIN} failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    target.join(profile).join(FILE)
}

/// A runtime to drive the loaded factory, the way the daemon drives it.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime")
        .block_on(future)
}

/// An owner and a key id nothing is stored under.
fn nothing_stored() -> (Owner, KeyId) {
    (
        Owner::new(Principal("uid:1000".to_owned()), "plugin-backends-test"),
        KeyId::P256([7u8; 33]),
    )
}

#[test]
fn the_shipped_keyring_plugin_loads_and_its_rung_is_offered() {
    let built = build_plugin();
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(&built, dir.path().join(FILE)).unwrap_or_else(|error| {
        panic!(
            "the shim should have been built at {}: {error}",
            built.display()
        )
    });
    // A store of this test's own: the point is that the *plugin* opens it.
    let state = tempfile::tempdir().unwrap();

    let plugins = host::load(dir.path());
    assert!(plugins.failures().is_empty(), "{:?}", plugins.failures());
    let names: Vec<&str> = plugins
        .factories()
        .iter()
        .map(|factory| factory.name())
        .collect();
    assert_eq!(names, ["keyring"], "the shipped shim must load");

    let (factories, _mapped) = plugins.into_factories();
    let survey = block_on(tpmd::registry::survey(&factories, state.path()));

    // Where this host has a credential store the rung is a candidate; where it
    // has none the backend reports *why* and the rung is skipped. Both are a
    // pass, and both mean the same thing: the plugin's own code ran, behind the
    // boundary, on a runtime of its own. What this test exists for is the third
    // outcome, which prints nothing at all because the process is gone.
    let offered: Vec<&str> = survey
        .candidates
        .iter()
        .map(|backend| backend.name())
        .chain(survey.skipped.iter().map(|(name, _)| *name))
        .collect();
    assert!(
        offered.contains(&"keyring"),
        "the plugin's rung is missing from the ladder: {offered:?}"
    );

    // And a call past `open` is plugin code too — one that goes to the store and
    // comes back with the backend's own answer. On a host with no credential
    // store there is no candidate to ask, and the assertion above carried the
    // weight; where there is one, this is the call that reaches `sea-orm`
    // through the plugin's own runtime.
    let (owner, key_id) = nothing_stored();
    for backend in &survey.candidates {
        let refused = block_on(backend.identify(&owner, &key_id));
        assert!(
            matches!(refused, Err(BackendError::UnknownKey)),
            "a key nobody stored must be reported unknown, from the plugin's own code: {refused:?}"
        );
    }
}
