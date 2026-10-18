//! Loading plugin backends from disk (the host side).
//!
//! This module is the whole of the daemon's `dlopen`, and the reason the
//! workspace's `unsafe` rule names a third module: mapping a shared object runs
//! whatever code is in it, as this process, so the file being mapped is a
//! *privilege* decision rather than a parsing one. Two things bound it:
//!
//! * the deployed directory is root-owned and not writable by group or others,
//!   and so is every file in it; the daemon runs as `tss`, which is not root,
//!   so nothing the daemon's own user can write is ever mapped into it;
//! * the symbol is looked up, and the plugin's ABI number read, before any
//!   pointer it returns is touched — a plugin from a different build is refused,
//!   not called.
//!
//! A plugin that is *absent* is not an event: the ladder simply does not have
//! that rung. A plugin that is *present and cannot be loaded* is pushed into
//! [`Plugins::failures`] so the daemon can say so — never dropped on the floor,
//! because that is how an installed backend comes to be silently missing.

use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use libloading::Library;
use tpmd_backend::BackendFactory;

use crate::{ABI_VERSION, ENTRY_SYMBOL, Entry};

/// Where the packaged plugins live.
pub const DEFAULT_DIR: &str = "/usr/lib/tpmd/backends";

/// The environment variable that moves [`DEFAULT_DIR`].
///
/// For tests and for a deployment that ships plugins elsewhere. It is not a
/// privilege hole: whoever can set a process's environment is already the one
/// who chose to run this daemon, and in the packaged service that is root
/// (through `tpmd.service`, not `/etc/default/tpmd`). It does, however, turn the
/// ownership check off — a test's temporary directory is owned by the test
/// runner, not by root — which is why the variable is not part of the deployed
/// configuration.
pub const DIR_ENV: &str = "TPMD_BACKEND_DIR";

/// The directory plugins are loaded from this run.
#[must_use]
pub fn directory() -> PathBuf {
    std::env::var_os(DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DIR))
}

/// The plugins that loaded, and the ones that could not.
///
/// Holds the mapped libraries for as long as it lives: a factory's code, and
/// the vtable of every backend opened through one, points into the shared
/// object, so unloading it while the daemon still holds a backend would be a
/// call into unmapped memory. The daemon holds a `Plugins` for its whole run for
/// exactly that reason.
#[derive(Default)]
pub struct Plugins {
    factories: Vec<Box<dyn BackendFactory>>,
    failures: Vec<(PathBuf, String)>,
    // Declared last so it drops last: the factories above must die before the
    // code they point into is unmapped. Never read; it is here to be kept.
    _libraries: Vec<Library>,
}

impl Plugins {
    /// The factories to survey, in file-name order.
    #[must_use]
    pub fn factories(&self) -> &[Box<dyn BackendFactory>] {
        &self.factories
    }

    /// Plugins that are present but were not loaded, each with why.
    ///
    /// Never empty by accident: everything that stopped a present plugin from
    /// loading lands here, so the daemon can report it rather than quietly
    /// offering one rung fewer than was installed.
    #[must_use]
    pub fn failures(&self) -> &[(PathBuf, String)] {
        &self.failures
    }

    /// Take the factories, and with them the guard that keeps their code mapped.
    ///
    /// The two are handed back separately so a caller can build whatever ladder
    /// it wants — the daemon prepends the dummy — while still holding the
    /// mapping open for as long as a factory, or a backend opened through one,
    /// may be called.
    #[must_use]
    pub fn into_factories(self) -> (Vec<Box<dyn BackendFactory>>, Mapped) {
        (
            self.factories,
            Mapped {
                _libraries: self._libraries,
            },
        )
    }
}

/// Mapped plugin code, kept so that it is not unmapped while it may be called.
///
/// Dropping this unmaps every plugin. The daemon holds one for its whole run:
/// the factory it was given, and the vtable of every backend opened through one,
/// point into the mapping, so unloading early would be a call into memory the
/// process no longer owns.
#[derive(Default)]
pub struct Mapped {
    // Underscored because it is kept, never read: the whole point of the field
    // is its `Drop`.
    _libraries: Vec<Library>,
}

/// Load every plugin in `dir`.
///
/// Files are considered in name order, and only `*.so`; anything else in the
/// directory is left alone. The directory itself, when it is the packaged one,
/// must be root-owned and not group- or other-writable.
#[must_use]
pub fn load(dir: &Path) -> Plugins {
    let mut plugins = Plugins::default();

    // The ownership requirement protects the *deployed* directory. An override
    // moves the directory on purpose, and a test's temporary directory is owned
    // by whoever ran the test; see `DIR_ENV`.
    let deployed = dir == Path::new(DEFAULT_DIR);

    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        // Absent is not a failure. A machine with only the core package has no
        // plugin directory at all, and the ladder is simply shorter.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return plugins,
        Err(error) => {
            plugins
                .failures
                .push((dir.to_owned(), format!("cannot be read: {error}")));
            return plugins;
        }
    };

    if deployed && let Some(why) = untrusted_dir(dir) {
        plugins.failures.push((dir.to_owned(), why));
        return plugins;
    }

    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "so"))
        .collect();
    paths.sort();

    for path in paths {
        if deployed && let Some(why) = untrusted_file(&path) {
            plugins.failures.push((path, why));
            continue;
        }
        match open_plugin(&path) {
            Ok((factory, library)) => {
                plugins.factories.push(factory);
                plugins._libraries.push(library);
            }
            Err(why) => plugins.failures.push((path, why)),
        }
    }

    plugins
}

/// Why the deployed plugin directory itself may not be trusted.
///
/// The per-file check below is the load-bearing one — it is what stops a file
/// the daemon's own user could rewrite from being mapped — but a directory the
/// daemon's user can write to is a directory whose contents can be swapped
/// between the two checks, so it is refused as a whole.
fn untrusted_dir(dir: &Path) -> Option<String> {
    let meta = match fs::metadata(dir) {
        Ok(meta) => meta,
        Err(error) => return Some(format!("cannot be inspected: {error}")),
    };
    trust(&meta, dir)
}

/// Why one deployed plugin file may not be trusted.
fn untrusted_file(path: &Path) -> Option<String> {
    let meta = match fs::metadata(path) {
        Ok(meta) => meta,
        Err(error) => return Some(format!("cannot be inspected: {error}")),
    };
    if !meta.is_file() {
        return Some("is not a regular file".to_owned());
    }
    trust(&meta, path)
}

/// The ownership and mode a deployed plugin (or its directory) must have.
fn trust(meta: &fs::Metadata, path: &Path) -> Option<String> {
    if meta.uid() != 0 {
        return Some(format!(
            "{} is owned by uid {}, not root, so the daemon's own user could have written it",
            path.display(),
            meta.uid()
        ));
    }
    if meta.mode() & 0o022 != 0 {
        return Some(format!(
            "{} is writable by group or others (mode {:04o})",
            path.display(),
            meta.mode() & 0o7777
        ));
    }
    None
}

/// A plugin's entry point, as the loader sees it; `unsafe` because calling a
/// function of unknown provenance is.
type EntryPoint = unsafe extern "C" fn() -> Entry;
/// Open one plugin and take the factory it offers.
///
/// Every `unsafe` operation in this crate is in this function, and each is
/// justified at its call site. Keeping them together is the point: a reviewer
/// reads one screen to see the whole of what a plugin may do to this process.
#[allow(unsafe_code)]
fn open_plugin(path: &Path) -> Result<(Box<dyn BackendFactory>, Library), String> {
    // SAFETY:
    // * mapping the file runs its initialisers as this process. It has been
    //   shown to be root-owned and not writable by anyone else (or, for a
    //   directory an operator or a test chose, to be whatever they chose), so
    //   what runs is code this machine's administrator installed.
    // * the symbol is looked up by name and, crucially, only *called* after the
    //   ABI number it would return has been read; on a mismatch nothing it
    //   exports is touched.
    unsafe {
        let library = Library::new(path).map_err(|error| format!("cannot be mapped: {error}"))?;
        let entry_point = *library
            .get::<EntryPoint>(ENTRY_SYMBOL)
            .map_err(|error| format!("exports no tpmd_plugin_entry symbol: {error}"))?;
        let entry = entry_point();
        if entry.abi != ABI_VERSION {
            return Err(format!(
                "speaks plugin ABI {} but this daemon speaks {ABI_VERSION}; \
                 it comes from a different build",
                entry.abi
            ));
        }
        // SAFETY: `make` hands back a pointer from `tpmd_plugin::boxed`, in a
        // plugin built from this revision; reclaiming it is the other half of
        // that transfer, and `BackendFactory: 'static` means the box may outlive
        // the call. The library is kept alive by the caller for at least as long
        // as any factory or backend made from it.
        let factory = *Box::from_raw((entry.make)());
        Ok((factory, library))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory that is simply not there is not an event: the ladder is just
    /// shorter. A machine with only the core package has no plugin directory.
    #[test]
    fn an_absent_directory_is_not_a_failure() {
        let plugins = load(Path::new("/nonexistent-tpmd-plugin-dir"));
        assert!(plugins.factories().is_empty());
        assert!(plugins.failures().is_empty());
    }

    /// A directory with nothing loadable in it is likewise not an event, and
    /// files that are not plugins are not looked at.
    #[test]
    fn a_directory_with_no_plugins_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("README"), b"not a plugin").unwrap();
        let plugins = load(dir.path());
        assert!(plugins.factories().is_empty());
        assert!(plugins.failures().is_empty());
    }

    /// The load-bearing half of the privilege argument: a plugin the daemon's
    /// own user could have written is refused, so the running user is treated as
    /// untrusted even though it is the one the daemon runs as.
    #[test]
    fn a_plugin_owned_by_the_running_user_is_untrusted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("planted.so");
        fs::write(&path, b"not a plugin").unwrap();
        let meta = fs::metadata(&path).unwrap();
        let why = trust(&meta, &path).expect("a file owned by this user must be refused");
        assert!(why.contains("not root"), "{why}");
    }
}
