//! The boundary between the daemon and a backend that is loaded at run time.
//!
//! Normally every backend this daemon can use is compiled into it. The
//! packaging split (`loadable-backends`) changes only *where a factory comes
//! from*: the daemon asks a shared object in a fixed directory for one, instead
//! of holding one in its own image. Everything after that — surveying,
//! selecting, opening, signing — is the same code over the same
//! [`BackendFactory`] trait, because this crate hands back an ordinary trait
//! object and nothing else.
//!
//! # The boundary, and its limits
//!
//! A plugin exports one symbol, `tpmd_plugin_entry`, returning
//!
//! ```text
//! #[repr(C)] struct Entry { abi: u32, make: extern "C" fn() -> *mut Box<dyn BackendFactory> }
//! ```
//!
//! `make` hands over a thin pointer to a boxed trait object: Fat pointers are
//! two words and not `#[repr(C)]`, so they cross the boundary only as pointers,
//! which is what [`boxed`] and the host's reclaiming code exist for.
//!
//! This is **not** a stable ABI and does not try to be one. It is a boundary
//! between two artifacts built from the same revision by the same compiler in
//! the same packaging run, and it holds exactly as long as that is true:
//!
//! * a trait object's vtable layout is a Rust implementation detail, so a host
//!   and a plugin from *different* builds may disagree about it;
//! * both sides allocate with the same allocator only because they are the same
//!   process built by the same toolchain, so the host may free a box a plugin
//!   allocated;
//! * `abi` therefore exists to turn the **detectable** mismatch — a plugin from
//!   a different revision of this crate — into a refusal rather than undefined
//!   behaviour. It cannot detect a mismatch between two revisions that happen to
//!   share the number, which is why the number must be bumped whenever the entry
//!   shape or the traits it carries change.
//!
//! The alternative, `abi_stable`, was considered and not taken: it buys
//! cross-compiler stability by rewriting both sides' types into its own, at the
//! cost of a large dependency and a second type system between the daemon and
//! every backend. The one deployment that exists — a `.deb` built and installed
//! as a unit — does not need that, and inventing the appearance of stability
//! here would make the real constraint (same build) invisible instead of stated.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::boxed::Box;

pub use tpmd_backend::{Backend, BackendError, BackendFactory};

#[cfg(all(target_os = "linux", feature = "host"))]
pub mod host;

/// The version of the boundary above.
///
/// Bump it whenever [`Entry`] changes shape or any trait reachable through it
/// does. The host refuses a plugin that answers with a different number, which
/// is the difference between a broken package and an unexplained crash.
pub const ABI_VERSION: u32 = 1;

/// The symbol a plugin exports to describe itself.
///
/// NUL-terminated because that is what a dynamic loader looks symbols up by.
pub const ENTRY_SYMBOL: &[u8] = b"tpmd_plugin_entry\0";

/// How a plugin hands the host one factory to survey.
///
/// Returns a [`boxed`] pointer; the host reclaims it with `Box::from_raw` and
/// owns it from then on.
pub type MakeFactory = extern "C" fn() -> *mut Box<dyn BackendFactory>;

/// What a plugin's entry point answers with.
///
/// `#[repr(C)]` so that both sides agree on the layout even though only the
/// `abi` field is ever read; the function pointer is opaque to the host until
/// the version has been checked.
#[repr(C)]
pub struct Entry {
    /// Which revision of this boundary the plugin was built against.
    pub abi: u32,
    /// Produces the plugin's one factory.
    pub make: MakeFactory,
}

/// Move a factory into a box the host can take ownership of.
///
/// The double box is deliberate: `make` has to return one pointer, and a
/// `Box<dyn BackendFactory>` is a fat pointer, so the thin pointer the ABI can
/// carry is a pointer to the box.
pub fn boxed<F>(factory: F) -> *mut Box<dyn BackendFactory>
where
    F: BackendFactory + 'static,
{
    Box::into_raw(Box::new(Box::new(factory) as Box<dyn BackendFactory>))
}

/// Export this crate as a plugin whose factory is `$factory`.
///
/// A shim crate's whole body is this macro: the backend crates stay plain
/// libraries, and the one unsafe-looking thing in a plugin — the unmangled
/// export — is written once, here, where it can be reviewed as a unit.
///
/// ```ignore
/// tpmd_plugin::export_backend!(tpmd_backend_keyring::KeyringFactory);
/// ```
///
/// A shim uses `#![deny(unsafe_code)]` rather than `#![forbid(unsafe_code)]`
/// for the same reason the Windows backends do: the `unsafe_code` lint counts
/// `#[unsafe(no_mangle)]` as unsafe, and `forbid` cannot be relaxed for the one
/// generated item. The `allow` below is the only relaxation; everything else in
/// the shim is still denied.
#[macro_export]
macro_rules! export_backend {
    ($factory:expr) => {
        /// The one symbol a plugin exports, called by the host before anything
        /// else; see `tpmd_plugin` for the boundary this belongs to.
        #[allow(unsafe_code)]
        #[unsafe(no_mangle)]
        pub extern "C" fn tpmd_plugin_entry() -> $crate::Entry {
            extern "C" fn make() -> *mut Box<dyn $crate::BackendFactory> {
                $crate::boxed($factory)
            }
            $crate::Entry {
                abi: $crate::ABI_VERSION,
                make,
            }
        }
    };
}
