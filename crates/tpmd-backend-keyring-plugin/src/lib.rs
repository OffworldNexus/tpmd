//! The loadable-plugin shim for the keyring backend.
//!
//! The backend itself stays a plain library; this crate is the packaging split's
//! way of asking it for one factory through the boundary in `tpmd-plugin`. It is
//! built as a `cdylib` only by the split (see `debian/rules`) — an ordinary
//! `cargo build` produces a library nothing links, and no shared object at all,
//! which is what keeps the normal build the monolith it always was.
//!
//! `deny`, not `forbid`: the one generated entry point is `unsafe(no_mangle)`,
//! which the `unsafe_code` lint counts as unsafe, and `forbid` cannot be relaxed
//! for it. It is the only such item here or in any shim; see
//! `tpmd_plugin::export_backend!`.

#![deny(unsafe_code)]
#![warn(missing_docs)]

tpmd_plugin::export_backend!(tpmd_backend_keyring::KeyringFactory);
