//! SeaORM entities for the shared store.
//!
//! Every backend writes into the **same** SQLite file but into its own table,
//! so the schema is a catalogue of mechanisms rather than a per-backend
//! database. The tables share the addressing convention the whole daemon
//! depends on: a key is `(principal, namespace, key_id)`, and all three are
//! part of the primary key so a foreign lookup is indistinguishable from a
//! missing key.

pub mod keys;
pub mod tpm_keys;
