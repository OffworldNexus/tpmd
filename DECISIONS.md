# Bootstrap decisions

The architecture document requires repository hosting, license and release
identity to be **recorded at bootstrap**, not silently assumed. This file
records them.

| Decision | Value | Rationale |
| --- | --- | --- |
| Repository hosting | `https://github.com/OffworldNexus/tpmd` | Matches the sibling Tunnel Weaver repository (`github.com/OffworldNexus/tunnel-weaver`). |
| License | Apache-2.0 | Same license as Tunnel Weaver; permissive with an explicit patent grant. |
| Authors | `Offworld Nexus Authors` | Same as Tunnel Weaver. |
| Edition | 2024 | Same as Tunnel Weaver. |
| Minimum Rust | 1.98 | Same as Tunnel Weaver (`rust-version = "1.98"`). |
| Default branch | `develop` | Requested at bootstrap; feature work happens on `feature/<linear-id>-…` branches. |
| Release signing | Not yet decided | No releases in WVR-140; revisit at packaging (WVR-145…150). |

## WVR-141 decisions

| Decision | Value | Rationale |
| --- | --- | --- |
| Storage | **One SeaORM-managed SQLite file** for every backend, one table per mechanism, **WAL** journal | A device has several backends and the daemon picks one at run time; a single migrated schema and a cheap-to-clone `DatabaseConnection` beat per-backend databases. WAL avoids read/write blocking; the sidecars stay covered by the `0700` directory. |
| TPM transport | **Hand-rolled** TPM 2.0 marshalling over `/dev/tpmrm*`; **no libtss2** | Keeps the crate pure Rust: no C toolchain to build, cross-compiles and unit-tests anywhere, and `cargo deny` stays simple. The architecture document permits system libtss2 for 1.x, so this is stricter than required. |
| Device selection | Scan `/dev/tpmrm0`…`tpmrm15`, then `/dev/tpm0`; `TPMD_TPM_DEVICE` overrides | A machine can host more than one TPM; never assume `tpmrm0`. |
| Backend selection | Runtime registry + `can_be_used()` + strongest `default_level()`, `--backend` to force | Backends are compiled in per OS but must prove they work here; the dummy is the guaranteed fallback. |
| System mode | `--system` (or root) → `/run/tpmd.sock` mode `0666`, `/var/lib/tpmd` | Reachability is not authorization; clients need no `tss` membership. Deployment, not the daemon, provisions the directory. |

## Dependency line

`tpmd` deliberately shares the Tunnel Weaver cryptographic line so signatures
produced by the agent verify with `weaver_mux::auth::verify` byte-for-byte:

- `p256 0.14` (ECDSA P-256 / SHA-256), `postcard 1.1`, `serde 1.0`,
  `thiserror 2.0`, `tokio 1.43`, `proptest 1.11`, `cargo-deny` configuration.

## Scope

WVR-140 implements the **dummy** engine and the complete consumer contract
only. The keyring, Linux TPM, Windows CNG and macOS Secure Enclave backends
are sibling tickets, as are packaging and distribution.
