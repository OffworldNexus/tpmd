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

## WVR-144 decisions

| Decision | Value | Rationale |
| --- | --- | --- |
| Backend name / levels | `windows-cng`; advertises **`hardware` only** | The only honest hardware claim on Windows is a non-exportable, TPM-backed Platform Crypto Provider key. A DPAPI-wrapped software key is *not* sealing, so there is no `sealed` rung to report; keyring/file arrive from WVR-151 and the dummy. |
| Custody check | Export policy must be `0` **and** `PCP_PLATFORM_TYPE` must report TPM 2.0 | "DPAPI alone is not proof of TPM-backed sealing": the level is read back from the provider, never inferred from its name. A key that fails either check is **destroyed** and the provision returns `backend_unavailable`. |
| Usability proof | A live probe key at every daemon start (create → sign → export public → delete), cached | The ticket requires ordinary-user key creation to be *verified*: opening the provider succeeds over a network logon while key creation is refused, so a provider-only check would select an unusable backend. |
| Key context | The owning user's **interactive** session; machine keys are not used | Matches the acceptance ("owning user's context", "no elevation") and the macOS LaunchAgent precedent. Per-user keys live in the user's CNG store; `LocalSystem` cannot use them. |
| Agent shape | Silent per-user process, no window, started at logon (mechanism owned by WVR-149) | A service as `LocalSystem` cannot use a user's keys; a systray icon is optional UX and belongs to packaging. |
| Observability | `tpmd status` (client-side, all platforms) | A silent process still has to be answerable: this is the first-class "is it running, and what can it do?" check, alongside Task Manager, the per-user pipe and the state directory. |
| `unsafe` | Scoped exemption for one `ffi` module, using `windows-sys` (`Win32_Security_Cryptography`) | CNG is an OS component (nothing bundled); confining all FFI to one module keeps the rest of the crate safe code, mirroring `tpmd-ipc`'s `winutil`. |
| Rig toolchain | rustup + **MSVC** via VS Build Tools on the Windows 11 VM | Matches what CI and shipping builds use (`x86_64-pc-windows-msvc`). |

## Dependency line

`tpmd` deliberately shares the Tunnel Weaver cryptographic line so signatures
produced by the agent verify with `weaver_mux::auth::verify` byte-for-byte:

- `p256 0.14` (ECDSA P-256 / SHA-256), `postcard 1.1`, `serde 1.0`,
  `thiserror 2.0`, `tokio 1.43`, `proptest 1.11`, `cargo-deny` configuration.

## Scope

WVR-140 implements the **dummy** engine and the complete consumer contract
only. The keyring, Linux TPM, Windows CNG and macOS Secure Enclave backends
are sibling tickets, as are packaging and distribution.
