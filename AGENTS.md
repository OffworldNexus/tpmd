# AGENTS.md — tpmd

Guidance for automated agents and humans working in this repository.

## What this is

`tpmd` is a local key agent: a daemon that owns private signing keys and signs
on behalf of local applications over a local IPC channel. This workspace
implements the **dummy** backend (a SQLite software P-256 store at security
level `file`) and the whole consumer contract around it.

Read, in order:

1. `docs/protocol.md` — the wire contract (handshake, operations, errors).
2. `docs/architecture.md` — crates, trust model, custody, platform details.
3. `docs/demo.md` — how to run the toy.

## Crates

| Crate | Role |
| --- | --- |
| `tpmd-proto` | Messages + Postcard frame codec. No OS/storage deps. |
| `tpmd-backend` | `Backend` trait, security levels, error taxonomy. |
| `tpmd-backend-dummy` | SQLite P-256 store (level `file`). |
| `tpmd-ipc` | Local endpoints, caller auth, secure filesystem, framed I/O. |
| `tpmd` | The daemon and its CLI. |
| `tpmd-client` | Consumer API. |
| `tpmd-demo` | Toy consumer. |

## Conventions

- Edition **2024**, `rust-version = "1.98"`, Apache-2.0.
- Cryptographic line matches Tunnel Weaver so signatures verify with
  `weaver_mux::auth::verify`: `p256 0.14`, `sha2`/`postcard` as pinned in the
  workspace `Cargo.toml`.
- `#![forbid(unsafe_code)]` everywhere except `tpmd-ipc`, whose Windows module
  (`winutil`) is the only place `unsafe` is allowed.
- Every public item is documented (`#![warn(missing_docs)]`); comments explain
  **why**, not what.
- Backends are one crate per mechanism, feature/target-gated, so a build for
  one OS never compiles another platform's backend.

## Testing

- Full suite (fast): `cargo test --workspace --all-targets -q` (~5s warm; sub-second test execution once built, timeout 600000ms).
- Single crate: `cargo test -p tpmd-proto -q` (~10s, timeout 120000ms).
- Single test: `cargo test -p tpmd --test daemon <name> -q` (~5s, timeout 120000ms).
- Static analysis, in order:
  - `cargo fmt --all --check` (write mode: `cargo fmt --all`)
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo deny check`
- Cross-compile check of the Windows transport without a C toolchain:
  `cargo check -p tpmd-ipc --target x86_64-pc-windows-msvc`.
- Always: redirect output to a temp file; silent on success; dump failures only.
- CI runs the full suite on `ubuntu-latest`, `windows-latest` and `macos-latest`.
- Last measured: 2026-10-14, full suite ~5s warm (36 tests; cold includes a full rebuild).

The cross-user test (`crates/tpmd/tests/cross_user.rs`) needs a second OS
account — `TPMD_TEST_OTHER_USER` (default `tpmdtest`) — and passwordless
`sudo -n`; it skips itself otherwise.

## Anti-patterns

- Do not trust a UID/SID claimed in a request payload: always derive it from
  kernel peer credentials.
- Do not silently weaken the security floor or replace a lost key with a weaker
  one. `select_level` is the only place that decision is made.
- Do not add key enumeration: keys are addressed by fingerprint only.
- Do not export private key material: no such operation exists.
