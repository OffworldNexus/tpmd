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
| `tpmd-backend` | `Backend` trait (async, object-safe), security levels, error taxonomy, `can_be_used`. |
| `tpmd-store` | SeaORM entities + migrations for the single shared SQLite file. |
| `tpmd-backend-dummy` | SQLite P-256 store (level `file`). |
| `tpmd-backend-keyring` | OS credential store (level `keyring`); one crate, one store per OS. |
| `tpmd-backend-linux-tpm` | Linux TPM 2.0 store (levels `sealed`, `hardware`); hand-rolled transport. |
| `tpmd-backend-windows-cng` | Windows CNG Platform Crypto Provider store (level `hardware`); one `unsafe` FFI module. |
| `tpmd-ipc` | Local endpoints, caller auth, secure filesystem, framed I/O. |
| `tpmd` | The daemon, its backend registry and its CLI. |
| `tpmd-plugin` | The run-time plugin boundary: the `dlopen` loader (host side) and the runtime a plugin's own code runs on. |
| `tpmd-backend-*-plugin` | The two `cdylib` shims the Debian split ships, one per backend package; an ordinary library in every other build. |
| `tpmd-plugin-fixture` | Test-only plugin, so the loader and the boundary are exercised against a real shared object. |
| `tpmd-client` | Consumer API. |
| `tpmd-demo` | Toy consumer. |

## Conventions

- Edition **2024**, `rust-version = "1.98"`, Apache-2.0.
- Cryptographic line matches Tunnel Weaver so signatures verify with
  `weaver_mux::auth::verify`: `p256 0.14`, `sha2`/`postcard` as pinned in the
  workspace `Cargo.toml`.
- `#![forbid(unsafe_code)]` everywhere except three deliberately scoped
  modules, each reviewed as a unit: `tpmd-ipc`'s Windows module (`winutil`, for
  pipe DACLs and peer SIDs), `tpmd-backend-windows-cng`'s `ffi` module (for
  CNG/NCrypt) and `tpmd-plugin`'s `host` module — the `dlopen` by which the
  packaging split loads a backend, which is a privilege decision rather than a
  parsing one, because mapping a file runs its code as this process. The shim
  and fixture crates use `deny` rather than `forbid` for their one generated
  `unsafe(no_mangle)` entry point. Nothing else may use `unsafe`.
- Every public item is documented (`#![warn(missing_docs)]`); comments explain
  **why**, not what.
- Backends are one crate per mechanism, gated so a build for one OS never
  compiles another platform's backend; **what is built** is compile-time, **what
  is used** is chosen at run time via `can_be_used()` + `default_level()`, with
  `--backend` to force one. The keyring backend serves all three platforms, so
  it is built everywhere and gates the *store* it links instead; a host whose
  store is unreachable reports `can_be_used() == false` and the ladder passes
  over it.

## Testing

- Full suite (fast): `cargo test --workspace --all-targets -q` (~1s warm; sub-second test execution once built, timeout 900000ms).
- The packaging split's build mode is a different feature set with tests of
  its own: `cargo test -p tpmd --no-default-features --features loadable-backends
  --all-targets -q` (~10s). CI runs it, and clippy over it, on Linux.
- Single crate: `cargo test -p tpmd-proto -q` (~10s, timeout 120000ms).
- Single test: `cargo test -p tpmd --test daemon <name> -q` (~5s, timeout 120000ms).
- Static analysis, in order:
  - `cargo fmt --all --check` (write mode: `cargo fmt --all`)
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo deny check`
- Cross-compile check of the Windows transport without a C toolchain:
  `cargo check -p tpmd-ipc --target x86_64-pc-windows-msvc`. The scope is
  deliberate: anything reaching `tpmd-store` drags in `libsqlite3-sys`'s bundled
  C build and needs an MSVC (or SDK) C toolchain this host does not have. To
  type-check a platform-gated *backend* without one, set
  `LIBSQLITE3_SYS_USE_PKG_CONFIG=1 PKG_CONFIG_ALLOW_CROSS=1` (env only; `cargo
  check` does not link).
- Always: redirect output to a temp file; silent on success; dump failures only.
- CI runs the full suite on `ubuntu-latest`, `windows-latest` and `macos-latest`.
- Last measured: 2026-10-17, full suite ~1s warm / ~3s when the workspace crates
  need rebuilding (91 tests; on this machine 6 self-skip — 5 without TPM access,
  1 without a second OS account — and 5 more would where no OS credential store
  answers; cold includes a full rebuild).

The cross-user test (`crates/tpmd/tests/cross_user.rs`) needs a second OS
account — `TPMD_TEST_OTHER_USER` (default `tpmdtest`) — and passwordless
`sudo -n`; it skips itself otherwise.

The Linux TPM tests (`crates/tpmd-backend-linux-tpm/tests/device.rs`) need a
real TPM and rights to open `/dev/tpmrm*` (usually the `tss` group). They
**self-skip** when the device cannot be opened, so CI stays green on the
TPM-less runners. To run them locally:

```sh
cargo test -p tpmd-backend-linux-tpm --all-targets --no-run
sudo ./target/debug/deps/device-<hash>          # or: sudo -g tss …
```

`tpm2-tools` is used only as a development reference for the TPM wire format;
it is **not** a build or runtime dependency (the transport is hand-rolled).
The daemon's store is one SeaORM-managed SQLite file in WAL mode.

The Windows CNG tests (`crates/tpmd-backend-windows-cng/tests/device.rs`) need a
live TPM 2.0 **and** a logon that may create a Platform Crypto Provider *user*
key. They **self-skip** otherwise, which keeps the TPM-less `windows-latest`
runner green. Note that WinRM is a *network* logon, where user-key creation is
refused: run them on the rig from the user's interactive session, e.g. through a
scheduled task with `/IT`.

The agent is a silent per-user process on Windows (no window); `tpmd status` is
the first-class way to ask whether one is running and what it can do.

The keyring tests come in two halves. The unit tests run against an in-crate mock
store and need nothing. The store-gated tests
(`crates/tpmd-backend-keyring/tests/device.rs`) run against the **real** OS
credential store; they **self-skip** where no store answers, which keeps the
headless runners green. Note that they write a real credential (under namespace
`tpmd-test`, destroyed again before they return): set `TPMD_TEST_KEYRING=0` to
skip them where touching the login keyring would prompt.

## Running a development build alongside the installed agent

The packages install a working agent, and a development build has to stay out of
its way. Three things are never shared:

| | The installed agent | A development build |
| --- | --- | --- |
| socket | `/run/tpmd/tpmd.sock`, created by `tpmd.socket` | `--socket /tmp/tpmd-dev/tpmd.sock` |
| state | `/var/lib/tpmd`, a real device identity | `--state-dir /tmp/tpmd-dev/state` |
| plugins | `/usr/lib/tpmd/backends`, from the `.deb`s | `--backend-dir` (or `TPMD_BACKEND_DIR`) |

```sh
mkdir -p /tmp/tpmd-dev
cargo run -p tpmd -- serve --user \
  --socket /tmp/tpmd-dev/tpmd.sock --state-dir /tmp/tpmd-dev/state \
  --backend-dir /tmp/tpmd-dev/backends --min-key-security file
```

`--user` because it is not root's agent, and a directory of its own because
binding a socket in the packaged paths is not a development build's business. A
`--backend-dir` that does not exist means no plugins, which is the honest answer
for a monolith build: that build links its backends in and never reads the
directory at all. To exercise a *split* build, put its own plugins there first —
`cp target/debug/libtpmd_backend_*_plugin.so /tmp/tpmd-dev/backends/`.

The third row is the one that bites. The packaged plugins are built by the pinned
container's toolchain and a debug build by the toolchain on this machine, and the
plugin ABI number catches a change in *shape*, not in *compiler* (see
`tpmd-plugin`'s module docs). Loading one into the other therefore does not
refuse: the daemon dies of a `SIGSEGV` with no message, which is also what a test
looks like when it inherits the machine's plugins. That is why `Config` carries
`plugin_dir` rather than letting the loader read the environment behind the
daemon's back, and why the tests that run a daemon point it at a directory with
nothing in it.


## Packaging

- Debian/Ubuntu `.deb`, published nightly to a signed APT repository (Cloudsmith)
  and installable with a two-line `sources.list.d` entry; the user-facing page is
  `docs/install.md`. One artifact per architecture serves every supported release.
- The published set is three packages, not one: `tpmd` — the daemon, with only
  the guaranteed `file` floor built in — plus one package per backend, each
  shipping a `cdylib` into `/usr/lib/tpmd/backends` that the daemon finds at run
  time. That is the `loadable-backends` build mode, `debian/rules`' default;
  a plain `cargo build` never reads that file and is still the monolith it
  always was.
- **Sources are published too, and the binaries are built from them.**
  `packaging/deb/build-source.sh` turns a commit (a `git archive`, never the
  working tree) into `tpmd_<version>.dsc` + one native `.tar.xz` with every
  crate vendored; `build-deb.sh` extracts that and builds offline — CI runs it
  under `--network none`. Two traps it handles, both of which fail the build
  rather than the user: dpkg-source always drops `*.a`/`*.so`/`.gitignore`
  from a native tarball, so each vendored crate's per-file checksum list is
  emptied (its package checksum, tied to `Cargo.lock`, stays); and `dh_clean`
  deletes `*.orig`, so it is told to leave `vendor/` alone. Try an uncommitted
  change with `TPMD_DEB_TREE` (see the script's header).
- **A plugin's code runs on a runtime of its own.** A plugin is a `cdylib`, so
  it links its own `tokio` and `sqlx`; a runtime context is a thread-local of
  the crate that set it, so a plugin polled on the daemon's runtime has `sqlx`
  abort the whole process — "this functionality requires a Tokio context", then
  an abort out of a `cdylib` frame, where the panic is no longer catchable.
  `tpmd-plugin` wraps every factory so this cannot be forgotten; see
  `tpmd-plugin::runtime` and the tests that assert it.
- Build it through the pinned container, always — the container is the *oldest*
  supported release, whose glibc becomes the published binary's floor:

  ```sh
  docker build -f packaging/deb/Dockerfile -t tpmd-deb .
  docker run --rm --user "$(id -u):$(id -g)" --env CARGO_HOME=/tmp/cargo-home \
    -v "$PWD:/tmp/src" -w /tmp/src tpmd-deb packaging/deb/build-deb.sh dist
  ```

  `--user` is load-bearing rather than decoration: it keeps the build from
  writing files your account cannot remove afterwards — the image's own
  `CARGO_HOME` is not writable by the invoking user, hence the override. The
  build itself happens in a temporary directory, never in the checkout; only
  `dist/` is written there.

- **Retention:** every stable release is kept; nightlies are pruned to the
  newest seven versions by `packaging/deb/prune-nightlies.py` (the workflow's
  `prune` job, after `verify`). Try it with `--dry-run`; it deletes whole
  versions and never one without `~nightly`.
- Verify an install for real (needs docker and network; installs from the
  *published* repository in a clean container per release): `packaging/deb/verify-install.sh`.
- **No distribution can build this package.** The workspace declares
  `rust-version = "1.94"` and edition 2024, and every currently supported release
  ships an older `rustc` — measured: 1.94 builds and passes the suite, 1.93 is
  refused (`sea-orm` and `sqlx` require 1.94). `debian/` therefore follows the
  Debian Rust Team's policy in *shape* while the binaries come from our own
  pinned toolchain; `docs/install.md` states the deviation and its consequences.
- macOS is packaged separately (`packaging/macos`, driven by fastlane). Like the
  Debian pipeline, neither runs on the push or pull-request path.

## Anti-patterns

- Do not trust a UID/SID claimed in a request payload: always derive it from
  kernel peer credentials.
- Do not silently weaken the security floor or replace a lost key with a weaker
  one. `select_level` is the only place that decision is made.
- Do not add key enumeration: keys are addressed by fingerprint only.
- Do not export private key material: no such operation exists.
- Do not call the OS credential store from an async thread. Its blocking API —
  and its `Drop` — call `block_on` on a runtime of its own, which panics on any
  thread that already has a runtime context, `spawn_blocking` threads included;
  `tpmd-backend-keyring` owns the only correct path and nothing else may take a
  shortcut around it.
- Do not park a client on a store that is *gone*. Only a **closed** store is
  waitable — something the user can change — and every wait must end in `OPENED`
  or an error. "Waiting for ever" is the failure the closed/gone split exists to
  prevent, so a hint provider that can never fire is a bug, not patience.
- Do not answer "not now" with `REJECT`. It closes the socket and is reserved for
  the fatal cases; a closed store is answered with the non-fatal `CLOSED`, which
  is the only refusal that keeps the connection.
- Do not point a development build at `/usr/lib/tpmd/backends`, and do not let a
  test inherit it. The ABI number matches while the compilers differ, so the
  failure is a `SIGSEGV` in the agent rather than an error anyone can read. See
  *Running a development build alongside the installed agent*.
- Do not drive a plugin's own code on the daemon's runtime, and do not export a
  factory with anything but `tpmd_plugin::export_backend!`. The two copies of
  `tokio` in the process have separate thread-locals, and the failure is an
  abort of the agent rather than an error a caller could see. See
  `tpmd-plugin::runtime`.
