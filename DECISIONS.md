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

## WVR-151 decisions

| Decision | Value | Rationale |
| --- | --- | --- |
| Crate line | `keyring-core` + one store crate per OS (`zbus-secret-service`, `apple-native`, `windows-native`), target-gated | The `keyring` crate cannot satisfy the ticket at any version: v4's own docs tell applications that choose stores per platform to link `keyring-core` plus store crates, and v3's `linux-native` is the *kernel* keyring — the exact store the ticket excludes. `keyring-core` + zbus keeps the whole line pure Rust (no C toolchain, no libdbus), and `dbus-secret-service` is unused for that reason. |
| Build gating | Built on **every** OS, unlike the hardware backends; the *store* is target-gated inside the crate | All three platforms have a credential store, so "is this backend built?" is always yes; "is this host's store reachable?" is a run-time question (`can_be_used()`), which is exactly the build-time/run-time split the registry already draws. No Cargo feature is introduced anywhere. |
| Level | Advertises **`keyring` only** | The scalar is held by the OS store but signing is software. Claiming `sealed`/`hardware` would be a lie; claiming `file` would understate it. |
| Store address | `(principal, namespace, key_id)` folded into the store's *user* half, length-prefixed | The store's namespace is flat `(service, user)`, so the triple must be folded injectively: plain concatenation would let a namespace containing the delimiter collide with a different principal. Length prefixes keep it readable in the store's own UI, and the exact address is persisted so a future scheme change cannot orphan keys. |
| Secret encoding | Hex **text**, not raw bytes | The Secret Service implementation some desktops ship (KDE Wallet) is UTF-8 only, so an arbitrary binary secret cannot be written through it. |
| Metadata | New `keyring_keys` table + migration (one table per mechanism) | Ownership has to be decided *before* the store is touched, and the exact entry address has to be recorded; it also separates "row present, credential gone" (`key_loss`) from "no row" (`unknown_key`). |
| Windows persistence | Creation asks for the store's `persistence = Local` and **fails** if the host refuses it — there is no second, weaker attempt | The store defaults to `Enterprise`, which roams with a roaming profile — wrong for something whose whole purpose is to identify *this* device. A logon session with no profile-backed credential manager (a Task Scheduler- or service-started process, i.e. how the Windows agent runs) *refuses* durable persistence with `ERROR_NO_SUCH_LOGON_SESSION`: measured on the Windows 11 rig, where `Local` and `Enterprise` both returned 1312 while `Session` succeeded, and where `cmdkey` succeeded only because it writes session-persistable credentials. Falling back to `Session` was tried first and rejected: it silently changes the promise the level makes — the key would evaporate at logoff, the device would return as a stranger needing re-pairing, and a background service's log is not where a caller finds that out. The refusal is surfaced instead, and it counts as *gone* rather than *closed* because nothing the user does in that session changes it; the fix is how the agent is started (WVR-149). |
| Ownership | Row lookup first, store second | A request under the wrong principal must be indistinguishable from a request for a key that was never minted, so the store must never be consulted for a foreign key. |
| Usability probe | Once at open: build the store and ask one read-only question; `NoEntry` **and** `NoStorageAccess` both count as usable | `NoEntry` is the ordinary state before a key exists, so it cannot mean "unusable". Falling through to the dummy whenever the store is *locked* would silently weaken custody to a plaintext file, so a locked store is deliberately left to fail per operation as `store_locked` — which is what it does. Measured on macOS: a read of a missing item needs no unlock at all, so the probe still answers, and a write against a locked keychain fails in about a second with an authorization error rather than waiting for one. |
| Selection | An unreachable store makes the backend unusable → ladder falls through to `dummy` and records why; `--backend keyring` is still honoured | Headless hosts (no session bus) must keep working, but an operator who explicitly asks for the keyring should be told `store_locked` rather than get a refusal to start. This is the one place where forcing an unusable backend is not refused, hence `Backend::forced_when_unusable`. |
| Store mechanism in `status` | The *value* of the existing free-form `Status.backend` (`keyring (secret-service)`), via `Backend::store_mechanism()` | Names the underlying store where the ticket asks for it without touching the wire type, the protocol version or `tpmd-client`. `WELCOME.capabilities.backend` keeps the bare name for machine matching. |
| Threading | Every store call on a thread with **no** async runtime context, serialised by a process-wide lock; a store that answered is kept for the process's life | Tokio enters the runtime context on `spawn_blocking` threads, and the Linux store's blocking API builds its own runtime and calls `block_on` — which panics there. Its `Drop` disconnects the same way, so the store is never dropped. |
| `unsafe` | None added | Unlike the CNG backend, no FFI of our own is needed: the stores are pure Rust (`zbus`) or OS frameworks reached through safe wrappers. |

## WVR-152 decisions

| Decision | Value | Rationale |
| --- | --- | --- |
| Closed vs gone | Two conditions, told apart by **who can change them**, and classified by the backend by probing existence | A locked keychain is a state the user changes; a missing device node is not. Nothing else distinguishes them usefully, and error text differs per platform and per provider — it has misled before (`cmdkey` succeeding while `CredWrite` refused). |
| The closed answer | A new, **non-fatal** `CLOSED` message; `REJECT` stays fatal | A user-session store is shut normally, so "not now" must be distinguishable from "you spoke nonsense" without closing the socket. Reusing `REJECT` would have made the two indistinguishable. |
| Waiting | `AWAIT`, an `Op` with **no timing**, answered by `Reply::Opened` through the existing `Response` | Detection belongs to the daemon — it knows its dependency — so a client should not be handed an interval to poll on. Reusing `Op`/`Reply` keeps `id` correlation, pipelining and out-of-order answers working, and grew the protocol by one message, one reject code, one op and one reply. |
| Gone backends | A new `RejectCode::BackendUnavailable`, fatal, with its own client error variant | Retrying cannot fix a missing dependency, and rule 12 requires applications be told to warn their user rather than to try again. Giving it its own variant stops it being lumped with a transport failure. |
| Detection | One watcher per daemon process, woken by `Backend::unlock_hints()`; a real Linux bus signal, a backoff interval elsewhere, and a 5 s safety net on Linux | Ten parked clients must not mean ten probe loops, and a daemon with nobody waiting must poll nothing. A hint is never a promise, so every one is followed by a probe. |
| No version bump | `PROTOCOL_VERSION` stays **1** | tpmd is 0.1.0 and has never been released: there is no peer to be compatible with, and every addition here is an append, so existing frames are byte-identical. `docs/protocol.md` §6 says the shape is unstable until the first release; the first *released* change is when the bump becomes real. |
| Selection | A **closed** backend is a candidate; a **gone** one is skipped with its reason | Falling to a plainer store because a keychain happens to be locked is a silent custody change. This is also why `can_be_used()` kept its narrow meaning ("usable now") and the ladder asks `store_status()` instead. |
| Store state on the wire | `StoreState` on `Capabilities` and `Status`; the same `Closed` shape as the message | `tpmd status` should answer "is it running, and can it sign right now?" without attempting an operation, and a client should parse one shape rather than two. |
| Concurrency | Requests are dispatched as tasks and answers written by a writer task | A parked `AWAIT` must not stop the connection: the protocol allows pipelined requests and out-of-order answers, and rule 9 lets a waiting client ask `STATUS`. |

## Dependency line

`tpmd` deliberately shares the Tunnel Weaver cryptographic line so signatures
produced by the agent verify with `weaver_mux::auth::verify` byte-for-byte:

- `p256 0.14` (ECDSA P-256 / SHA-256), `postcard 1.1`, `serde 1.0`,
  `thiserror 2.0`, `tokio 1.43`, `proptest 1.11`, `cargo-deny` configuration.

## Scope

WVR-140 implements the **dummy** engine and the complete consumer contract.
WVR-141 adds the Linux TPM backend, WVR-144 the Windows CNG backend and the
`tpmd status` command, and WVR-151 the universal OS-credential-store backend.
The macOS Secure Enclave backend (WVR-142) and packaging and distribution
(WVR-145…150) are sibling tickets.
