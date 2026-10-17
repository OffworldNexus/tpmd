# tpmd

`tpmd` is a local **key agent**: a daemon that owns private signing keys and
signs on behalf of local applications, so applications never hold or export
private key material. Applications talk to it over a local IPC channel using
the `tpmd-client` Rust library.

This workspace builds four backends behind one interface: the **dummy** engine
(a software P-256 store in SQLite, level `file`), the **OS credential store**
(level `keyring`, on every platform), the **Linux TPM** (`sealed` and
`hardware`) and the **Windows CNG Platform Crypto Provider** (`hardware`). The
consumer contract — daemon, IPC protocol, client library and a toy consumer — is
the same for all of them.

- Design and wire protocol: [`docs/protocol.md`](docs/protocol.md)
- Architecture and custody notes: [`docs/architecture.md`](docs/architecture.md)
- Runnable toy usage: [`docs/demo.md`](docs/demo.md)
- Bootstrap decisions: [`DECISIONS.md`](DECISIONS.md)

## Workspace layout

| Crate | Role |
| --- | --- |
| `tpmd-proto` | Serializable messages, Postcard frame codec, limits, version negotiation. No OS or storage dependencies. |
| `tpmd-backend` | The `Backend` trait (async, object-safe), `SecurityLevel`, `Principal` and the error taxonomy. |
| `tpmd-store` | SeaORM entities and migrations for the one SQLite file every backend shares. |
| `tpmd-backend-dummy` | SQLite software P-256 store (level `file`). |
| `tpmd-backend-keyring` | OS credential store (level `keyring`): Secret Service, login keychain or Credential Manager, one store per OS. |
| `tpmd-backend-linux-tpm` | Linux TPM 2.0 store (levels `sealed` and `hardware`), hand-rolled transport, no libtss2. |
| `tpmd-backend-windows-cng` | Windows CNG Platform Crypto Provider store (level `hardware`), all FFI in one module. |
| `tpmd-ipc` | Cross-platform local endpoint: Unix socket, macOS socket, Windows named pipe, with native caller authentication. |
| `tpmd` | The daemon: serve loop, caller authentication, namespace and floor enforcement, backend registry and selection, CLI. |
| `tpmd-client` | The consumer API, hiding the transport. |
| `tpmd-demo` | A toy consumer that walks the Tunnel Weaver key life-cycle with a simulated relay. |

## Quick start (Linux / macOS)

```sh
# terminal 1 — start the agent against a scratch state directory
cargo run -p tpmd -- serve --state-dir /tmp/tpmd-demo

# terminal 2 — run the toy life-cycle
cargo run -p tpmd-demo -- --state-dir /tmp/tpmd-demo run
```

See [`docs/demo.md`](docs/demo.md) for the full walk-through, including the
Windows commands.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
