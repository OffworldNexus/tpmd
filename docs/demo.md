# Running the toy

`tpmd-demo` is a toy consumer that walks the whole key life-cycle Tunnel
Weaver needs, with a simulated relay. It only needs the `tpmd` agent and never
touches Tunnel Weaver or its infrastructure.

## The few-command happy path

The shortest path is a single command. `tpmd-demo run` is self-contained: it
starts the real `tpmd` binary (found next to the demo), does everything, and
stops it.

```sh
cargo build --workspace          # so target/debug/tpmd exists next to the demo
cargo run -p tpmd-demo -- run
```

It prints, in order:

1. the capability announce (algorithms, levels, encodings, principal);
2. the `sealed` floor correctly refusing the dummy store;
3. a key provisioned at `file` with explicit consent — and its fingerprint;
4. the public key enrolled with a simulated relay;
5. a Tunnel Weaver-style transcript signed and verified, a mutated transcript
   rejected, and deterministic re-signing;
6. an agent restart, after which the same identity is resumed;
7. a destroy followed by a fresh identity;
8. an unreachable agent after shutdown.

To point it at your own state directory:

```sh
cargo run -p tpmd-demo -- --state-dir /tmp/tpmd-demo run
```

## Running the agent and the toy separately

Two terminals, which is also the shape Tunnel Weaver will use:

```sh
# terminal 1 — the agent (its own state directory)
cargo run -p tpmd -- serve --state-dir /tmp/tpmd-demo

# terminal 2 — the toy
cargo run -p tpmd-demo -- provision          # prints a fingerprint
cargo run -p tpmd-demo -- describe <fingerprint>
cargo run -p tpmd-demo -- sign <fingerprint> "hello"
cargo run -p tpmd-demo -- status
cargo run -p tpmd-demo -- errors             # representative failures
```

By default the agent binds the per-user endpoint:

* Linux: `$XDG_RUNTIME_DIR/tpmd/tpmd.sock`
* macOS: `$TMPDIR/tpmd/tpmd.sock`
* Windows: `\\.\pipe\tpmd-<hash-of-your-SID>`

Use `--socket` (Unix) to override it. The client tries the per-user endpoint
first, then the Linux system endpoint `/run/tpmd.sock`.

## What each subcommand does

| Command | Effect |
| --- | --- |
| `run` | Full self-contained life-cycle, spawning and restarting the agent. |
| `probe` | Connect without a key and print the capability announce and status. |
| `provision` | Create a key at the `file` floor (with consent) and print its fingerprint. |
| `sign <fingerprint> <message>` | Sign a UTF-8 message; print the 64-byte `r‖s` hex. |
| `describe <fingerprint>` | Print a key's metadata (algorithm, level, creation time). |
| `destroy <fingerprint>` | Destroy a key permanently. |
| `status` | Print the daemon status for this namespace. |
| `errors` | Show an unreachable agent, a refused floor and an unknown key. |

## Verifying a signature by hand

The signature is standard ECDSA P-256 / SHA-256 over the SHA-256 of the
message, and the fingerprint is the SEC1-compressed public key, so any P-256
implementation verifies it — including Tunnel Weaver's `weaver_mux::auth::verify`.
The demo already proves this internally on every run by verifying with the
`p256` crate directly.

## Windows notes

The Windows build uses a named pipe instead of a Unix socket. The same
commands work; `--socket` is Unix-only, and the default endpoint is the
per-user pipe. Run the agent and the toy from the same user account.
