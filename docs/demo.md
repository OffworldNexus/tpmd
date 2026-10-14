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
2. the `sealed` floor being enforced: refused by the dummy, already met on a
   machine with a usable TPM;
3. a key provisioned at the strongest level the selected backend offers — `file`
   for the dummy, `sealed`/`hardware` on a TPM — and its fingerprint;
4. the public key enrolled with a simulated relay;
5. a Tunnel Weaver-style transcript signed and verified, a mutated transcript
   rejected, and a second signature checked (deterministic on a software
   signer, fresh-nonce and still valid on hardware);
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
| `provision` | Create a key at the strongest level available (with consent) and print its fingerprint. |
| `sign <fingerprint> <message>` | Sign a UTF-8 message; print the 64-byte `r‖s` hex. |
| `describe <fingerprint>` | Print a key's metadata (algorithm, level, creation time). |
| `destroy <fingerprint>` | Destroy a key permanently. |
| `status` | Print the daemon status for this namespace. |
| `errors` | Show an unreachable agent, an enforced floor and an unknown key. |

## Choosing a backend

The daemon compiles in every backend supported on this OS and picks the
strongest one that actually works here (the dummy is the guaranteed fallback).

```sh
# see what was chosen and what the machine can reach
cargo run -p tpmd -- serve --state-dir /tmp/tpmd-demo          # auto-selects
cargo run -p tpmd-demo -- status

# force one; an unbuilt or unusable backend is refused with a clear reason
cargo run -p tpmd -- serve --backend linux-tpm --state-dir /tmp/tpmd-demo
cargo run -p tpmd -- serve --backend dummy --state-dir /tmp/tpmd-demo
```

On Linux the TPM backend reaches `sealed` and `hardware`; opening
`/dev/tpmrm*` needs the `tss` group (or a udev `uaccess` rule), so run the
agent as `tss`/root or add yourself to that group. `TPMD_TPM_DEVICE` overrides
which device node is used.

The shortest way to exercise the TPM backend without becoming root yourself is
to let the toy start the agent under `sudo`:

```sh
cargo run -p tpmd-demo -- run --sudo     # Linux only
```

The daemon runs as root (so it can open the TPM) while the client stays your
own user, so the key is scoped to *your* principal. The socket is mode `0666`
in that case, which is why the unprivileged client can still connect. When the
toy stops the agent it sends `SIGTERM` through `sudo`, so no root daemon is
left behind.

The agent is started in a **detached session** (`setsid`), so `sudo` never takes
over your terminal — without it, `sudo` writes a stray NUL and clears `ONLCR`,
leaving your terminal printing a staircase. A detached session has no
controlling terminal, so `sudo` cannot prompt: `--sudo` expects passwordless
`sudo` (or a recently cached credential).

`--system` runs the shared daemon: the endpoint becomes `/run/tpmd.sock`
(mode `0666`), the state directory `/var/lib/tpmd`, and mode defaults to
system when the effective uid is 0. `--user` forces the per-user endpoint even
as root.

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
