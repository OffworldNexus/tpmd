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

## Dependency line

`tpmd` deliberately shares the Tunnel Weaver cryptographic line so signatures
produced by the agent verify with `weaver_mux::auth::verify` byte-for-byte:

- `p256 0.14` (ECDSA P-256 / SHA-256), `postcard 1.1`, `serde 1.0`,
  `thiserror 2.0`, `tokio 1.43`, `proptest 1.11`, `cargo-deny` configuration.

## Scope

WVR-140 implements the **dummy** engine and the complete consumer contract
only. The keyring, Linux TPM, Windows CNG and macOS Secure Enclave backends
are sibling tickets, as are packaging and distribution.
