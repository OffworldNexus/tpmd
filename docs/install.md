# Installing tpmd

`tpmd` is published as Debian packages from a signed APT repository, two
channels deep, built nightly for every currently supported Debian-like
release. One artifact per architecture serves them all: the daemon's only
runtime dependency is glibc, so a single build installs and runs from Debian
12 through sid and from Ubuntu 22.04 through 26.04.

The published set is the agent plus one package per backend above the built-in
floor. Installing `tpmd` brings the whole ladder with it — the backend
packages are recommended rather than required, so
`apt-get install --no-install-recommends tpmd` gives the agent alone, which
serves at `file` and refuses what it cannot protect.

## Install

```sh
curl -1sLf 'https://dl.cloudsmith.io/public/offworld-nexus/apt/cfg/setup/bash.deb.sh' | sudo -E bash
sudo apt-get update
sudo apt-get install tpmd
```

The first line adds the repository and its signing key. The second installs the
system agent, enables it and starts it.

<a href="https://cloudsmith.com"><img alt="OSS hosting by cloudsmith" src="https://img.shields.io/badge/OSS%20hosting%20by-cloudsmith-blue?logo=cloudsmith&style=flat-square"></a>

Package repository hosting is graciously provided by [Cloudsmith](https://cloudsmith.com),
the only fully hosted, cloud-native, universal package management solution.

Then ask it what it can do:

```sh
tpmd status
tpmd backend show
```

On a machine with a usable TPM the daemon reaches `sealed` or `hardware`. On a
machine without one it still starts — and refuses key operations rather than
handing out a weaker key than it was asked for. That distinction is the point of
the daemon, so it is worth understanding before changing anything; see
[Security floor](#security-floor).

## What gets installed

| Path | What it is |
| --- | --- |
| `/usr/bin/tpmd` | the agent |
| `/usr/lib/systemd/system/tpmd.socket` | the listening socket |
| `/usr/lib/systemd/system/tpmd.service` | the agent |
| `/etc/default/tpmd` | configuration, read by the service |
| `/usr/lib/sysusers.d/tpmd.conf` | ensures the `tss` user exists |
| `/usr/lib/udev/rules.d/60-tpmd.rules` | gives `tss` access to `/dev/tpmrm*` |
| `/var/lib/tpmd/keys.sqlite` | the key store — **the device identity** |
| `/run/tpmd/tpmd.sock` | the endpoint clients connect to |
| `/usr/lib/tpmd/backends/*.so` | the backends above the floor, one file per backend package |

The last line is the split. `tpmd-backend-keyring` and
`tpmd-backend-linux-tpm` each own one shared object, and the agent loads
whatever it finds there when it starts: a machine that never installs one
simply has a shorter ladder, and removing one removes exactly that rung
without touching the agent's own files.

The socket is created by systemd (`tpmd.socket`), not by the daemon: it exists
before the service starts, so a client reaching a cold machine is answered once
the agent comes up instead of racing it. It is world-writable (`0666`) on
purpose — any local user may connect, and the daemon decides what each caller
may do from the kernel's peer credentials, which a client cannot forge.

The service runs as **`tss`**, the standard TPM access identity, and holds no
capabilities at all. It cannot see your home directory, has no network access
beyond local sockets, and can write only inside `/var/lib/tpmd`.

## Configuration

`/etc/default/tpmd` is the only configuration file, and it is a conffile: your
edits survive upgrades. Everything in it is commented out by default, because
the defaults are the intended configuration.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TPMD_STATE_DIR` | `/var/lib/tpmd` | where the key store lives |
| `TPMD_MIN_SECURITY` | `sealed` | the weakest custody the daemon will serve |
| `TPMD_TPM_DEVICE` | scan `/dev/tpmrm*` | pin one TPM device node |
| `RUST_LOG` | `warn,tpmd=info` | log filter; `RUST_LOG=info` also shows the storage layer |

After changing it:

```sh
sudo systemctl restart tpmd
```

## Security floor

Keys live at a level, weakest first:

| Level | What it means |
| --- | --- |
| `file` | the key is a plain row in the store: a copied file is a working identity |
| `keyring` | the key is in the OS credential store: a copy needs the user's password |
| `sealed` | the key is wrapped by the TPM: a copy is inert anywhere else |
| `hardware` | the key never leaves the TPM or the Secure Enclave, not even to sign |

`TPMD_MIN_SECURITY` is the floor. An operation below it is **refused**, with the
required and available levels in the error, rather than served at a level the
operator did not agree to. The daemon never re-keys a device to satisfy a
request, and never replaces a lost key with a weaker one.

A machine that cannot reach the floor is not broken and does not crash-loop: the
service starts, `tpmd status` reports what it achieved, and key operations fail
with an explicit reason. If you *want* that machine to serve at a lower level,
say so deliberately:

```sh
echo 'TPMD_MIN_SECURITY=file' | sudo tee -a /etc/default/tpmd
sudo systemctl restart tpmd
```

## User mode

The packaged service is the *system* agent: it serves every user of the machine.
An application that wants a private agent of its own can run one under its own
account instead, with its own store and its own socket:

```sh
tpmd serve --user
```

That agent binds `$XDG_RUNTIME_DIR/tpmd/tpmd.sock` (`0600`), keeps its store in
`$XDG_DATA_HOME/tpmd/`, and reads none of `/etc/default/tpmd`. Clients try the
per-user endpoint first and the system endpoint second, so both can exist
without either being configured.

## Upgrading and removing

Upgrades replace the binaries and restart the service; keys are untouched, and
an existing device identity keeps working across them, including across a
machine reboot.

```sh
sudo apt-get upgrade tpmd
```

Removing the package **keeps** the store, deliberately. A device identity is not
something that should disappear because a package was removed, and `apt purge`
does not remove it either:

```sh
sudo apt-get remove tpmd      # service stops, /var/lib/tpmd survives
sudo apt-get purge tpmd       # same: /var/lib/tpmd survives
```

To destroy the identity, say so explicitly — this is irreversible, and the
machine will have to pair again:

```sh
sudo rm -rf /var/lib/tpmd
```

## Checking an install by hand

The package ships the agent and nothing else — the commands below are all it
takes:

```sh
tpmd status              # listening, which backend, which level, store state
tpmd backend show        # what this machine chose and why
```

`tpmd-demo`, the toy consumer that walks a whole key life cycle, is a
development tool: it is built from the source tree and documented in
`docs/demo.md`, and it is deliberately not part of the package.

## Nightly and release versions

Every build is a version. Nightly builds are stamped
`0.1.0~nightly<YYYYMMDD>.r<run>+g<commit>`, and a tagged release is its bare
version (`0.1.0`). The tilde sorts nightlies *below* the release they lead to, so
the first tagged release supersedes every nightly that came before it and
`apt-get upgrade` does the right thing without argument. The run number is what
orders two nightlies of the same day; the commit hash alone would not.

**What the repository keeps.** Every stable release, for ever. Of the nightlies,
the newest seven *versions* — each one whole, every package and architecture and
its source together — and older ones are deleted once a newer nightly has
installed cleanly on every supported release. A nightly is therefore something
to upgrade from, not something to pin: `apt-get install tpmd=<version>` of a
nightly works for about a week. Pin a stable release instead.

A `v*` tag is a release, and the same pipeline builds it: the bare version, to
the `main` component, and — once every platform is packaging — the built
packages attached to a GitHub release for that tag. That release step is gated on
a repository variable (`RELEASE_ARTIFACTS_COMPLETE`), so a tag cannot mint a
release carrying a partial set; today it is unset, and a tag publishes to `main`
and stops there. Each platform's packaging workflow appends its own artifacts to
the same release, so the release becomes complete without any one workflow
having to know about the others.

To follow releases instead of nightlies, install and then hold:

```sh
sudo apt-mark hold tpmd
```

## Source packages

Every published version has its source package beside it, in the same channel:

```sh
apt-get source tpmd                # the newest one apt knows about
apt-get source tpmd=<version>      # the source of exactly what you installed
```

The setup script above already adds the `deb-src` line this needs. The source
is the commit the version was stamped from, plus every Rust dependency vendored
into `vendor/`, so it builds without the network. It is not a courtesy copy:
the published binaries are built *from* it, offline, so a source that could not
rebuild them would never have been published.

To rebuild from it, use the same pinned toolchain the binaries were built with
(see [below](#why-this-package-is-not-built-by-the-distribution) for why the
distribution's own `rustc` cannot), for instance:

```sh
docker build -f packaging/deb/Dockerfile -t tpmd-deb .
docker run --rm --network none --user "$(id -u):$(id -g)" \
  --env CARGO_HOME=/tmp/cargo-home --env TPMD_DEB_DSC=/tmp/src/tpmd_<version>.dsc \
  -v "$PWD:/tmp/src" -w /tmp/src/tpmd-<version> \
  tpmd-deb packaging/deb/build-deb.sh /tmp/src/dist
```

The vendored crates keep their checksum against `Cargo.lock` but not the
per-file lists cargo usually checks: `dpkg-source` leaves files such as `*.a`
and `.gitignore` out of a source tarball whatever it is told, and Debian's own
Rust packaging drops those lists for the same reason. The tarball as a whole is
covered by the `.dsc`'s checksums, which the repository signs.

## Building the package yourself

```sh
docker build -f packaging/deb/Dockerfile -t tpmd-deb .
docker run --rm --user "$(id -u):$(id -g)" --env CARGO_HOME=/tmp/cargo-home \
  -v "$PWD:/tmp/src" -w /tmp/src tpmd-deb packaging/deb/build-deb.sh dist
```

`--user` keeps the build from writing files your account cannot remove
afterwards. The script builds the source package from the current commit first
(`packaging/deb/build-source.sh`) and then the binaries from that source
package, exactly as the published ones are; everything lands in `dist/`.

The build runs in the *oldest* supported release (`ubuntu:22.04`) because
whatever glibc it compiles against becomes the floor for the published binary.
`packaging/deb/verify-install.sh` then installs the result from the published
repository inside a clean container per supported release and walks the whole
life cycle on each.

## Why this package is not built by the distribution

The Debian Rust Team's policy asks for a package whose Rust code is compiled
during the build, against the distribution's own `rustc`, with dependencies
taken from packaged crate sources. That is not possible here, and it is worth
being plain about why:

* `Cargo.toml` declares `rust-version = "1.94"` and uses edition 2024. Edition
  2024 alone needs rustc 1.85; 1.94 is the true floor, and it belongs to the
  store's dependencies (`sea-orm`, `sqlx`) rather than to our own code.
* Every currently supported release ships an older compiler than that floor:
  Debian 12 has 1.63, Ubuntu 22.04 has 1.66, Ubuntu 24.04 has 1.75, and Debian 13
  and Ubuntu 26.04 have 1.85 — which builds neither this workspace nor the
  RustCrypto stack it depends on.
* So a build-dependency on the toolchain could not be satisfied on any target,
  and the binaries are built in a pinned container instead
  (`packaging/deb/Dockerfile`), against a pinned toolchain.

What that costs: the published binary is trusted on our signature and the
repository's, not on the distribution's build reproducibility. Two consequences
worth naming: the binary is stripped at build time by the workspace's release
profile, and no `-dbgsym` package is published, because a separate
debug-symbol repository is an archive convention and this repository is not an
archive.

What it does not
change: the packaging itself follows the policy in shape — `debian/rules`, the
control fields, a DEP-5 `debian/copyright`, the debhelper systemd integration,
`/etc/default`, man pages, and a package that is lintian-clean. An upload to the
Debian archive would be blocked on the toolchain floor, not on a rewrite.
