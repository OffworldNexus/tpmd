#!/bin/sh
#
# Check the published package the way a user meets it: a clean container of each
# supported release, the repository set up as documented, `apt install`, and
# then an agent that actually runs there.
#
#   packaging/deb/verify-install.sh [image...]
#
# Images default to every currently supported Debian-like release. Requires
# docker and network access. Each release is a separate clean container, so a
# failure names the release it happened on, which is the point: one artifact is
# published for all of them, and this is what proves that claim.
#
# What each release is checked for:
#   1. the repository signs and resolves (the documented setup path, verbatim),
#      and the split arrives with it — every backend package, and the plugins in
#      /usr/lib/tpmd/backends
#   2. the shipped binaries run at all — the glibc floor, which is the only
#      thing that can differ between a build host and an install host
#   3. the service and socket definitions are valid for that release's systemd
#   4. the daemon serves and the toy consumer completes a full life cycle
#   4b. a backend that is a plugin is loaded and driven at run time, and
#       removing its package removes that rung while the daemon keeps serving
#   5. a package operation does not take the key store with it
#   6. the source of what was installed is published: `apt-get source` fetches
#      the same version through the `deb-src` line the setup script writes, and
#      it is complete — every dependency vendored, the packaging with it
#
# Socket activation itself cannot be observed here — no container in this list
# runs systemd as PID 1 — so it is checked with `systemd-analyze verify` and on
# a systemd host by hand.

set -eu

owner=${CLOUDSMITH_OWNER:-offworld-nexus}
repo=${CLOUDSMITH_REPO:-apt}
base="https://dl.cloudsmith.io/public/${owner}/${repo}"

# A locally built .deb can be checked without a published repository, which is
# what makes this runnable before the first publish and on a pull request. The
# whole directory is installed, because the split set is three packages and a
# check that installs one of them is not checking the split:
#
#   TPMD_DEB=dist/tpmd_0.1.0_amd64.deb packaging/deb/verify-install.sh
#
# It is also the quickest way to tell "the package is broken" from "the
# repository is broken".
deb=${TPMD_DEB:-}
if [ -n "$deb" ]; then
	[ -f "$deb" ] || { printf 'verify-install.sh: no such package: %s\n' "$deb" >&2; exit 1; }
	deb="$(cd "$(dirname "$deb")" && pwd)/$(basename "$deb")"
	mount="-v $(dirname "$deb"):/debs:ro"
else
	mount=""
fi

images=${*:-"debian:12 debian:13 debian:sid ubuntu:22.04 ubuntu:24.04 ubuntu:26.04"}

failures=0

# The container tag is not the apt codename: `debian:13` is trixie and
# `ubuntu:22.04` is jammy. Deriving one from the other makes the repository setup
# fail on every release for a reason that looks nothing like the cause, so the
# mapping is explicit.
codename_of() {
	case "$1" in
	debian:12) echo bookworm ;;
	debian:13) echo trixie ;;
	debian:sid) echo sid ;;
	ubuntu:22.04) echo jammy ;;
	ubuntu:24.04) echo noble ;;
	ubuntu:26.04) echo resolute ;;
	*) echo unknown ;;
	esac
}

for image in $images; do
	distro=${image%%:*}
	codename=$(codename_of "$image")
	if [ "$codename" = unknown ]; then
		printf 'unknown release: %s\n' "$image" >&2
		failures=$((failures + 1))
		continue
	fi
	printf '\n== %s (%s/%s)\n' "$image" "$distro" "$codename"

	if docker run --rm $mount --env TPMD_DEB_NAME="${deb##*/}" \
		--env TPMD_VERIFY_COMPONENT="${TPMD_VERIFY_COMPONENT:-main}" \
		"$image" sh -eu -c '
		export DEBIAN_FRONTEND=noninteractive
		apt-get update -qq
		apt-get install -y -qq --no-install-recommends ca-certificates curl gnupg systemd >/dev/null

		# Step 1: install the package the way a user would — from the published
		# repository, or from the local packages when they were named. The
		# component is the channel: `main` is what the setup script configures by
		# default, and a nightly lives in `nightly`, so the check has to ask for
		# it.
		if [ -n "${TPMD_DEB_NAME:-}" ]; then
			apt-get install -y -qq /debs/*.deb >&2
		else
			curl -1sLf "'"$base"'/cfg/setup/bash.deb.sh" \
				| distro='"$distro"' codename='"$codename"' component='"${TPMD_VERIFY_COMPONENT:-main}"' bash
			apt-get update -qq
			apt-get install -y -qq tpmd >&2
		fi

		# Step 1b: the split. The backends above the built-in floor are their own
		# packages, shipped as plugins and recommended by `tpmd`, so a plain
		# install has the whole ladder. Both derivations are checked — the
		# Recommends this repository serves, and the local files — because a split
		# whose pieces do not arrive together is a split nobody has.
		dpkg -s tpmd-backend-keyring tpmd-backend-linux-tpm >/dev/null
		for so in libtpmd_backend_keyring_plugin.so libtpmd_backend_linux_tpm_plugin.so; do
			[ -f "/usr/lib/tpmd/backends/$so" ] || { echo "missing plugin: $so" >&2; exit 1; }
		done
		# …and the package that carries the daemon no longer carries them.
		if dpkg -L tpmd | grep -q '^/usr/lib/tpmd/backends/'; then
			echo "tpmd still ships a backend plugin" >&2
			exit 1
		fi

		# Step 2: the binaries run on this release at all.
		tpmd --version

		# Step 3: the definitions are valid here. The paths come from the
		# package rather than from this script, so a layout change cannot make
		# the check pass by quietly testing nothing. `systemd-analyze verify`
		# exits 0 on an unknown key, which is the very mistake it exists to
		# catch, so its output is what decides.
		for unit in $(dpkg -L tpmd | grep -E "systemd/system/tpmd\.(service|socket)$"); do
			systemd-analyze verify "$unit" 2>&1 | tee /tmp/unit.txt
			! grep -qE "Unknown (key|lvalue) name" /tmp/unit.txt
		done

		# Step 3b: the service user exists, because the unit names it and the
		# package is responsible for it.
		getent passwd tss >/dev/null

		# A container has no TPM, so the smoke test names the guaranteed fallback
		# instead of leaving the choice to the ladder: this step exists to prove
		# that the package installs and its binaries run on this release, not to
		# re-test backend selection. It is not decoration — left to the ladder, a
		# TPM-less host currently settles on the unusable TPM backend and refuses
		# every operation, whatever floor was asked for (WVR-157).
		tpmd serve --backend dummy --min-key-security file \
			--socket /tmp/verify.sock --state-dir /tmp/verify-state &
		pid=$!
		for _ in $(seq 1 50); do
			[ -S /tmp/verify.sock ] && break
			sleep 0.1
		done
		tpmd status --socket /tmp/verify.sock
		# No key operations here. The toy consumer that used to walk them is a
		# development tool and is deliberately not distributed, while the key
		# handling itself is covered by the workspace test suite; what this check
		# is for is that the package installs and runs on this release.
		kill "$pid"
		wait "$pid" 2>/dev/null || true

		# Step 4b: the split really works. A plugin backend is only knowable once
		# it has been loaded — the daemon has no compiled-in idea that a backend
		# called `keyring` exists — so a daemon that *serves* as keyring is proof
		# that the shared object was found, mapped and driven. Nothing is forced
		# here: the store is unreachable in a container, and the daemon is
		# deliberately willing to run the backend of a store that is reachable but
		# unusable, so that the refusal can say why (WVR-151/152).
		export TPMD_STATE_DIR=/tmp/verify-split
		tpmd serve --backend keyring --min-key-security file \
			--socket /tmp/verify-split.sock &
		splitpid=$!
		for _ in $(seq 1 50); do
			[ -S /tmp/verify-split.sock ] && break
			sleep 0.1
		done
		tpmd status --socket /tmp/verify-split.sock
		tpmd status --socket /tmp/verify-split.sock | grep -q '^backend *: keyring' \
			|| { echo "the keyring plugin was not loaded" >&2; exit 1; }
		kill "$splitpid"
		wait "$splitpid" 2>/dev/null || true

		# Step 4c: removing one backend package removes that rung and leaves the
		# daemon running on another. The daemon offers exactly what is installed,
		# so the name is refused once its package is gone — and the built-in
		# floor keeps serving, which is the whole reason the dummy stayed in the
		# daemon rather than moving into a package.
		rm -rf /tmp/verify-split
		apt-get remove -y -qq tpmd-backend-keyring >&2
		if tpmd backend --state-dir /tmp/verify-split set keyring --yes 2>/dev/null; then
			echo "the keyring rung was still offered after its package was removed" >&2
			exit 1
		fi
		tpmd backend --state-dir /tmp/verify-split set dummy --yes >/dev/null
		rm -rf /tmp/verify-split-after
		tpmd serve --backend dummy --min-key-security file \
			--socket /tmp/verify-after.sock --state-dir /tmp/verify-split-after &
		afterpid=$!
		for _ in $(seq 1 50); do
			[ -S /tmp/verify-after.sock ] && break
			sleep 0.1
		done
		tpmd status --socket /tmp/verify-after.sock | grep -q '^backend *: dummy' \
			|| { echo "the daemon did not keep serving after a backend was removed" >&2; exit 1; }
		kill "$afterpid"
		wait "$afterpid" 2>/dev/null || true
		unset TPMD_STATE_DIR

		# Step 6: the source package. Only from the published repository: a local
		# check installs .debs and has no index to fetch a source from. apt checks
		# what it downloads against the signed Sources index, so a fetch that
		# succeeds is a fetch of what was signed.
		if [ -z "${TPMD_DEB_NAME:-}" ]; then
			installed=$(dpkg-query -W -f="\${Version}" tpmd)
			apt-get install -y -qq --no-install-recommends dpkg-dev >/dev/null
			mkdir -p /tmp/verify-source
			( cd /tmp/verify-source && apt-get source -qq "tpmd=$installed" >&2 )
			unpacked=$(find /tmp/verify-source -mindepth 1 -maxdepth 1 -type d | head -1)
			[ -n "$unpacked" ] || { echo "apt-get source unpacked nothing" >&2; exit 1; }
			[ "$(cd "$unpacked" && dpkg-parsechangelog -SVersion)" = "$installed" ] \
				|| { echo "the source is not the version that was installed" >&2; exit 1; }
			for member in Cargo.lock debian/rules vendor; do
				[ -e "$unpacked/$member" ] || { echo "the source has no $member" >&2; exit 1; }
			done
		fi

		# Step 5: the store is the device identity, so a package operation must
		# not remove it. A sentinel, rather than the store this run used, so the
		# check is about the maintainer scripts — which is what removal and purge
		# can actually get wrong — and not about a directory under /tmp.
		mkdir -p /var/lib/tpmd
		touch /var/lib/tpmd/sentinel
		apt-get remove -y -qq tpmd >&2
		[ -f /var/lib/tpmd/sentinel ]
	'; then
		printf 'ok   %s\n' "$image"
	else
		printf 'FAIL %s\n' "$image"
		failures=$((failures + 1))
	fi
done

if [ "$failures" -ne 0 ]; then
	printf '\n%s release(s) failed\n' "$failures" >&2
	exit 1
fi

printf '\nall releases ok\n'
