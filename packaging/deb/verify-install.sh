#!/bin/sh
#
# Check the package the way a user meets it: a clean container of each
# supported release, the repository (or local pre-publish artifacts) set up as
# documented, `apt install`, and an agent that actually runs there.
#
#   packaging/deb/verify-install.sh [image...]
#
# Images default to every currently supported Debian-like release. Requires
# docker and network access. Each release is a separate clean container, so a
# failure names the release it happened on, which is the point: one artifact is
# published for all of them, and this is what proves that claim.
#
# Modes:
#   - Live repository (default): configures `${OFFWORLD_APT_URL:-https://apt.offworld-nexus.app}`
#     with `Types: deb deb-src`, `Suites: any-distro`, `Components: ${TPMD_VERIFY_COMPONENT:-main}`,
#     installs `tpmd` (bringing the recommended backend plugin packages), and
#     fetches + checks the matching source package via `apt-get source`.
#   - Local pre-publish gate (`TPMD_DEB=dist/tpmd_..._amd64.deb`, optional
#     `TPMD_DSC=dist/tpmd_....dsc`): installs the built `.deb` set directly in
#     each release container before staging `offworld-dist`, and verifies the
#     `.dsc` unpacks cleanly with `dpkg-source -x`.

set -eu

apt_url=${OFFWORLD_APT_URL:-https://apt.offworld-nexus.app}
apt_url=${apt_url%/}
component=${TPMD_VERIFY_COMPONENT:-main}

deb=${TPMD_DEB:-}
dsc=${TPMD_DSC:-}
mount=""
if [ -n "$deb" ]; then
	[ -f "$deb" ] || { printf 'verify-install.sh: no such package: %s\n' "$deb" >&2; exit 1; }
	deb="$(cd "$(dirname "$deb")" && pwd)/$(basename "$deb")"
	mount="-v $(dirname "$deb"):/debs:ro"
fi
if [ -n "$dsc" ]; then
	[ -f "$dsc" ] || { printf 'verify-install.sh: no such dsc: %s\n' "$dsc" >&2; exit 1; }
	dsc="$(cd "$(dirname "$dsc")" && pwd)/$(basename "$dsc")"
	mount="$mount -v $(dirname "$dsc"):/dscs:ro"
fi

images=${*:-"debian:12 debian:13 debian:sid ubuntu:22.04 ubuntu:24.04 ubuntu:26.04"}

failures=0

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

	if docker run --rm $mount \
		--env TPMD_DEB_NAME="${deb##*/}" \
		--env TPMD_DSC_NAME="${dsc##*/}" \
		--env OFFWORLD_APT_URL="$apt_url" \
		--env TPMD_VERIFY_COMPONENT="$component" \
		"$image" sh -eu -c '
		export DEBIAN_FRONTEND=noninteractive
		apt-get update -qq
		apt-get install -y -qq --no-install-recommends ca-certificates curl gnupg systemd >/dev/null

		# Step 1: install the package set — from local pre-publish artifacts when
		# named, or from the signed Offworld Nexus APT repository as documented.
		if [ -n "${TPMD_DEB_NAME:-}" ]; then
			apt-get install -y -qq /debs/*.deb >&2
		else
			install -d -m 0755 /etc/apt/keyrings
			curl -fsSL "${OFFWORLD_APT_URL}/keyring.gpg" \
				-o /etc/apt/keyrings/offworld-nexus.gpg
			cat >/etc/apt/sources.list.d/offworld-nexus.sources <<EOF
Types: deb deb-src
URIs: ${OFFWORLD_APT_URL}
Suites: any-distro
Components: ${TPMD_VERIFY_COMPONENT}
Signed-By: /etc/apt/keyrings/offworld-nexus.gpg
EOF
			apt-get update -qq
			apt-get install -y -qq tpmd >&2
		fi

		# Step 1b: the split. Both recommended backend plugin packages arrive
		# with `tpmd`, and `tpmd` itself carries neither plugin.
		dpkg -s tpmd-backend-keyring tpmd-backend-linux-tpm >/dev/null
		for so in libtpmd_backend_keyring_plugin.so libtpmd_backend_linux_tpm_plugin.so; do
			[ -f "/usr/lib/tpmd/backends/$so" ] || { echo "missing plugin: $so" >&2; exit 1; }
		done
		if dpkg -L tpmd | grep -q "^/usr/lib/tpmd/backends/"; then
			echo "tpmd still ships a backend plugin" >&2
			exit 1
		fi

		# Step 2: the binaries run on this release at all.
		tpmd --version

		# Step 3: systemd unit verification (`systemd-analyze verify` exits 0 on
		# unknown keys, so inspect its output explicitly).
		for unit in $(dpkg -L tpmd | grep -E "systemd/system/tpmd\.(service|socket)$"); do
			systemd-analyze verify "$unit" 2>&1 | tee /tmp/unit.txt
			! grep -qE "Unknown (key|lvalue) name" /tmp/unit.txt
		done

		# Step 3b: the service user exists.
		getent passwd tss >/dev/null

		# Step 4: daemon serves on the built-in dummy backend.
		tpmd serve --backend dummy --min-key-security file \
			--socket /tmp/verify.sock --state-dir /tmp/verify-state &
		pid=$!
		for _ in $(seq 1 50); do
			[ -S /tmp/verify.sock ] && break
			sleep 0.1
		done
		tpmd status --socket /tmp/verify.sock
		kill "$pid"
		wait "$pid" 2>/dev/null || true

		# Step 4b: plugin backend loads and runs on its isolated runtime.
		export TPMD_STATE_DIR=/tmp/verify-split
		tpmd serve --backend keyring --min-key-security file \
			--socket /tmp/verify-split.sock &
		splitpid=$!
		for _ in $(seq 1 50); do
			[ -S /tmp/verify-split.sock ] && break
			sleep 0.1
		done
		tpmd status --socket /tmp/verify-split.sock
		tpmd status --socket /tmp/verify-split.sock | grep -q "^backend *: keyring" \
			|| { echo "the keyring plugin was not loaded" >&2; exit 1; }
		kill "$splitpid"
		wait "$splitpid" 2>/dev/null || true

		# Step 4c: removing one backend plugin package removes only that rung.
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
		tpmd status --socket /tmp/verify-after.sock | grep -q "^backend *: dummy" \
			|| { echo "the daemon did not keep serving after a backend was removed" >&2; exit 1; }
		kill "$afterpid"
		wait "$afterpid" 2>/dev/null || true
		unset TPMD_STATE_DIR

		# Step 6: source package completeness — via `dpkg-source -x` when checking
		# local pre-publish artifacts, or via `apt-get source` from the live
		# signed repository.
		installed=$(dpkg-query -W -f="\${Version}" tpmd)
		if [ -n "${TPMD_DSC_NAME:-}" ]; then
			apt-get install -y -qq --no-install-recommends dpkg-dev xz-utils >/dev/null
			mkdir -p /tmp/verify-source
			dpkg-source -x "/dscs/${TPMD_DSC_NAME}" /tmp/verify-source/unpacked >&2
			unpacked=/tmp/verify-source/unpacked
		elif [ -z "${TPMD_DEB_NAME:-}" ]; then
			apt-get install -y -qq --no-install-recommends dpkg-dev xz-utils >/dev/null
			mkdir -p /tmp/verify-source
			( cd /tmp/verify-source && apt-get source -qq "tpmd=$installed" >&2 )
			unpacked=$(find /tmp/verify-source -mindepth 1 -maxdepth 1 -type d | head -1)
		else
			unpacked=""
		fi
		if [ -n "$unpacked" ]; then
			[ "$(cd "$unpacked" && dpkg-parsechangelog -SVersion)" = "$installed" ] \
				|| { echo "the source is not the version that was installed" >&2; exit 1; }
			for member in Cargo.lock debian/rules vendor; do
				[ -e "$unpacked/$member" ] || { echo "the source has no $member" >&2; exit 1; }
			done
		fi

		# Step 5: package removal preserves `/var/lib/tpmd`.
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
