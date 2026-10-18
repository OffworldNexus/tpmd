#!/bin/sh
#
# Build the tpmd .debs for one architecture, from the source package.
#
#   packaging/deb/build-deb.sh [output-dir]
#
# Run it inside the pinned container (packaging/deb/Dockerfile), because the
# binary's floor is the glibc of whatever it is built against — see that file.
#
# Environment:
#   TPMD_DEB_DSC      the source package to build. Without it, one is built from
#                     the commit first (packaging/deb/build-source.sh) and left
#                     in the output directory beside the binaries.
#   TPMD_DEB_VERSION, TPMD_DEB_DIST, TPMD_DEB_COMMIT
#                     passed to build-source.sh when it runs; see there.
#
# The binaries are always built from the source package, never from the
# checkout, and offline: the source the repository publishes is then the source
# the published binaries were built from, and a source package that cannot
# rebuild them fails here instead of being published. The checkout is never
# written to — the build happens in a temporary directory.

set -eu

out=${1:-dist}
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"

mkdir -p "$out"
out=$(cd "$out" && pwd)

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

dsc=${TPMD_DEB_DSC:-}
if [ -z "$dsc" ]; then
	# The one this run built, not whichever .dsc an earlier run left behind.
	touch "$work/started"
	packaging/deb/build-source.sh "$out"
	dsc=$(find "$out" -maxdepth 1 -name 'tpmd_*.dsc' -newer "$work/started" | head -1)
	[ -n "$dsc" ] || { printf 'build-deb.sh: build-source.sh produced no .dsc\n' >&2; exit 1; }
fi
[ -f "$dsc" ] || { printf 'build-deb.sh: no such source package: %s\n' "$dsc" >&2; exit 1; }
dsc=$(cd "$(dirname "$dsc")" && pwd)/$(basename "$dsc")
dpkg-source --extract "$dsc" "$work/tpmd" > /dev/null
cd "$work/tpmd"

printf 'building tpmd %s for %s from %s\n' \
	"$(dpkg-parsechangelog -SVersion)" "$(dpkg-architecture -qDEB_HOST_ARCH)" "$(basename "$dsc")"

# The split is debian/rules' default, which is what makes the published source
# rebuild the published set; named here as well so this script never depends on
# a default it did not see. No network: everything the build needs is in the
# source package's vendor/, and a build that reached out would be one the
# published source cannot reproduce.
TPMD_DEB_SPLIT=1 CARGO_NET_OFFLINE=true \
	dpkg-buildpackage --build=binary --no-sign

# The binaries land next to the source tree, which is dpkg's convention and not
# ours; collect them where the caller asked. The pattern covers every package in
# the set, not just the daemon: `tpmd_*` silently dropped the backend packages,
# which then never reached the repository while every check still passed.
find "$work" -maxdepth 1 -name 'tpmd*.deb' -exec mv {} "$out" \;

printf 'artifacts:\n'
ls -l "$out"
