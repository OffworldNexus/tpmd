#!/bin/sh
#
# Build the tpmd .deb for one architecture from this working tree.
#
#   packaging/deb/build-deb.sh [output-dir]
#
# Run it inside the pinned container (packaging/deb/Dockerfile), because the
# binary's floor is the glibc of whatever it is built against — see that file.
#
# Environment:
#   TPMD_DEB_VERSION  full Debian version to stamp. Defaults to whatever the
#                     committed changelog says.
#   TPMD_DEB_DIST     suite recorded in the stamp. Defaults to "unstable".
#   TPMD_DEB_COMMIT   commit recorded in the stamp. Defaults to git HEAD.
#
# The committed changelog is left exactly as it was found: a generated entry is
# prepended for the build and removed again on exit.

# The split build mode, turned on here and nowhere else: the daemon is built
# with `loadable-backends` (so it loads its backends from /usr/lib/tpmd/backends
# rather than linking them in) and one shared object is built per backend
# package. A plain `cargo build` asks for neither, which is what keeps the normal
# build the monolith it has always been. See debian/rules.
TPMD_DEB_SPLIT=1
export TPMD_DEB_SPLIT

set -eu

out=${1:-dist}
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"

if [ ! -f debian/changelog ]; then
	printf 'build-deb.sh: run me from a tpmd checkout\n' >&2
	exit 1
fi

mkdir -p "$out"
out=$(cd "$out" && pwd)

version=${TPMD_DEB_VERSION:-$(dpkg-parsechangelog -SVersion)}
dist=${TPMD_DEB_DIST:-unstable}
commit=${TPMD_DEB_COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}

# A generated entry is prepended rather than the committed one being rewritten,
# so the history survives in the built package's changelog. The backup lives
# outside debian/ on purpose: dh_clean removes `debian/*.orig` during the build,
# and a trap that then could not restore would fail the build under `set -e`.
backup=$(mktemp)
cp debian/changelog "$backup"
restore() { cp -f "$backup" debian/changelog || true; rm -f "$backup"; }
trap restore EXIT INT TERM

if [ "$version" != "$(dpkg-parsechangelog -SVersion)" ]; then
	{
		printf 'tpmd (%s) %s; urgency=medium\n\n' "$version" "$dist"
		printf '  * Automated build of commit %s.\n\n' "$commit"
		printf ' -- %s  %s\n\n' "$(dpkg-parsechangelog -SMaintainer)" "$(date -R)"
		cat "$backup"
	} > debian/changelog
fi

printf 'building tpmd %s for %s\n' "$version" "$(dpkg-architecture -qDEB_HOST_ARCH)"

# Binary only: nothing here is uploaded to the archive, so no source package is
# produced and no orig tarball is needed.
dpkg-buildpackage --build=binary --no-sign --unsigned-source

# The binaries land next to the source tree, which is dpkg's convention and not
# ours; collect them where the caller asked. The pattern covers every package in
# the set, not just the daemon: `tpmd_*` silently dropped the backend packages,
# which then never reached the repository while every check still passed.
find .. -maxdepth 1 -name 'tpmd*.deb' -exec mv {} "$out" \;

printf 'artifacts:\n'
ls -l "$out"
