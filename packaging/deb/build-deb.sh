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
	# Read before the redirection, never inside it. Inside, the file the
	# substitution reads is the one the redirection has already truncated, so the
	# maintainer comes out empty and the trailer is written as " --   <date>": a
	# malformed entry that lintian rejects as "badly formatted trailer line" and
	# that dpkg refuses to parse. It is invisible in the tree, because the trap
	# below restores the file the moment the build ends — the only copy of what a
	# package was stamped with is inside the package.
	maintainer=$(dpkg-parsechangelog -SMaintainer)
	built_on=$(date -R)
	{
		printf 'tpmd (%s) %s; urgency=medium\n\n' "$version" "$dist"
		printf '  * Automated build of commit %s.\n\n' "$commit"
		printf ' -- %s  %s\n\n' "$maintainer" "$built_on"
		cat "$backup"
	} > debian/changelog

	# So check what was written. A nightly is the first build that has a generated
	# entry at all — a release stamps the version already in the changelog and
	# generates nothing — which is exactly why this went unnoticed: the entry only
	# ever appears in a package nobody parses by hand.
	#
	# `dpkg-parsechangelog` warns on stderr and still exits 0, and those warnings
	# are what lintian turns into a failed package, so they are what is checked.
	warnings=$(dpkg-parsechangelog -SVersion 2>&1 >/dev/null) || {
		printf 'build-deb.sh: the generated changelog entry cannot be parsed:\n%s\n' \
			"$warnings" >&2
		exit 1
	}
	if [ -n "$warnings" ]; then
		printf 'build-deb.sh: the generated changelog entry is malformed:\n%s\n' \
			"$warnings" >&2
		exit 1
	fi
fi

printf 'building tpmd %s for %s\n' "$version" "$(dpkg-architecture -qDEB_HOST_ARCH)"

# Binary only: nothing here is uploaded to the archive, so no source package is
# produced and no orig tarball is needed.
dpkg-buildpackage --build=binary --no-sign --unsigned-source

# The binaries land next to the source tree, which is dpkg's convention and not
# ours; collect them where the caller asked.
find .. -maxdepth 1 -name 'tpmd_*.deb' -exec mv {} "$out" \;

printf 'artifacts:\n'
ls -l "$out"
