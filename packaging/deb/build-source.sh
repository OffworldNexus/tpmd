#!/bin/sh
#
# Build the tpmd Debian source package from a commit.
#
#   packaging/deb/build-source.sh [output-dir]
#
# Produces tpmd_<version>.dsc and tpmd_<version>.tar.xz, the pair the
# repository publishes next to the binaries and that `apt-get source tpmd`
# fetches. Run it inside the pinned container (packaging/deb/Dockerfile), like
# build-deb.sh, which builds the published binaries *from* this source package.
#
# Environment:
#   TPMD_DEB_VERSION  full Debian version to stamp. Defaults to whatever the
#                     committed changelog says.
#   TPMD_DEB_DIST     suite recorded in the stamp. Defaults to "unstable".
#   TPMD_DEB_COMMIT   commit recorded in the stamp. Defaults to git HEAD.
#   TPMD_DEB_TREE     what to package. Defaults to HEAD; any tree-ish git
#                     accepts, e.g. the working tree's, to try a change before
#                     committing it:
#                       TPMD_DEB_TREE=$(GIT_INDEX_FILE=$(mktemp -u) sh -c \
#                         'git add -A && git write-tree')
#
# What the source contains is a *commit*, not the working tree: it is a
# `git archive`, so nothing ignored, built or uncommitted can leak into a
# published tarball.
#
# It is self-contained. Every crate the workspace depends on is vendored into
# `vendor/`, and debian/rules builds offline from there whenever that directory
# exists, so the source rebuilds the binaries without the network. It is one
# native tarball rather than an upstream tarball plus a vendor component, because
# the repository rejects multi-component source packages.

set -eu

out=${1:-dist}
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"

if [ ! -f debian/changelog ]; then
	printf 'build-source.sh: run me from a tpmd checkout\n' >&2
	exit 1
fi

mkdir -p "$out"
out=$(cd "$out" && pwd)

version=${TPMD_DEB_VERSION:-$(dpkg-parsechangelog -SVersion)}
dist=${TPMD_DEB_DIST:-unstable}
commit=${TPMD_DEB_COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
tree="$work/tpmd"
mkdir "$tree"
git archive --format=tar "${TPMD_DEB_TREE:-HEAD}" | tar -x -C "$tree"
cd "$tree"

if [ "$version" != "$(dpkg-parsechangelog -SVersion)" ]; then
	# Read before the redirection, never inside it: inside, the file the
	# substitution reads is the one the redirection has already truncated, so the
	# maintainer comes out empty and the trailer is written as " --   <date>",
	# which dpkg refuses to parse.
	maintainer=$(dpkg-parsechangelog -SMaintainer)
	built_on=$(date -R)
	committed=$(cat debian/changelog)
	{
		printf 'tpmd (%s) %s; urgency=medium\n\n' "$version" "$dist"
		printf '  * Automated build of commit %s.\n\n' "$commit"
		printf ' -- %s  %s\n\n' "$maintainer" "$built_on"
		printf '%s\n' "$committed"
	} > debian/changelog

	# `dpkg-parsechangelog` warns on stderr and still exits 0, and those warnings
	# are what lintian turns into a failed package, so they are what is checked.
	warnings=$(dpkg-parsechangelog -SVersion 2>&1 >/dev/null) || {
		printf 'build-source.sh: the generated changelog entry cannot be parsed:\n%s\n' \
			"$warnings" >&2
		exit 1
	}
	if [ -n "$warnings" ]; then
		printf 'build-source.sh: the generated changelog entry is malformed:\n%s\n' \
			"$warnings" >&2
		exit 1
	fi
fi

printf 'vendoring the dependencies of tpmd %s\n' "$version"
cargo vendor --locked --quiet vendor > /dev/null

# dpkg-source drops its default ignore list from a native tarball whatever it is
# told — `*.a`, `*.so`, `.gitignore` and the like — and some vendored crates ship
# exactly those, listed file by file in the `.cargo-checksum.json` cargo checks
# before building: the source would then refuse to build anywhere. So each crate
# keeps the checksum that ties it to Cargo.lock and loses its per-file list,
# which is what Debian's own Rust packaging does. Integrity of the files is the
# .dsc's job, and the repository's signature over it. None of what is dropped is
# built on Linux; the binaries build-deb.sh makes from this source prove it.
for sum in vendor/*/.cargo-checksum.json; do
	sed -i 's/"files":{[^}]*}/"files":{}/' "$sum"
	grep -q '"files":{}' "$sum" || {
		printf 'build-source.sh: cannot rewrite %s\n' "$sum" >&2
		exit 1
	}
done

# With no per-file list to satisfy, what is not a build input can go, and two
# kinds are worth removing rather than shipping: each crate's `Cargo.toml.orig`
# (the manifest before cargo normalised it, which lintian reads as a patch
# failure and dh_clean deletes anyway) and prebuilt Windows binaries kept as test
# fixtures, which a source package should not carry.
find vendor -name Cargo.toml.orig -delete
find vendor \( -iname '*.dll' -o -iname '*.exe' -o -iname '*.lib' \) -delete

cd "$work"
printf 'building the source package of tpmd %s\n' "$version"
dpkg-source --build tpmd

mv "$work"/tpmd_*.dsc "$work"/tpmd_*.tar.* "$out"/
printf 'artifacts:\n'
ls -l "$out"/tpmd_*.dsc "$out"/tpmd_*.tar.*
