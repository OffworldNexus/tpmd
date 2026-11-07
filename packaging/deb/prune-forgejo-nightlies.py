#!/usr/bin/env python3
"""Keep the newest nightlies on the Forgejo mirror and delete the rest.

    FORGEJO_PACKAGES_TOKEN=… packaging/deb/prune-forgejo-nightlies.py [--keep 7] [--dry-run]

The same policy as prune-nightlies.py, applied to the second repository: a
nightly is every package published under one version and is kept or deleted
whole, so the mirror never serves half of one. Only versions that say they are
nightlies (`~nightly` in the version) are considered; a stable release is kept
for ever, whatever this is told. The token needs `write:package` on the owner.

The listing comes from the generic package API rather than the Debian one: it
returns one row per package name and version whatever distribution, component
or architecture its files belong to, which is exactly the "whole version" the
policy is about. The delete is the same API, and removes the version from every
channel at once.

Standard library only, so it runs on a bare CI runner.
"""

from __future__ import annotations

import argparse
import functools
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

# The instance's default_max_response_items, so a nightly's three packages per
# architecture do not spread over more pages than they have to.
PAGE_SIZE = 50
NIGHTLY_MARKER = "~nightly"


def request(method: str, url: str, token: str) -> tuple[int, bytes]:
    """One API call; the body is returned and an HTTP error is raised, so the
    caller decides whether a 404 is a problem (for a delete, it is)."""
    req = urllib.request.Request(
        url, method=method, headers={"Authorization": f"token {token}"}
    )
    with urllib.request.urlopen(req, timeout=60) as response:
        return response.status, response.read()


def packages(base: str, owner: str, token: str) -> list[dict]:
    """Every Debian package of the owner, across all pages."""
    found: list[dict] = []
    page = 1
    while True:
        url = (
            f"{base}/api/v1/packages/{urllib.parse.quote(owner)}"
            f"?type=debian&page={page}&limit={PAGE_SIZE}"
        )
        _, body = request("GET", url, token)
        batch = json.loads(body)
        if not batch:
            break
        found.extend(batch)
        page += 1
    return found


def dpkg_order(left: str, right: str) -> int:
    """Debian version order, from dpkg itself rather than a reimplementation:
    `~` sorts before everything, and no string sort gets that right."""
    if left == right:
        return 0
    lower = subprocess.run(
        ["dpkg", "--compare-versions", left, "lt", right], check=False
    ).returncode == 0
    return -1 if lower else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--keep", type=int, default=7, help="nightly versions to keep")
    parser.add_argument("--dry-run", action="store_true", help="report, delete nothing")
    args = parser.parse_args()
    if args.keep < 1:
        parser.error("--keep must be at least 1: the newest nightly is what users run")

    base = os.environ.get("FORGEJO_URL", "https://forge.offworld.nexus").rstrip("/")
    owner = os.environ.get("FORGEJO_OWNER", "OffworldNexus")
    token = os.environ.get("FORGEJO_PACKAGES_TOKEN", "")
    if not token:
        print("prune-forgejo-nightlies: FORGEJO_PACKAGES_TOKEN is not set", file=sys.stderr)
        return 1

    by_version: dict[str, list[dict]] = {}
    for package in packages(base, owner, token):
        if package.get("type") != "debian":
            continue
        if NIGHTLY_MARKER in package["version"]:
            by_version.setdefault(package["version"], []).append(package)

    newest_first = sorted(by_version, key=functools.cmp_to_key(dpkg_order), reverse=True)
    kept, doomed = newest_first[: args.keep], newest_first[args.keep :]

    for version in kept:
        print(f"keep    {version} ({len(by_version[version])} packages)")
    failures = 0
    for version in doomed:
        for package in by_version[version]:
            label = f"{package['name']} {version}"
            # The version goes in whole, percent-encoded: a nightly carries a
            # `+`, and a raw one in a path is asking for an encoding argument.
            url = (
                f"{base}/api/v1/packages/{urllib.parse.quote(owner)}/debian"
                f"/{urllib.parse.quote(package['name'])}"
                f"/{urllib.parse.quote(package['version'], safe='')}"
            )
            if args.dry_run:
                print(f"would delete {label}")
                continue
            try:
                request("DELETE", url, token)
                print(f"deleted {label}")
            except urllib.error.HTTPError as error:
                print(f"FAILED  {label}: HTTP {error.code}", file=sys.stderr)
                failures += 1
    print(
        f"{len(kept)} nightly version(s) kept, {len(doomed)} "
        f"{'would be ' if args.dry_run else ''}deleted"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
