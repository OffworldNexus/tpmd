#!/usr/bin/env python3
"""Keep the newest nightlies in the APT repository and delete the rest.

    CLOUDSMITH_API_KEY=… packaging/deb/prune-nightlies.py [--keep 7] [--dry-run]

The policy is about *versions*: a nightly is every file published under one
version — the daemon, each backend, every architecture and the source package —
and it is kept or deleted whole, so the repository never serves half of one.
Only versions that say they are nightlies (`~nightly` in the version) are ever
considered; a stable release is kept for ever, whatever this is told.

Cloudsmith's own retention rule is deliberately not used: it counts *files*, so
"seven nightlies" would be a number that changes with every package and
architecture added, and it cannot tell a complete version from one that only
half-published. The workflow runs this after a nightly has installed cleanly on
every release, so a broken build never pushes a good one out.

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
import urllib.request

API = "https://api.cloudsmith.io/v1"
NIGHTLY_MARKER = "~nightly"


def request(method: str, url: str, key: str) -> tuple[int, bytes]:
    """One API call; the status is returned rather than raised for DELETE."""
    req = urllib.request.Request(url, method=method, headers={"X-Api-Key": key})
    with urllib.request.urlopen(req, timeout=60) as response:
        return response.status, response.read()


def packages(owner: str, repo: str, key: str) -> list[dict]:
    """Every package in the repository, across all pages."""
    found: list[dict] = []
    page = 1
    while True:
        url = f"{API}/packages/{owner}/{repo}/?page={page}&page_size=250"
        try:
            _, body = request("GET", url, key)
        except urllib.error.HTTPError as error:
            # Past the last page the API answers 404 rather than an empty list.
            if error.code == 404 and page > 1:
                break
            raise
        batch = json.loads(body)
        if not batch:
            break
        found.extend(batch)
        page += 1
    return found


def dpkg_order(left: str, right: str) -> int:
    """Debian version order, from dpkg itself rather than a reimplementation:
    `~` sorts before everything, which is the whole reason a nightly sorts below
    the release it precedes, and no string sort gets that right."""
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

    owner = os.environ.get("CLOUDSMITH_OWNER", "offworld-nexus")
    repo = os.environ.get("CLOUDSMITH_REPO", "apt")
    key = os.environ.get("CLOUDSMITH_API_KEY", "")
    if not key:
        print("prune-nightlies: CLOUDSMITH_API_KEY is not set", file=sys.stderr)
        return 1

    by_version: dict[str, list[dict]] = {}
    for package in packages(owner, repo, key):
        if NIGHTLY_MARKER in package["version"]:
            by_version.setdefault(package["version"], []).append(package)

    newest_first = sorted(by_version, key=functools.cmp_to_key(dpkg_order), reverse=True)
    kept, doomed = newest_first[: args.keep], newest_first[args.keep :]

    for version in kept:
        print(f"keep    {version} ({len(by_version[version])} files)")
    failures = 0
    for version in doomed:
        for package in by_version[version]:
            label = f"{package['filename']}"
            if args.dry_run:
                print(f"would delete {label}")
                continue
            try:
                request("DELETE", f"{API}/packages/{owner}/{repo}/{package['slug_perm']}/", key)
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
