#!/usr/bin/env python3
"""Write the release notes for an automatically cut security patch.

    security-release-notes.py --deny-json /tmp/deny.json \
        --lock Cargo.lock --version 0.1.1 --output /tmp/release-notes.md

The input is the `cargo deny --format json check advisories` output taken
against the strict config (the one with every TEMPORARY ignore removed), so
the notes describe exactly the advisories the patch fixes. The old version
comes from the inclusion graph in that output, the new one from the updated
`Cargo.lock`; an advisory whose crate did not move is an error, because a
release that says "security" must not carry the same vulnerable version.

The first line is the release title used by the release workflow; the rest is
prepended to GitHub's generated notes (docs/releasing.md).

Standard library only (`tomllib` needs Python 3.11, which every GitHub runner
has), so it runs on a bare CI runner.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import tomllib


def graph_versions(node: object, found: dict[str, set[str]]) -> None:
    """Collect every `Krate` name/version in a cargo-deny inclusion graph."""
    if isinstance(node, dict):
        krate = node.get("Krate")
        if isinstance(krate, dict):
            name = krate.get("name")
            version = krate.get("version")
            if isinstance(name, str) and isinstance(version, str):
                found.setdefault(name, set()).add(version)
        for value in node.values():
            graph_versions(value, found)
    elif isinstance(node, list):
        for value in node:
            graph_versions(value, found)


def order(version: str) -> tuple:
    """A crude but sufficient Debian-ish ordering for the versions here."""
    parts = []
    for piece in version.split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits or 0))
    return tuple(parts)


def advisories(path: pathlib.Path) -> list[dict]:
    """The vulnerability diagnostics in a cargo-deny JSON stream."""
    fixed = []
    for line in path.read_text().splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        fields = event.get("fields", {})
        if event.get("type") != "diagnostic" or fields.get("code") != "vulnerability":
            continue
        advisory = fields.get("advisory", {})
        found: dict[str, set[str]] = {}
        graph_versions(fields.get("graphs", []), found)
        fixed.append(
            {
                "id": advisory.get("id", "RUSTSEC-unknown"),
                "title": advisory.get("title", "untitled advisory"),
                "package": advisory.get("package", "unknown"),
                "url": advisory.get("url"),
                "old": sorted(found.get(advisory.get("package"), set())),
            }
        )
    return fixed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--deny-json", required=True, type=pathlib.Path)
    parser.add_argument("--lock", required=True, type=pathlib.Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()

    vulnerabilities = advisories(args.deny_json)
    if not vulnerabilities:
        print("security-release-notes: the deny output has no vulnerabilities", file=sys.stderr)
        return 1

    lock = tomllib.loads(args.lock.read_text())
    installed: dict[str, list[str]] = {}
    for package in lock.get("package", []):
        installed.setdefault(package["name"], []).append(package["version"])

    lines = [
        f"tpmd {args.version} (security)",
        "",
        "This patch updates the dependencies tpmd carries and fixes whatever the",
        "upgrade broke. The workspace test suite and the packaging install matrix",
        "gate it.",
        "",
        "## Security",
        "",
    ]
    failures = 0
    for advisory in vulnerabilities:
        package = advisory["package"]
        old = advisory["old"][0] if advisory["old"] else "unknown"
        candidates = installed.get(package, [])
        new = max(candidates, key=order) if candidates else None
        if new is None or new == old:
            print(
                f"security-release-notes: {advisory['id']} is not fixed: "
                f"{package} is still {old}",
                file=sys.stderr,
            )
            failures += 1
            new = old
        link = f" ([advisory]({advisory['url']}))" if advisory.get("url") else ""
        lines.append(f"- **{advisory['id']}** — {advisory['title']}{link}.")
        lines.append(f"  `{package}` {old} → {new}.")
    if failures:
        return 1

    lines += [
        "",
        "## Upgrade",
        "",
        "```sh",
        "sudo apt-get update",
        "sudo apt-get install --only-upgrade tpmd",
        "```",
        "",
        "The Cloudsmith repository and the Forgejo mirror carry the same version,",
        "so a machine configured for either upgrades the same way. Keys live in",
        "`/var/lib/tpmd` and are untouched by an upgrade.",
        "",
    ]
    args.output.write_text("\n".join(lines))
    print(args.output.read_text())
    return 0


if __name__ == "__main__":
    sys.exit(main())
