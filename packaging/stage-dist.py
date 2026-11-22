#!/usr/bin/env python3
"""Validate and stage built native packages into an offworld-dist bundle.

Stdlib-only so every GitHub Actions runner (Linux, macOS, Windows) and local
developer checkout can run it with zero third-party dependencies.

Usage
-----
In a GitHub Actions workflow (followed by ``actions/upload-artifact@v4`` with
``name: offworld-dist``)::

    python3 packaging/stage-dist.py \\
        --source tpmd \\
        --channel "${{ needs.version.outputs.channel }}" \\
        --version "${{ needs.version.outputs.version }}" \\
        --out "$RUNNER_TEMP/offworld-dist" \\
        --file "deb:amd64:dist/*_amd64.deb" \\
        --file "deb:arm64:dist/*_arm64.deb" \\
        --file "deb-src:source:dist/*.dsc"

Local dry-run rehearsal (validates globs, naming, nightly sort stamps, and
package control headers without writing an output directory)::

    uv run python packaging/stage-dist.py --dry-run \\
        --source tpmd --channel nightly \\
        --version "0.1.2~nightly20261122.r1+gdeadbeef" \\
        --ref refs/heads/develop \\
        --file "deb:amd64:dist/*_amd64.deb" \\
        --file "deb-src:source:dist/*.dsc"
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

VALID_FORMATS = (
    "deb",
    "deb-src",
    "rpm",
    "apk",
    "arch",
    "macos",
    "windows",
    "tarball",
)
VALID_CHANNELS = ("stable", "nightly")
SOURCE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
ARCH_RE = re.compile(r"^[a-zA-Z0-9._-]{1,32}$")
DEB_FILE_RE = re.compile(
    r"^(?P<name>[a-z0-9][a-z0-9+.-]*)_(?P<ver>[^_]+)_(?P<arch>[a-z0-9]+)\.u?deb$"
)


class StageError(RuntimeError):
    """Raised when artifact staging violates the Offworld packaging contract."""


def sha256_file(path: Path) -> str:
    """Compute hex SHA-256 digest of ``path``."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_dsc_referenced_files(dsc_path: Path) -> list[Path]:
    """Return companion source tarballs listed in a Debian ``.dsc`` file."""
    companions: list[Path] = []
    seen: set[str] = set()
    in_files = False
    for raw in dsc_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if raw.startswith(("Files:", "Checksums-Sha256:", "Checksums-Sha1:")):
            in_files = True
            continue
        if in_files:
            if raw.startswith((" ", "\t")):
                parts = raw.strip().split()
                if len(parts) >= 3:
                    fname = parts[-1]
                    if "/" in fname or fname in ("..", "."):
                        raise StageError(f"Unsafe filename {fname!r} in {dsc_path}")
                    if fname not in seen:
                        seen.add(fname)
                        companion = dsc_path.parent / fname
                        if not companion.is_file():
                            raise StageError(
                                f"{dsc_path} references companion file {companion}, which is missing"
                            )
                        companions.append(companion)
            else:
                in_files = False
    return companions


def inspect_deb(path: Path, expected_arch: str, channel: str) -> dict[str, str]:
    """Validate Debian binary filename, nightly sorting stamp, and control headers."""
    m = DEB_FILE_RE.match(path.name)
    if not m:
        raise StageError(
            f"Debian package {path.name!r} must follow <name>_<version>_<arch>.deb naming"
        )
    pkg_name = m.group("name")
    pkg_ver = m.group("ver")
    file_arch = m.group("arch")
    if file_arch not in (expected_arch, "all"):
        raise StageError(
            f"Debian package {path.name!r} filename arch {file_arch!r} != declared {expected_arch!r}"
        )
    if channel == "nightly" and "~nightly" not in pkg_ver:
        raise StageError(
            f"Nightly Debian package {path.name!r} version {pkg_ver!r} must contain '~nightly' so APT sorts it below stable"
        )
    if channel == "stable" and "~nightly" in pkg_ver:
        raise StageError(
            f"Stable Debian package {path.name!r} version {pkg_ver!r} must not contain '~nightly'"
        )
    dpkg_deb = shutil.which("dpkg-deb")
    if dpkg_deb:
        proc = subprocess.run(
            [dpkg_deb, "--field", str(path), "Package", "Version", "Architecture"],
            check=False,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise StageError(f"dpkg-deb rejected {path}: {proc.stderr.strip()}")
        fields: dict[str, str] = {}
        for line in proc.stdout.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                fields[k.strip()] = v.strip()
        ctrl_arch = fields.get("Architecture", "")
        if ctrl_arch not in (expected_arch, "all"):
            raise StageError(
                f"{path.name}: control Architecture {ctrl_arch!r} != expected {expected_arch!r}"
            )
        return {
            "pkg_name": fields.get("Package", pkg_name),
            "pkg_version": fields.get("Version", pkg_ver),
            "pkg_arch": ctrl_arch or file_arch,
        }
    return {"pkg_name": pkg_name, "pkg_version": pkg_ver, "pkg_arch": file_arch}


def inspect_rpm(path: Path, expected_arch: str, channel: str) -> dict[str, str]:
    """Validate RPM binary filename, nightly pre-release stamp, and RPM headers."""
    if not path.name.endswith(".rpm") or path.name.endswith(".src.rpm"):
        raise StageError(f"RPM artifact {path.name!r} must be a binary .rpm")
    if channel == "nightly" and "0.nightly" not in path.name and ".nightly." not in path.name:
        raise StageError(
            f"Nightly RPM {path.name!r} must carry a pre-release nightly stamp (e.g. -0.nightly.<date>.r<run>.g<sha>)"
        )
    if channel == "stable" and "nightly" in path.name:
        raise StageError(f"Stable RPM {path.name!r} must not carry a nightly stamp")

    rpm_bin = shutil.which("rpm")
    if rpm_bin:
        proc = subprocess.run(
            [rpm_bin, "-qp", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n", str(path)],
            check=False,
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0 and "\t" in proc.stdout:
            name, ver_rel, arch = proc.stdout.strip().splitlines()[0].split("\t", 2)
            if arch not in (expected_arch, "noarch"):
                raise StageError(
                    f"{path.name}: RPM header ARCH {arch!r} != expected {expected_arch!r}"
                )
            return {"pkg_name": name, "pkg_version": ver_rel, "pkg_arch": arch}
    return {"pkg_name": "", "pkg_version": "", "pkg_arch": expected_arch}


def validate_file_for_format(path: Path, fmt: str, arch: str, channel: str) -> dict[str, str]:
    """Validate one candidate artifact file according to its ecosystem format."""
    if not path.is_file() or path.stat().st_size == 0:
        raise StageError(f"Artifact {path} is missing or empty")
    if fmt == "deb":
        return inspect_deb(path, arch, channel)
    if fmt == "deb-src":
        return {"pkg_name": "", "pkg_version": "", "pkg_arch": "source"}
    if fmt == "rpm":
        return inspect_rpm(path, arch, channel)
    if fmt == "apk":
        if not path.name.endswith(".apk"):
            raise StageError(f"Alpine package {path.name!r} must end with .apk")
        return {"pkg_name": "", "pkg_version": "", "pkg_arch": arch}
    if fmt == "arch":
        if not (path.name.endswith(".pkg.tar.zst") or path.name.endswith(".pkg.tar.xz")):
            raise StageError(f"Arch package {path.name!r} must end with .pkg.tar.zst or .pkg.tar.xz")
        return {"pkg_name": "", "pkg_version": "", "pkg_arch": arch}
    return {"pkg_name": "", "pkg_version": "", "pkg_arch": arch}


def stage_bundle(
    *,
    source: str,
    channel: str,
    version: str,
    file_specs: list[str],
    out_dir: Path | None,
    commit: str,
    ref: str,
    repository: str,
    run_id: int,
    run_number: int,
    keep_nightlies: int = 7,
    github_release: bool = False,
    homebrew: dict | None = None,
    scoop: dict | None = None,
    dry_run: bool = False,
    cwd: Path | None = None,
) -> dict:
    """Validate all ``file_specs`` and materialize ``out_dir/manifest.json`` + ``files/``."""
    if not SOURCE_RE.match(source):
        raise StageError(f"Invalid source slug {source!r}")
    if channel not in VALID_CHANNELS:
        raise StageError(f"Invalid channel {channel!r}; expected one of {VALID_CHANNELS}")
    if not version or any(ch.isspace() for ch in version):
        raise StageError(f"Invalid version {version!r}")
    if keep_nightlies < 1 or keep_nightlies > 100:
        raise StageError(f"keep-nightlies must be between 1 and 100 (got {keep_nightlies})")
    if channel == "stable" and not ref.startswith("refs/tags/v"):
        raise StageError(
            f"channel='stable' requires a refs/tags/v* ref (got {ref!r}); use channel='nightly' on branches"
        )
    if github_release and channel != "stable":
        raise StageError("--github-release is only valid when --channel=stable")
    if not file_specs:
        raise StageError("At least one --file '<format>:<arch>:<glob>' entry is required")

    base_dir = cwd or Path.cwd()
    if not dry_run:
        if out_dir is None:
            raise StageError("--out is required unless --dry-run is set")
        if out_dir.exists():
            shutil.rmtree(out_dir)
        (out_dir / "files").mkdir(parents=True, exist_ok=True)

    staged_keys: set[tuple[str, str]] = set()
    artifacts: list[dict] = []

    def add_one(src_path: Path, fmt: str, arch: str) -> None:
        key = (fmt, src_path.name)
        if key in staged_keys:
            return
        meta = validate_file_for_format(src_path, fmt, arch, channel)
        rel_dest = Path("files") / fmt / src_path.name
        target_for_hash = src_path
        if not dry_run:
            assert out_dir is not None
            dest = out_dir / rel_dest
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_path, dest)
            target_for_hash = dest
        staged_keys.add(key)
        entry = {
            "path": rel_dest.as_posix(),
            "filename": src_path.name,
            "format": fmt,
            "arch": arch,
            "sha256": sha256_file(target_for_hash),
            "size": target_for_hash.stat().st_size,
        }
        if meta.get("pkg_name"):
            entry["pkg_name"] = meta["pkg_name"]
        if meta.get("pkg_version"):
            entry["pkg_version"] = meta["pkg_version"]
        if meta.get("pkg_arch"):
            entry["pkg_arch"] = meta["pkg_arch"]
        artifacts.append(entry)

    for spec in file_specs:
        spec = spec.strip()
        if not spec or spec.startswith("#"):
            continue
        parts = spec.split(":", 2)
        if len(parts) != 3:
            raise StageError(
                f"Malformed --file entry {spec!r}; expected '<format>:<arch>:<glob>'"
            )
        fmt, arch, pattern = (p.strip() for p in parts)
        if fmt not in VALID_FORMATS:
            raise StageError(
                f"Unsupported format {fmt!r} in {spec!r}; valid: {VALID_FORMATS}"
            )
        if not ARCH_RE.match(arch):
            raise StageError(f"Invalid architecture token {arch!r} in {spec!r}")

        matches = sorted(
            Path(p)
            for p in glob.glob(str(base_dir / pattern), recursive=True)
            if Path(p).is_file()
        )
        if not matches:
            raise StageError(f"Pattern {pattern!r} ({fmt}:{arch}) matched 0 files")

        for match in matches:
            add_one(match, fmt, arch)
            if fmt == "deb-src" and match.name.endswith(".dsc"):
                for companion in parse_dsc_referenced_files(match):
                    add_one(companion, "deb-src", "source")

    manifest = {
        "schema": 1,
        "source": source,
        "repository": repository,
        "channel": channel,
        "version": version,
        "commit": commit,
        "ref": ref,
        "run_id": run_id,
        "run_number": run_number,
        "keep_nightlies": keep_nightlies,
        "github_release": github_release,
        "homebrew": homebrew,
        "scoop": scoop,
        "artifacts": artifacts,
    }
    if not dry_run:
        assert out_dir is not None
        (out_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return manifest


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint."""
    p = argparse.ArgumentParser(description="Stage artifacts into an offworld-dist bundle.")
    p.add_argument("--source", required=True, help="Source package slug (e.g. tpmd)")
    p.add_argument("--channel", required=True, choices=VALID_CHANNELS)
    p.add_argument("--version", required=True, help="Release version or nightly stamp")
    p.add_argument("--out", help="Output directory to write manifest.json and files/")
    p.add_argument(
        "--file",
        dest="files",
        action="append",
        default=[],
        help="<format>:<arch>:<glob> entry (repeatable)",
    )
    p.add_argument("--keep-nightlies", type=int, default=7)
    p.add_argument("--github-release", action="store_true")
    p.add_argument("--homebrew-json", default="")
    p.add_argument("--scoop-json", default="")
    p.add_argument("--commit", default=os.environ.get("GITHUB_SHA", ""))
    p.add_argument("--ref", default=os.environ.get("GITHUB_REF", ""))
    p.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    p.add_argument("--run-id", type=int, default=int(os.environ.get("GITHUB_RUN_ID", "0") or "0"))
    p.add_argument(
        "--run-number", type=int, default=int(os.environ.get("GITHUB_RUN_NUMBER", "0") or "0")
    )
    p.add_argument("--dry-run", action="store_true", help="Validate only; print manifest JSON")
    args = p.parse_args(argv)

    try:
        homebrew = json.loads(args.homebrew_json) if args.homebrew_json.strip() else None
        scoop = json.loads(args.scoop_json) if args.scoop_json.strip() else None
        out_dir = Path(args.out).resolve() if args.out else None
        manifest = stage_bundle(
            source=args.source.strip(),
            channel=args.channel.strip(),
            version=args.version.strip(),
            file_specs=args.files,
            out_dir=out_dir,
            commit=args.commit.strip(),
            ref=args.ref.strip(),
            repository=args.repository.strip(),
            run_id=args.run_id,
            run_number=args.run_number,
            keep_nightlies=args.keep_nightlies,
            github_release=args.github_release,
            homebrew=homebrew,
            scoop=scoop,
            dry_run=args.dry_run,
        )
    except (StageError, json.JSONDecodeError) as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1

    if args.dry_run:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    else:
        print(
            f"Staged {len(manifest['artifacts'])} artifact(s) for "
            f"{manifest['source']} {manifest['version']} ({manifest['channel']}) -> {out_dir}"
        )
        for item in manifest["artifacts"]:
            print(
                f"  - [{item['format']}/{item['arch']}] {item['filename']} "
                f"({item['size']} B, sha256={item['sha256'][:12]}…)"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
