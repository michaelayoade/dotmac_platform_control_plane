"""Bind the candidate's served UI bytes to its locked Kernel artifact.

The Kernel stylesheet is generated during the Kernel release build, so its
bytes may legitimately change when the repository-wide Tailwind input changes
even if ``dotmac_kernel/static`` has no tracked diff.  A free-floating asset
digest cannot explain that change.  This record therefore moves only as one
closed tuple: installed distribution/version, locked wheel digest, asset count,
and the digest of the installed asset manifest.

This module reads local evidence only.  It never imports the candidate or
executes package code; ``acceptance.sh`` obtains the installed facts and the
image's build-time, post-install wheel provenance from the already-built image
and sends the closed four-line report on stdin.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA = "dotmac-platform-ui-assets/1"
DISTRIBUTION = "dotmac-kernel"
EXPECTED_KEYS = frozenset(
    {
        "schema",
        "distribution",
        "version",
        "wheel_sha256",
        "asset_count",
        "asset_manifest_sha256",
    }
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class UiAssetRefusal(ValueError):
    """The declared, locked, and installed asset facts do not agree."""


@dataclass(frozen=True)
class UiAssetExpectation:
    version: str
    wheel_sha256: str
    asset_count: int
    asset_manifest_sha256: str


def _mapping(value: object, *, subject: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise UiAssetRefusal(f"{subject} is not an object")
    return value


def load_expectation(path: Path) -> UiAssetExpectation:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise UiAssetRefusal(
            f"{path} is missing or invalid ({error.__class__.__name__})"
        ) from error
    record = _mapping(raw, subject=str(path))
    keys = frozenset(record)
    if keys != EXPECTED_KEYS:
        raise UiAssetRefusal(
            f"{path} has a non-closed shape: missing={sorted(EXPECTED_KEYS - keys)}, "
            f"extra={sorted(keys - EXPECTED_KEYS)}"
        )
    if record["schema"] != SCHEMA:
        raise UiAssetRefusal(f"unsupported UI asset schema {record['schema']!r}")
    if record["distribution"] != DISTRIBUTION:
        raise UiAssetRefusal(
            f"UI assets are attributed to {record['distribution']!r}, "
            f"not {DISTRIBUTION!r}"
        )

    version = record["version"]
    wheel_sha256 = record["wheel_sha256"]
    asset_count = record["asset_count"]
    asset_manifest_sha256 = record["asset_manifest_sha256"]
    if not isinstance(version, str) or not version:
        raise UiAssetRefusal("UI asset version is not a non-empty string")
    if not isinstance(wheel_sha256, str) or SHA256.fullmatch(wheel_sha256) is None:
        raise UiAssetRefusal("UI asset wheel_sha256 is not 64 lowercase hex")
    if (
        not isinstance(asset_count, int)
        or isinstance(asset_count, bool)
        or asset_count < 1
    ):
        raise UiAssetRefusal("UI asset_count is not a positive integer")
    if (
        not isinstance(asset_manifest_sha256, str)
        or SHA256.fullmatch(asset_manifest_sha256) is None
    ):
        raise UiAssetRefusal("UI asset_manifest_sha256 is not 64 lowercase hex")
    return UiAssetExpectation(
        version=version,
        wheel_sha256=wheel_sha256,
        asset_count=asset_count,
        asset_manifest_sha256=asset_manifest_sha256,
    )


def _toml(path: Path, *, subject: str) -> Mapping[str, Any]:
    try:
        return _mapping(
            tomllib.loads(path.read_text(encoding="utf-8")), subject=subject
        )
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise UiAssetRefusal(
            f"{path} is missing or invalid ({error.__class__.__name__})"
        ) from error


def declared_kernel_version(pyproject_path: Path) -> str:
    document = _toml(pyproject_path, subject=str(pyproject_path))
    try:
        declaration = document["tool"]["poetry"]["dependencies"][DISTRIBUTION]
    except (KeyError, TypeError) as error:
        raise UiAssetRefusal(
            f"{pyproject_path} has no {DISTRIBUTION!r} Poetry dependency"
        ) from error
    if not isinstance(declaration, dict) or set(declaration) != {
        "version",
        "extras",
        "source",
    }:
        raise UiAssetRefusal(
            f"{pyproject_path} {DISTRIBUTION!r} declaration changed shape"
        )
    version = declaration["version"]
    if not isinstance(version, str) or not version:
        raise UiAssetRefusal(
            f"{pyproject_path} {DISTRIBUTION!r} version is not a non-empty string"
        )
    return version


def locked_kernel_wheel(lock_path: Path) -> tuple[str, str]:
    document = _toml(lock_path, subject=str(lock_path))
    packages = document.get("package")
    if not isinstance(packages, list):
        raise UiAssetRefusal(f"{lock_path} has no package array")
    matches = [
        package
        for package in packages
        if isinstance(package, dict) and package.get("name") == DISTRIBUTION
    ]
    if len(matches) != 1:
        raise UiAssetRefusal(
            f"{lock_path} names {DISTRIBUTION!r} {len(matches)} times, not once"
        )
    package = matches[0]
    version = package.get("version")
    files = package.get("files")
    if not isinstance(version, str) or not isinstance(files, list):
        raise UiAssetRefusal(f"{lock_path} has an invalid {DISTRIBUTION!r} entry")
    wheels = [
        entry
        for entry in files
        if isinstance(entry, dict)
        and isinstance(entry.get("file"), str)
        and entry["file"].endswith(".whl")
    ]
    if len(wheels) != 1:
        raise UiAssetRefusal(
            f"{lock_path} records {len(wheels)} {DISTRIBUTION!r} wheels, not one"
        )
    wheel = wheels[0]
    expected_filename = f"dotmac_kernel-{version}-py3-none-any.whl"
    if wheel.get("file") != expected_filename:
        raise UiAssetRefusal(
            f"{lock_path} wheel is {wheel.get('file')!r}, "
            f"expected {expected_filename!r}"
        )
    raw_hash = wheel.get("hash")
    if not isinstance(raw_hash, str) or not raw_hash.startswith("sha256:"):
        raise UiAssetRefusal(f"{lock_path} wheel has no sha256 coordinate")
    digest = raw_hash.removeprefix("sha256:")
    if SHA256.fullmatch(digest) is None:
        raise UiAssetRefusal(f"{lock_path} wheel sha256 is not 64 lowercase hex")
    return version, digest


def parse_installed_report(text: str) -> tuple[int, str, str, str]:
    lines = text.splitlines()
    if len(lines) != 4:
        raise UiAssetRefusal(
            f"candidate emitted {len(lines)} UI asset report lines, expected 4"
        )
    try:
        count = int(lines[0])
    except ValueError as error:
        raise UiAssetRefusal(
            f"candidate asset count is not an integer: {lines[0]!r}"
        ) from error
    digest, version, installed_wheel_sha256 = lines[1:]
    if count < 1:
        raise UiAssetRefusal("candidate asset count is not positive")
    if SHA256.fullmatch(digest) is None:
        raise UiAssetRefusal("candidate asset manifest digest is not 64 lowercase hex")
    if not version:
        raise UiAssetRefusal("candidate installed Kernel version is empty")
    if SHA256.fullmatch(installed_wheel_sha256) is None:
        raise UiAssetRefusal(
            "candidate Kernel wheel provenance is not 64 lowercase hex"
        )
    return count, digest, version, installed_wheel_sha256


def verify(
    *, expectation_path: Path, pyproject_path: Path, lock_path: Path, report: str
) -> UiAssetExpectation:
    expected = load_expectation(expectation_path)
    declared_version = declared_kernel_version(pyproject_path)
    locked_version, locked_digest = locked_kernel_wheel(lock_path)
    (
        installed_count,
        installed_digest,
        installed_version,
        installed_wheel_digest,
    ) = parse_installed_report(report)

    versions = {expected.version, declared_version, locked_version, installed_version}
    if len(versions) != 1:
        raise UiAssetRefusal(
            "Kernel versions disagree: "
            f"expected={expected.version}, manifest={declared_version}, "
            f"lock={locked_version}, installed={installed_version}"
        )
    if expected.wheel_sha256 != locked_digest:
        raise UiAssetRefusal(
            "Kernel wheel coordinate disagrees: "
            f"expected={expected.wheel_sha256}, lock={locked_digest}"
        )
    if expected.wheel_sha256 != installed_wheel_digest:
        raise UiAssetRefusal(
            "candidate Kernel wheel provenance disagrees: "
            f"installed={installed_wheel_digest}, expected={expected.wheel_sha256}"
        )
    if expected.asset_count != installed_count:
        raise UiAssetRefusal(
            f"installed Kernel serves {installed_count} UI assets, "
            f"expected {expected.asset_count}"
        )
    if expected.asset_manifest_sha256 != installed_digest:
        raise UiAssetRefusal(
            "installed Kernel UI asset manifest disagrees: "
            f"installed={installed_digest}, expected={expected.asset_manifest_sha256}"
        )
    return expected


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expectation", type=Path, required=True)
    parser.add_argument("--pyproject", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        expected = verify(
            expectation_path=args.expectation,
            pyproject_path=args.pyproject,
            lock_path=args.lock,
            report=sys.stdin.read(),
        )
    except UiAssetRefusal as error:
        print(f"UI asset contract refused: {error}", file=sys.stderr)
        return 1
    print(
        f"{expected.asset_count} UI assets from {DISTRIBUTION} {expected.version}; "
        f"manifest and locked wheel coordinates agree"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
