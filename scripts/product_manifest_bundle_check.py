#!/usr/bin/env python3
"""Job 2's own re-derivation and check, before anything is installed.

Job 2 holds no credential and must not simply trust job 1's artifact: it
re-derives the same private-distribution list from the candidate ref's own
checked-out `pyproject.toml` (`product_manifest_acquire.private_distributions`,
unchanged) and refuses — rather than letting `pip install` fail somewhere
less legible — if a declared private distribution has no matching artifact in
the bundle `acquire` uploaded. On success it prints exactly the `name==version`
pip specifiers the private-distribution install step consumes, so nothing
hand-parses the manifest a second time in a different shape.
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import kernel_lock  # noqa: E402
from product_manifest_acquire import private_distributions  # noqa: E402


def bundle_problems(plan: dict[str, str], bundle_files: Path) -> list[str]:
    """Every declared private distribution, against what was actually
    acquired. Read the files that exist in `bundle_files` rather than trust a
    manifest of what SHOULD be there — a directory listing cannot itself lie
    about what job 1 uploaded."""

    if not bundle_files.is_dir():
        return [f"{bundle_files} does not exist; nothing was acquired"]
    acquired = [entry.name for entry in bundle_files.iterdir() if entry.is_file()]
    problems: list[str] = []
    for package, version in sorted(plan.items()):
        matches = [
            name
            for name in acquired
            if kernel_lock.artifact_belongs_to(name, package, version)
        ]
        if not matches:
            problems.append(
                f"{package} {version} is declared in tool.poetry.dependencies, "
                f"bound to {kernel_lock.INDEX_SOURCE_NAME!r}, but no matching "
                "artifact exists in the acquired bundle"
            )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--bundle-files", type=Path, required=True)
    args = parser.parse_args(argv)

    with args.manifest.open("rb") as handle:
        manifest = tomllib.load(handle)
    plan = private_distributions(manifest)

    problems = bundle_problems(plan, args.bundle_files)
    if problems:
        for problem in problems:
            print(f"::error::{problem}")
        return 1

    for package, version in sorted(plan.items()):
        print(f"{package}=={version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
