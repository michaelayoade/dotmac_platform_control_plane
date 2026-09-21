#!/usr/bin/env python3
"""Acquire every privately-published distribution
`product-manifest-regenerate.yml` job 1 holds the credential for, and
hash-verify them the same way `kernel-lock.yml`'s `acquire` job does.

`scripts/generate_product_manifest.py`'s `build_manifest()` calls
`vendor_cp.assembly.build_spec()`, which composes every module this
repository declares — and `importlib.metadata.version(...)` reads each
module's DISTRIBUTION version, not the literal on its `ModuleManifest`. This
branch's specific repin (`dotmac-kernel` and `dotmac-deployment-control`
moving; see the workflow's own header comment for the full causal chain) is
what made `test_product_manifest.py` fail, but the generator needs the WHOLE
composed set importable, not just the two distributions that moved — so this
module acquires every distribution the candidate ref's own `pyproject.toml`
binds to the private index, derived from that manifest rather than a
hardcoded name list, so a future composed distribution cannot be silently
left out of the bundle.

This module does not invent a second acquisition mechanism. It reads the
candidate ref's own `pyproject.toml` as DATA (name/version pairs, never
executed) and calls `kernel_lock.acquire` — the exact function
`kernel-lock.yml`'s `acquire` job uses to hold the credential, validate every
index-supplied link against the approved origin, and lay the downloaded bytes
out as a local PEP 503 index with recorded sha256 digests. Runs no Poetry, no
pip, and no code from the candidate checkout or from any downloaded package:
curl (via `kernel_lock.fetch`), sha256, and file-writing only.
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import kernel_lock  # noqa: E402


def private_distributions(manifest: dict[str, object]) -> dict[str, str]:
    """Every `tool.poetry.dependencies` entry bound to the private index, and
    the EXACT version it is pinned at, read straight out of the manifest.

    Derived rather than named, so a distribution added to the composed
    assembly tomorrow is acquired automatically instead of silently missing
    from the bundle the day someone forgets to update a list here. Scoped to
    the main dependency table: every composed module this repository runs is
    a runtime dependency, never a dev-only or group-only one, and the
    candidate ref's own `manifest_problems` (`kernel-lock.yml`'s guard) is the
    place a private dependency hiding in another table is refused, not this
    one, which only derives what to fetch.
    """

    poetry = manifest.get("tool", {})
    poetry = poetry.get("poetry", {}) if isinstance(poetry, dict) else {}
    dependencies = poetry.get("dependencies", {}) if isinstance(poetry, dict) else {}
    if not isinstance(dependencies, dict):
        raise kernel_lock.Refusal(
            "tool.poetry.dependencies is not a table; cannot derive what to acquire"
        )

    plan: dict[str, str] = {}
    for name, spec in sorted(dependencies.items()):
        if not isinstance(spec, dict):
            continue
        if spec.get("source") != kernel_lock.INDEX_SOURCE_NAME:
            continue
        version = spec.get("version")
        if not isinstance(version, str) or not kernel_lock._EXACT_VERSION.fullmatch(
            version
        ):
            raise kernel_lock.Refusal(
                f"{name} is bound to {kernel_lock.INDEX_SOURCE_NAME!r} with "
                f"the constraint {version!r}. Acquisition can only be closed "
                "around an exact pin; a range would need this module to "
                "decide what it resolves to."
            )
        plan[name] = version

    if not plan:
        raise kernel_lock.Refusal(
            f"no dependency in tool.poetry.dependencies is bound to "
            f"{kernel_lock.INDEX_SOURCE_NAME!r}; nothing to acquire"
        )
    return plan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)

    with args.manifest.open("rb") as handle:
        manifest = tomllib.load(handle)
    plan = private_distributions(manifest)
    for package, version in sorted(plan.items()):
        print(f"acquiring {package} {version}")
    digests = kernel_lock.acquire(plan, args.out)
    for name, digest in sorted(digests.items()):
        print(f"{name}  {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
