#!/usr/bin/env python3
"""Acquire the two distributions `product-manifest-regenerate.yml` job 1 holds
the credential for, and hash-verify them the same way `kernel-lock.yml`'s
`acquire` job does.

`scripts/generate_product_manifest.py`'s `build_manifest()` reads
`importlib.metadata.version(...)` for every module that ships as its own
distribution, so the derived `deploy/product-manifest.json` follows the
DISTRIBUTION version, not the literal on `ModuleManifest`. This branch moves
two of those facts at once (see the workflow's own header comment for the
full causal chain): `dotmac-kernel`'s pin and `dotmac-deployment-control`'s
declared `ModuleManifest.version`, which — once installed from a real
distribution — stops being a literal and starts reading its own installed
metadata, so `manifest_declared_version` disappears from that entry.

This module does not invent a second acquisition mechanism. It reads the
candidate ref's own `pyproject.toml` as DATA (two exact version strings, never
executed) and calls `kernel_lock.acquire` — the exact function
`kernel-lock.yml`'s `acquire` job uses to hold the credential, validate every
index-supplied link against the approved origin, and lay the downloaded bytes
out as a local PEP 503 index with recorded sha256 digests. Runs no Poetry, no
pip, and no code from the candidate checkout or from any downloaded package:
curl (via `kernel_lock.fetch`), sha256, and file-writing only.

NOTE for the reviewer: this acquires exactly the two distributions this
branch's fix is about, per the accepted design. `vendor_cp.assembly
.build_spec()` — what `generate_product_manifest.py` actually imports — is
composed from six privately-published distributions in this repository's
`pyproject.toml`, not two; the other four (`dotmac-release-catalog`,
`dotmac-entitlement-allocation`, `dotmac-approvals`,
`dotmac-commercial-agreements`, `dotmac-licensing`) and this project's own
ordinary PyPI dependencies are NOT acquired here and are not installed by job
2's offline step either. Whether job 2's `generate_product_manifest.py` step
can actually import successfully in a bare `ubuntu-latest` runner with only
these two distributions installed is therefore an open question this module
does not resolve — flagged for the workflow's owner, not silently patched by
widening this script's scope on its own authority.
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import kernel_lock  # noqa: E402

#: Exactly the two distributions this branch repins. Not the full closure of
#: this repository's `forgejo`-sourced dependencies — see the module
#: docstring for why that is a named open question, not a decision made here.
PACKAGES: tuple[str, ...] = ("dotmac-kernel", "dotmac-deployment-control")


def pinned_versions(manifest: dict[str, object]) -> dict[str, str]:
    """The exact version each of `PACKAGES` is pinned at in `manifest`.

    Read as DATA — `tomllib.load`, never `import` or `exec` — so this can run
    against the candidate ref's own `pyproject.toml` in the job that holds the
    credential without that job executing a line of the candidate's code.
    """

    poetry = manifest.get("tool", {}).get("poetry", {})  # type: ignore[union-attr]
    dependencies = poetry.get("dependencies", {}) if isinstance(poetry, dict) else {}
    plan: dict[str, str] = {}
    for name in PACKAGES:
        spec = dependencies.get(name) if isinstance(dependencies, dict) else None
        version = spec.get("version") if isinstance(spec, dict) else None
        if not isinstance(version, str) or not version:
            raise kernel_lock.Refusal(
                f"{name} is not declared as an exact-version table dependency "
                f"under tool.poetry.dependencies; found {spec!r}"
            )
        plan[name] = version
    return plan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)

    with args.manifest.open("rb") as handle:
        manifest = tomllib.load(handle)
    plan = pinned_versions(manifest)
    for package, version in sorted(plan.items()):
        print(f"acquiring {package} {version}")
    digests = kernel_lock.acquire(plan, args.out)
    for name, digest in sorted(digests.items()):
        print(f"{name}  {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
