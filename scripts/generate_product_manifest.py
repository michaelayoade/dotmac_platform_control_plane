#!/usr/bin/env python3
"""Generate `deploy/product-manifest.json` from the real composed assembly.

`assembly.manifest_digest` in the deployment descriptor is what
`dotmac-deploy drift` uses to tell an approved module set from any other. Until
this existed the descriptor carried the all-zero placeholder, which is a
syntactically perfect digest that names nothing — the descriptor parsed, and the
gate reported green on a composition nobody had pinned.

## Why the version recorded is the DISTRIBUTION's, not the manifest's

A module carries a version literal on its `ModuleManifest` and its wheel carries
one in distribution metadata, and those are two copies of the same fact. They
can disagree: at the time of writing `dotmac-deployment-control` declares
`0.1.0a2` on its manifest while the installed distribution is `0.1.0a6`.

The manifest records the DISTRIBUTION version, because that is artifact
identity — it is the thing the lockfile pins, the thing the hash covers, and the
thing that decides which code is actually running. A manifest built from the
other copy would be a truthful hash of an untruthful document, which is worse
than no digest at all.

Both are emitted where they differ, so the disagreement is visible in the
artifact rather than resolved silently.
"""

from __future__ import annotations

import hashlib
import json
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from vendor_cp.assembly import build_spec

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "deploy" / "product-manifest.json"

#: Module code -> the distribution that ships it. A module with no entry is
#: assembled in this repository and has no separate distribution identity.
DISTRIBUTIONS = {
    "release_catalog": "dotmac-release-catalog",
    "entitlement_allocation": "dotmac-entitlement-allocation",
    "approvals": "dotmac-approvals",
    "commercial_agreements": "dotmac-commercial-agreements",
    "licensing": "dotmac-licensing",
    "deployment_control": "dotmac-deployment-control",
}


def _distribution_version(distribution: str) -> str | None:
    try:
        return version(distribution)
    except PackageNotFoundError:  # pragma: no cover - install-time only
        return None


def build_manifest() -> dict[str, object]:
    spec = build_spec()
    modules: list[dict[str, object]] = []
    for manifest in spec.modules:
        code = getattr(manifest, "code", None) or getattr(manifest, "name", "")
        entry: dict[str, object] = {"code": code}
        declared = getattr(manifest, "version", None)
        contract = getattr(manifest, "contract_version", None)
        if contract is not None:
            entry["contract_version"] = contract
        distribution = DISTRIBUTIONS.get(code)
        if distribution is None:
            # Assembled here; the repository revision is its identity.
            entry["source"] = "assembly"
            if declared:
                entry["declared_version"] = declared
        else:
            installed = _distribution_version(distribution)
            entry["distribution"] = distribution
            entry["version"] = installed
            if declared and installed and declared != installed:
                # Recorded rather than reconciled: two copies of one fact that
                # disagree is a finding for the module's own repository.
                entry["manifest_declared_version"] = declared
        modules.append(entry)

    return {
        "schema": "ProductAssemblyManifest.v1",
        "assembly": spec.name,
        "web_enabled": spec.web_enabled,
        "module_planes": sorted(
            (
                {"module": s.module, "planes": sorted(str(p) for p in s.planes)}
                for s in spec.module_planes
            ),
            key=lambda entry: entry["module"],
        ),
        "modules": sorted(modules, key=lambda m: str(m["code"])),
    }


def canonical_bytes(manifest: dict[str, object]) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(manifest: dict[str, object]) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(manifest)).hexdigest()


def main() -> int:
    manifest = build_manifest()
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(digest(manifest))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
