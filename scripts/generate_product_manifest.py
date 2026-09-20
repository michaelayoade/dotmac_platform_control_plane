#!/usr/bin/env python3
"""Generate the prospective source-composition record from this checkout.

`assembly.manifest_digest` in the deployment descriptor is what
`dotmac-deploy drift` uses to tell an approved module set from any other. Until
this existed the descriptor carried the all-zero placeholder, which is a
syntactically perfect digest that names nothing — the descriptor parsed, and the
gate reported green on a composition nobody had pinned.

## Why the version recorded is the DISTRIBUTION's, not the manifest's

A module's manifest version and its wheel's distribution metadata can disagree.
Deployment Control a13 derives its manifest version from installed metadata;
older releases carried a stale literal. Keep the comparison for any future
module that still declares a conflicting version.

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

# `deploy/product-manifest.json` is part of the ACCEPTED production descriptor.
# It remains the bytes the running deployment was promoted with; regenerating it
# from a branch would falsely claim that the branch has been deployed. Branch
# composition is emitted below `deploy/prospective/` instead.
PROSPECTIVE_DIR = ROOT / "deploy" / "prospective"
MANIFEST = PROSPECTIVE_DIR / "product-manifest.json"
SOURCE_COMPOSITION = PROSPECTIVE_DIR / "source-composition.json"

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


def composed_effective_heads() -> list[str]:
    """Derive the rows Alembic retains after a composed ``heads`` upgrade.

    This is deliberately not a handwritten release list. ``depends_on`` heads
    are graph heads but are subsumed from ``alembic_version`` by the revision
    that depends on them, so a prospective migration claim has to make the same
    subtraction as the deploy path.
    """
    from alembic.script import ScriptDirectory

    from vendor_cp.migrations import make_alembic_config

    # Building Alembic's Config constructs no engine; this coordinate is never
    # dialled. It merely lets ScriptDirectory load the composed graph.
    script = ScriptDirectory.from_config(
        make_alembic_config("postgresql+psycopg://descriptor@127.0.0.1:5432/none")
    )
    heads = set(script.get_heads())
    dependencies: set[str] = set()
    for revision in script.walk_revisions("base", "heads"):
        declared = revision.dependencies or ()
        dependencies.update((declared,) if isinstance(declared, str) else declared)
    return sorted(heads - dependencies)


def build_source_composition(
    manifest: dict[str, object] | None = None,
) -> dict[str, object]:
    """The branch source subject; intentionally not a deployment candidate.

    It identifies the composition produced by this checkout and its migration
    graph, but has no image, release coordinate, receipt, or promotion claim.
    A receipt and the existing promotion mechanism are still required before
    any value here may replace accepted production truth.
    """
    prospective_manifest = build_manifest() if manifest is None else manifest
    return {
        "schema": "ProspectiveSourceComposition.v1",
        "manifest": {
            "path": "deploy/prospective/product-manifest.json",
            "digest": digest(prospective_manifest),
        },
        "migration": {"expected_heads": composed_effective_heads()},
    }


def main() -> int:
    manifest = build_manifest()
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    SOURCE_COMPOSITION.write_text(
        json.dumps(build_source_composition(manifest), indent=2, sort_keys=True) + "\n"
    )
    print(digest(manifest))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
