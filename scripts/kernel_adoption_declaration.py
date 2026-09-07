#!/usr/bin/env python3
"""Derive `.dotmac/kernel-adoption.json` from the inventories that already exist.

Every classification in the declaration is a fact this repository already
holds somewhere else. Writing them out by hand would create a second hand-kept
copy of each, and a census maintained twice is a census wrong once -- which is
the exact defect `tests/architecture/test_kernel_database_importers.py` was
written for after a `*.py` glob reported ten importers where there were eleven.

So nothing here is typed. Each field names its source:

| field | derived from |
| --- | --- |
| `required_surfaces` | the observed Kernel imports, cross-checked against
  `kernel_floor.ASSEMBLY_KERNEL_SYMBOLS` |
| the floor on each | `kernel_floor.declared_pin()` |
| `transitional_surfaces[].baseline` |
  `test_kernel_database_importers.KERNEL_DATABASE_IMPORTERS` |
| `source_surface.digest` | Governance's own renderer, never a local reimplementation |
| `kernel_catalogue` | `scripts/kernel_adoption_observation.py`'s catalogue |

## This is a generator, not a gate

There is deliberately no `--check` mode, and its absence is a decision rather
than an omission. The Governance runner ALREADY refuses every drift this file
could detect: `kernel.source.surface-drift` when the digest stops describing
the source, `kernel.surface.unclassified` when an import is classified as
nothing, `kernel.required.unused` when a declared dependency has no import, and
the transitional ratchet when a retiring site appears, vanishes or swaps a
symbol. A second comparison here would be a second writer of one verdict, and
the first sign of the drift would be the two disagreeing about which is right.

Run it when the surface moves; let CI's runner be the acceptance owner.

## Why the floor is the declared pin

`RequiredSurface.floor` is "a version the product has demonstrated it needs".
For a LIBRARY that is a lower bound it declares for its own imports. This is an
ASSEMBLY: it pins the Kernel exactly, and `scripts/kernel_floor.py` exists to
make that pin the tightest version satisfying everything composed.
`tests/architecture/test_kernel_floor.py` asserts `declared_pin() ==
effective_kernel_floor()` directly, so reading the pin here is reading the
effective floor -- through an equality something else proves, rather than by
recomputing a number this file would then own a second copy of.
`effective_kernel_floor()` itself is not called here because it resolves
installed distribution metadata, and the declaration must be derivable from a
checkout.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path, PurePosixPath
from typing import Final

REPO_ROOT: Final = Path(__file__).resolve().parents[1]

DECLARATION: Final = REPO_ROOT / ".dotmac" / "kernel-adoption.json"

CONTRACT: Final = "KernelAdoptionDeclaration.v2"

#: The one surface this assembly is retiring, and everything a retirement needs.
#: `owner` and `expiry` make someone answerable by a date; `retirement_issue` is
#: where the work is tracked, so the undertaking exists outside this file.
TRANSITIONAL_MODULE: Final = "dotmac_kernel.db"
TRANSITION_OWNER: Final = "Vendor Control Plane runtime owner"
TRANSITION_EXPIRY: Final = "2026-09-30"
TRANSITION_ISSUE: Final = (
    "https://github.com/michaelayoade/dotmac_platform_control_plane/issues/179"
)
TRANSITION_REPLACEMENT: Final = (
    "one product-owned DatabaseRuntime exposed through this assembly's own "
    "session boundaries, replacing the kernel's module-level engine built at "
    "import time from DATABASE_URL"
)

#: Where the floor for every required surface is demonstrated. It is the module
#: that derives this assembly's pin, and it names all seventeen Kernel modules
#: in `ASSEMBLY_KERNEL_SYMBOLS` -- which is what makes it a proof ABOUT each
#: subject rather than a path that merely exists.
FLOOR_PROOF: Final = PurePosixPath("scripts/kernel_floor.py")


def _local(name: str) -> object:
    """Import a repository-local module that is not on a package path."""
    for location in (REPO_ROOT / "tests" / "architecture", REPO_ROOT / "scripts"):
        if str(location) not in sys.path:
            sys.path.insert(0, str(location))
    return __import__(name)


def _observed_modules() -> dict[str, set[str]]:
    """Every Kernel module the executable surface imports, and the names taken."""
    entrypoints = _local("python_entrypoints")
    found: dict[str, set[str]] = {}
    for path in entrypoints.python_sources():  # type: ignore[attr-defined]
        for module, name, _line in entrypoints.imports_of(path):  # type: ignore[attr-defined]
            if module == "dotmac_kernel" or module.startswith("dotmac_kernel."):
                found.setdefault(module, set()).add(name or "<whole module>")
    return found


def _required_surfaces(floor: str) -> list[dict[str, str]]:
    """Every observed Kernel module except the one being retired.

    Cross-checked against `kernel_floor.ASSEMBLY_KERNEL_SYMBOLS`, which is the
    closed declaration of this assembly's Kernel surface and is itself held
    equal to a live scan by `tests/architecture/test_kernel_floor.py`. Two
    sources agreeing is not redundancy here: one is measured from the tree and
    one is reviewed, and a disagreement means the declaration is being written
    against a surface nobody approved.
    """
    kernel_floor = _local("kernel_floor")
    observed = set(_observed_modules())
    declared = set(kernel_floor.ASSEMBLY_KERNEL_SYMBOLS)  # type: ignore[attr-defined]
    if observed != declared:
        raise SystemExit(
            "the measured Kernel surface and scripts/kernel_floor.py's closed "
            f"ASSEMBLY_KERNEL_SYMBOLS disagree. Only measured: "
            f"{sorted(observed - declared)}; only declared: "
            f"{sorted(declared - observed)}. Reconcile them before writing a "
            "declaration -- a required-surface inventory derived from a "
            "surface nobody reviewed is a list, not an inventory."
        )
    return [
        {
            "module": module,
            "floor": floor,
            "proven_by": FLOOR_PROOF.as_posix(),
        }
        for module in sorted(observed)
        if module != TRANSITIONAL_MODULE
    ]


def _transitional_surfaces() -> list[dict[str, object]]:
    """The retiring surface's baseline, from the census that already owns it."""
    importers = _local("test_kernel_database_importers")
    baseline = [
        {"path": path, "symbol": symbol}
        for path, symbols in importers.KERNEL_DATABASE_IMPORTERS.items()  # type: ignore[attr-defined]
        for symbol in sorted(symbols)
    ]
    baseline.sort(key=lambda entry: (entry["path"], entry["symbol"]))
    return [
        {
            "module": TRANSITIONAL_MODULE,
            "owner": TRANSITION_OWNER,
            "expiry": TRANSITION_EXPIRY,
            "retirement_issue": TRANSITION_ISSUE,
            "replacement": TRANSITION_REPLACEMENT,
            "baseline": baseline,
        }
    ]


def _surface_identity_digest(governance_root: Path) -> str:
    """Governance's OWN v2 rendering of the measured surface, never a local one.

    `dmg-kernel-surface-v2` -- selected explicitly, per Michael's ruling that
    Platform must state the algorithm rather than let a stale field keep
    naming v1. v1 recorded only the name an import binds LOCALLY, so two
    different Kernel symbols aliased to the same local name rendered and
    digested identically; v2 keeps both halves (the name the Kernel publishes
    and the name this file bound it to) as separate fields.

    Uses `engine.surface_identity_facts` (source -> v2 facts) and
    `engine.observed_surface_identity` (facts -> digest) directly --
    `observed_surface_identity` is Governance's own named seam for "the value
    a migrating product declares" (its docstring says so explicitly). A local
    reimplementation of the AST walk and merge rule would be the one thing
    that can make the binding lie: the product would compute one rendering,
    the runner another, and a mismatch would report "the source moved" for a
    document whose rendering rule moved instead.
    """
    if str(governance_root) not in sys.path:
        sys.path.insert(0, str(governance_root))
    from kernel_adoption_control.engine import (
        observed_surface_identity,
        surface_identity_facts,
    )

    entrypoints = _local("python_entrypoints")
    sources: dict[PurePosixPath, str] = {}
    for path in entrypoints.python_sources():  # type: ignore[attr-defined]
        relative = PurePosixPath(
            path.relative_to(entrypoints.ROOT).as_posix()  # type: ignore[attr-defined]
        )
        sources[relative] = path.read_text(encoding="utf-8", errors="replace")
    facts = surface_identity_facts(sources)
    digest, _rendering = observed_surface_identity(facts)
    return digest


def build(
    governance_root: Path, declared_at: str, predecessor: str
) -> dict[str, object]:
    kernel_floor = _local("kernel_floor")
    observation = _local("kernel_adoption_observation")
    floor = kernel_floor.declared_pin()  # type: ignore[attr-defined]
    catalogue = observation._catalogue(REPO_ROOT)  # type: ignore[attr-defined]  # noqa: SLF001
    return {
        "contract": CONTRACT,
        "applicability": "applicable",
        "declared_at": declared_at,
        "source_predecessor": predecessor,
        "source_surface": {
            "algorithm": "dmg-kernel-surface-v2",
            "digest": _surface_identity_digest(governance_root),
        },
        "kernel_catalogue": {
            "version": catalogue.version,
            "revision": catalogue.revision,
            "artifact_digest": catalogue.artifact_digest,
            "catalogue_digest": _catalogue_digest(governance_root, catalogue),
        },
        "required_surfaces": _required_surfaces(floor),
        "prohibited_surfaces": [],
        "transitional_surfaces": _transitional_surfaces(),
    }


def _catalogue_digest(governance_root: Path, catalogue: object) -> str:
    if str(governance_root) not in sys.path:
        sys.path.insert(0, str(governance_root))
    from kernel_adoption_control.surface import catalogue_digest

    return catalogue_digest(
        version=catalogue.version,  # type: ignore[attr-defined]
        revision=catalogue.revision,  # type: ignore[attr-defined]
        supported=catalogue.supported,  # type: ignore[attr-defined]
        internal=catalogue.internal,  # type: ignore[attr-defined]
        root_exports=catalogue.root_exports,  # type: ignore[attr-defined]
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--governance-root", required=True, type=Path)
    parser.add_argument("--declared-at", required=True)
    parser.add_argument(
        "--source-predecessor",
        required=True,
        help="a commit this declaration's own commit will descend from",
    )
    arguments = parser.parse_args(argv)
    document = build(
        arguments.governance_root,
        arguments.declared_at,
        arguments.source_predecessor,
    )
    DECLARATION.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {DECLARATION.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
