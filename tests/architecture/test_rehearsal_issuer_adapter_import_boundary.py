"""`rehearsal_issuer_adapter.py` is a LEAF module -- held to it here.

It mirrors `host_admission_adapter.py`'s own boundary and reasoning: a
conformance suite for the rehearsal-issuer choreography should never need the
rest of the CP application's dependency closure just to import a handful of
Protocols and one orchestration function. `rehearsal_issuer.py` (the HEAVY
half, which queries the database through `plan_inputs`/`candidate`/`adapter`)
is deliberately kept OUT of this file for the identical reason `adapter.py`'s
operator workflow is kept out of `host_admission_adapter.py`.

So the boundary is an ALLOWLIST, not a blocklist naming `vendor_cp`,
`dotmac_deployment_control` and `dotmac_deployment_foundation` specifically:
an allowlist also catches a new, unrelated Dotmac package that a blocklist
would miss entirely. This leaf module needs no SQLAlchemy at all -- it
touches no database -- so its allowlist is narrower than
`host_admission_adapter.py`'s.
"""

from __future__ import annotations

from pathlib import Path

from import_scanner import module_targets, scan_imports

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
LEAF_MODULE = SRC / "vendor_cp" / "deployment" / "rehearsal_issuer_adapter.py"

#: Every top-level module the leaf file may reach. Stdlib it actually uses
#: today. A new stdlib import that is still stdlib is fine to add here; a new
#: dotmac_* or vendor_cp import is exactly what this test exists to catch.
ALLOWED_TOP_LEVEL_MODULES = frozenset(
    {
        "__future__",
        "collections",  # collections.abc.Mapping
        "dataclasses",
        "enum",
        "typing",
    }
)


def _top_level(module: str) -> str:
    return module.split(".", 1)[0]


def _offenders(targets: frozenset[str]) -> list[str]:
    return sorted(
        target
        for target in targets
        if _top_level(target) not in ALLOWED_TOP_LEVEL_MODULES
    )


def test_the_leaf_module_exists() -> None:
    """The premise: if this file moved or was renamed, every assertion below
    would be vacuously scanning nothing."""
    assert LEAF_MODULE.exists(), LEAF_MODULE


def test_the_leaf_module_reaches_no_vendor_cp_sibling_or_unreleased_dependency() -> (
    None
):
    """The whole point of keeping this a leaf: no `vendor_cp.*` sibling, no
    `dotmac_deployment_control`, no `dotmac_deployment_foundation`, no other
    Dotmac package, no SQLAlchemy -- only stdlib."""
    targets = module_targets(scan_imports(LEAF_MODULE, source_root=SRC))
    offenders = _offenders(targets)
    assert offenders == [], (
        f"vendor_cp/deployment/rehearsal_issuer_adapter.py reaches {offenders}, "
        "outside its declared leaf boundary (stdlib only) -- see its module "
        "docstring for why this file must stay import-light."
    )


def test_the_boundary_scan_can_see_a_planted_violation(tmp_path: Path) -> None:
    """SENSITIVITY. An allowlist scan that found nothing to object to over a
    real file could mean the boundary holds, or that the scanner cannot see a
    violation at all -- this proves the second reading false."""
    package = tmp_path / "src"
    package.mkdir()
    planted = package / "planted_leaf.py"
    planted.write_text(
        "from vendor_cp.deployment.plan_inputs import resolve_plan_inputs\n"
        "import dotmac_deployment_control\n"
        "import dotmac_deployment_foundation\n"
        "from dotmac_kernel import NotFoundError\n"
        "from sqlalchemy.orm import Session\n"
    )
    targets = module_targets(scan_imports(planted, source_root=package))
    assert _offenders(targets) == [
        "dotmac_deployment_control",
        "dotmac_deployment_foundation",
        "dotmac_kernel",
        "sqlalchemy.orm",
        "vendor_cp.deployment.plan_inputs",
    ]


def test_the_allowlist_is_not_vacuously_permissive(tmp_path: Path) -> None:
    """The other direction: a file that genuinely stays inside the boundary
    (stdlib only, every form the real leaf module actually uses) must report
    zero offenders, or the allowlist itself is wrong rather than the
    scanner."""
    package = tmp_path / "src"
    package.mkdir()
    clean = package / "clean_leaf.py"
    clean.write_text(
        "from __future__ import annotations\n"
        "from collections.abc import Mapping\n"
        "from dataclasses import dataclass, field\n"
        "from enum import StrEnum\n"
        "from typing import Final, Protocol\n"
    )
    targets = module_targets(scan_imports(clean, source_root=package))
    assert _offenders(targets) == []
