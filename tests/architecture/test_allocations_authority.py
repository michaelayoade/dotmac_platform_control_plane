"""The module owns allocations, and the legacy writer is gone for good.

Vendor CP now has no local writer for release artifacts, approvals or
allocations. This holds the last of those at zero, and — more usefully — keeps
the ALLOCATION DATA surface confined to the adapter while leaving the catalogue
PORT freely importable, because those are different things that happen to live in
one distribution.

* `CapabilityCatalogueReader` and the typed errors are a boundary CONTRACT: the
  commercial services accept a catalogue and map its refusals to HTTP. Any module
  may name them.
* `stage_allocation`, `allocation_product` and the ORM types are the AUTHORITY's
  surface. Only the adapter may name them, or the seam is not a seam.
"""

from __future__ import annotations

import ast
from pathlib import Path

from import_scanner import reaches_module, scan_imports, source_files

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
PACKAGE = SRC / "vendor_cp"

MODULE = "dotmac_entitlement_allocation"
ADAPTER = "vendor_cp/allocations/adapter.py"

#: Retired with the switch. Named so the ratchet has something to look for.
RETIRED_MODULES = (
    "vendor_cp.allocations.service",
    "vendor_cp.allocations.models",
    "vendor_cp.allocations.preflight",
)

#: The allocation AUTHORITY surface — permitted in the adapter alone.
AUTHORITY_NAMES = frozenset(
    {
        "stage_allocation",
        "allocation_product",
        "snapshot_fingerprint",
        "Allocation",
        "AllocationEntry",
        "AllocationView",
        "AllocatedCapability",
        "AllocationStatus",
        "STAGED",
        "ContractSnapshot",
        "ContractEntitlement",
    }
)

#: The catalogue PORT and composition handles — importable anywhere.
PORT_NAMES = frozenset(
    {
        "CapabilityCatalogueReader",
        "AllocationError",
        "AllocationConflictError",
        "DuplicateCapabilityError",
        "EmptyAllocationError",
        "IncompleteAllocationError",
        "UndeclaredCapabilityError",
        "UnknownProductError",
        "module",
        "versions_dir",
    }
)


def _refs(path: Path):
    return scan_imports(path, source_root=SRC)


def _names_from_module(path: Path) -> set[str]:
    return {
        ref.name
        for ref in _refs(path)
        if ref.name is not None
        and ref.module
        and (ref.module == MODULE or ref.module.startswith(f"{MODULE}."))
    }


def test_the_legacy_allocation_writer_no_longer_exists() -> None:
    for name in ("service.py", "models.py", "preflight.py"):
        assert not (PACKAGE / "allocations" / name).exists(), name


def test_no_source_file_calls_the_retired_modules() -> None:
    """Zero, and it stays zero."""
    callers = sorted(
        f"{path.relative_to(SRC).as_posix()} -> {module}"
        for path in source_files(PACKAGE)
        for module in RETIRED_MODULES
        if reaches_module(_refs(path), module)
    )
    assert callers == [], callers


def test_the_ratchet_can_still_see_a_caller(tmp_path: Path) -> None:
    """SENSITIVITY. An empty result is what this asserts, and a broken detector
    produces the same thing."""
    package = tmp_path / "src" / "vendor_cp" / "somewhere"
    package.mkdir(parents=True)
    probe = package / "probe.py"
    probe.write_text(f"from {RETIRED_MODULES[0]} import stage_allocation\n")
    assert reaches_module(
        scan_imports(probe, source_root=tmp_path / "src"), RETIRED_MODULES[0]
    )


def test_only_the_adapter_names_the_allocation_authority_surface() -> None:
    """The seam is a seam only if nothing routes around it."""
    offenders = sorted(
        f"{path.relative_to(SRC).as_posix()}: {sorted(taken)}"
        for path in source_files(PACKAGE)
        if path.relative_to(SRC).as_posix() != ADAPTER
        and (taken := _names_from_module(path) & AUTHORITY_NAMES)
    )
    assert not offenders, (
        "the allocation authority surface must be reached through "
        f"`{ADAPTER}` alone: {offenders}"
    )


def test_the_adapter_really_does_use_that_surface() -> None:
    """NON-VACUITY: if the adapter named none of it, the guard above would pass
    while the seam did nothing."""
    taken = _names_from_module(PACKAGE / "allocations" / "adapter.py")
    assert {"stage_allocation", "allocation_product"} <= taken


def test_the_adapter_exposes_no_unused_public_surface() -> None:
    """Every public adapter function has a real caller in this repository.

    An adapter function nobody calls is worse than dead code, because the
    documentation describes it as the path. `allocation_product()` shipped
    exactly like that: defined here, named in ARCHITECTURE.md and ADR-0006 as
    what licence issuance reads, and called by nothing — while issuance took the
    product from the caller's command instead. The prose said one authority; the
    code had two, and the prose is what stopped anyone looking.

    So an unused public function fails the build rather than the review.
    """
    adapter_path = PACKAGE / "allocations" / "adapter.py"
    tree = ast.parse(adapter_path.read_text())
    public = {
        node.name
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and not node.name.startswith("_")
    }
    assert public, "the adapter defines no public functions; this guard is vacuous"

    # Every identifier USED anywhere else in the package: attribute access
    # (`allocations.allocation_product(...)`, which is how licensing reaches it),
    # bare names, and imported aliases. `_names_from_module` is deliberately not
    # reused here — it reports names imported FROM the module, and would see
    # none of the attribute calls that are the adapter's actual usage shape.
    callers: set[str] = set()
    for path in source_files(PACKAGE):
        if path == adapter_path:
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Attribute):
                callers.add(node.attr)
            elif isinstance(node, ast.Name):
                callers.add(node.id)
            elif isinstance(node, ast.ImportFrom):
                callers.update(a.asname or a.name for a in node.names)

    unused = sorted(public - callers)
    assert not unused, (
        f"public adapter functions with no caller in {PACKAGE.name}: {unused}. "
        "Either wire them where the documentation says they are used, or remove "
        "them — an unused seam is a claim nothing keeps true."
    )


def test_the_catalogue_port_stays_importable() -> None:
    """The commercial services legitimately accept a catalogue and map its
    refusals. Confining THAT would be confining a boundary contract, not an
    authority — and would push those callers into re-declaring a protocol, which
    is the duplication ADR-0006 § 4 exists to avoid."""
    port_users = {
        path.relative_to(SRC).as_posix()
        for path in source_files(PACKAGE)
        if _names_from_module(path) & PORT_NAMES
    }
    assert "vendor_cp/contracts/adapter.py" in port_users
    assert "vendor_cp/offers/service.py" in port_users


def test_every_module_name_is_classified() -> None:
    """No third category. A name that is neither port nor authority is one
    nobody has decided about, and it would slip past both guards."""
    unclassified = sorted(
        f"{path.relative_to(SRC).as_posix()}: {name}"
        for path in source_files(PACKAGE)
        for name in _names_from_module(path)
        if name not in AUTHORITY_NAMES and name not in PORT_NAMES
    )
    assert not unclassified, unclassified


def test_the_adapter_is_typed_at_the_seam() -> None:
    source = (PACKAGE / "allocations" / "adapter.py").read_text()
    assert ": Any" not in source
    assert "-> Any" not in source


def test_offers_and_licensing_surfaces_stay_withheld() -> None:
    """Bootstrap still withholds the high-consequence delivery/issuer route and
    the Vendor-owned offer surface; persistence owners remain composed."""
    from vendor_cp.deployment_profile import PRODUCTION_BOOTSTRAP, deployment_profile

    withheld = deployment_profile(PRODUCTION_BOOTSTRAP).withheld_surfaces
    assert {"licence_delivery", "offers"} <= withheld
