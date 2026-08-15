"""The shadow-overlap exception states enforceable premises, or it is not one.

`vendor_cp.shadow_overlaps` lets exactly two kernel-gate violations through:
`public.allocations` and `public.allocation_entries` shadow the composed
`mod_ealloc` schema. An exception like that is only legitimate while the reasons
it gives are true, and ADR-0018 is explicit that a guard exemption must state an
ENFORCEABLE premise — otherwise the region is unmonitored, not exempt.

So each premise gets a test:

* **one writer at every instant** — nothing under `src/` imports the module's
  write surface, so the legacy service cannot have quietly acquired a rival;
* **no new legacy writer paths** — the set of modules touching the legacy
  allocation models is exact, so a new caller fails the build;
* **it names what removes it** — the cutover gate referenced actually exists in
  the checked-in architecture document;
* **it expires** — a review date that fails loudly rather than a comment nobody
  re-reads.

The live half of the ratchet — that the database really does report these two
overlaps and no others — lives in
`tests/migration/test_composed_live_catalog.py`, because it needs a migrated
database.
"""

from __future__ import annotations

import ast
from datetime import date
from pathlib import Path

from vendor_cp.shadow_overlaps import (
    AUTHORITATIVE_WRITER,
    DECLARED_OVERLAP_COUNT,
    LEGACY_ALLOCATION_CALL_SITES,
    MODULE_IMPORTS_ALLOWED_DURING_SHADOW,
    MODULE_WRITE_SURFACE,
    REVIEW_BY,
    SHADOW_OVERLAPS,
    overlapped_legacy_tables,
)

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
PACKAGE = SRC / "vendor_cp"

LEGACY_MODELS_MODULE = "vendor_cp.allocations.models"
MODULE_PACKAGE = "dotmac_entitlement_allocation"


def _source_files() -> list[Path]:
    return [p for p in PACKAGE.rglob("*.py") if "__pycache__" not in p.parts]


def _imports_from(path: Path, module: str) -> set[str]:
    """Names imported from `module` by this file (empty when it imports none)."""
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.ImportFrom) and node.module == module:
            names.update(alias.name for alias in node.names)
    return names


def test_the_declaration_covers_exactly_two_pairs() -> None:
    """A third overlap is a new fact needing a new decision, not a list entry."""
    assert len(SHADOW_OVERLAPS) == DECLARED_OVERLAP_COUNT == 2
    assert overlapped_legacy_tables() == {
        "public.allocations",
        "public.allocation_entries",
    }
    assert {overlap.module_table for overlap in SHADOW_OVERLAPS} == {
        "mod_ealloc.allocations",
        "mod_ealloc.allocation_entries",
    }
    assert all(
        overlap.authoritative_writer == AUTHORITATIVE_WRITER
        for overlap in SHADOW_OVERLAPS
    )


def test_the_legacy_writer_is_still_the_only_writer() -> None:
    """The premise the whole exception rests on.

    Shadow composition is a migration phase with ONE authoritative writer. The
    enforceable form of that is: no vendor code imports the module's write
    surface. `stage_allocation` appearing anywhere under `src/` means a second
    writer exists, at which point this exception is describing a state that
    ended.
    """
    writers = sorted(
        f"{path.relative_to(SRC).as_posix()}: {sorted(used)}"
        for path in _source_files()
        if (used := _imports_from(path, MODULE_PACKAGE) & MODULE_WRITE_SURFACE)
    )
    assert not writers, (
        "the composed module's write surface is imported, so the legacy service "
        "is no longer the only allocation writer — retire the legacy writer and "
        f"delete `vendor_cp.shadow_overlaps` instead: {writers}"
    )


def test_module_imports_stay_inside_the_shadow_allowlist() -> None:
    """What vendor code may take from the module while the legacy writer owns
    the data: composition handles, the typed catalogue port, its errors and the
    read helpers. Anything else is the cutover starting without being declared."""
    unexpected = sorted(
        f"{path.relative_to(SRC).as_posix()}: {sorted(extra)}"
        for path in _source_files()
        if (
            extra := _imports_from(path, MODULE_PACKAGE)
            - MODULE_IMPORTS_ALLOWED_DURING_SHADOW
        )
    )
    assert not unexpected, f"undeclared import from {MODULE_PACKAGE}: {unexpected}"


def test_no_new_call_sites_against_the_legacy_allocation_tables() -> None:
    """Exact set, so it ratchets in both directions.

    A NEW importer fails: new work belongs on the module's boundary, not on
    tables scheduled for retirement. A REMOVED one also fails, because that is
    cutover progress and the declaration should record it in the same change.
    """
    actual = {
        path.relative_to(SRC).as_posix()
        for path in _source_files()
        if _imports_from(path, LEGACY_MODELS_MODULE)
    }
    assert actual == LEGACY_ALLOCATION_CALL_SITES, (
        "the set of modules touching the legacy allocation models changed; "
        "update LEGACY_ALLOCATION_CALL_SITES in the same change, and justify "
        f"any addition: {sorted(actual ^ LEGACY_ALLOCATION_CALL_SITES)}"
    )


def test_the_call_site_detector_would_notice_a_new_importer(tmp_path: Path) -> None:
    """SENSITIVITY. A ratchet that cannot see a violation is a comment.

    Writes a probe module that imports the legacy models and proves the same
    reader reports it — without adding it to the package, so the real assertion
    above stays honest.
    """
    probe = tmp_path / "probe.py"
    probe.write_text(f"from {LEGACY_MODELS_MODULE} import Allocation\n")
    assert _imports_from(probe, LEGACY_MODELS_MODULE) == {"Allocation"}

    clean = tmp_path / "clean.py"
    clean.write_text("x = 1\n")
    assert _imports_from(clean, LEGACY_MODELS_MODULE) == set()


def test_every_overlap_names_a_gate_that_actually_exists() -> None:
    """An exception whose end is a phrase nobody can find is a permanent one."""
    architecture = (ROOT / "docs" / "ARCHITECTURE.md").read_text()
    assert "Allocation cutover gate" in architecture
    assert "the legacy models, service, FK and writer path are retired" in architecture

    for overlap in SHADOW_OVERLAPS:
        assert "Allocation cutover gate" in overlap.retired_by
        assert "ARCHITECTURE.md" in overlap.retired_by


def test_the_declaration_has_not_outlived_its_review_date() -> None:
    """The expiry, as a loud failure rather than a silent lapse.

    Deliberately NOT an auto-disable: a date that quietly switches a gate back on
    would break the build for a reason nobody connects to this file, and a date
    that quietly switches it OFF would be worse. It fails here, naming the
    cutover, so the overlap is either retired or re-justified by a person.
    """
    assert date.today() <= REVIEW_BY, (
        f"the allocation shadow overlap passed its review date ({REVIEW_BY}). "
        "Either the cutover gate in docs/ARCHITECTURE.md has completed — in "
        "which case delete `vendor_cp.shadow_overlaps` — or it has not, and the "
        "exception needs re-justifying with a new date and a reason it slipped."
    )
