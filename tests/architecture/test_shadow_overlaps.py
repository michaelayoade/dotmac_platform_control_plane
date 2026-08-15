"""The shadow-overlap exception states enforceable premises, or it is not one.

`vendor_cp.shadow_overlaps` lets exactly two kernel-gate violations through:
`public.allocations` and `public.allocation_entries` shadow the composed
`mod_ealloc` schema. An exception like that is only legitimate while the reasons
it gives are true, and ADR-0018 is explicit that a guard exemption must state an
ENFORCEABLE premise — otherwise the region is unmonitored, not exempt.

So each premise gets a test:

* **one writer at every instant** — nothing under `src/` imports the module's
  write surface or reaches past its public package, so the legacy service cannot
  have quietly acquired a rival;
* **no new legacy writer paths** — the set of modules touching the legacy
  allocation models is exact, so a new caller fails the build;
* **the permitted imports are the ACTUAL imports** — not a pre-authorisation of
  what the cutover will need, which would let the cutover proceed without the
  ratchet ever moving;
* **it names what removes it** — the cutover gate referenced actually exists in
  the checked-in architecture document;
* **it expires** — a review date that fails loudly rather than a comment nobody
  re-reads.

Every scan goes through `import_scanner`, which handles `import x`,
`import x as y`, `from x import y`, `from x import y as z`, `from x.sub import
y`, `from . import y` and `from .. import y`. The earlier version of this file
matched only `from <exact module> import <name>`, so every other form could
introduce a second writer while this exemption stayed green;
`test_import_scanner.py` is the per-form mutation proof.

The live half of the ratchet — that the database really does report these two
overlaps and no others — lives in
`tests/migration/test_composed_live_catalog.py`, because it needs a migrated
database.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

from import_scanner import (
    names_from,
    reaches_module,
    scan_imports,
    source_files,
    submodule_reach_ins,
)

from vendor_cp.shadow_overlaps import (
    AUTHORITATIVE_WRITER,
    DECLARED_OVERLAP_COUNT,
    LEGACY_ALLOCATION_CALL_SITES,
    LEGACY_MODELS_MODULE,
    MODULE_IMPORTS_ALLOWED_DURING_SHADOW,
    MODULE_PACKAGE,
    MODULE_WRITE_SURFACE,
    REVIEW_BY,
    SHADOW_OVERLAPS,
    overlapped_legacy_tables,
)

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
PACKAGE = SRC / "vendor_cp"


def _refs(path: Path):
    return scan_imports(path, source_root=SRC)


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

    Shadow composition is a migration phase with ONE authoritative writer, so no
    vendor code may take the module's write surface — under any name, from the
    package or from a submodule.
    """
    writers = sorted(
        f"{path.relative_to(SRC).as_posix()}: {sorted(taken)}"
        for path in source_files(PACKAGE)
        if (taken := names_from(_refs(path), MODULE_PACKAGE) & MODULE_WRITE_SURFACE)
    )
    assert not writers, (
        "the composed module's write surface is imported, so the legacy service "
        "is no longer the only allocation writer — retire the legacy writer and "
        f"delete `vendor_cp.shadow_overlaps` instead: {writers}"
    )


def test_no_source_file_reaches_past_the_module_public_surface() -> None:
    """The other half of the one-writer premise.

    A name allowlist on the package alone is bypassed by
    `from dotmac_entitlement_allocation.service import stage_allocation`, which
    takes the write surface without naming it at the package level. Reaching into
    ANY submodule is refused, so the allowlist cannot be routed around.
    """
    reach_ins = sorted(
        f"{path.relative_to(SRC).as_posix()}: {sorted(found)}"
        for path in source_files(PACKAGE)
        if (found := submodule_reach_ins(_refs(path), MODULE_PACKAGE))
    )
    assert not reach_ins, (
        f"vendor code may use only the top-level {MODULE_PACKAGE} surface; "
        f"reaching into a submodule bypasses the import allowlist: {reach_ins}"
    )


def test_module_imports_stay_inside_the_shadow_allowlist() -> None:
    """What vendor code may take from the module while the legacy writer owns
    the data. Anything else is the cutover starting without being declared."""
    unexpected = sorted(
        f"{path.relative_to(SRC).as_posix()}: {sorted(extra)}"
        for path in source_files(PACKAGE)
        if (
            extra := names_from(_refs(path), MODULE_PACKAGE)
            - MODULE_IMPORTS_ALLOWED_DURING_SHADOW
        )
    )
    assert not unexpected, f"undeclared import from {MODULE_PACKAGE}: {unexpected}"


def test_the_allowlist_holds_no_name_nobody_imports() -> None:
    """The allowlist is a RATCHET, so it may not run ahead of the code.

    It previously pre-authorised the three names the cutover turns on
    (`ContractSnapshot`, `allocation_product`, `snapshot_fingerprint`), which
    meant the activation adapter could be built and the consumer switched with
    this guard never moving. Exact equality forces that argument to happen in the
    change that needs the name.
    """
    actually_imported: set[str] = set()
    for path in source_files(PACKAGE):
        actually_imported |= names_from(_refs(path), MODULE_PACKAGE)
    assert actually_imported == set(MODULE_IMPORTS_ALLOWED_DURING_SHADOW), (
        "the permitted-import set must equal what the code imports; a "
        "pre-authorised name lets the cutover begin without moving this ratchet: "
        f"{sorted(set(MODULE_IMPORTS_ALLOWED_DURING_SHADOW) ^ actually_imported)}"
    )


def test_no_new_call_sites_against_the_legacy_allocation_tables() -> None:
    """Exact set, so it ratchets in both directions.

    A NEW importer fails: new work belongs on the module's boundary, not on
    tables scheduled for retirement. A REMOVED one also fails, because that is
    cutover progress and the declaration should record it in the same change.
    """
    actual = {
        path.relative_to(SRC).as_posix()
        for path in source_files(PACKAGE)
        if reaches_module(_refs(path), LEGACY_MODELS_MODULE)
    }
    assert actual == LEGACY_ALLOCATION_CALL_SITES, (
        "the set of modules touching the legacy allocation models changed; "
        "update LEGACY_ALLOCATION_CALL_SITES in the same change, and justify "
        f"any addition: {sorted(actual ^ LEGACY_ALLOCATION_CALL_SITES)}"
    )


def test_these_guards_are_not_vacuous() -> None:
    """NON-VACUITY for every scan above.

    Each guard is an assertion that a computed set is empty or equals a declared
    one, and a scanner that silently returned nothing would satisfy most of them.
    So: the declared sets are non-empty, and the scanner really does find imports
    in real source files.
    """
    assert LEGACY_ALLOCATION_CALL_SITES
    assert MODULE_IMPORTS_ALLOWED_DURING_SHADOW
    assert MODULE_WRITE_SURFACE

    files = source_files(PACKAGE)
    assert len(files) > 30, "the source sweep found almost no files"
    with_imports = [path for path in files if _refs(path)]
    assert len(with_imports) > 20, "the scanner found almost no imports"

    # And it really is reading THIS package's module surface, not an empty set.
    seen: set[str] = set()
    for path in files:
        seen |= names_from(_refs(path), MODULE_PACKAGE)
    assert seen, f"no import from {MODULE_PACKAGE} was observed at all"


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

    Deliberately NOT an auto-disable: a date that quietly switched a gate back on
    would break the build for a reason nobody connects to this file, and one that
    quietly switched it OFF would be worse. It fails here, naming the cutover, so
    the overlap is either retired or re-justified by a person.
    """
    assert date.today() <= REVIEW_BY, (
        f"the allocation shadow overlap passed its review date ({REVIEW_BY}). "
        "Either the cutover gate in docs/ARCHITECTURE.md has completed — in "
        "which case delete `vendor_cp.shadow_overlaps` — or it has not, and the "
        "exception needs re-justifying with a new date and a reason it slipped."
    )
