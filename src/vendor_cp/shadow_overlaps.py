"""Legacy tables that shadow a composed module's schema, during ONE migration.

`dotmac-entitlement-allocation` owns `mod_ealloc.allocations` and
`mod_ealloc.allocation_entries`. This assembly also has `public.allocations` and
`public.allocation_entries`, created by vendor migration `v005` long before the
module existed. The kernel's live-catalogue gate reports that overlap, and it is
RIGHT to: a module table sitting in the host compatibility namespace is normally
a module that failed to move into its own schema.

Here it is something else — the observable footprint of an authority migration
that is deliberately unfinished. This module is the assembly-local declaration of
that state, and it is written to expire.

## What this is NOT

**Not a dual-authority design.** There is exactly ONE writer at every instant,
and it is the legacy one: `vendor_cp.allocations.service`. The module is composed
for its schema, its lineage and its typed boundary; nothing here calls its write
surface, and `mod_ealloc` stays empty until the cutover. The same rule the owner
applied to Approvals applies here — shadow is a bounded migration phase with one
authoritative writer, never parallel operation.

**Not a kernel relaxation.** The gate is untouched. Every other assembly still
fails on a host squatter, as it should; only this assembly, for exactly these two
pairs, subtracts a violation it has declared, justified and dated. Weakening the
kernel to solve one product's migration would disarm the check fleet-wide.

**Not a rename.** The obvious way to make the gate quiet is to rename
`public.allocations` out of the module's namespace. That hides a real migration
state behind cosmetics, so the overlap stays visible until the cutover retires
it.

**Not a precedent.** Approvals is not composed and stays blocked on its own
cutover contract. This declaration covers two named tables of one module.

## What removes it

`docs/ARCHITECTURE.md` § "Allocation cutover gate", step 4: the activation
adapter constructs the module's `ContractSnapshot`, the consumer switches once,
licence issuance reads `allocation_product()`, and **the legacy models, service,
FK and writer path are retired after parity**. That retirement drops these two
`public` tables, the overlap disappears, and this module is deleted rather than
edited. `preflight_allocation_cutover` is the read-only proof for steps 1-3.

## Why the ratchet runs in both directions

`tests/migration/test_composed_live_catalog.py` asserts the LIVE overlap set
equals this declaration exactly. Rising fails: a third overlap is a new fact that
needs its own decision, not a quiet addition to a list. Falling also fails: if a
table stops overlapping, someone finished part of a cutover, and the declaration
must be lowered in that same change. A backlog that silently shrinks is how
"temporary" becomes permanent with nobody having decided anything.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Final

#: The one module whose schema is shadowed. Named so a second module appearing
#: here is a visible decision rather than another tuple entry.
SHADOWED_MODULE: Final[str] = "entitlement_allocation"

#: The single authoritative writer, for the whole duration of this state.
AUTHORITATIVE_WRITER: Final[str] = "vendor_cp.allocations.service"

#: The checked-in gate whose completion deletes this module.
RETIRED_BY: Final[str] = (
    "docs/ARCHITECTURE.md § 'Allocation cutover gate' step 4 — the legacy "
    "models, service, FK and writer path are retired after parity"
)

#: Review-by date. NOT an auto-expiry: nothing here silently stops working on a
#: date, because a lapsed exception that disables a gate is worse than the
#: exception. It is the point at which the overlap must be re-justified or the
#: cutover re-planned, and the test failure names it.
REVIEW_BY: Final[date] = date(2026, 11, 30)


@dataclass(frozen=True, slots=True)
class ShadowOverlap:
    """One legacy table shadowing one module table, with its justification."""

    legacy_table: str
    module_table: str
    authoritative_writer: str
    retired_by: str

    def __post_init__(self) -> None:
        for qualified in (self.legacy_table, self.module_table):
            if qualified.count(".") != 1:
                raise ValueError(
                    f"{qualified!r} must be schema-qualified — an unqualified "
                    "name cannot say which plane it names"
                )
        if not self.legacy_table.startswith("public."):
            raise ValueError(
                f"{self.legacy_table!r} is not in the host compatibility "
                "namespace, so it is not shadowing anything"
            )
        if self.legacy_table.split(".", 1)[1] != self.module_table.split(".", 1)[1]:
            raise ValueError(
                "a shadow overlap is the SAME table name in two schemas; "
                f"{self.legacy_table!r} and {self.module_table!r} differ"
            )
        if not self.retired_by.strip():
            raise ValueError(
                f"{self.legacy_table!r} needs the gate that removes it — an "
                "exception with no named end is a permanent one"
            )


#: EXACTLY these two pairs. Both were created by vendor migration `v005`, both
#: are read and written today by `vendor_cp.allocations.service`, and both
#: disappear together when the cutover retires the legacy writer.
SHADOW_OVERLAPS: Final[tuple[ShadowOverlap, ...]] = (
    ShadowOverlap(
        legacy_table="public.allocations",
        module_table="mod_ealloc.allocations",
        authoritative_writer=AUTHORITATIVE_WRITER,
        retired_by=RETIRED_BY,
    ),
    ShadowOverlap(
        legacy_table="public.allocation_entries",
        module_table="mod_ealloc.allocation_entries",
        authoritative_writer=AUTHORITATIVE_WRITER,
        retired_by=RETIRED_BY,
    ),
)

#: The ratchet's declared height, spelled out rather than derived from `len()`.
#: A number someone has to edit is a number someone has to think about; `len()`
#: of the tuple above would move silently with it.
DECLARED_OVERLAP_COUNT: Final[int] = 2

#: Every `vendor_cp` module permitted to touch the LEGACY allocation tables.
#: This is requirement "no new legacy writer paths" made enforceable: the set is
#: exact, so a new importer fails and a removed one fails too.
#:
#: `service` is the writer. `preflight` reads them to audit cutover readiness and
#: is documented as never mutating a legacy row. `licensing.service` reads an
#: allocation to issue against it. Nothing else may join this list — a new caller
#: belongs on the module's boundary, not on the legacy models.
LEGACY_ALLOCATION_CALL_SITES: Final[frozenset[str]] = frozenset(
    {
        "vendor_cp/allocations/service.py",
        "vendor_cp/allocations/preflight.py",
        "vendor_cp/licensing/service.py",
    }
)

#: Names from the composed module that vendor code imports today. This is the
#: EXACT current set, not a permit for what the cutover will eventually need.
#:
#: It previously pre-authorised `ContractSnapshot`, `allocation_product` and
#: `snapshot_fingerprint` — the three names the cutover actually turns on. That
#: made the ratchet useless in the one direction that matters: the activation
#: adapter could be built, the consumer switched and licence issuance repointed,
#: all without a single guard moving. A name is added here in the change that
#: starts using it, which is the change that should be arguing for it.
#:
#: `stage_allocation` is absent and stays absent: it is the module's WRITE
#: surface, and importing it is how a second writer appears without anyone
#: deciding to create one.
MODULE_IMPORTS_ALLOWED_DURING_SHADOW: Final[frozenset[str]] = frozenset(
    {
        "AllocationError",
        "CapabilityCatalogueReader",
        "UndeclaredCapabilityError",
        "UnknownProductError",
        "module",
        "versions_dir",
    }
)

#: The module's write surface. Importing any of these anywhere under `src/`
#: means the module has started writing, which ends this shadow state — at which
#: point the legacy writer must already be retired, not merely quieter.
MODULE_WRITE_SURFACE: Final[frozenset[str]] = frozenset({"stage_allocation"})

#: The composed module's importable package. Vendor code may use its top-level
#: PUBLIC surface and nothing below it: reaching into `…​.service` bypasses the
#: name allowlist above and is how the write surface arrives under another name.
MODULE_PACKAGE: Final[str] = "dotmac_entitlement_allocation"

#: The legacy models module. Any reference to it, in any import form, is a call
#: site against tables scheduled for retirement.
LEGACY_MODELS_MODULE: Final[str] = "vendor_cp.allocations.models"


def overlapped_legacy_tables() -> frozenset[str]:
    """`{'public.allocations', ...}` — what the live gate is expected to report."""
    return frozenset(overlap.legacy_table for overlap in SHADOW_OVERLAPS)


def overlap_for(legacy_table: str) -> ShadowOverlap | None:
    for overlap in SHADOW_OVERLAPS:
        if overlap.legacy_table == legacy_table:
            return overlap
    return None


__all__ = [
    "AUTHORITATIVE_WRITER",
    "LEGACY_MODELS_MODULE",
    "MODULE_PACKAGE",
    "DECLARED_OVERLAP_COUNT",
    "LEGACY_ALLOCATION_CALL_SITES",
    "MODULE_IMPORTS_ALLOWED_DURING_SHADOW",
    "MODULE_WRITE_SURFACE",
    "RETIRED_BY",
    "REVIEW_BY",
    "SHADOWED_MODULE",
    "SHADOW_OVERLAPS",
    "ShadowOverlap",
    "overlap_for",
    "overlapped_legacy_tables",
]
