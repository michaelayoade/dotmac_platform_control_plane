"""The ADR-0028 proof, now that a selectable module is actually composed.

The contract PR could assert only half of this and said so: the four-fact proof
needs a SELECTABLE module, and none was composed then. `dotmac-approvals` is, so
the proof it deferred is written here, against a real migrated database.

All four facts, about ONE database:

1. kernel `0001` created `public.tenants` and `public.app_current_tenant_id()`;
2. this assembly explicitly selected `ModulePlane.PLATFORM` for `approvals`;
3. every `mod_approvals` PLATFORM table exists;
4. no `mod_approvals` TENANT table exists.

Facts 1 and 4 together are the whole point, and neither alone would do. A control
plane with no tenant catalogue would also lack tenant approval tables and would
prove nothing about which mechanism kept them out; a control plane that simply
never installed the module would prove nothing at all. Under kernel a60 this
combination was unrepresentable — a bound catalogue WAS the instruction to build
the tenant plane.

Table names are imported from `dotmac_approvals.models`, never retyped: a proof
that the tenant tables are absent must read the module's real list, or it keeps
passing after the module renames one.
"""

from __future__ import annotations

from alembic import command
from dotmac_approvals.models import PLATFORM_TABLES, TENANT_TABLES
from dotmac_kernel.planes import ModulePlane
from dotmac_kernel.prerequisites import TENANT_SCOPE_CATALOG_V1
from sqlalchemy import create_engine, text

from vendor_cp.assembly import build_spec
from vendor_cp.migration_bindings import (
    ASSEMBLY_MODULE_PLANES,
    ASSEMBLY_PREREQUISITE_BINDINGS,
)
from vendor_cp.migrations import make_alembic_config

APPROVALS_SCHEMA = "mod_approvals"


def _upgrade(url: str, target: str = "heads") -> None:
    command.upgrade(make_alembic_config(url), target)


def _scalar(url: str, statement: str, **params: object) -> object:
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            return conn.execute(text(statement), params).scalar()
    finally:
        engine.dispose()


def _relation_exists(url: str, schema: str, table: str) -> bool:
    return bool(
        _scalar(
            url,
            "SELECT to_regclass(:qualified) IS NOT NULL",
            qualified=f"{schema}.{table}",
        )
    )


def test_a_bound_tenant_catalogue_installs_only_the_selected_platform_plane(
    scratch_db: str,
) -> None:
    """The combination kernel a60 could not express."""
    _upgrade(scratch_db)

    # 1. The tenant catalogue is REALLY here — kernel 0001 built it — and this
    #    assembly binds it, truthfully.
    assert _relation_exists(scratch_db, "public", "tenants")
    assert _scalar(
        scratch_db,
        "SELECT to_regprocedure('public.app_current_tenant_id()') IS NOT NULL",
    )
    assert TENANT_SCOPE_CATALOG_V1.name in {
        binding.prerequisite for binding in ASSEMBLY_PREREQUISITE_BINDINGS
    }

    # 2. And the assembly selected the platform plane, explicitly.
    selected = {
        ModulePlane(plane)
        for selection in ASSEMBLY_MODULE_PLANES
        if selection.module == "approvals"
        for plane in selection.planes
    }
    assert selected == {ModulePlane.PLATFORM}

    # 3. The selected plane was built.
    missing = [
        table
        for table in PLATFORM_TABLES
        if not _relation_exists(scratch_db, APPROVALS_SCHEMA, table)
    ]
    assert not missing, f"selected PLATFORM approval tables are absent: {missing}"

    # 4. The unselected plane was not — despite its prerequisite being bound.
    built = [
        table
        for table in TENANT_TABLES
        if _relation_exists(scratch_db, APPROVALS_SCHEMA, table)
    ]
    assert not built, (
        "tenant approval tables exist in a control plane that never selected "
        f"the tenant plane: {built}"
    )


def test_the_proof_is_reading_real_table_names(scratch_db: str) -> None:
    """SENSITIVITY. Fact 4 is an ABSENCE, and an absence is also what a typo
    produces. So: both lists are non-empty and disjoint, and the same reader that
    reports the tenant tables missing finds the platform tables present."""
    assert TENANT_TABLES and PLATFORM_TABLES
    assert not set(TENANT_TABLES) & set(PLATFORM_TABLES)

    _upgrade(scratch_db)
    assert _relation_exists(scratch_db, APPROVALS_SCHEMA, PLATFORM_TABLES[0])
    assert not _relation_exists(scratch_db, APPROVALS_SCHEMA, TENANT_TABLES[0])


def test_the_spec_carries_the_selection_the_database_reflects() -> None:
    """Kernel-side validation runs on what the SPEC declares. A selection living
    only in `migration_bindings` would order migrations correctly and still let
    `create_app` compose a selectable module with no stated intent."""
    assert tuple(build_spec().module_planes) == ASSEMBLY_MODULE_PLANES


def test_the_legacy_tables_are_gone_and_were_not_replaced_in_place(
    scratch_db: str,
) -> None:
    """The authority switched, and the plane selection still holds.

    This test asserted the opposite during the shadow phase — that the legacy
    `public` tables were untouched — which was right then and is wrong now: v013
    dropped them along with the writer that owned them.

    The half that does NOT change is the interesting one. The module's TENANT
    tables share their names with the legacy ones (`approval_policies`,
    `approval_records`), so "the legacy tables are gone" could equally describe
    the module's tenant plane having been built over them. It was not: the
    selection is PLATFORM-only, so those names now exist in neither namespace.
    """
    _upgrade(scratch_db)
    assert not _relation_exists(scratch_db, "public", "approval_policies")
    assert not _relation_exists(scratch_db, "public", "approval_records")
    assert not _relation_exists(scratch_db, APPROVALS_SCHEMA, "approval_policies")
    assert not _relation_exists(scratch_db, APPROVALS_SCHEMA, "approval_records")

    # And the plane that WAS selected is present, so these are not four absences
    # produced by nothing having been installed at all.
    assert _relation_exists(scratch_db, APPROVALS_SCHEMA, "platform_approval_requests")
