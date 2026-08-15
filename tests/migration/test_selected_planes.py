"""The ADR-0028 proof: a bound tenant catalogue that installs no tenant plane.

Kernel `0.1.0a60` derived a module's installed planes from prerequisite
availability. Under that model this assembly had exactly two options, and both
were wrong:

* bind `tenant_scope_catalog.v1` — truthful, since kernel `0001` really does
  create `public.tenants` here — and thereby install tenant approval tables in a
  control plane that has no tenants to scope them to; or
* withhold the binding to keep them out, which states something false about the
  database in order to get the right DDL.

`a61` separates *where an effect comes from* from *what this product installs*.
The test below is the one that could not be written before, because it asserts
all four facts about a single migrated database at once:

1. kernel `0001` created `public.tenants` and `public.app_current_tenant_id()`;
2. this assembly explicitly selected `ModulePlane.PLATFORM` for `approvals`;
3. every `mod_approvals` PLATFORM table exists;
4. no `mod_approvals` TENANT table exists.

Facts 1 and 4 together are the whole point. Either alone is unremarkable — a
control plane without a tenant catalogue would also lack tenant approval tables,
and would prove nothing about which mechanism kept them out.

Table names are imported from `dotmac_approvals.models`, never retyped: a proof
that the tenant tables are absent must be reading the module's real list, or it
would keep passing after the module renamed one.
"""

from __future__ import annotations

from alembic import command
from dotmac_approvals.models import PLATFORM_TABLES, TENANT_TABLES
from dotmac_kernel.planes import ModulePlane
from sqlalchemy import create_engine, text

from vendor_cp.migration_bindings import ASSEMBLY_MODULE_PLANES
from vendor_cp.migrations import make_alembic_config

APPROVALS_SCHEMA = "mod_approvals"


def _upgrade(url: str, target: str = "heads") -> None:
    command.upgrade(make_alembic_config(url), target)


def _exists(url: str, statement: str, **params: object) -> bool:
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            return bool(conn.execute(text(statement), params).scalar())
    finally:
        engine.dispose()


def _relation_exists(url: str, schema: str, table: str) -> bool:
    return _exists(
        url,
        "SELECT to_regclass(:qualified) IS NOT NULL",
        qualified=f"{schema}.{table}",
    )


def test_a_bound_tenant_catalogue_installs_only_the_selected_platform_plane(
    scratch_db: str,
) -> None:
    _upgrade(scratch_db)

    # 1. The tenant catalogue is REALLY here — kernel 0001 built it.
    assert _relation_exists(scratch_db, "public", "tenants")
    assert _exists(
        scratch_db,
        "SELECT to_regprocedure('public.app_current_tenant_id()') IS NOT NULL",
    )

    # 2. And this assembly selected the platform plane, explicitly.
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
    """SENSITIVITY. Fact 4 is an absence, and an absence is exactly what a typo
    also produces. Assert the two name lists are non-empty and disjoint, so
    "no tenant table exists" cannot be true merely because the list was empty
    or because it accidentally names the platform tables."""
    assert TENANT_TABLES and PLATFORM_TABLES
    assert not set(TENANT_TABLES) & set(PLATFORM_TABLES)

    # And that the absence check can see a table when there IS one: the platform
    # names come from the same module list and are found by the same reader.
    _upgrade(scratch_db)
    assert _relation_exists(scratch_db, APPROVALS_SCHEMA, PLATFORM_TABLES[0])


def test_the_vendor_local_approval_tables_are_untouched(scratch_db: str) -> None:
    """The module is composed in SHADOW. `vendor_cp.approvals` remains the
    authoritative writer, so its `public` tables must still be there — and must
    not have been silently replaced by the module's identically-named tenant
    tables, which live in `mod_approvals` and were not built."""
    _upgrade(scratch_db)
    assert _relation_exists(scratch_db, "public", "approval_policies")
    assert _relation_exists(scratch_db, "public", "approval_records")
    assert not _relation_exists(scratch_db, APPROVALS_SCHEMA, "approval_policies")
