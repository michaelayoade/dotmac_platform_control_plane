"""What this assembly can honestly prove about planes today — and what it cannot.

## The full ADR-0028 proof is NOT here

The distinguishing proof of a61 needs four facts about one migrated database:
kernel `0001` created `public.tenants`; the assembly explicitly selected
`ModulePlane.PLATFORM` for a dual-plane module; that module's platform tables
exist; its tenant tables do not. Facts two through four require a SELECTABLE
module to be composed, and this bootstrap composes none. `dotmac-release-catalog`
and `dotmac-entitlement-allocation` each declare a single supported plane set, so
their contract is atomic and the kernel refuses a selection for them outright.

`dotmac-approvals` is the first selectable module Vendor will compose, and it
arrives with the cutover contract, not before it. **The four-fact proof lands in
that shadow-composition PR**, against `mod_approvals`. Anything asserted here
before then would be a test whose name promised more than its body checked.

## What IS proven here

The half that does not depend on a selectable module, and that still says
something a reviewer would otherwise take on trust: the tenant catalogue really
is present and really is bound, and no tenant-plane table exists anywhere in this
database's module schemas regardless. That combination is the state the a60 model
could not hold — under it a bound catalogue was itself the instruction to build
tenant tables.

It is deliberately NOT described as a proof of selection. Nothing here selects
anything yet.
"""

from __future__ import annotations

from alembic import command
from dotmac_kernel.prerequisites import TENANT_SCOPE_CATALOG_V1
from sqlalchemy import create_engine, text

from vendor_cp.assembly import build_spec
from vendor_cp.migration_bindings import (
    ASSEMBLY_MODULE_PLANES,
    ASSEMBLY_PREREQUISITE_BINDINGS,
)
from vendor_cp.migrations import make_alembic_config

MODULE_SCHEMAS = ("mod_ealloc", "mod_rel")

TENANT_SCOPED_MODULE_TABLES_SQL = (
    "SELECT c.relname FROM pg_class c "
    "JOIN pg_namespace n ON n.oid = c.relnamespace "
    "JOIN information_schema.columns col "
    "  ON col.table_schema = n.nspname AND col.table_name = c.relname "
    "WHERE n.nspname = ANY(:schemas) "
    "  AND c.relkind = 'r' AND col.column_name = 'tenant_id'"
)


def _upgrade(url: str, target: str = "heads") -> None:
    command.upgrade(make_alembic_config(url), target)


def _scalar(url: str, statement: str, **params: object) -> object:
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            return conn.execute(text(statement), params).scalar()
    finally:
        engine.dispose()


def _rows(url: str, statement: str, **params: object) -> list[str]:
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            return [row[0] for row in conn.execute(text(statement), params).all()]
    finally:
        engine.dispose()


def test_the_tenant_catalogue_exists_and_is_bound(scratch_db: str) -> None:
    """Fact one of the four, true today and worth pinning now.

    Every later plane argument rests on it: this control plane genuinely has a
    tenant catalogue, so keeping tenant tables out can never be explained away
    by the catalogue being absent.
    """
    _upgrade(scratch_db)

    assert _scalar(scratch_db, "SELECT to_regclass('public.tenants') IS NOT NULL")
    assert _scalar(
        scratch_db,
        "SELECT to_regprocedure('public.app_current_tenant_id()') IS NOT NULL",
    )
    assert TENANT_SCOPE_CATALOG_V1.name in {
        binding.prerequisite for binding in ASSEMBLY_PREREQUISITE_BINDINGS
    }


def test_no_module_schema_holds_a_tenant_scoped_table(scratch_db: str) -> None:
    """The composed control plane builds no tenant plane at all — with a bound,
    present catalogue sitting right there in `public`.

    A weaker statement than the a61 selection proof, and labelled as such: with
    no selectable module composed this shows the OUTCOME without demonstrating
    the MECHANISM. The mechanism is proven in the shadow-composition PR.
    """
    _upgrade(scratch_db)
    tenant_scoped = _rows(
        scratch_db, TENANT_SCOPED_MODULE_TABLES_SQL, schemas=list(MODULE_SCHEMAS)
    )
    assert not tenant_scoped, (
        "the vendor control plane is not a product data plane — no module "
        f"schema may hold a tenant-scoped table: {tenant_scoped}"
    )


def test_the_assembly_selects_no_module_plane_because_none_is_selectable() -> None:
    """Guards the claim this file's docstring makes.

    A selectable module composed WITHOUT a selection already fails
    `ProductAssemblySpec` construction. This asserts the cheaper inverse: while
    the selection tuple is empty, the reduced proof above is the honest one —
    and the moment it stops being empty this test fails, sending the next author
    to write the full four-fact proof instead of inheriting this one.
    """
    assert ASSEMBLY_MODULE_PLANES == ()
    assert tuple(build_spec().module_planes) == ()
