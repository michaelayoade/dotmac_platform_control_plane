"""The composed database, audited as a whole — every table, not a chosen few.

Until now the only privilege proof this repo had was
`test_platform_role_access_and_tenant_role_denial`, which names `vendor_accounts`
and ten licence tables by hand. A hand-picked list proves exactly the tables
someone remembered: `v011` added columns and nobody revisited it, and a `v012`
adding a whole table would be swept by nothing at all while the suite stayed
green.

So this module audits the WHOLE composed database — the kernel lineage, the
Release Catalog module, the Entitlement Allocation module and the vendor
lineage — deriving its table set from the live catalogue rather than a literal
list. Two halves, because the composed database has two namespaces:

1. **Module schemas** (`mod_rel`, `mod_ealloc`, `mod_approvals`) go through the
   kernel's own
   canonical gate, `dotmac_kernel.migrations.catalog.audit_live_schemas`. That
   is the contract every registered module schema is held to fleet-wide, and
   consuming it rather than re-deriving it is the point: a rule the kernel
   tightens tightens here, in the release that ships it.

2. **`public`** — the kernel's compatibility namespace plus this assembly's own
   lineage — is not walked by that gate (it has documented exceptions a module
   schema does not get), so this module supplies the assembly-side policy for
   it. Every table is CLASSIFIED from the catalogue, never enumerated:

   * `tenant_id NOT NULL` → tenant plane: RLS ENABLEd **and** FORCEd, with at
     least one policy. Enabled-without-forced is the one that reads as safe:
     migrations run as the owning role, which bypasses its own policy.
   * no `tenant_id` but RLS enabled → the kernel's subtype pattern
     (`party_persons`, `party_organizations`), which inherits isolation through
     an `EXISTS` join to `parties`. Same requirement.
   * no `tenant_id`, no RLS → the PLATFORM plane, where every vendor table
     lives. Here the REVOKE *is* the isolation, so the assertion is that
     `app_user` holds **none** of PostgreSQL's seven table privileges — read
     through the kernel's canonical `ROLE_TABLE_PRIVILEGES_SQL`, which also
     catches a column-level grant that a table-level inquiry reports as
     "revoked".
   * nullable `tenant_id` → NEITHER plane, and therefore **unmonitored** rather
     than exempt (ADR-0018). The kernel has exactly three such tables and they
     are named below; a fourth appearing fails, because an unmonitored region
     that grows silently is how a real tenant table ends up governed by nothing.

The vendor-owned subset is derived by diffing `public` after `kernel@head`
against `public` after `heads`, so the sweep cannot fall behind its own
lineage: a `v012` table is covered the moment the migration runs.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from alembic import command
from dotmac_kernel.migrations.catalog import (
    ROLE_TABLE_PRIVILEGES_SQL,
    TABLE_PRIVILEGES,
    audit_live_schemas,
    audited_schemas,
)
from dotmac_kernel.namespaces import NamespaceRegistry
from sqlalchemy import Connection, create_engine, text

from vendor_cp.assembly import build_spec
from vendor_cp.migrations import make_alembic_config

# The tenant application role. Kernel 0001 gives it USAGE on `public`, so a
# table there is reachable unless nothing was granted on it — which is why this
# sweep asks the catalogue what the role effectively holds instead of reading
# migrations for an explicit REVOKE.
APP_ROLE = "app_user"

# The two schemas the kernel's module gate must find. Asserted because
# `audit_live_schemas` over zero schemas returns zero violations — the exact
# shape of a gate that has silently stopped running.
EXPECTED_MODULE_SCHEMAS = frozenset({"mod_approvals", "mod_ealloc", "mod_rel"})

# Kernel-owned `public` tables the kernel deliberately GRANTS to the tenant role
# despite their having no `tenant_id`: `GRANT SELECT ON tenants, tenant_domains
# TO app_user, platform_api` (kernel 0001, `_grant_roles`). They are the tenant
# catalogue — a tenant-scoped request resolves its own row through them — and
# the grant is read-only, which is asserted separately below. Two entries, both
# traceable to one migration line; a third would be a kernel decision this
# assembly should have to look at rather than inherit.
TENANT_CATALOGUE_READABLE = frozenset({"tenants", "tenant_domains"})

# Kernel tables whose `tenant_id` is NULLABLE, so they sit in neither plane:
# NULL means deployment/platform scope and a UUID means tenant scope, in one
# table, so neither contract applies to the table whole. This assembly does not
# audit them and says so, rather than calling them exempt. Exact equality, not a
# subset: the set shrinking means the kernel resolved one and this list is now
# telling a reviewer something false.
UNMONITORED_SPLIT_SCOPE = frozenset(
    {
        "domain_settings",  # kernel 0002 — the documented hard-rule-11 exception
        "feature_flag_overrides",  # kernel 0013 — NULL = deployment scope
        "domain_setting_history",  # kernel 0014 — mirrors domain_settings
    }
)

# Alembic's own bookkeeping table: owned by no lineage and holding no data.
# It is swept as a platform table anyway (nothing grants it to `app_user`); it
# is named only so the vendor-lineage diff does not count it as vendor-owned.
ALEMBIC_BOOKKEEPING = "alembic_version"

PUBLIC_TABLES_SQL = (
    "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity "
    "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
    "WHERE n.nspname = 'public' AND c.relkind = 'r'"
)

PUBLIC_TENANT_COLUMNS_SQL = (
    "SELECT table_name, is_nullable FROM information_schema.columns "
    "WHERE table_schema = 'public' AND column_name = 'tenant_id'"
)

PUBLIC_POLICY_COUNTS_SQL = (
    "SELECT tablename, count(*) FROM pg_policies "
    "WHERE schemaname = 'public' GROUP BY tablename"
)

SCHEMA_USAGE_SQL = "SELECT has_schema_privilege(:role, :schema, 'USAGE')"


@contextmanager
def _connection(url: str) -> Iterator[Connection]:
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            yield conn
    finally:
        engine.dispose()


def _upgrade(url: str, target: str = "heads") -> None:
    command.upgrade(make_alembic_config(url), target)


class PublicSchema:
    """A plain description of `public`, classified into planes.

    Description first, decision second — the same split the kernel's catalog
    module uses, so a failure reports what the database actually said."""

    def __init__(self, conn: Connection) -> None:
        self.rls: dict[str, tuple[bool, bool]] = {
            name: (bool(enabled), bool(forced))
            for name, enabled, forced in conn.execute(text(PUBLIC_TABLES_SQL)).all()
        }
        self.tenant_column_nullable: dict[str, bool] = {
            name: nullable == "YES"
            for name, nullable in conn.execute(text(PUBLIC_TENANT_COLUMNS_SQL)).all()
        }
        self.policies: dict[str, int] = dict(
            conn.execute(text(PUBLIC_POLICY_COUNTS_SQL)).all()
        )
        self.app_role_privileges: dict[str, tuple[str, ...]] = {}
        for row in conn.execute(
            text(ROLE_TABLE_PRIVILEGES_SQL), {"schema": "public", "role": APP_ROLE}
        ).all():
            # The select list is positional and ordered exactly as the kernel's
            # `TABLE_PRIVILEGES`; `strict=True` fails loudly if the kernel ever
            # adds an eighth rather than silently dropping it.
            self.app_role_privileges[row[0]] = tuple(
                privilege
                for privilege, held in zip(TABLE_PRIVILEGES, row[1:], strict=True)
                if held
            )

    @property
    def tables(self) -> frozenset[str]:
        return frozenset(self.rls)

    def tenant_plane(self) -> frozenset[str]:
        """`tenant_id NOT NULL`, plus the no-column subtype tables that carry
        RLS anyway (isolation inherited through an EXISTS join to the parent)."""
        scoped = {
            name
            for name, nullable in self.tenant_column_nullable.items()
            if not nullable and name in self.rls
        }
        subtypes = {
            name
            for name, (enabled, _) in self.rls.items()
            if enabled and name not in self.tenant_column_nullable
        }
        return frozenset(scoped | subtypes)

    def split_scope(self) -> frozenset[str]:
        return frozenset(
            name
            for name, nullable in self.tenant_column_nullable.items()
            if nullable and name in self.rls
        )

    def platform_plane(self) -> frozenset[str]:
        """Everything left: no tenant discriminator and no RLS."""
        return self.tables - self.tenant_plane() - self.split_scope()


def _public_schema(url: str) -> PublicSchema:
    with _connection(url) as conn:
        return PublicSchema(conn)


# ── 1. Module schemas: the kernel's own canonical gate ──────────────────────


def test_composed_module_schemas_pass_the_kernel_live_catalog_gate(
    scratch_db: str,
) -> None:
    """`mod_rel` and `mod_ealloc`, held to the contract the kernel defines.

    This is the gate that makes the a4 module pins load-bearing. Through a3 both
    modules declared their tables in `ModuleManifest.tables` — the TENANT
    contract — while their migrations built platform-shaped tables, and nothing
    in this repo looked at the live catalogue to notice the disagreement.
    """
    registry = NamespaceRegistry.from_manifests(build_spec().modules)
    assert frozenset(audited_schemas(registry)) == EXPECTED_MODULE_SCHEMAS

    _upgrade(scratch_db)
    with _connection(scratch_db) as conn:
        violations = audit_live_schemas(conn, registry)
    assert violations == ()


@pytest.mark.parametrize("schema_name", sorted(EXPECTED_MODULE_SCHEMAS))
def test_module_schemas_are_unreachable_by_the_tenant_role(
    scratch_db: str, schema_name: str
) -> None:
    """Schema `USAGE` is the outer door; the per-table REVOKE the kernel gate
    proves is the inner one. A control plane owes the tenant role neither."""
    _upgrade(scratch_db)
    with _connection(scratch_db) as conn:
        granted = conn.execute(
            text(SCHEMA_USAGE_SQL), {"role": APP_ROLE, "schema": schema_name}
        ).scalar_one()
    assert not granted


# ── 2. `public`: the assembly-owned policy for the compatibility namespace ──


def test_every_tenant_scoped_public_table_forces_rls_with_a_policy(
    scratch_db: str,
) -> None:
    _upgrade(scratch_db)
    schema = _public_schema(scratch_db)
    tenant_plane = schema.tenant_plane()
    assert tenant_plane, "the kernel lineage must contribute tenant-scoped tables"

    bad = [
        f"{name}: enabled={schema.rls[name][0]} forced={schema.rls[name][1]} "
        f"policies={schema.policies.get(name, 0)}"
        for name in sorted(tenant_plane)
        if not all(schema.rls[name]) or schema.policies.get(name, 0) < 1
    ]
    assert not bad, f"tenant-scoped tables must FORCE RLS and carry a policy: {bad}"


def test_every_platform_plane_public_table_is_revoked_from_the_tenant_role(
    scratch_db: str,
) -> None:
    """The whole composed platform plane, not a hand-picked subset.

    On this plane the REVOKE is the isolation, so an un-revoked table is exactly
    as exposed as a tenant table with no policy — and reads just as safe.
    """
    _upgrade(scratch_db)
    schema = _public_schema(scratch_db)
    platform = schema.platform_plane()
    assert platform, "the composed database must contain platform-plane tables"

    bad = [
        f"{name}: {APP_ROLE} holds {sorted(held)}"
        for name in sorted(platform - TENANT_CATALOGUE_READABLE)
        if (held := schema.app_role_privileges.get(name, ()))
    ]
    assert not bad, f"platform-plane tables must be REVOKEd from {APP_ROLE}: {bad}"

    # Without this the allowlist would also excuse an INSERT, a TRUNCATE or a
    # TRIGGER on the tenant catalogue — "readable" is the premise it states.
    over_granted = {
        name: sorted(set(schema.app_role_privileges.get(name, ())) - {"SELECT"})
        for name in sorted(TENANT_CATALOGUE_READABLE & platform)
    }
    assert not any(over_granted.values()), (
        "the tenant catalogue is readable, never writable, by the tenant role: "
        f"{over_granted}"
    )


def test_the_unmonitored_split_scope_set_is_exactly_the_declared_one(
    scratch_db: str,
) -> None:
    """A region this assembly does not audit is NAMED, and may not grow.

    Nullable `tenant_id` means one table holds both platform-scope and
    tenant-scope rows, so neither plane's contract applies to it whole. Stating
    that is honest; letting a fourth such table appear unnoticed is not.
    """
    _upgrade(scratch_db)
    assert _public_schema(scratch_db).split_scope() == UNMONITORED_SPLIT_SCOPE


# ── 3. The vendor lineage's own contribution, derived not listed ────────────


def test_every_vendor_owned_table_is_platform_plane_and_fully_revoked(
    scratch_db: str,
) -> None:
    """Diff `public` across the two lineages instead of naming tables.

    This is what the hand-written licence-table list was standing in for. It
    cannot fall behind: a table added by a future `v0NN` is in the diff the
    moment its migration runs.
    """
    _upgrade(scratch_db, "kernel@head")
    kernel_tables = _public_schema(scratch_db).tables

    _upgrade(scratch_db, "heads")
    schema = _public_schema(scratch_db)
    vendor_tables = schema.tables - kernel_tables - {ALEMBIC_BOOKKEEPING}

    # Sensitivity: the diff must actually find the vendor lineage. Eleven
    # migrations create well over a dozen tables; a floor rather than an exact
    # count keeps this from becoming a second list to maintain.
    assert len(vendor_tables) >= 15, sorted(vendor_tables)
    assert "vendor_accounts" in vendor_tables

    misplaced = sorted(vendor_tables & (schema.tenant_plane() | schema.split_scope()))
    assert not misplaced, (
        "the vendor control plane is not a product data plane — a vendor table "
        f"must carry no tenant discriminator: {misplaced}"
    )

    exposed = {
        name: sorted(held)
        for name in sorted(vendor_tables)
        if (held := schema.app_role_privileges.get(name, ()))
    }
    assert not exposed, f"every vendor table must be REVOKEd from {APP_ROLE}: {exposed}"


def test_the_privilege_sweep_would_notice_a_granted_vendor_table(
    scratch_db: str,
) -> None:
    """SENSITIVITY. A sweep that passes because it observed nothing is not a
    gate, so grant the tenant role SELECT on one vendor table and prove the
    catalogue reader reports it."""
    _upgrade(scratch_db)
    engine = create_engine(scratch_db)
    try:
        with engine.begin() as conn:
            conn.execute(text("GRANT SELECT ON vendor_accounts TO app_user"))
        assert "SELECT" in _public_schema(scratch_db).app_role_privileges.get(
            "vendor_accounts", ()
        )
        with engine.begin() as conn:
            conn.execute(text("REVOKE SELECT ON vendor_accounts FROM app_user"))
    finally:
        engine.dispose()

    assert not _public_schema(scratch_db).app_role_privileges.get("vendor_accounts")
