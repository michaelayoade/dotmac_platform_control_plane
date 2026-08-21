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

1. **Module schemas** (`mod_rel`, `mod_ealloc`, `mod_approvals`,
   `mod_agreements`, `mod_licensing`) go through the
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
   * the TENANT CATALOGUE (`tenants`, `tenant_domains`) → its own category. It
     is what tenancy is defined by, so kernel 0001 leaves it outside RLS and
     grants it read-only to the tenant role. Note `tenant_domains` carries
     `tenant_id NOT NULL` as a parent FK, not as a scoping discriminator, so a
     classifier keyed on that column alone demands FORCEd RLS on a table the
     kernel deliberately leaves open — CI caught exactly that. Excluded from
     both planes and held to its own contract instead.
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
from pathlib import Path

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

# The five schemas the kernel's module gate must find. Asserted because
# `audit_live_schemas` over zero schemas returns zero violations — the exact
# shape of a gate that has silently stopped running.
EXPECTED_MODULE_SCHEMAS = frozenset(
    {"mod_agreements", "mod_approvals", "mod_ealloc", "mod_licensing", "mod_rel"}
)

# THE TENANT CATALOGUE — its own category, and neither plane.
#
# Kernel 0001 is explicit: "`tenants` and `tenant_domains` (NOT under RLS —
# platform-level)". They are the thing tenancy is defined BY, so they cannot be
# governed by a policy that calls `app_current_tenant_id()` to decide who may
# read the row that defines the tenant. The kernel grants both read-only to the
# tenant role in one line of `_grant_roles`.
#
# Naming them explicitly matters, because `tenant_domains` DOES carry
# `tenant_id NOT NULL` — an FK to its parent tenant, not a scoping
# discriminator. A classifier keyed purely on that column calls it tenant-plane
# and then demands FORCEd RLS on a table the kernel deliberately leaves open;
# CI caught exactly that. `tenants` itself has no such column and would have
# slipped into the platform plane instead, where the read grant would have
# looked like an un-revoked control-plane table.
#
# Two entries, both traceable to one migration line, and both held to their own
# contract below: no RLS, and read-only to the tenant role. A third would be a
# kernel decision this assembly should have to look at rather than inherit.
TENANT_CATALOGUE = frozenset({"tenants", "tenant_domains"})

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
            if not nullable and name in self.rls and name not in TENANT_CATALOGUE
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
        """Everything left: no tenant discriminator, no RLS, not the catalogue."""
        return self.tables - self.tenant_plane() - self.split_scope() - TENANT_CATALOGUE

    def tenant_catalogue(self) -> frozenset[str]:
        """The catalogue tables actually present."""
        return frozenset(TENANT_CATALOGUE & self.tables)


def _public_schema(url: str) -> PublicSchema:
    with _connection(url) as conn:
        return PublicSchema(conn)


# ── 1. Module schemas: the kernel's own canonical gate ──────────────────────


def test_composed_module_schemas_pass_the_kernel_live_catalog_gate(
    scratch_db: str,
) -> None:
    """Every composed module schema, held to the contract the kernel defines.

    This is the gate that makes the a4 module pins load-bearing. Through a3 both
    modules declared their tables in `ModuleManifest.tables` — the TENANT
    contract — while their migrations built platform-shaped tables, and nothing
    in this repo looked at the live catalogue to notice the disagreement.

    NOTHING is tolerated any more. This test used to subtract two declared
    shadow overlaps — the legacy `public.allocations` / `public.allocation_entries`
    tables shadowing `mod_ealloc` — and that exemption retired with the tables
    themselves in `v014`. An exemption whose premise has evaporated does not
    become harmless; it silently widens what the gate permits (ADR-0018), so it
    is removed rather than left describing nothing.
    """
    spec = build_spec()
    # `module_planes` is REQUIRED here, not optional decoration: without it the
    # registry falls back to the atomic "every declared plane is installed"
    # view, expects the module's TENANT tables, and reports them missing on a
    # correct platform-only install. The expected set is a function of the
    # assembly's SELECTION (ADR-0028), so the selection has to be supplied.
    registry = NamespaceRegistry.from_manifests(
        spec.modules, module_planes=spec.module_planes
    )
    assert frozenset(audited_schemas(registry)) == EXPECTED_MODULE_SCHEMAS

    _upgrade(scratch_db)
    with _connection(scratch_db) as conn:
        violations = audit_live_schemas(conn, registry)

    assert violations == (), (
        "the composed module schemas must satisfy the kernel gate with no "
        f"exemptions at all: {violations}"
    )


def test_no_waiver_mechanism_exists_for_the_kernel_gate(scratch_db: str) -> None:
    """The exemption is GONE, and its absence is checked rather than assumed.

    `vendor_cp.shadow_overlaps` declared two host-squatter waivers while the
    legacy allocation tables shadowed `mod_ealloc`. `v014` drops those tables, so
    the premise is gone — and a waiver whose premise has evaporated is worse than
    no waiver, because it keeps widening the gate for facts nobody has examined.

    Removing it is only half the job: this asserts the module is gone and that
    the gate is consumed with no subtraction, so a future author cannot restore
    a waiver quietly by re-adding the helper.
    """
    assert not (
        Path(__file__).resolve().parents[2] / "src" / "vendor_cp" / "shadow_overlaps.py"
    ).exists()

    # No subtraction helper survives in this suite either — the gate is consumed
    # raw, so a waiver cannot creep back as a "small" filter.
    #
    # Asked of the MODULE NAMESPACE, not of the file's text: a source-text check
    # would forbid a token its own assertion contains, and fail forever. (It did.)
    import sys

    suite = sys.modules[__name__]
    assert not hasattr(suite, "_partition_shadow_overlaps")

    # And the live gate really does report nothing to waive.
    spec = build_spec()
    registry = NamespaceRegistry.from_manifests(
        spec.modules, module_planes=spec.module_planes
    )
    _upgrade(scratch_db)
    with _connection(scratch_db) as conn:
        assert audit_live_schemas(conn, registry) == ()


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
        for name in sorted(platform)
        if (held := schema.app_role_privileges.get(name, ()))
    ]
    assert not bad, f"platform-plane tables must be REVOKEd from {APP_ROLE}: {bad}"


def catalogue_violations(privileges: dict[str, set[str]]) -> list[str]:
    """The catalogue's privilege DECISION, pure and therefore provable.

    Exactly `{"SELECT"}` per table. Split out from the live test so both failure
    directions can be demonstrated against synthetic input: a live test can only
    show that the READER observed a change, which is a weaker claim than the
    guard rejecting it.
    """
    return [
        f"{name}: {sorted(held)}"
        for name, held in sorted(privileges.items())
        if held != {"SELECT"}
    ]


def test_a_fully_revoked_catalogue_fails_the_decision() -> None:
    """ACCEPTANCE: missing SELECT must fail.

    This is the case the previous "nothing beyond SELECT" form passed. A
    catalogue nobody can read is not the contract — kernel 0001 grants SELECT
    because a tenant-scoped request resolves its own row through these tables.
    """
    assert catalogue_violations({"tenants": set()}) == ["tenants: []"]


def test_an_over_granted_catalogue_fails_the_decision() -> None:
    """ACCEPTANCE: excess privilege must fail."""
    assert catalogue_violations({"tenants": {"SELECT", "INSERT"}}) == [
        "tenants: ['INSERT', 'SELECT']"
    ]


def test_the_exact_grant_passes_the_decision() -> None:
    """NON-VACUITY: the decision must accept the real, correct state, or the two
    cases above would pass for a guard that rejects everything."""
    assert (
        catalogue_violations({"tenants": {"SELECT"}, "tenant_domains": {"SELECT"}})
        == []
    )


def test_the_tenant_catalogue_is_open_but_read_only(scratch_db: str) -> None:
    """The catalogue's own contract, so excluding it from both planes is a
    checked premise rather than a hole.

    No RLS — a policy calling `app_current_tenant_id()` cannot decide who may
    read the row that DEFINES the tenant. And read-only to the tenant role:
    without this, "the catalogue is exempt" would also excuse an INSERT, a
    TRUNCATE or a TRIGGER on it.
    """
    _upgrade(scratch_db)
    schema = _public_schema(scratch_db)
    catalogue = schema.tenant_catalogue()
    assert catalogue == TENANT_CATALOGUE, sorted(catalogue)

    under_rls = sorted(name for name in catalogue if schema.rls[name][0])
    assert not under_rls, (
        "the tenant catalogue is deliberately not under RLS (kernel 0001); "
        f"a policy here would gate reading the row that defines the tenant: {under_rls}"
    )

    # EXACT equality, not "nothing beyond SELECT". The weaker form was satisfied
    # by a fully REVOKED catalogue, which is not the contract at all: kernel 0001
    # deliberately grants SELECT, and a tenant-scoped request resolves its own
    # row through these tables. A guard that accepts an unreadable catalogue is
    # asserting half of a two-sided rule and reporting the whole of it.
    wrong = catalogue_violations(
        {name: set(schema.app_role_privileges.get(name, ())) for name in catalogue}
    )
    assert not wrong, (
        f"the tenant catalogue must be exactly readable by {APP_ROLE} — SELECT "
        f"present, nothing else: {wrong}"
    )


def test_the_catalogue_guard_notices_a_revoked_catalogue(scratch_db: str) -> None:
    """SENSITIVITY for the REQUIRED half, which is the half that was missing.

    Revoke SELECT on a catalogue table and the reader must report it. Without
    this, "exactly {SELECT}" could be satisfied by a privilege reader that
    returned nothing for every table, and the previous "nothing beyond SELECT"
    form would have passed outright.
    """
    _upgrade(scratch_db)
    engine = create_engine(scratch_db)
    try:
        with engine.begin() as conn:
            conn.execute(text("REVOKE SELECT ON tenant_domains FROM app_user"))
        revoked = _public_schema(scratch_db).app_role_privileges.get(
            "tenant_domains", ()
        )
        assert "SELECT" not in revoked, (
            "the privilege reader did not observe a REVOKE, so the catalogue "
            "guard cannot be trusted in the direction that requires a grant"
        )
        with engine.begin() as conn:
            conn.execute(text("GRANT SELECT ON tenant_domains TO app_user"))
    finally:
        engine.dispose()

    # And restored — otherwise this test would leave the scratch database in a
    # state that makes the guard above pass or fail for the wrong reason.
    assert "SELECT" in _public_schema(scratch_db).app_role_privileges.get(
        "tenant_domains", ()
    )


def test_the_catalogue_guard_notices_an_over_granted_catalogue(
    scratch_db: str,
) -> None:
    """SENSITIVITY for the FORBIDDEN half, so both directions are proven."""
    _upgrade(scratch_db)
    engine = create_engine(scratch_db)
    try:
        with engine.begin() as conn:
            conn.execute(text("GRANT INSERT ON tenants TO app_user"))
        held = _public_schema(scratch_db).app_role_privileges.get("tenants", ())
        assert "INSERT" in held
        with engine.begin() as conn:
            conn.execute(text("REVOKE INSERT ON tenants FROM app_user"))
    finally:
        engine.dispose()

    assert set(_public_schema(scratch_db).app_role_privileges.get("tenants", ())) == {
        "SELECT"
    }


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

    # Sensitivity: the diff must actually find the vendor lineage. A floor
    # rather than an exact count keeps this from becoming a second list to
    # maintain.
    #
    # LOWERED 14 -> 12 by `v015_agreements_authority`, then 12 -> 7 by
    # `v016_licensing_authority`, deliberately. Commercial
    # Agreements moved to `dotmac-commercial-agreements`, and the two empty
    # legacy tables were dropped with their writer. `mod_agreements` is audited
    # above and is not part of `public`. Licensing's five issuer tables moved
    # to `mod_licensing`; the five delivery tables remain in `public`.
    #
    # A floor that fails when the count FALLS is doing its job: it forces this
    # decision to be made and written down rather than absorbed silently. Lower
    # it only alongside the migration that retires the tables.
    assert len(vendor_tables) >= 7, sorted(vendor_tables)
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
