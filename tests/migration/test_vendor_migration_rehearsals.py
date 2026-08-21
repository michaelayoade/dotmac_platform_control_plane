"""Vendor migration rehearsals on real PostgreSQL (the AccountService
deployability gate).

Proves the `vendor_accounts` lineage the way production runs it: composed with
the kernel base lineage, migrated by `app_admin`, with the platform-catalog grant
boundary enforced by real roles. Each rehearsal provisions its OWN scratch
database so the composed `upgrade` runs end-to-end in isolation.

Requires the test Postgres cluster (roles + kernel schema) from `make test-db-up`;
skips when `TEST_DATABASE_URL` is unset.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from pathlib import Path

import pytest
from alembic import command
from alembic.script import ScriptDirectory
from dotmac_kernel.prerequisites import installed_bindings
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

from vendor_cp.migration_bindings import ASSEMBLY_PREREQUISITE_BINDINGS
from vendor_cp.migrations import composed_version_locations, make_alembic_config

KERNEL_HEAD = "0026_platform_audit_log"  # current pin (0.1.0a77)
PREVIOUS_KERNEL_HEAD = "0012_platform_outbox"  # former pin (0.1.0a9)
RELEASE_CATALOG_HEAD = "rl_0001_release_artifacts"

# The a5/a6 repin extended two module lineages, and it changed the version-ROW
# topology as well as the head names — which is the whole reason these rehearsals
# name revisions instead of using `@head` aliases.
#
# Before: `v012` depends on `ap_0001_approvals` and `v014` on
# `ea_0001_allocations`, so each module head was an ANCESTOR of a vendor
# revision. A `depends_on` edge makes its target an ancestor of the depending
# revision, and `alembic_version` holds current heads rather than every applied
# revision — so both appeared in `script.get_heads()` and NOT in `_versions()`.
#
# After: the vendor `depends_on` edges still point at the lineage ROOTS, while
# the heads have moved on to DDL-free verification revisions nothing depends on.
# `ap_0002_outbox_relay` and `ea_0003_platform_audit_log` are therefore both
# static heads AND version rows, and the `_versions()` expectations below grew by
# exactly those two.
#
# The vendor edges are deliberately NOT re-pointed at the new heads. They express
# what v012 and v014 need — the approval and allocation TABLES — and a
# verification revision is not that. Widening a dependency to whatever happens to
# be at the tip would make every future module release a vendor-lineage change.
ENTITLEMENT_ALLOCATION_HEAD = "ea_0003_platform_audit_log"
APPROVALS_HEAD = "ap_0002_outbox_relay"
COMMERCIAL_AGREEMENTS_HEAD = "cg_0001_agreements"
LICENSING_HEAD = "li_0001_licensing"
# Composed at the ADR-0011 cutover. Unlike approvals and allocation, this
# module head IS depended on by a vendor revision — `v017` names it — so it
# is an ancestor and NOT a version row, the same shape `ap_0001` had before
# a5 moved that lineage past it.
DEPLOYMENT_CONTROL_HEAD = "dc_0001_deployment_control"
VENDOR_ROOT = "v001_vendor_accounts"
VENDOR_ROOT_DEP = "0009_platform_audit_inbox"  # what v001 depends_on
VENDOR_HEAD = "v017_deployment_target_authority"

#: The vendor head as it stood BEFORE allocation authority moved.
#:
#: A rehearsal of "an existing deployment we are upgrading FROM" must name the
#: revision it means. `vendor@head` is an alias, and using it here silently
#: re-described the scenario every time the head advanced: once `v014` declared
#: `depends_on = ea_0001_allocations`, upgrading to `vendor@head` installed the
#: module lineage, so the "before modules" state the test set up was no longer
#: that state at all.
PREVIOUS_VENDOR_HEAD = "v013_approvals_authority_switch"


# `scratch_db` and the DSN rewriter MOVED to `tests/migration/conftest.py`.
# They were defined here, which meant the composed live-catalogue audit could
# not reuse them without importing across modules of a test PACKAGE — the
# import-path fragility that file's docstring already warns about. Both arrive
# as FIXTURES (`scratch_db`, `url_for`), which is that file's stated convention.


def _upgrade(url: str, target: str = "heads") -> None:
    command.upgrade(make_alembic_config(url), target)


def _q(url: str, sql: str, **params):
    eng = create_engine(url)
    try:
        with eng.connect() as conn:
            return conn.execute(text(sql), params).scalar()
    finally:
        eng.dispose()


def _table_exists(url: str, table: str) -> bool:
    return bool(_q(url, "SELECT to_regclass('public.' || :t) IS NOT NULL", t=table))


def _qualified_table_exists(url: str, table: str) -> bool:
    return bool(_q(url, "SELECT to_regclass(:t) IS NOT NULL", t=table))


def _column_names(url: str, table: str) -> set[str]:
    eng = create_engine(url)
    try:
        with eng.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema='public' AND table_name=:t"
                ),
                {"t": table},
            ).scalars()
            return set(rows)
    finally:
        eng.dispose()


def _versions(url: str) -> set[str]:
    eng = create_engine(url)
    try:
        with eng.connect() as conn:
            if not conn.execute(
                text("SELECT to_regclass('public.alembic_version') IS NOT NULL")
            ).scalar():
                return set()
            return set(
                conn.execute(text("SELECT version_num FROM alembic_version")).scalars()
            )
    finally:
        eng.dispose()


# ─────────────────────────────────────────────────────────────────────────────
# Rehearsal 1 — fresh install
# ─────────────────────────────────────────────────────────────────────────────
def test_fresh_install_creates_vendor_accounts(scratch_db: str) -> None:
    _upgrade(scratch_db, "heads")
    assert _table_exists(scratch_db, "vendor_accounts")
    assert _table_exists(scratch_db, "offer_versions")
    # v013 DROPPED these: approval authority moved to the module, and the empty
    # legacy tables went with the writer that owned them.
    assert not _table_exists(scratch_db, "approval_policies")
    assert not _table_exists(scratch_db, "approval_records")
    # v015 DROPPED these after checking the greenfield premise under lock.
    assert not _table_exists(scratch_db, "contracts")
    assert not _table_exists(scratch_db, "contract_lines")
    # v014 DROPPED these: allocation authority moved to the module, and the
    # empty legacy tables went with the writer that owned them.
    assert not _table_exists(scratch_db, "allocations")
    assert not _table_exists(scratch_db, "allocation_entries")
    # v016 retired only the local issuer. Delivery remains Vendor-owned.
    for retired in (
        "licence_signing_keys",
        "licences",
        "licence_issuances",
        "licence_revocation_entries",
        "licence_revocation_lists",
    ):
        assert not _table_exists(scratch_db, retired)
    assert _table_exists(scratch_db, "licence_deliveries")
    assert "product_code" in _column_names(scratch_db, "offer_versions")
    # Kernel platform tables the AccountService depends on are present too.
    assert _table_exists(scratch_db, "platform_audit_events")
    assert _table_exists(scratch_db, "platform_idempotency_records")
    assert _qualified_table_exists(scratch_db, "mod_rel.release_artifacts")
    assert _qualified_table_exists(scratch_db, "mod_rel.artifact_attestations")
    assert _qualified_table_exists(scratch_db, "mod_ealloc.allocations")
    assert _qualified_table_exists(scratch_db, "mod_ealloc.allocation_entries")
    assert _qualified_table_exists(scratch_db, "mod_agreements.agreements")
    assert _qualified_table_exists(scratch_db, "mod_agreements.agreement_lines")
    assert _qualified_table_exists(scratch_db, "mod_agreements.agreement_events")
    assert _qualified_table_exists(scratch_db, "mod_licensing.signing_keys")
    assert _qualified_table_exists(scratch_db, "mod_licensing.licences")
    assert _qualified_table_exists(scratch_db, "mod_licensing.licence_issuances")
    assert _qualified_table_exists(scratch_db, "mod_licensing.licence_acknowledgements")
    assert _qualified_table_exists(scratch_db, "mod_licensing.revocations")
    assert _qualified_table_exists(scratch_db, "mod_licensing.revocation_lists")
    cols = _column_names(scratch_db, "vendor_accounts")
    assert {
        "id",
        "external_ref",
        "display_name",
        "status",
        "created_at",
        "updated_at",
    } <= cols
    # PLATFORM catalog: no tenant_id, and RLS is NOT enabled.
    assert "tenant_id" not in cols
    assert not _q(
        scratch_db,
        "SELECT relrowsecurity FROM pg_class WHERE oid='vendor_accounts'::regclass",
    )
    # VERSION ROWS, which are not the same set as the static heads.
    #
    # `alembic_version` holds current heads only, and a `depends_on` edge makes
    # its target an ANCESTOR of the depending revision rather than a head in its
    # own right. `v012` depends on `ap_0001_approvals`, `v014` on
    # `ea_0001_allocations`, `v015` on `cg_0001_agreements`, and `v016` on
    # `li_0001_licensing`. Commercial
    # Agreements in turn depends on kernel `0018` and `0026`, so the current
    # kernel head is an ancestor too. All four revisions are genuinely applied;
    # none remains a version ROW once the Vendor lineage reaches v016.
    #
    # They are still static heads, and `test_eight_head_topology` asserts all eight
    # through `script.get_heads()`. Listing them here as well would report them
    # missing on a perfectly complete database.
    #
    # The approvals and allocation HEADS are a different case since the a5/a6
    # repin: the vendor edges depend on those lineages' ROOTS, so their new
    # DDL-free tips are depended on by nothing and remain version rows.
    assert _versions(scratch_db) == {
        RELEASE_CATALOG_HEAD,
        VENDOR_HEAD,
        APPROVALS_HEAD,
        ENTITLEMENT_ALLOCATION_HEAD,
    }


def test_ci_cluster_rehearses_the_production_role_bootstrap(
    postgres_url: str,
) -> None:
    """CI starts the same separate bootstrap/migrator roles as production."""
    server = create_engine(postgres_url)
    try:
        with server.connect() as conn:
            assert conn.execute(
                text(
                    "SELECT rolsuper, rolcreaterole, rolbypassrls, rolcanlogin "
                    "FROM pg_roles WHERE rolname='app_admin'"
                )
            ).one() == (False, False, True, True)
            assert conn.execute(
                text(
                    "SELECT rolname, rolsuper, rolcreaterole, rolbypassrls "
                    "FROM pg_roles WHERE rolname IN "
                    "('outbox_dispatcher', 'platform_outbox_dispatcher') "
                    "ORDER BY rolname"
                )
            ).all() == [
                ("outbox_dispatcher", False, False, False),
                ("platform_outbox_dispatcher", False, False, False),
            ]
            assert conn.execute(
                text(
                    "SELECT rolpassword IS NULL FROM pg_authid "
                    "WHERE rolname='postgres'"
                )
            ).scalar_one()
            assert (
                conn.execute(
                    text(
                        "SELECT pg_get_userbyid(datdba) FROM pg_database "
                        "WHERE datname=current_database()"
                    )
                ).scalar_one()
                == "app_admin"
            )
            assert (
                conn.execute(
                    text(
                        "SELECT pg_get_userbyid(nspowner) FROM pg_namespace "
                        "WHERE nspname='public'"
                    )
                ).scalar_one()
                == "app_admin"
            )
    finally:
        server.dispose()


def test_alembic_env_installs_the_vendor_prerequisite_bindings(
    scratch_db: str,
) -> None:
    _upgrade(scratch_db, "heads")

    assert installed_bindings() == ASSEMBLY_PREREQUISITE_BINDINGS


# ─────────────────────────────────────────────────────────────────────────────
# Rehearsal 2 — eight-head topology
# ─────────────────────────────────────────────────────────────────────────────
def test_eight_head_topology(scratch_db: str) -> None:
    script = ScriptDirectory.from_config(make_alembic_config(scratch_db))
    assert set(script.get_heads()) == {
        KERNEL_HEAD,
        ENTITLEMENT_ALLOCATION_HEAD,
        RELEASE_CATALOG_HEAD,
        APPROVALS_HEAD,
        COMMERCIAL_AGREEMENTS_HEAD,
        LICENSING_HEAD,
        DEPLOYMENT_CONTROL_HEAD,
        VENDOR_HEAD,
    }
    kernel_head = script.get_revision("kernel@head")
    vendor_head = script.get_revision("vendor@head")
    release_catalog_head = script.get_revision("release_catalog@head")
    allocation_head = script.get_revision("entitlement_allocation@head")
    agreement_head = script.get_revision("commercial_agreements@head")
    licensing_head = script.get_revision("licensing@head")
    deployment_head = script.get_revision("deployment_control@head")
    assert kernel_head.revision == KERNEL_HEAD
    assert vendor_head.revision == VENDOR_HEAD
    assert release_catalog_head.revision == RELEASE_CATALOG_HEAD
    assert allocation_head.revision == ENTITLEMENT_ALLOCATION_HEAD
    assert agreement_head.revision == COMMERCIAL_AGREEMENTS_HEAD
    assert licensing_head.revision == LICENSING_HEAD
    assert deployment_head.revision == DEPLOYMENT_CONTROL_HEAD
    # The vendor head is the tip of a single-parent chain that walks back to the
    # vendor ROOT; the ROOT is its own branch that DEPENDS ON (is not a child of)
    # a kernel head, so the lineages advance independently.
    node = vendor_head
    while node.down_revision is not None:
        assert isinstance(node.down_revision, str)  # linear vendor lineage
        node = script.get_revision(node.down_revision)
    assert node.revision == VENDOR_ROOT
    root = node
    assert root.down_revision is None
    deps = root.dependencies
    deps = (deps,) if isinstance(deps, str) else tuple(deps or ())
    assert VENDOR_ROOT_DEP in deps


# ─────────────────────────────────────────────────────────────────────────────
# Rehearsal 3 — platform-role access, tenant-role denial
# ─────────────────────────────────────────────────────────────────────────────
def test_platform_role_access_and_tenant_role_denial(
    scratch_db: str, url_for: Callable[..., str]
) -> None:
    _upgrade(scratch_db, "heads")

    # platform_api may INSERT + SELECT vendor_accounts.
    plat = create_engine(
        url_for(scratch_db, scratch_db.rsplit("/", 1)[1], user="platform_api")
    )
    try:
        with plat.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO vendor_accounts "
                    "(id, external_ref, display_name, status) "
                    "VALUES (gen_random_uuid(), 'r1', 'Acme', 'active')"
                )
            )
        with plat.connect() as conn:
            assert (
                conn.execute(text("SELECT count(*) FROM vendor_accounts")).scalar() == 1
            )
    finally:
        plat.dispose()

    plat = create_engine(
        url_for(scratch_db, scratch_db.rsplit("/", 1)[1], user="platform_api")
    )
    try:
        with plat.connect() as conn:
            assert (
                conn.execute(
                    text("SELECT count(*) FROM mod_ealloc.allocations")
                ).scalar()
                == 0
            )
    finally:
        plat.dispose()

    # The module is a platform catalogue. The online platform role can read it,
    # while the product data-plane role is denied below.
    plat = create_engine(
        url_for(scratch_db, scratch_db.rsplit("/", 1)[1], user="platform_api")
    )
    try:
        with plat.connect() as conn:
            assert (
                conn.execute(
                    text("SELECT count(*) FROM mod_rel.release_artifacts")
                ).scalar()
                == 0
            )
    finally:
        plat.dispose()

    # app_user (tenant application role) may NOT even SELECT — REVOKEd. Each check
    # uses a FRESH connection: a permission error aborts the transaction, so a
    # second statement on the same connection would fail as "transaction aborted"
    # rather than "permission denied".
    appu = create_engine(
        url_for(scratch_db, scratch_db.rsplit("/", 1)[1], user="app_user")
    )
    try:
        with appu.connect() as conn:
            with pytest.raises(DBAPIError, match="permission denied"):
                conn.execute(text("SELECT count(*) FROM vendor_accounts")).scalar()
        with appu.connect() as conn:
            with pytest.raises(DBAPIError, match="permission denied"):
                conn.execute(
                    text(
                        "INSERT INTO vendor_accounts (id, external_ref, display_name) "
                        "VALUES (gen_random_uuid(), 'x', 'y')"
                    )
                )
        # The old WS8 licence tables carried the same REVOKE, proven here by a
        # ten-name literal list. That list is GONE: it covered the tables
        # someone remembered, so every later migration silently widened the gap
        # between what shipped and what was checked.
        #
        # `test_composed_live_catalog.py` now sweeps EVERY vendor-owned table,
        # derived by diffing `public` across the two lineages, for all seven
        # PostgreSQL table privileges including the column-level ones. One
        # module-owned licence table stays here as the live-connection
        # counterpart: the sweep reads `has_table_privilege`, and this proves a
        # real connection is refused, so a catalogue that lied would not pass
        # both.
        with appu.connect() as conn:
            with pytest.raises(DBAPIError, match="permission denied"):
                conn.execute(
                    text("SELECT count(*) FROM mod_licensing.licences")
                ).scalar()
        with appu.connect() as conn:
            with pytest.raises(DBAPIError, match="permission denied"):
                conn.execute(
                    text("SELECT count(*) FROM mod_rel.release_artifacts")
                ).scalar()
        with appu.connect() as conn:
            with pytest.raises(DBAPIError, match="permission denied"):
                conn.execute(
                    text("SELECT count(*) FROM mod_ealloc.allocations")
                ).scalar()
    finally:
        appu.dispose()


# ─────────────────────────────────────────────────────────────────────────────
# Rehearsal 4 — upgrade from a kernel-only database
# ─────────────────────────────────────────────────────────────────────────────
def test_upgrade_from_kernel_only(scratch_db: str) -> None:
    # An existing deployment on the kernel schema but without the vendor lineage.
    _upgrade(scratch_db, "kernel@head")
    assert _table_exists(scratch_db, "platform_admins")
    assert not _table_exists(scratch_db, "vendor_accounts")
    assert _versions(scratch_db) == {KERNEL_HEAD}

    # Deploy the vendor and module lineages on top — data-safe.
    _upgrade(scratch_db, "heads")
    assert _table_exists(scratch_db, "vendor_accounts")
    assert _table_exists(scratch_db, "offer_versions")
    assert not _table_exists(scratch_db, "contracts")
    # The module owns approvals now; the legacy tables are created by v003 and
    # dropped again by v013 within the same composed upgrade.
    assert not _table_exists(scratch_db, "approval_policies")
    assert _qualified_table_exists(
        scratch_db, "mod_approvals.platform_approval_requests"
    )
    # Allocations moved to the module too (v014); the legacy tables are created
    # by v005 and dropped again within the same composed upgrade.
    assert not _table_exists(scratch_db, "allocations")
    assert _qualified_table_exists(scratch_db, "mod_ealloc.allocations")
    assert _qualified_table_exists(scratch_db, "mod_agreements.agreements")
    assert _qualified_table_exists(scratch_db, "mod_rel.release_artifacts")
    assert _qualified_table_exists(scratch_db, "mod_ealloc.allocations")
    assert _versions(scratch_db) == {
        RELEASE_CATALOG_HEAD,
        VENDOR_HEAD,
        APPROVALS_HEAD,
        ENTITLEMENT_ALLOCATION_HEAD,
    }


def test_upgrade_from_previous_vendor_deployment_preserves_data(
    scratch_db: str,
) -> None:
    """Rehearse an existing empty Vendor estate into all module lineages."""
    _upgrade(scratch_db, PREVIOUS_VENDOR_HEAD)
    _upgrade(scratch_db, PREVIOUS_KERNEL_HEAD)
    assert _versions(scratch_db) == {PREVIOUS_KERNEL_HEAD, PREVIOUS_VENDOR_HEAD}
    assert not _qualified_table_exists(scratch_db, "mod_rel.release_artifacts")
    assert not _qualified_table_exists(scratch_db, "mod_ealloc.allocations")
    assert not _qualified_table_exists(scratch_db, "mod_agreements.agreements")
    assert not _qualified_table_exists(scratch_db, "mod_licensing.licences")

    account_id = str(uuid.uuid4())
    eng = create_engine(scratch_db)
    try:
        with eng.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO vendor_accounts "
                    "(id, external_ref, display_name, status) "
                    "VALUES (:id, 'pre-module', 'Existing Vendor', 'active')"
                ),
                {"id": account_id},
            )
    finally:
        eng.dispose()

    _upgrade(scratch_db, "heads")

    assert _qualified_table_exists(scratch_db, "mod_rel.release_artifacts")
    assert _qualified_table_exists(scratch_db, "mod_ealloc.allocations")
    assert _qualified_table_exists(scratch_db, "mod_agreements.agreements")
    assert _qualified_table_exists(scratch_db, "mod_licensing.licences")
    assert (
        _q(
            scratch_db,
            "SELECT count(*) FROM vendor_accounts WHERE id = CAST(:id AS uuid)",
            id=account_id,
        )
        == 1
    )
    assert _versions(scratch_db) == {
        RELEASE_CATALOG_HEAD,
        VENDOR_HEAD,
        APPROVALS_HEAD,
        ENTITLEMENT_ALLOCATION_HEAD,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Rehearsal 5 — kernel advance keeps the vendor head independent
# ─────────────────────────────────────────────────────────────────────────────
def test_kernel_advance_keeps_vendor_head_independent(
    scratch_db: str, tmp_path: Path
) -> None:
    """Simulate a FUTURE kernel migration (a child of the kernel head). The
    vendor and module heads must remain separate heads — and a composed upgrade
    must still apply all seven lineages."""
    synth_rev = "9999_synthetic_kernel_advance"
    (tmp_path / f"{synth_rev}.py").write_text(
        "revision = '9999_synthetic_kernel_advance'\n"
        f"down_revision = '{KERNEL_HEAD}'\n"
        "branch_labels = None\n"
        "depends_on = None\n"
        "def upgrade():\n    pass\n"
        "def downgrade():\n    pass\n"
    )
    cfg = make_alembic_config(scratch_db)
    cfg.set_main_option(
        "version_locations", f"{composed_version_locations()} {tmp_path}"
    )
    script = ScriptDirectory.from_config(cfg)
    # Kernel advances independently; the vendor and module heads are untouched.
    assert set(script.get_heads()) == {
        synth_rev,
        ENTITLEMENT_ALLOCATION_HEAD,
        RELEASE_CATALOG_HEAD,
        APPROVALS_HEAD,
        COMMERCIAL_AGREEMENTS_HEAD,
        LICENSING_HEAD,
        DEPLOYMENT_CONTROL_HEAD,
        VENDOR_HEAD,
    }

    command.upgrade(cfg, "heads")
    assert _table_exists(scratch_db, "vendor_accounts")
    assert _versions(scratch_db) == {
        synth_rev,
        RELEASE_CATALOG_HEAD,
        VENDOR_HEAD,
        APPROVALS_HEAD,
        ENTITLEMENT_ALLOCATION_HEAD,
    }


# ─────────────────────────────────────────────────────────────────────────────
# v010 — legacy deliveries created before the destination boundary
# ─────────────────────────────────────────────────────────────────────────────


def test_v010_quarantines_legacy_deliveries_including_active_ones(
    scratch_db: str,
) -> None:
    """A v009-era delivery has no resolved destination. Both the in-flight and
    the ACTIVE ones must be parked.

    `active` is the case that matters: it was established under the previous
    semantics, where an acknowledgement needed no proven deployment identity,
    so it records only that someone claimed the licence was applied. Leaving it
    active would preserve exactly the unproven authority v010 exists to remove
    — and it would never be re-examined, because active rows are excluded from
    replay.
    """
    _upgrade(scratch_db, "v009_delivery_attempts")

    eng = create_engine(scratch_db)
    ids = {k: str(uuid.uuid4()) for k in ("target", "lic", "iss", "d1", "d2", "c", "a")}
    try:
        with eng.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO licences (id, customer_ref, product, generation) "
                    "VALUES (:id, 'cust-legacy', 'dotmac-sub', 1)"
                ),
                {"id": ids["lic"]},
            )
            # Seeded, because at the v009 state this rehearsal builds,
            # `licence_issuances.allocation_id` still carries a real foreign key
            # to `public.allocations`. `v014` later drops that constraint and the
            # table with it — but this test is standing at v009, where the
            # constraint exists and must be satisfied.
            conn.execute(
                text(
                    "INSERT INTO contracts (id, customer_ref, legal_entity, "
                    "currency_code, term_start, term_end, status, content_hash) "
                    "VALUES (:id, 'cust-legacy', 'Dotmac Ltd', 'USD', "
                    "'2026-01-01', '2026-12-31', 'active', 'h')"
                ),
                {"id": ids["c"]},
            )
            conn.execute(
                text(
                    "INSERT INTO allocations (id, contract_id, customer_ref, "
                    "content_hash, status, source_event_id) VALUES "
                    "(:id, :c, 'cust-legacy', 'h', 'staged', 'evt')"
                ),
                {"id": ids["a"], "c": ids["c"]},
            )
            conn.execute(
                text(
                    "INSERT INTO licence_issuances (id, licence_id, allocation_id, "
                    "version, digest, key_id, envelope, status) VALUES "
                    "(:id, :lic, :a, 1, 'sha256:x', 'k', '{}'::jsonb, 'issued')"
                ),
                {"id": ids["iss"], "lic": ids["lic"], "a": ids["a"]},
            )
            for key, state in (("d1", "delivered"), ("d2", "active")):
                conn.execute(
                    text(
                        "INSERT INTO licence_deliveries (id, issuance_id, target_ref) "
                        "VALUES (:id, :iss, :ref)"
                    ),
                    {"id": ids[key], "iss": ids["iss"], "ref": f"legacy-{key}"},
                )
                conn.execute(
                    text(
                        "INSERT INTO licence_delivery_states "
                        "(id, delivery_id, state) VALUES (:id, :d, :state)"
                    ),
                    {"id": str(uuid.uuid4()), "d": ids[key], "state": state},
                )

        # v010 EXACTLY, which is what this test is named for and all it needs.
        #
        # Driving it to `heads` would drag `v014`'s greenfield precondition into
        # a test about delivery quarantine: the allocation row seeded above for
        # v009's foreign key is precisely what `v014` fails closed on. The two
        # requirements are irreconcilable at `heads` and neither is wrong — they
        # just belong to different points in the lineage, which is what naming
        # the target keeps straight.
        _upgrade(scratch_db, "v010_delivery_hardening")

        with eng.connect() as conn:
            states = dict(
                conn.execute(
                    text(
                        "SELECT delivery_id, state FROM licence_delivery_states "
                        "WHERE delivery_id = ANY(:ids)"
                    ),
                    {"ids": [ids["d1"], ids["d2"]]},
                ).all()
            )
        assert states[uuid.UUID(ids["d1"])] == "parked"
        # The important one: an ACTIVE legacy row is quarantined too.
        assert states[uuid.UUID(ids["d2"])] == "parked"
    finally:
        eng.dispose()


def test_v010_check_constraint_rejects_a_new_delivery_without_a_target(
    scratch_db: str,
) -> None:
    """Existing rows are tolerated (NOT VALID) but every NEW row must carry a
    destination — otherwise the boundary would only apply to code paths that
    remembered to enforce it."""
    _upgrade(scratch_db, "heads")
    eng = create_engine(scratch_db)
    try:
        with eng.begin() as conn:
            with pytest.raises(DBAPIError, match="ck_licence_delivery_has_target"):
                conn.execute(
                    text(
                        "INSERT INTO licence_deliveries (id, issuance_id, target_ref) "
                        "VALUES (gen_random_uuid(), gen_random_uuid(), 'x')"
                    )
                )
    finally:
        eng.dispose()


# ─────────────────────────────────────────────────────────────────────────────
# v011 — product identity expand stage
# ─────────────────────────────────────────────────────────────────────────────


def test_v011_preserves_historical_rows_as_explicitly_unclassified(
    scratch_db: str,
) -> None:
    """The migration may not invent a default product for existing commerce."""
    _upgrade(scratch_db, "v010_delivery_hardening")
    offer_id = str(uuid.uuid4())
    contract_id = str(uuid.uuid4())
    eng = create_engine(scratch_db)
    try:
        with eng.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO offer_versions "
                    "(id, offer_code, version, amount, currency_code, "
                    "capability_codes) VALUES "
                    "(:id, 'legacy', 1, '10.00', 'USD', '[\"cap.a\"]'::jsonb)"
                ),
                {"id": offer_id},
            )
            conn.execute(
                text(
                    "INSERT INTO contracts (id, customer_ref, legal_entity, "
                    "currency_code, term_start, term_end, status) VALUES "
                    "(:id, 'cust', 'Dotmac Ltd', 'USD', '2026-01-01', "
                    "'2026-12-31', 'draft')"
                ),
                {"id": contract_id},
            )

        _upgrade(scratch_db, "v011_product_identity")

        with eng.connect() as conn:
            assert (
                conn.execute(
                    text("SELECT product_code FROM offer_versions WHERE id=:id"),
                    {"id": offer_id},
                ).scalar_one()
                is None
            )
            assert (
                conn.execute(
                    text("SELECT product_code FROM contracts WHERE id=:id"),
                    {"id": contract_id},
                ).scalar_one()
                is None
            )
    finally:
        eng.dispose()


def test_v011_offer_identity_is_product_qualified_in_postgres(scratch_db: str) -> None:
    _upgrade(scratch_db, "v011_product_identity")
    eng = create_engine(scratch_db)
    try:
        with eng.begin() as conn:
            for product in ("dotmac-sub", "dotmac-erp"):
                conn.execute(
                    text(
                        "INSERT INTO offer_versions "
                        "(id, product_code, offer_code, version, amount, "
                        "currency_code, capability_codes) VALUES "
                        "(gen_random_uuid(), :product, 'pro', 1, '10.00', "
                        "'USD', '[]'::jsonb)"
                    ),
                    {"product": product},
                )
            with pytest.raises(DBAPIError, match="uq_offer_versions_product_code_ver"):
                conn.execute(
                    text(
                        "INSERT INTO offer_versions "
                        "(id, product_code, offer_code, version, amount, "
                        "currency_code, capability_codes) VALUES "
                        "(gen_random_uuid(), 'dotmac-sub', 'pro', 1, '10.00', "
                        "'USD', '[]'::jsonb)"
                    )
                )
    finally:
        eng.dispose()


def test_v011_rejects_new_unclassified_commercial_rows(scratch_db: str) -> None:
    """NOT VALID preserves history; it still governs every new write."""
    _upgrade(scratch_db, "v011_product_identity")
    eng = create_engine(scratch_db)
    try:
        with pytest.raises(DBAPIError, match="ck_offer_versions_product_identity"):
            with eng.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO offer_versions "
                        "(id, offer_code, version, amount, currency_code, "
                        "capability_codes) VALUES "
                        "(gen_random_uuid(), 'unclassified', 1, '10.00', "
                        "'USD', '[]'::jsonb)"
                    )
                )
        with pytest.raises(DBAPIError, match="ck_contracts_product_identity"):
            with eng.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO contracts (id, customer_ref, legal_entity, "
                        "currency_code, term_start, term_end, status) VALUES "
                        "(gen_random_uuid(), 'cust', 'Dotmac Ltd', 'USD', "
                        "'2026-01-01', '2026-12-31', 'draft')"
                    )
                )
    finally:
        eng.dispose()
