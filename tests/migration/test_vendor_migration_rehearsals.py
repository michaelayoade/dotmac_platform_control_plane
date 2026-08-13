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
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

from vendor_cp.migrations import composed_version_locations, make_alembic_config

KERNEL_HEAD = "0023_audit_actor_and_forensics"  # current pin (0.1.0a50)
PREVIOUS_KERNEL_HEAD = "0012_platform_outbox"  # former pin (0.1.0a9)
RELEASE_CATALOG_HEAD = "rl_0001_release_artifacts"
ENTITLEMENT_ALLOCATION_HEAD = "ea_0001_allocations"
VENDOR_ROOT = "v001_vendor_accounts"
VENDOR_ROOT_DEP = "0009_platform_audit_inbox"  # what v001 depends_on
VENDOR_HEAD = "v011_product_identity"


def _superuser_url(postgres_url: str) -> str:
    """The cluster superuser URL, taken from the `postgres_url` fixture
    (conftest), which skips locally but FAILS under REQUIRE_POSTGRES_TESTS=1 —
    so this suite cannot pass by being skipped in required CI."""
    return postgres_url


def _url_for(base_url: str, dbname: str, *, user: str | None = None) -> str:
    scheme_userhost, _, _ = base_url.rpartition("/")
    if user is not None:
        scheme, _, userhost = scheme_userhost.partition("://")
        host = userhost.rpartition("@")[2]
        scheme_userhost = f"{scheme}://{user}@{host}"
    return f"{scheme_userhost}/{dbname}"


@pytest.fixture
def scratch_db(postgres_url: str) -> Iterator[str]:
    """Create an isolated scratch DB and yield an APP_ADMIN url for it.

    Migrations run as `app_admin` (the production migrator, BYPASSRLS) so the
    table owner + grants match production. The cluster superuser only creates the
    DB and hands its public schema to app_admin (which exists globally once
    `make test-db-up` has run the kernel's initial migration)."""
    superuser = _superuser_url(postgres_url)
    name = f"vcp_rehearsal_{uuid.uuid4().hex[:12]}"
    server = create_engine(superuser, isolation_level="AUTOCOMMIT")
    with server.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    setup = create_engine(_url_for(superuser, name), isolation_level="AUTOCOMMIT")
    with setup.connect() as conn:
        conn.execute(text("ALTER SCHEMA public OWNER TO app_admin"))
        # A stateful MODULE owns and creates its own schema. PostgreSQL checks
        # CREATE on the database for CREATE SCHEMA; owning `public` only covered
        # the pre-module kernel + assembly rehearsal.
        conn.execute(text(f'GRANT CREATE ON DATABASE "{name}" TO app_admin'))
        # The access canary must connect as the real online roles. Granting a
        # database connection does not grant schema/table access; the module
        # migration remains the authority for those privileges and denials.
        conn.execute(
            text(
                f'GRANT CONNECT ON DATABASE "{name}" TO platform_api, app_user, '
                "app_admin"
            )
        )
    setup.dispose()
    try:
        yield _url_for(superuser, name, user="app_admin")
    finally:
        with server.connect() as conn:
            conn.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :n AND pid <> pg_backend_pid()"
                ),
                {"n": name},
            )
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}"'))
        server.dispose()


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
    assert _table_exists(scratch_db, "approval_policies")
    assert _table_exists(scratch_db, "approval_records")
    assert _table_exists(scratch_db, "contracts")
    assert _table_exists(scratch_db, "contract_lines")
    assert _table_exists(scratch_db, "allocations")
    assert _table_exists(scratch_db, "allocation_entries")
    assert "product_code" in _column_names(scratch_db, "offer_versions")
    assert "product_code" in _column_names(scratch_db, "contracts")
    # Kernel platform tables the AccountService depends on are present too.
    assert _table_exists(scratch_db, "platform_audit_events")
    assert _table_exists(scratch_db, "platform_idempotency_records")
    assert _qualified_table_exists(scratch_db, "mod_rel.release_artifacts")
    assert _qualified_table_exists(scratch_db, "mod_rel.artifact_attestations")
    assert _qualified_table_exists(scratch_db, "mod_ealloc.allocations")
    assert _qualified_table_exists(scratch_db, "mod_ealloc.allocation_entries")
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
    # Four independent runtime heads: kernel, vendor assembly and both installed
    # modules each retain their own migration authority.
    assert _versions(scratch_db) == {
        KERNEL_HEAD,
        ENTITLEMENT_ALLOCATION_HEAD,
        RELEASE_CATALOG_HEAD,
        VENDOR_HEAD,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Rehearsal 2 — four-head topology
# ─────────────────────────────────────────────────────────────────────────────
def test_four_head_topology(scratch_db: str) -> None:
    script = ScriptDirectory.from_config(make_alembic_config(scratch_db))
    assert set(script.get_heads()) == {
        KERNEL_HEAD,
        ENTITLEMENT_ALLOCATION_HEAD,
        RELEASE_CATALOG_HEAD,
        VENDOR_HEAD,
    }
    kernel_head = script.get_revision("kernel@head")
    vendor_head = script.get_revision("vendor@head")
    release_catalog_head = script.get_revision("release_catalog@head")
    allocation_head = script.get_revision("entitlement_allocation@head")
    assert kernel_head.revision == KERNEL_HEAD
    assert vendor_head.revision == VENDOR_HEAD
    assert release_catalog_head.revision == RELEASE_CATALOG_HEAD
    assert allocation_head.revision == ENTITLEMENT_ALLOCATION_HEAD
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
def test_platform_role_access_and_tenant_role_denial(scratch_db: str) -> None:
    _upgrade(scratch_db, "heads")

    # platform_api may INSERT + SELECT vendor_accounts.
    plat = create_engine(
        _url_for(scratch_db, scratch_db.rsplit("/", 1)[1], user="platform_api")
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
        _url_for(scratch_db, scratch_db.rsplit("/", 1)[1], user="platform_api")
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
        _url_for(scratch_db, scratch_db.rsplit("/", 1)[1], user="platform_api")
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
        _url_for(scratch_db, scratch_db.rsplit("/", 1)[1], user="app_user")
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
        # The WS8 licence tables carry the same REVOKE. The signing-key registry
        # holds public material only, but a tenant application role has no
        # business reading which keys exist or what a customer was issued.
        for table in (
            "licence_signing_keys",
            "licences",
            "licence_issuances",
            "licence_deliveries",
            "licence_delivery_states",
            "licence_ack_records",
            "licence_revocation_entries",
            "licence_revocation_lists",
            "licence_delivery_attempts",
            "licence_delivery_targets",
        ):
            with appu.connect() as conn:
                with pytest.raises(DBAPIError, match="permission denied"):
                    conn.execute(text(f"SELECT count(*) FROM {table}")).scalar()  # noqa: S608
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
    assert _table_exists(scratch_db, "approval_policies")
    assert _table_exists(scratch_db, "contracts")
    assert _table_exists(scratch_db, "allocations")
    assert _qualified_table_exists(scratch_db, "mod_rel.release_artifacts")
    assert _qualified_table_exists(scratch_db, "mod_ealloc.allocations")
    assert _versions(scratch_db) == {
        KERNEL_HEAD,
        ENTITLEMENT_ALLOCATION_HEAD,
        RELEASE_CATALOG_HEAD,
        VENDOR_HEAD,
    }


def test_upgrade_from_previous_vendor_deployment_preserves_data(
    scratch_db: str,
) -> None:
    """Rehearse a9 + vendor v010 to a45 + both installed module lineages."""
    _upgrade(scratch_db, "vendor@head")
    _upgrade(scratch_db, PREVIOUS_KERNEL_HEAD)
    assert _versions(scratch_db) == {PREVIOUS_KERNEL_HEAD, VENDOR_HEAD}
    assert not _qualified_table_exists(scratch_db, "mod_rel.release_artifacts")
    assert not _qualified_table_exists(scratch_db, "mod_ealloc.allocations")

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
    assert (
        _q(
            scratch_db,
            "SELECT count(*) FROM vendor_accounts WHERE id = CAST(:id AS uuid)",
            id=account_id,
        )
        == 1
    )
    assert _versions(scratch_db) == {
        KERNEL_HEAD,
        ENTITLEMENT_ALLOCATION_HEAD,
        RELEASE_CATALOG_HEAD,
        VENDOR_HEAD,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Rehearsal 5 — kernel advance keeps the vendor head independent
# ─────────────────────────────────────────────────────────────────────────────
def test_kernel_advance_keeps_vendor_head_independent(
    scratch_db: str, tmp_path: Path
) -> None:
    """Simulate a FUTURE kernel migration (a child of the kernel head). The
    vendor and module heads must remain separate heads — and a composed upgrade
    must still apply all four lineages."""
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
        VENDOR_HEAD,
    }

    command.upgrade(cfg, "heads")
    assert _table_exists(scratch_db, "vendor_accounts")
    assert _versions(scratch_db) == {
        synth_rev,
        ENTITLEMENT_ALLOCATION_HEAD,
        RELEASE_CATALOG_HEAD,
        VENDOR_HEAD,
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

        _upgrade(scratch_db, "heads")

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

        _upgrade(scratch_db, "heads")

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
    _upgrade(scratch_db, "heads")
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
    _upgrade(scratch_db, "heads")
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
