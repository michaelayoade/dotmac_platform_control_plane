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

import os
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

from vendor_cp.migrations import composed_version_locations, make_alembic_config

KERNEL_HEAD = "0011_outbox_relay_leasing"  # current pin (0.1.0a5)
VENDOR_ROOT = "v001_vendor_accounts"
VENDOR_ROOT_DEP = "0009_platform_audit_inbox"  # what v001 depends_on
VENDOR_HEAD = "v003_approval_policies"


def _superuser_url() -> str:
    url = os.getenv("TEST_DATABASE_URL")
    if not url:
        pytest.skip(
            "TEST_DATABASE_URL not set — vendor migration rehearsals need Postgres"
        )
    return url


def _url_for(base_url: str, dbname: str, *, user: str | None = None) -> str:
    scheme_userhost, _, _ = base_url.rpartition("/")
    if user is not None:
        scheme, _, userhost = scheme_userhost.partition("://")
        host = userhost.rpartition("@")[2]
        scheme_userhost = f"{scheme}://{user}@{host}"
    return f"{scheme_userhost}/{dbname}"


@pytest.fixture
def scratch_db() -> Iterator[str]:
    """Create an isolated scratch DB and yield an APP_ADMIN url for it.

    Migrations run as `app_admin` (the production migrator, BYPASSRLS) so the
    table owner + grants match production. The cluster superuser only creates the
    DB and hands its public schema to app_admin (which exists globally once
    `make test-db-up` has run the kernel's initial migration)."""
    superuser = _superuser_url()
    name = f"vcp_rehearsal_{uuid.uuid4().hex[:12]}"
    server = create_engine(superuser, isolation_level="AUTOCOMMIT")
    with server.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    setup = create_engine(_url_for(superuser, name), isolation_level="AUTOCOMMIT")
    with setup.connect() as conn:
        conn.execute(text("ALTER SCHEMA public OWNER TO app_admin"))
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
    # Kernel platform tables the AccountService depends on are present too.
    assert _table_exists(scratch_db, "platform_audit_events")
    assert _table_exists(scratch_db, "platform_inbox_records")
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
    # Two runtime heads: the vendor root pins kernel 0009, but the pin has since
    # advanced to 0010, so the kernel head is no longer subsumed by the vendor
    # lineage — both appear (the two-head topology this lineage is built for).
    assert _versions(scratch_db) == {KERNEL_HEAD, VENDOR_HEAD}


# ─────────────────────────────────────────────────────────────────────────────
# Rehearsal 2 — two-head topology
# ─────────────────────────────────────────────────────────────────────────────
def test_two_head_topology(scratch_db: str) -> None:
    script = ScriptDirectory.from_config(make_alembic_config(scratch_db))
    assert set(script.get_heads()) == {KERNEL_HEAD, VENDOR_HEAD}
    kernel_head = script.get_revision("kernel@head")
    vendor_head = script.get_revision("vendor@head")
    assert kernel_head.revision == KERNEL_HEAD
    assert vendor_head.revision == VENDOR_HEAD
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

    # Deploy the vendor lineage on top — adopts both vendor tables, data-safe.
    _upgrade(scratch_db, "heads")
    assert _table_exists(scratch_db, "vendor_accounts")
    assert _table_exists(scratch_db, "offer_versions")
    assert _table_exists(scratch_db, "approval_policies")
    assert _versions(scratch_db) == {KERNEL_HEAD, VENDOR_HEAD}


# ─────────────────────────────────────────────────────────────────────────────
# Rehearsal 5 — kernel advance keeps the vendor head independent
# ─────────────────────────────────────────────────────────────────────────────
def test_kernel_advance_keeps_vendor_head_independent(
    scratch_db: str, tmp_path: Path
) -> None:
    """Simulate a FUTURE kernel migration (a child of the kernel head). The
    vendor head must remain a separate head — the two-head topology the vendor
    lineage is designed for — and a composed upgrade must still apply both."""
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
    # Kernel head has advanced to the synthetic revision; vendor head is untouched.
    assert set(script.get_heads()) == {synth_rev, VENDOR_HEAD}

    command.upgrade(cfg, "heads")
    assert _table_exists(scratch_db, "vendor_accounts")
    assert _versions(scratch_db) == {synth_rev, VENDOR_HEAD}
