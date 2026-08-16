"""The greenfield allocation switch, proved against a real database.

`v014` is valid only because the legacy tables are EMPTY, so the load-bearing
test is the one where that premise is FALSE. The rest proves the transfer:
`platform_api` gains what it needs on `mod_ealloc` and nothing more, the tenant
role stays out, and the legacy estate is gone.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from alembic import command
from sqlalchemy import create_engine, text

from vendor_cp.migrations import make_alembic_config

PRIOR_REVISION = "v013_approvals_authority_switch"
SWITCH_REVISION = "v014_allocations_authority_switch"

SCHEMA = "mod_ealloc"
MODULE_TABLES = ("allocations", "allocation_entries")
LEGACY_TABLES = ("allocations", "allocation_entries")

ONLINE_ROLE = "platform_api"
TENANT_ROLE = "app_user"
GRANTED = ("SELECT", "INSERT", "UPDATE", "DELETE")
NEVER_GRANTED = ("TRUNCATE", "REFERENCES", "TRIGGER")
COLUMN_GRANTABLE = frozenset({"SELECT", "INSERT", "UPDATE", "REFERENCES"})


def _upgrade(url: str, target: str = "heads") -> None:
    command.upgrade(make_alembic_config(url), target)


def _holds(url: str, role: str, qualified: str, privilege: str) -> bool:
    statement = "SELECT has_table_privilege(:role, :rel, :priv)"
    if privilege in COLUMN_GRANTABLE:
        statement += " OR has_any_column_privilege(:role, :rel, :priv)"
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            return bool(
                conn.execute(
                    text(statement),
                    {"role": role, "rel": qualified, "priv": privilege},
                ).scalar()
            )
    finally:
        engine.dispose()


def _exists(url: str, qualified: str) -> bool:
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            return bool(
                conn.execute(
                    text("SELECT to_regclass(:q) IS NOT NULL"), {"q": qualified}
                ).scalar()
            )
    finally:
        engine.dispose()


# ── The premise, checked ────────────────────────────────────────────────────


def test_a_populated_legacy_table_stops_the_switch(scratch_db: str) -> None:
    """THE test.

    A row in the legacy estate means the greenfield assumption was wrong, and the
    correct response to a wrong premise is to change nothing at all.
    """
    _upgrade(scratch_db, PRIOR_REVISION)

    engine = create_engine(scratch_db)
    try:
        with engine.begin() as conn:
            contract_id = str(uuid.uuid4())
            conn.execute(
                text(
                    "INSERT INTO contracts (id, product_code, customer_ref, "
                    "legal_entity, currency_code, term_start, term_end, status) "
                    "VALUES (:id, 'dotmac-sub', 'cust', 'Dotmac Ltd', 'USD', "
                    "'2026-01-01', '2026-12-31', 'active')"
                ),
                {"id": contract_id},
            )
            conn.execute(
                text(
                    "INSERT INTO allocations (id, contract_id, customer_ref, "
                    "content_hash, status, source_event_id) VALUES "
                    "(:id, :c, 'cust', 'h', 'staged', 'evt')"
                ),
                {"id": str(uuid.uuid4()), "c": contract_id},
            )
    finally:
        engine.dispose()

    with pytest.raises(RuntimeError, match="requires an EMPTY legacy"):
        _upgrade(scratch_db, SWITCH_REVISION)

    # Nothing happened.
    for table in LEGACY_TABLES:
        assert _exists(scratch_db, f"public.{table}")
    assert not _holds(scratch_db, ONLINE_ROLE, f"{SCHEMA}.allocations", "INSERT")


def test_the_empty_check_is_not_vacuous(scratch_db: str) -> None:
    """NON-VACUITY: the same migration succeeds on a genuinely empty estate, so
    the refusal above is about the ROWS rather than a broken migration."""
    _upgrade(scratch_db, PRIOR_REVISION)
    _upgrade(scratch_db, SWITCH_REVISION)
    for table in LEGACY_TABLES:
        assert not _exists(scratch_db, f"public.{table}")


# ── The transfer ────────────────────────────────────────────────────────────


@pytest.mark.parametrize("table", MODULE_TABLES)
def test_the_online_role_can_operate_the_module(scratch_db: str, table: str) -> None:
    _upgrade(scratch_db)
    qualified = f"{SCHEMA}.{table}"

    missing = [p for p in GRANTED if not _holds(scratch_db, ONLINE_ROLE, qualified, p)]
    assert not missing, f"{ONLINE_ROLE} cannot operate {qualified}: {missing}"

    excess = [p for p in NEVER_GRANTED if _holds(scratch_db, ONLINE_ROLE, qualified, p)]
    assert not excess, f"{ONLINE_ROLE} holds {excess} on {qualified}"


@pytest.mark.parametrize("table", MODULE_TABLES)
def test_the_tenant_role_is_still_shut_out(scratch_db: str, table: str) -> None:
    _upgrade(scratch_db)
    qualified = f"{SCHEMA}.{table}"
    held = [
        p
        for p in (*GRANTED, *NEVER_GRANTED)
        if _holds(scratch_db, TENANT_ROLE, qualified, p)
    ]
    assert not held, f"{TENANT_ROLE} holds {held} on {qualified}"


def test_the_privilege_reader_would_notice_a_missing_grant(scratch_db: str) -> None:
    """SENSITIVITY for the positive half: revoke a granted privilege and prove
    the same reader reports it absent, so "all present" cannot pass by reading
    nothing."""
    _upgrade(scratch_db)
    qualified = f"{SCHEMA}.allocations"
    engine = create_engine(scratch_db)
    try:
        with engine.begin() as conn:
            conn.execute(text(f"REVOKE INSERT ON {qualified} FROM {ONLINE_ROLE}"))  # noqa: S608
        assert not _holds(scratch_db, ONLINE_ROLE, qualified, "INSERT")
        with engine.begin() as conn:
            conn.execute(text(f"GRANT INSERT ON {qualified} TO {ONLINE_ROLE}"))  # noqa: S608
    finally:
        engine.dispose()
    assert _holds(scratch_db, ONLINE_ROLE, qualified, "INSERT")


# ── The estate is gone ──────────────────────────────────────────────────────


def test_the_legacy_tables_are_dropped_and_the_module_owns_the_names(
    scratch_db: str,
) -> None:
    """The module's tables share their NAMES with the legacy ones, so "the legacy
    tables are gone" must not be satisfied by the module's having been built over
    them. They live in different schemas, and both facts are asserted."""
    _upgrade(scratch_db)
    for table in LEGACY_TABLES:
        assert not _exists(scratch_db, f"public.{table}")
    for table in MODULE_TABLES:
        assert _exists(scratch_db, f"{SCHEMA}.{table}")


def test_downgrade_is_refused(scratch_db: str) -> None:
    _upgrade(scratch_db)
    with pytest.raises(RuntimeError, match="cannot be downgraded"):
        command.downgrade(make_alembic_config(scratch_db), PRIOR_REVISION)
    # Inert: the switch's effects are all still in place.
    assert not _exists(scratch_db, "public.allocations")
    assert _holds(scratch_db, ONLINE_ROLE, f"{SCHEMA}.allocations", "INSERT")


def test_the_migration_takes_the_lock_it_needs_up_front() -> None:
    """It DROPs these tables, so it takes ACCESS EXCLUSIVE once, before reading
    anything — escalating mid-transaction is how deadlocks are made."""
    source = (
        Path(__file__).resolve().parents[2]
        / "alembic"
        / "versions"
        / "v014_allocations_authority_switch.py"
    ).read_text()
    assert "IN ACCESS EXCLUSIVE MODE" in source
    assert source.index("LOCK TABLE") < source.index("_require_empty")
    assert "IN SHARE MODE" not in source
