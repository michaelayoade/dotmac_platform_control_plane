"""The greenfield authority switch, proved against a real database.

`v013` is valid only because the legacy tables are EMPTY. That is the premise the
whole change rests on, so it is checked under lock in the same transaction that
drops them — and the important test here is the one where the premise is FALSE.

The switch also reverses v012's revoke, so the privilege assertions run the other
way: `platform_api` must now hold what it needs to operate the module, and still
nothing beyond it.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from alembic import command
from dotmac_approvals.models import PLATFORM_TABLES
from sqlalchemy import create_engine, text

from vendor_cp.migrations import make_alembic_config

SHADOW_REVISION = "v012_approvals_shadow_readonly"
SWITCH_REVISION = "v013_approvals_authority_switch"
SCHEMA = "mod_approvals"
ONLINE_ROLE = "platform_api"
TENANT_ROLE = "app_user"

GRANTED = ("SELECT", "INSERT", "UPDATE", "DELETE")
NEVER_GRANTED = ("TRUNCATE", "REFERENCES", "TRIGGER")
COLUMN_GRANTABLE = frozenset({"SELECT", "INSERT", "UPDATE", "REFERENCES"})

LEGACY_TABLES = ("approval_policies", "approval_records")


def _upgrade(url: str, target: str = "heads") -> None:
    command.upgrade(make_alembic_config(url), target)


def _holds(url: str, role: str, table: str, privilege: str) -> bool:
    statement = "SELECT has_table_privilege(:role, :rel, :priv)"
    if privilege in COLUMN_GRANTABLE:
        statement += " OR has_any_column_privilege(:role, :rel, :priv)"
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            return bool(
                conn.execute(
                    text(statement),
                    {"role": role, "rel": f"{SCHEMA}.{table}", "priv": privilege},
                ).scalar()
            )
    finally:
        engine.dispose()


def _table_exists(url: str, qualified: str) -> bool:
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


# ── The premise: EMPTY, checked rather than assumed ─────────────────────────


def test_a_populated_legacy_table_stops_the_switch(scratch_db: str) -> None:
    """THE test.

    Everything else here describes a switch that went ahead. This one describes
    the case the check exists for: a row in the legacy estate means the
    greenfield premise was wrong, and the correct response to a wrong premise is
    to change nothing at all.
    """
    _upgrade(scratch_db, SHADOW_REVISION)

    engine = create_engine(scratch_db)
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO approval_policies "
                    "(id, policy_code, version, quorum, allow_self_approval) "
                    "VALUES (:id, 'legacy', 1, 2, false)"
                ),
                {"id": str(uuid.uuid4())},
            )
    finally:
        engine.dispose()

    with pytest.raises(RuntimeError, match="requires an EMPTY legacy estate"):
        _upgrade(scratch_db, SWITCH_REVISION)

    # Nothing happened: the tables are still there, the column was not added,
    # and the online role did not gain write access.
    for table in LEGACY_TABLES:
        assert _table_exists(scratch_db, f"public.{table}")
    assert not _holds(scratch_db, ONLINE_ROLE, PLATFORM_TABLES[0], "INSERT")

    engine = create_engine(scratch_db)
    try:
        with engine.connect() as conn:
            columns = set(
                conn.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_name='contracts'"
                    )
                ).scalars()
            )
    finally:
        engine.dispose()
    assert (
        "approval_request_id" not in columns
    ), "the switch made a change before verifying its premise"


def test_the_empty_check_is_not_vacuous(scratch_db: str) -> None:
    """NON-VACUITY: the same migration succeeds when the estate really is empty,
    so the refusal above is about the ROWS and not about the migration being
    broken."""
    _upgrade(scratch_db, SHADOW_REVISION)
    _upgrade(scratch_db, SWITCH_REVISION)
    for table in LEGACY_TABLES:
        assert not _table_exists(scratch_db, f"public.{table}")


# ── The transfer ────────────────────────────────────────────────────────────


@pytest.mark.parametrize("table", PLATFORM_TABLES)
def test_the_online_role_can_operate_the_module(scratch_db: str, table: str) -> None:
    """v012's revoke, reversed — verified as an OUTCOME, both directions."""
    _upgrade(scratch_db)

    missing = [p for p in GRANTED if not _holds(scratch_db, ONLINE_ROLE, table, p)]
    assert not missing, f"{ONLINE_ROLE} cannot operate {table}: missing {missing}"

    excess = [p for p in NEVER_GRANTED if _holds(scratch_db, ONLINE_ROLE, table, p)]
    assert not excess, f"{ONLINE_ROLE} holds {excess} on {table}"


@pytest.mark.parametrize("table", PLATFORM_TABLES)
def test_the_tenant_role_is_still_shut_out(scratch_db: str, table: str) -> None:
    """The authority moved between control-plane roles. It did not open the
    module to the tenant application role, which has no business here at all."""
    _upgrade(scratch_db)
    held = [
        p
        for p in (*GRANTED, *NEVER_GRANTED)
        if _holds(scratch_db, TENANT_ROLE, table, p)
    ]
    assert not held, f"{TENANT_ROLE} holds {held} on {table}"


def test_the_privilege_reader_would_notice_a_missing_grant(scratch_db: str) -> None:
    """SENSITIVITY for the positive half: revoke one of the granted privileges
    and prove the same reader reports it absent."""
    _upgrade(scratch_db)
    table = PLATFORM_TABLES[0]
    engine = create_engine(scratch_db)
    try:
        with engine.begin() as conn:
            conn.execute(
                text(f"REVOKE INSERT ON {SCHEMA}.{table} FROM {ONLINE_ROLE}")  # noqa: S608
            )
        assert not _holds(scratch_db, ONLINE_ROLE, table, "INSERT")
        with engine.begin() as conn:
            conn.execute(
                text(f"GRANT INSERT ON {SCHEMA}.{table} TO {ONLINE_ROLE}")  # noqa: S608
            )
    finally:
        engine.dispose()
    assert _holds(scratch_db, ONLINE_ROLE, table, "INSERT")


# ── The estate is gone, and the contract carries a request ──────────────────


def test_the_legacy_tables_are_dropped(scratch_db: str) -> None:
    _upgrade(scratch_db)
    for table in LEGACY_TABLES:
        assert not _table_exists(scratch_db, f"public.{table}")


def test_the_contract_carries_its_approval_request(scratch_db: str) -> None:
    # Assert the historical v013 effect at v013. At composed heads v015 has
    # retired this entire legacy table in favour of Commercial Agreements.
    _upgrade(scratch_db, SWITCH_REVISION)
    engine = create_engine(scratch_db)
    try:
        with engine.connect() as conn:
            columns = set(
                conn.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_name='contracts'"
                    )
                ).scalars()
            )
    finally:
        engine.dispose()
    assert "approval_request_id" in columns


def test_downgrade_is_refused(scratch_db: str) -> None:
    """An authority moves forward or not at all: restoring the legacy tables
    would produce a database no running version can serve."""
    _upgrade(scratch_db)
    with pytest.raises(RuntimeError, match="cannot be downgraded"):
        command.downgrade(make_alembic_config(scratch_db), SHADOW_REVISION)

    # Inert: the switch's effects are all still in place.
    assert not _table_exists(scratch_db, "public.approval_policies")
    assert _holds(scratch_db, ONLINE_ROLE, PLATFORM_TABLES[0], "INSERT")


def test_the_migration_takes_the_lock_it_needs_up_front() -> None:
    """Escalating SHARE -> ACCESS EXCLUSIVE mid-transaction is how deadlocks are
    made. The migration DROPs these tables, so it takes the strongest lock it
    will need once, before reading anything."""
    source = (
        Path(__file__).resolve().parents[2]
        / "alembic"
        / "versions"
        / "v013_approvals_authority_switch.py"
    ).read_text()
    assert "IN ACCESS EXCLUSIVE MODE" in source
    assert source.index("LOCK TABLE") < source.index("_require_empty")
    assert "IN SHARE MODE" not in source
