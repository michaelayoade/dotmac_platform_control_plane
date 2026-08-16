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
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ProgrammingError

from vendor_cp.migrations import make_alembic_config

#: Targeting the vendor lineage alone leaves the MODULE lineages unapplied —
#: they are separate heads, and `mod_ealloc` would not exist. A pre-v014 database
#: is every head EXCEPT the one under test, which Alembic cannot express in a
#: single target, so the module heads are applied explicitly first.
PRE_SWITCH_TARGETS = (
    "rl_0001_release_artifacts",
    "ea_0001_allocations",
    "v013_approvals_authority_switch",
)
PRIOR_REVISION = "v013_approvals_authority_switch"
SWITCH_REVISION = "v014_allocations_authority"

SCHEMA = "mod_ealloc"
MODULE_TABLES = ("allocations", "allocation_entries")
LEGACY_TABLES = ("allocations", "allocation_entries")

ONLINE_ROLE = "platform_api"
TENANT_ROLE = "app_user"
REQUIRED_TABLE_PRIVILEGES = ("SELECT", "INSERT")
FORBIDDEN_TABLE_PRIVILEGES = (
    "UPDATE",
    "DELETE",
    "TRUNCATE",
    "REFERENCES",
    "TRIGGER",
)
ALL_TABLE_PRIVILEGES = (
    *REQUIRED_TABLE_PRIVILEGES,
    *FORBIDDEN_TABLE_PRIVILEGES,
)
ALLOCATION_UPDATE_COLUMNS = frozenset({"sealed", "updated_at"})
COLUMN_GRANTABLE = frozenset({"SELECT", "INSERT", "UPDATE", "REFERENCES"})


def _upgrade(url: str, target: str = "heads") -> None:
    command.upgrade(make_alembic_config(url), target)


def _upgrade_to_pre_switch(url: str) -> None:
    """Everything except `v014` — including the module lineages."""
    for target in PRE_SWITCH_TARGETS:
        _upgrade(url, target)


def _scalar(url: str, statement: str, parameters: dict[str, str]) -> bool:
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            return bool(conn.execute(text(statement), parameters).scalar())
    finally:
        engine.dispose()


def _table_holds(url: str, role: str, qualified: str, privilege: str) -> bool:
    return _scalar(
        url,
        "SELECT has_table_privilege(:role, :rel, :priv)",
        {"role": role, "rel": qualified, "priv": privilege},
    )


def _column_holds(
    url: str, role: str, qualified: str, column: str, privilege: str
) -> bool:
    return _scalar(
        url,
        "SELECT has_column_privilege(:role, :rel, :column, :priv)",
        {"role": role, "rel": qualified, "column": column, "priv": privilege},
    )


def _holds_any(url: str, role: str, qualified: str, privilege: str) -> bool:
    statement = "SELECT has_table_privilege(:role, :rel, :priv)"
    if privilege in COLUMN_GRANTABLE:
        statement += " OR has_any_column_privilege(:role, :rel, :priv)"
    return _scalar(
        url,
        statement,
        {"role": role, "rel": qualified, "priv": privilege},
    )


def _columns(url: str, qualified: str) -> tuple[str, ...]:
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            return tuple(
                conn.execute(
                    text(
                        "SELECT attname FROM pg_attribute "
                        "WHERE attrelid = to_regclass(:rel) "
                        "AND attnum > 0 AND NOT attisdropped ORDER BY attnum"
                    ),
                    {"rel": qualified},
                ).scalars()
            )
    finally:
        engine.dispose()


def _privilege_snapshot(
    url: str, role: str
) -> tuple[tuple[str, str, str, bool], ...]:
    facts: list[tuple[str, str, str, bool]] = []
    for table in MODULE_TABLES:
        qualified = f"{SCHEMA}.{table}"
        for privilege in ALL_TABLE_PRIVILEGES:
            facts.append(
                (table, "table", privilege, _table_holds(url, role, qualified, privilege))
            )
        for column in _columns(url, qualified):
            for privilege in ("UPDATE", "REFERENCES"):
                facts.append(
                    (
                        table,
                        column,
                        privilege,
                        _column_holds(url, role, qualified, column, privilege),
                    )
                )
    return tuple(facts)


def _role_url(url: str, role: str) -> str:
    parsed = make_url(url)
    return parsed.set(username=role, password=None).render_as_string(
        hide_password=False
    )


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
    _upgrade_to_pre_switch(scratch_db)

    # The privilege state BEFORE, so "nothing happened" is measured rather than
    # guessed. It is deliberately not asserted to any particular value here:
    # `ea_0001_allocations` grants the online role DML on the module's tables the
    # moment it installs, and — unlike approvals, which vendor `v012` held
    # read-only through a shadow phase — allocations was never revoked. So the
    # role legitimately holds INSERT before this migration runs, and asserting
    # its ABSENCE would be importing an expectation from a phase that allocations
    # never had.
    before = _privilege_snapshot(scratch_db, ONLINE_ROLE)
    # NON-VACUITY for the equality below. If `_holds` reported False for
    # everything — a broken reader, a mistyped relation — then `after == before`
    # would hold trivially and prove nothing. The module's install grant means
    # some of these must be True.
    assert any(fact[-1] for fact in before), (
        "the privilege reader observed nothing at all before the refusal; "
        "the unchanged-state comparison below would be vacuous"
    )

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

    # Nothing happened: the legacy estate still stands...
    for table in LEGACY_TABLES:
        assert _exists(scratch_db, f"public.{table}")

    # ...and no privilege moved in EITHER direction. Equality against the
    # measured before-state is what makes this a real "unchanged" assertion:
    # a refusal that granted something on its way out, or that revoked
    # something, fails here regardless of which way it went.
    after = _privilege_snapshot(scratch_db, ONLINE_ROLE)
    assert after == before


def test_the_empty_check_is_not_vacuous(scratch_db: str) -> None:
    """NON-VACUITY: the same migration succeeds on a genuinely empty estate, so
    the refusal above is about the ROWS rather than a broken migration."""
    _upgrade_to_pre_switch(scratch_db)
    _upgrade(scratch_db, SWITCH_REVISION)
    for table in LEGACY_TABLES:
        assert not _exists(scratch_db, f"public.{table}")


# ── The transfer ────────────────────────────────────────────────────────────


@pytest.mark.parametrize("table", MODULE_TABLES)
def test_the_online_role_gets_the_module_exact_write_shape(
    scratch_db: str, table: str
) -> None:
    _upgrade(scratch_db)
    qualified = f"{SCHEMA}.{table}"

    missing = [
        privilege
        for privilege in REQUIRED_TABLE_PRIVILEGES
        if not _table_holds(scratch_db, ONLINE_ROLE, qualified, privilege)
    ]
    assert not missing, f"{ONLINE_ROLE} cannot create/read {qualified}: {missing}"

    excess = [
        privilege
        for privilege in FORBIDDEN_TABLE_PRIVILEGES
        if _table_holds(scratch_db, ONLINE_ROLE, qualified, privilege)
    ]
    assert not excess, f"{ONLINE_ROLE} holds table privileges {excess} on {qualified}"

    expected_updates = (
        ALLOCATION_UPDATE_COLUMNS if table == "allocations" else frozenset()
    )
    columns = _columns(scratch_db, qualified)
    actual_updates = {
        column
        for column in columns
        if _column_holds(scratch_db, ONLINE_ROLE, qualified, column, "UPDATE")
    }
    assert actual_updates == expected_updates
    assert not {
        column
        for column in columns
        if _column_holds(scratch_db, ONLINE_ROLE, qualified, column, "REFERENCES")
    }


@pytest.mark.parametrize("table", MODULE_TABLES)
def test_the_tenant_role_is_still_shut_out(scratch_db: str, table: str) -> None:
    _upgrade(scratch_db)
    qualified = f"{SCHEMA}.{table}"
    held = [
        privilege
        for privilege in ALL_TABLE_PRIVILEGES
        if _holds_any(scratch_db, TENANT_ROLE, qualified, privilege)
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
        assert not _table_holds(scratch_db, ONLINE_ROLE, qualified, "INSERT")
        with engine.begin() as conn:
            conn.execute(text(f"GRANT INSERT ON {qualified} TO {ONLINE_ROLE}"))  # noqa: S608
    finally:
        engine.dispose()
    assert _table_holds(scratch_db, ONLINE_ROLE, qualified, "INSERT")


def test_raw_online_sql_cannot_rewrite_or_delete_allocation_facts(
    scratch_db: str,
) -> None:
    """The service needs INSERT plus the one-way seal, not general DML."""
    _upgrade(scratch_db)
    online = create_engine(_role_url(scratch_db, ONLINE_ROLE))
    allocation_id = str(uuid.uuid4())
    try:
        with online.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO mod_ealloc.allocations "
                    "(id, contract_ref, product_code, customer_ref, content_hash, "
                    "status, source_event_id, snapshot_fingerprint, sealed) "
                    "VALUES (:id, :contract, 'dotmac-sub', 'customer-original', "
                    "'content', 'staged', 'event', :fingerprint, false)"
                ),
                {
                    "id": allocation_id,
                    "contract": str(uuid.uuid4()),
                    "fingerprint": "f" * 64,
                },
            )
            conn.execute(
                text(
                    "INSERT INTO mod_ealloc.allocation_entries "
                    "(id, allocation_id, capability_code, quantity) "
                    "VALUES (:id, :allocation, 'cap.a', 1)"
                ),
                {"id": str(uuid.uuid4()), "allocation": allocation_id},
            )
            conn.execute(
                text(
                    "UPDATE mod_ealloc.allocations "
                    "SET sealed = true, updated_at = now() WHERE id = :id"
                ),
                {"id": allocation_id},
            )

        refused = (
            "UPDATE mod_ealloc.allocations "
            "SET customer_ref = 'tampered' WHERE id = :id",
            "DELETE FROM mod_ealloc.allocation_entries WHERE allocation_id = :id",
            "UPDATE mod_ealloc.allocation_entries SET quantity = 2 "
            "WHERE allocation_id = :id",
            "DELETE FROM mod_ealloc.allocations WHERE id = :id",
        )
        for statement in refused:
            with pytest.raises(ProgrammingError, match="permission denied"):
                with online.begin() as conn:
                    conn.execute(text(statement), {"id": allocation_id})
    finally:
        online.dispose()

    engine = create_engine(scratch_db)
    try:
        with engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT customer_ref, sealed FROM mod_ealloc.allocations "
                    "WHERE id = :id"
                ),
                {"id": allocation_id},
            ).one()
            quantity = conn.execute(
                text(
                    "SELECT quantity FROM mod_ealloc.allocation_entries "
                    "WHERE allocation_id = :id"
                ),
                {"id": allocation_id},
            ).scalar_one()
    finally:
        engine.dispose()
    assert row == ("customer-original", True)
    assert quantity == 1


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


def test_no_foreign_key_reaches_the_module_or_the_dropped_estate(
    scratch_db: str,
) -> None:
    """`licence_issuances.allocation_id` used to carry an FK to
    `public.allocations`.

    That constraint had to go, and for two reasons rather than one. PostgreSQL
    refuses to drop a table a foreign key still depends on, so it BLOCKED the
    switch — the unit suite found it before CI did. And it must not simply be
    re-pointed at `mod_ealloc.allocations`, because no FK may cross into a
    module's schema (ADR-0023): a module's tables are its own, and a constraint
    on them would make this assembly's DDL depend on the module's.

    So the column stays as an OPAQUE reference. The rule that actually matters —
    one issued version per staged allocation — is a unique constraint on
    `licence_issuances` and is untouched, which this asserts too.
    """
    _upgrade(scratch_db)
    engine = create_engine(scratch_db)
    try:
        with engine.connect() as conn:
            crossing = conn.execute(
                text(
                    "SELECT c.conname, rn.nspname, r.relname FROM pg_constraint c "
                    "JOIN pg_class t ON t.oid = c.conrelid "
                    "JOIN pg_class r ON r.oid = c.confrelid "
                    "JOIN pg_namespace rn ON rn.oid = r.relnamespace "
                    "WHERE c.contype = 'f' AND t.relname = 'licence_issuances'"
                )
            ).all()
            uniques = set(
                conn.execute(
                    text(
                        "SELECT conname FROM pg_constraint c "
                        "JOIN pg_class t ON t.oid = c.conrelid "
                        "WHERE c.contype = 'u' AND t.relname = 'licence_issuances'"
                    )
                ).scalars()
            )
    finally:
        engine.dispose()

    offending = [row for row in crossing if row[2] in ("allocations",)]
    assert (
        not offending
    ), f"a foreign key still points at an allocations table: {offending}"
    assert (
        "uq_licence_issuance_allocation" in uniques
    ), "the one-issuance-per-allocation rule was lost with the foreign key"


def test_downgrade_is_refused(scratch_db: str) -> None:
    _upgrade(scratch_db)
    with pytest.raises(RuntimeError, match="cannot be downgraded"):
        command.downgrade(make_alembic_config(scratch_db), PRIOR_REVISION)
    # Inert: the switch's effects are all still in place.
    assert not _exists(scratch_db, "public.allocations")
    assert _table_holds(
        scratch_db, ONLINE_ROLE, f"{SCHEMA}.allocations", "INSERT"
    )


def test_the_migration_takes_the_lock_it_needs_up_front() -> None:
    """It DROPs these tables, so it takes ACCESS EXCLUSIVE once, before reading
    anything — escalating mid-transaction is how deadlocks are made."""
    source = (
        Path(__file__).resolve().parents[2]
        / "alembic"
        / "versions"
        / "v014_allocations_authority.py"
    ).read_text()
    assert "IN ACCESS EXCLUSIVE MODE" in source
    assert source.index("LOCK TABLE") < source.index("_require_empty")
    assert "IN SHARE MODE" not in source
    assert 'LOCK_TABLES = ("allocations", "allocation_entries")' in source
    assert 'DROP_TABLES = ("allocation_entries", "allocations")' in source
    assert 'for table in LOCK_TABLES' in source
    assert 'for table in DROP_TABLES' in source
