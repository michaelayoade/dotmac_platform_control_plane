"""The grant, proved against a real composed database.

This is the half of `PlatformDataGovernanceV1` that is enforcement rather than
discipline. `tests/architecture/test_data_governance.py` shows that no composed
code removes a row from a retained table; nothing there can show that the
DATABASE refuses one. These tests connect as the actual online roles and ask
PostgreSQL.

## The before/after is the evidence that the DEPLOY PATH is the consumer

A test that migrated and then found `DELETE` revoked could not distinguish "the
deploy path governs this database" from "some migration happened to revoke it".
So each proof drives the SAME database twice: once with `make_alembic_config`
(the rehearsal composition, which does not set `require_composed_heads`), where
the online role still holds `DELETE`; then once with `deploy_config`, where the
migrations are already applied and the ONLY thing that runs is the post-condition
— and the privilege is gone. The privilege moving on the second call, with no
DDL between, is what makes the binding executed rather than merely present.

## Both directions, always

A revoke checked only where it should bite is satisfied by revoking everything,
which is the failure vendor `v017`'s post-condition already refuses. So the
transient table is checked in the positive direction too: `platform_api` must
still be able to delete a `feature_flag_overrides` row, because the platform
console's clear action does exactly that.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager

import pytest
from alembic import command
from sqlalchemy import Connection, create_engine, text

from vendor_cp.data_governance import (
    CONTRACT,
    ONLINE_ROLES,
    POLICY_BY_TABLE,
    DataGovernanceRefusal,
    Disposition,
    admission_refusal,
    enforce_retention,
    tables_permitting_online_deletion,
)
from vendor_cp.migrations import deploy_config, make_alembic_config

LIVE_TABLES = (
    "SELECT n.nspname, c.relname FROM pg_catalog.pg_class c "
    "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
    "WHERE c.relkind = 'r' AND n.nspname NOT IN "
    "('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%'"
)

HOLDS = "SELECT has_table_privilege(:role, :table, :privilege)"

TRANSIENT = "public.feature_flag_overrides"

#: Which `(role, table)` pairs may delete, read from the catalogue rather than
#: listed. A hand-picked set of tables is the regression `AGENTS.md` rule 10
#: names; what is named here is the DECISION, and the subjects are derived.
DELETE_HOLDERS = (
    "SELECT r.rolname, n.nspname, c.relname "
    "FROM pg_catalog.pg_class c "
    "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
    "CROSS JOIN pg_catalog.pg_roles r "
    "WHERE c.relkind = 'r' AND n.nspname NOT IN "
    "('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%' "
    "AND r.rolname IN ('platform_api', 'app_user') "
    "AND has_table_privilege(r.oid, c.oid, 'DELETE')"
)


@contextmanager
def _connect(url: str) -> Iterator[Connection]:
    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            yield connection
    finally:
        engine.dispose()


def _rehearse(url: str) -> None:
    """Compose to heads WITHOUT the deploy post-condition."""
    command.upgrade(make_alembic_config(url), "heads")


def _deploy(url: str) -> None:
    """The deploy path. On an already-composed database the migrations are a
    no-op and the post-condition is the only thing that runs."""
    command.upgrade(deploy_config(url), "heads")


def _holds(connection: Connection, role: str, table: str, privilege: str) -> bool:
    return bool(
        connection.execute(
            text(HOLDS), {"role": role, "table": table, "privilege": privilege}
        ).scalar_one()
    )


def _delete_holders(connection: Connection) -> set[tuple[str, str]]:
    return {
        (role, f"{schema}.{table}")
        for role, schema, table in connection.execute(text(DELETE_HOLDERS)).all()
    }


def _live_tables(connection: Connection) -> tuple[str, ...]:
    return tuple(
        f"{schema}.{table}"
        for schema, table in connection.execute(text(LIVE_TABLES)).all()
    )


# ── requirement 1 and 4: the catalogue and the enumeration agree ────────────


def test_every_table_the_composed_database_holds_is_classified(
    scratch_db: str,
) -> None:
    """Derived from the live catalogue, never from a list of tables to look at.

    Both directions: an unclassified table refuses, and a classification the
    database does not have refuses too.
    """
    _rehearse(scratch_db)
    with _connect(scratch_db) as connection:
        observed = _live_tables(connection)

    assert observed, "the composed database must contain tables"
    assert admission_refusal(observed) == "", admission_refusal(observed)
    assert set(observed) == set(POLICY_BY_TABLE)


def test_a_new_unclassified_table_refuses_the_deploy(scratch_db: str) -> None:
    """MEASURED, not asserted: what actually happens when a table arrives that
    nobody classified.

    Created after the composition, exactly as a repinned module's lineage would
    create one. The enforcement refuses, names the table and names the file to
    classify it in, and — because it runs inside the composed upgrade's
    transaction — nothing is committed.
    """
    _rehearse(scratch_db)
    with _connect(scratch_db) as connection:
        with connection.begin():
            connection.execute(
                text("CREATE TABLE public.unclassified_arrival (id int)")
            )
        with connection.begin():
            with pytest.raises(DataGovernanceRefusal) as raised:
                enforce_retention(connection)

    message = str(raised.value)
    assert "public.unclassified_arrival" in message
    assert "data_governance.py" in message
    assert CONTRACT in message


def test_a_classified_table_the_database_lost_refuses_too(scratch_db: str) -> None:
    """The other direction, driven. Without it the check above is satisfied by a
    classification that simply names everything anyone might create."""
    _rehearse(scratch_db)
    with _connect(scratch_db) as connection:
        with connection.begin():
            connection.execute(text("DROP TABLE public.relay_heartbeats CASCADE"))
        with connection.begin():
            with pytest.raises(DataGovernanceRefusal) as raised:
                enforce_retention(connection)

    assert "public.relay_heartbeats" in str(raised.value)


# ── requirement 2: the grant, and the deploy path that applies it ───────────


def test_the_deploy_path_is_what_withholds_delete(scratch_db: str) -> None:
    """Rehearse, observe the privilege widely held; deploy, observe it gone.

    No DDL runs between the two observations — the second `upgrade` finds every
    lineage already at heads, so the migrations are a no-op and the ONLY thing
    that executes is the post-condition. The privileges moving is therefore
    attributable to the enforcement and to nothing else, which is what makes
    this a binding a deployment EXECUTES rather than one that merely exists.

    The subjects are derived from the catalogue. Only the two decisions are
    written down: that a rehearsal really does leave DELETE widely granted (or
    the after-state would prove nothing), and that what survives is exactly the
    one table classified for it.
    """
    _rehearse(scratch_db)
    with _connect(scratch_db) as connection:
        before = _delete_holders(connection)

    assert len(before) >= 15, (
        f"the composed migrations left only {len(before)} (role, table) pairs "
        "holding DELETE. This test's after-state means nothing unless the "
        "before-state is genuinely permissive"
    )
    assert any(table != TRANSIENT for _, table in before)

    _deploy(scratch_db)
    with _connect(scratch_db) as connection:
        after = _delete_holders(connection)

    assert after == {(role, TRANSIENT) for role in ONLINE_ROLES}, sorted(after)


def test_no_online_role_may_truncate_a_governed_table(scratch_db: str) -> None:
    """`TRUNCATE` destroys rows without issuing a `DELETE`. A DELETE-only revoke
    leaves it open, and a check that only asked about DELETE would not notice."""
    _deploy(scratch_db)
    with _connect(scratch_db) as connection:
        for qualified in sorted(POLICY_BY_TABLE):
            for role in ONLINE_ROLES:
                assert not _holds(
                    connection, role, qualified, "TRUNCATE"
                ), f"{role} may TRUNCATE {qualified}"


def test_the_online_role_is_actually_refused_the_statement(
    scratch_db: str, url_for: Callable[..., str]
) -> None:
    """Not `has_table_privilege` — the statement itself, as `platform_api`.

    A catalogue reading is a claim about what the database would do. This makes
    it do it.
    """
    _deploy(scratch_db)
    database = scratch_db.rpartition("/")[2]
    online = url_for(scratch_db, database, user="platform_api")

    with _connect(online) as connection:
        with pytest.raises(Exception) as raised:  # noqa: B017 - driver error class
            connection.execute(
                text("DELETE FROM public.platform_audit_events WHERE false")
            )
        assert "permission denied" in str(raised.value).lower()


def test_the_transient_table_stays_deletable_by_the_online_role(
    scratch_db: str, url_for: Callable[..., str]
) -> None:
    """The half that makes the revoke non-vacuous.

    `public.feature_flag_overrides` is classified LIFECYCLE_DELETE because the
    kernel's platform console clears an override by deleting the row. A
    governance run that took `DELETE` here would leave that action failing
    against the database, and every denial test above would still pass.
    """
    _deploy(scratch_db)
    assert tables_permitting_online_deletion() == (TRANSIENT,)
    database = scratch_db.rpartition("/")[2]
    online = url_for(scratch_db, database, user="platform_api")

    with _connect(online) as connection:
        with connection.begin():
            connection.execute(
                text("DELETE FROM public.feature_flag_overrides WHERE false")
            )


def test_a_transient_policy_nothing_can_act_on_is_refused(scratch_db: str) -> None:
    """SENSITIVITY for the non-vacuity check itself.

    `DELETE` is taken away from the one table classified `LIFECYCLE_DELETE`, and
    the enforcement must refuse rather than report a clean run. Without this, the
    positive-direction check could be a function that never fails.
    """
    _deploy(scratch_db)
    with _connect(scratch_db) as connection:
        with connection.begin():
            connection.execute(
                text(f"REVOKE DELETE ON {TRANSIENT} FROM platform_api, app_user")
            )
        with connection.begin():
            with pytest.raises(DataGovernanceRefusal) as raised:
                enforce_retention(connection)

    assert TRANSIENT in str(raised.value)
    assert "LIFECYCLE_DELETE" in str(raised.value)


def test_the_enforcement_is_idempotent_and_reports_what_it_examined(
    scratch_db: str,
) -> None:
    """A run that examined nothing returns no violations, which is what a
    conforming database also returns. The counts are how they are told apart —
    the same reason `DriftReport` carries `compared`."""
    _deploy(scratch_db)
    with _connect(scratch_db) as connection:
        with connection.begin():
            first = enforce_retention(connection)
        with connection.begin():
            second = enforce_retention(connection)

    assert first == second
    assert first.tables_examined == len(POLICY_BY_TABLE)
    assert first.tables_withheld == len(POLICY_BY_TABLE) - 1
    assert first.tables_permitting_deletion == 1
    assert first.revocations_issued == first.tables_withheld
    assert first.cascade_edges_examined > 0
    assert first.definer_functions_examined > 0


def test_reading_and_writing_survive_the_revoke(scratch_db: str) -> None:
    """Vendor `v017`'s lesson, generalised: a projection nothing can rebuild is
    a broken delivery path rather than a sealed one. Retention withholds two
    privileges; a control plane that lost `SELECT` or `INSERT` would be a
    different kind of outage that every denial assertion above would miss.

    Compared against a reading taken BEFORE, over every governed table, so this
    is not a sample and not a literal expectation that could drift from what the
    composed migrations actually grant.
    """
    keys = [
        (role, qualified, privilege)
        for qualified in sorted(POLICY_BY_TABLE)
        for role in ONLINE_ROLES
        for privilege in ("SELECT", "INSERT", "UPDATE")
    ]
    _rehearse(scratch_db)
    with _connect(scratch_db) as connection:
        before = {key: _holds(connection, *key) for key in keys}
    assert sum(before.values()) > 50, sum(before.values())

    _deploy(scratch_db)
    with _connect(scratch_db) as connection:
        after = {key: _holds(connection, *key) for key in keys}

    lost = sorted(key for key, held in before.items() if held and not after[key])
    assert not lost, lost


def test_the_tenant_role_holds_nothing_it_held_before_either(scratch_db: str) -> None:
    """`app_user` is an online role and is covered by the same revoke, even
    though this assembly opens no tenant session. The classification governs the
    DATABASE, not the subset of it this application happens to use today."""
    _deploy(scratch_db)
    with _connect(scratch_db) as connection:
        for qualified, policy in sorted(POLICY_BY_TABLE.items()):
            if policy.disposition is Disposition.LIFECYCLE_DELETE:
                continue
            assert not _holds(connection, "app_user", qualified, "DELETE"), qualified
