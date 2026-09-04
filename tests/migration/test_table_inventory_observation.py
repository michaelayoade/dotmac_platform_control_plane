"""The inventory against a real server: read-only, complete, and honest about UNKNOWN.

Three properties that only a database can settle, and each with its control:

1. the transaction really is READ ONLY — the server refuses a write, and a read
   in the same transaction still succeeds;
2. the inventory really is complete — every table the catalogue holds appears,
   compared against an independently derived set rather than a count;
3. a table the observer cannot read comes back UNKNOWN and not zero — driven
   through a real privilege refusal, with a readable table in the same run as
   the control.

What this canNOT settle is production emptiness. A migrated scratch database is
empty BY CONSTRUCTION, so a zero here is a fact about the fixture. That
measurement is `vendor-cp-prod`'s, under Michael's step 8 authorization, and is
named as an obligation rather than asserted from a place that cannot see it.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime

import pytest
from alembic import command
from sqlalchemy import Connection, create_engine, text

from vendor_cp.deployment.table_inventory import (
    ObservationBinding,
    ReadOutcome,
    observe_table_inventory,
)
from vendor_cp.migrations import make_alembic_config


def _binding() -> ObservationBinding:
    return ObservationBinding(
        database_identity=f"scratch@{uuid.uuid4()}",
        image_reference="ghcr.io/example@sha256:" + "a" * 64,
        source_revision="b" * 40,
        migration_heads=("v019_relay_heartbeat",),
        observed_at=datetime.now(UTC),
    )


@contextmanager
def _connect(url: str) -> Iterator[Connection]:
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            yield conn
    finally:
        engine.dispose()


@pytest.fixture
def migrated(scratch_db: str) -> str:
    command.upgrade(make_alembic_config(scratch_db), "heads")
    return scratch_db


def test_the_observation_runs_in_a_transaction_the_server_refuses_writes_in(
    migrated: str,
) -> None:
    """READ ONLY is a refusal by the database, not a promise by this module.

    Both halves: a write is refused, and a read in the same transaction still
    works — otherwise "refused" could just mean the connection was broken.
    """
    with _connect(migrated) as conn:
        observe_table_inventory(conn, binding=_binding())
        with pytest.raises(Exception) as refused:
            conn.execute(text("CREATE TABLE read_only_canary (id int)"))
        assert "read-only" in str(refused.value).lower()
        conn.rollback()
        # The control: reading still works, so the refusal was about writing.
        with _connect(migrated) as fresh:
            observed = observe_table_inventory(fresh, binding=_binding())
        assert observed.tables


def test_the_inventory_holds_every_table_the_catalogue_holds(
    migrated: str,
) -> None:
    """Completeness compared against an independently derived set.

    A count would pass while naming different tables, which is exactly the
    mistake an inventory cannot afford: a governance decision rests on WHICH
    tables it saw.
    """
    with _connect(migrated) as conn:
        observed = observe_table_inventory(conn, binding=_binding())
    with _connect(migrated) as conn:
        expected = {
            f"{row[0]}.{row[1]}"
            for row in conn.execute(
                text(
                    "SELECT n.nspname, c.relname FROM pg_catalog.pg_class c "
                    "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE c.relkind = 'r' AND n.nspname NOT IN "
                    "('pg_catalog', 'information_schema') "
                    "AND n.nspname NOT LIKE 'pg_toast%'"
                )
            )
        }
    assert expected, "the migrated database holds no tables, so this proves nothing"
    assert {t.qualified for t in observed.tables} == expected


def test_the_inventory_spans_the_module_schemas_as_well_as_public(
    migrated: str,
) -> None:
    """The tenant-plane and platform-plane tables both have to be in scope: the
    concern this feeds covers ALL of them, and an inventory that quietly stopped
    at `public` would report a clean estate it had not looked at."""
    with _connect(migrated) as conn:
        observed = observe_table_inventory(conn, binding=_binding())
    schemas = {t.schema for t in observed.tables}
    assert "public" in schemas
    assert {s for s in schemas if s.startswith("mod_")}, sorted(schemas)


def test_a_table_the_observer_cannot_read_is_unknown_not_zero(
    migrated: str, url_for: Callable[..., str]
) -> None:
    """THE PROPERTY THAT MATTERS MOST, against a real privilege refusal.

    A timeout or a denial rendered as `0` would justify retiring a table that is
    full. The control is in the same run: at least one table the observer CAN
    read comes back COUNTED, so this is a discrimination rather than a blanket
    UNKNOWN.
    """
    with _connect(migrated) as conn:
        database = conn.execute(text("SELECT current_database()")).scalar_one()
        conn.execute(text("CREATE TABLE public.forbidden_canary (id int)"))
        conn.execute(text("REVOKE ALL ON public.forbidden_canary FROM app_user"))
        conn.execute(text("GRANT SELECT ON public.vendor_accounts TO app_user"))
        conn.commit()

    with _connect(url_for(migrated, database, user="app_user")) as conn:
        observed = observe_table_inventory(conn, binding=_binding())

    by_name = {t.qualified: t for t in observed.tables}
    forbidden = by_name["public.forbidden_canary"]
    assert forbidden.outcome is ReadOutcome.UNKNOWN
    assert forbidden.row_count is None

    readable = by_name["public.vendor_accounts"]
    assert readable.outcome is ReadOutcome.COUNTED, (
        "no table was readable, so UNKNOWN above proves nothing about " "discrimination"
    )
    assert observed.complete is False


def test_emptiness_here_is_a_fact_about_the_fixture(migrated: str) -> None:
    """Recorded so nobody mistakes this suite for the production measurement.

    A migrated scratch database is empty by construction, so every zero below is
    a fact about a fixture. Whether production's tenant-plane tables are empty
    is measurable only on `vendor-cp-prod`, under its own authorization, and no
    assertion here may stand in for it.
    """
    with _connect(migrated) as conn:
        observed = observe_table_inventory(conn, binding=_binding())
    counted = [t for t in observed.tables if t.outcome is ReadOutcome.COUNTED]
    assert counted
    assert all(t.row_count == 0 for t in counted), (
        "a freshly migrated database holds rows, which means this fixture is "
        "not the empty-by-construction baseline this comment describes"
    )
