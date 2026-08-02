"""Two-session proof that replay claims are actually disjoint (Postgres).

This lives under `tests/migration` because it needs a REAL Postgres: `FOR
UPDATE SKIP LOCKED` is a no-op on SQLite, so the unit suite cannot prove the
property it most needs proving. A green unit run says nothing about whether two
replay workers collide — which is exactly how the original race survived
review.

The sensitivity check matters as much as the claim: the second session must be
shown to SKIP a locked row while still seeing an unlocked one. A test that only
asserts "session B got nothing" would pass just as happily if the query were
broken and returned nothing to anybody.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine


def _database_url() -> str:
    url = os.getenv("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL not set — this needs a real Postgres")
    return url


@pytest.fixture
def engine() -> Iterator[Engine]:
    eng = create_engine(_database_url(), future=True)
    yield eng
    eng.dispose()


@pytest.fixture
def claim_table(engine: Engine) -> Iterator[str]:
    """A disposable table with the shape the claim query locks over. Using a
    scratch table keeps the test about the LOCKING SEMANTICS rather than about
    the licensing schema, so it stays valid as that schema evolves."""
    name = f"replay_claim_{uuid.uuid4().hex[:10]}"
    with engine.begin() as conn:
        conn.execute(
            text(
                f"CREATE TABLE {name} ("
                "  id serial PRIMARY KEY,"
                "  state text NOT NULL,"
                "  created_at timestamptz NOT NULL DEFAULT now()"
                ")"
            )
        )
        conn.execute(
            text(f"INSERT INTO {name} (state) VALUES ('delivered'), ('delivered')")
        )
    try:
        yield name
    finally:
        with engine.begin() as conn:
            conn.execute(text(f"DROP TABLE IF EXISTS {name}"))


def _claim(conn, table: str, limit: int) -> list[int]:
    rows = conn.execute(
        text(
            f"SELECT id FROM {table} WHERE state = 'delivered' "
            "ORDER BY created_at, id LIMIT :limit FOR UPDATE SKIP LOCKED"
        ),
        {"limit": limit},
    ).scalars()
    return list(rows)


def test_two_sessions_claim_disjoint_work(engine: Engine, claim_table: str) -> None:
    """The property the replay driver depends on: concurrent workers never
    receive the same delivery, so they cannot compute the same next attempt
    number and race on the unique constraint."""
    first = engine.connect()
    second = engine.connect()
    try:
        first.begin()
        second.begin()

        claimed_a = _claim(first, claim_table, limit=1)
        claimed_b = _claim(second, claim_table, limit=1)

        assert len(claimed_a) == 1
        # SENSITIVITY: B must get the OTHER row — not nothing. If the lock hint
        # were wrong in a way that starved B, this assertion fails rather than
        # passing vacuously.
        assert len(claimed_b) == 1
        assert set(claimed_a).isdisjoint(claimed_b)
    finally:
        first.rollback()
        second.rollback()
        first.close()
        second.close()


def test_a_locked_row_is_skipped_not_waited_on(
    engine: Engine, claim_table: str
) -> None:
    """With only one eligible row, the second session must come back EMPTY and
    immediately — skipping, not blocking. A blocking claim would serialise the
    whole replay fleet behind one slow delivery."""
    with engine.begin() as conn:
        conn.execute(
            text(
                f"UPDATE {claim_table} SET state = 'active' WHERE id = ("
                f"SELECT MIN(id) FROM {claim_table})"
            )
        )

    first = engine.connect()
    second = engine.connect()
    try:
        first.begin()
        second.begin()
        # Prove the row IS claimable before locking it, so an empty result in
        # the second session cannot be blamed on the fixture.
        assert len(_claim(first, claim_table, limit=5)) == 1
        second.execute(text("SET LOCAL lock_timeout = '2s'"))
        assert _claim(second, claim_table, limit=5) == []
    finally:
        first.rollback()
        second.rollback()
        first.close()
        second.close()
