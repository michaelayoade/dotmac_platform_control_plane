"""A migration under a live writer fence — the D16 CI proof.

`admin migrate` (`vendor_cp.cli.commands.admin_migrate`) connects with
`MIGRATION_DATABASE_URL` (the `app_admin` DSN) and, through
`vendor_cp.migrations.deploy_config`/`make_alembic_config`,
`os.environ.setdefault("DATABASE_URL", url)`. The ops container that actually
runs a deploy has `DATABASE_URL` already set to the `app_user` DSN, so that
`setdefault` is a no-op there: `DATABASE_URL` stays pointed at a WRITER role
for the whole migration. If any migration, `env.py`, or a kernel import path
opened a writer-role connection instead of the `app_admin` one this call was
actually given, a fenced deploy would fail on every single run — defeating
the whole point of the D16 fence. This test proves it does not: it fences
every writer role on a scratch database, runs the real migration path the
deploy script uses with `DATABASE_URL` pointed at the fenced `app_user` DSN
throughout, and shows the migration succeeds while the fence never opens.

Requires the test Postgres cluster (roles + kernel schema) from
`make test-db-up`; skips (or fails under `REQUIRE_POSTGRES_TESTS=1`) when
`TEST_DATABASE_URL` is unset — see `tests/migration/conftest.py`.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Iterator
from contextlib import contextmanager

import pytest
from alembic.script import ScriptDirectory
from sqlalchemy import Connection, create_engine, text
from sqlalchemy.exc import OperationalError

from vendor_cp.deployment.image_heads import composed_effective_heads
from vendor_cp.deployment.transition_fence import (
    fence_is_holding,
    fence_writers,
    restore_writers,
)
from vendor_cp.migrations import make_alembic_config

#: A few seconds — bounded, never open-ended, matching
#: `test_transition_fence.py`'s own convention.
SESSION_WAIT_SECONDS = 3.0

FENCE_ID = "fenced-migration-test"


@contextmanager
def _connect(url: str, *, autocommit: bool = False) -> Iterator[Connection]:
    engine = create_engine(url, isolation_level="AUTOCOMMIT" if autocommit else None)
    try:
        with engine.connect() as conn:
            conn.execute(text("SET lock_timeout = '5s'"))
            yield conn
    finally:
        engine.dispose()


def _dbname(url: str) -> str:
    return url.rpartition("/")[2]


def _versions(url: str) -> set[str]:
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            return set(
                conn.execute(text("SELECT version_num FROM alembic_version")).scalars()
            )
    finally:
        engine.dispose()


def test_a_migration_under_a_live_fence_succeeds_and_the_fence_still_holds(
    scratch_db: str,
    postgres_url: str,
    url_for: Callable[..., str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The non-vacuity control runs first: a NEW connection as `app_user`
    against the fenced scratch database is refused with `OperationalError`.
    That establishes the fence genuinely blocks writer connections in THIS
    database over THIS channel — so the migration succeeding afterward, under
    the same fence, is evidence no writer-role connection was needed by any
    migration, `env.py`, or kernel import path on this path, not an artifact
    of a fence that was never actually closed.
    """
    db = _dbname(scratch_db)
    app_user_url = url_for(postgres_url, db, user="app_user")

    with _connect(scratch_db, autocommit=True) as conn:
        proof = fence_writers(
            conn,
            database=db,
            fence_id=FENCE_ID,
            session_wait_seconds=SESSION_WAIT_SECONDS,
        )
    with _connect(scratch_db) as conn:
        assert fence_is_holding(conn, proof) is True

    # Non-vacuity control: the fence genuinely blocks a new writer connection.
    with pytest.raises(OperationalError, match="permission denied"):
        with _connect(app_user_url):
            pass

    # The environment exactly as the ops container sets it: the migrator's own
    # `app_admin` URL as `MIGRATION_DATABASE_URL`, and the fenced `app_user`
    # URL as `DATABASE_URL` — the value `deploy_config`'s
    # `os.environ.setdefault("DATABASE_URL", url)` must NOT override.
    monkeypatch.setenv("MIGRATION_DATABASE_URL", scratch_db)
    monkeypatch.setenv("DATABASE_URL", app_user_url)

    # The REAL migration path the deploy script uses, exercising the
    # `setdefault` behaviour `deploy_config`/`make_alembic_config` rely on.
    from vendor_cp.cli.commands import admin_migrate

    result = admin_migrate(argparse.Namespace(target="heads"))
    assert result.data["target"] == "heads"

    # `alembic_version` holds the composed heads — read the same way the
    # existing migration rehearsals do (`composed_effective_heads`, not
    # `ScriptDirectory.get_heads()`, since a `depends_on` edge prunes a
    # subsumed dependency from the version table).
    config = make_alembic_config(scratch_db)
    expected_heads = set(composed_effective_heads(config))
    assert _versions(scratch_db) == expected_heads

    # Still fenced: no writer reconnected and no grant was reopened while the
    # migration ran.
    with _connect(scratch_db) as conn:
        assert fence_is_holding(conn, proof) is True

    with _connect(scratch_db, autocommit=True) as conn:
        restore_writers(
            conn,
            proof,
            database=db,
            expected_fence_id=FENCE_ID,
            session_wait_seconds=SESSION_WAIT_SECONDS,
        )

    # PUBLIC/writer CONNECT is back: a new connection as `app_user` succeeds.
    with _connect(app_user_url) as conn:
        assert conn.execute(text("SELECT 1")).scalar_one() == 1


def test_composed_effective_heads_is_a_real_check_not_vacuously_empty(
    scratch_db: str,
) -> None:
    """A guard on the guard: `composed_effective_heads` must actually name a
    non-empty set of revisions, or the assertion above (`_versions(...) ==
    expected_heads`) could pass on an empty database with an empty expected
    set, proving nothing about the migration having run at all."""
    config = make_alembic_config(scratch_db)
    heads = composed_effective_heads(config)
    assert heads
    # And they are real graph heads, not an arbitrary non-empty tuple.
    script = ScriptDirectory.from_config(config)
    assert set(heads) <= set(script.get_heads())
