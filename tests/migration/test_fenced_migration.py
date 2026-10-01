"""A migration under a live writer fence — the D16 CI proof.

The real deploy identity migrates as `app_admin` with `MIGRATION_DATABASE_URL`
while the ops container's `DATABASE_URL`/`PLATFORM_DATABASE_URL` stay pointed
at the WRITER roles (`app_user`/`platform_api` — see
`docker-compose.production.yml`'s migrate-once service, which sets exactly
those three). If any migration, `env.py`, or a kernel import path opened a
writer-role connection instead of the `app_admin` one it was actually given,
a fenced deploy would fail on every single run — defeating the whole point of
the D16 fence. This test proves it does not: it fences every writer role on a
scratch database, then runs the REAL `dotmac-platform admin migrate` console
script — in a subprocess, exactly as
`.github/workflows/ci.yml`'s `poetry run dotmac-platform admin migrate` step
does — with `DATABASE_URL`/`PLATFORM_DATABASE_URL` pointed at the fenced
writer roles the whole time, and shows the migration succeeds while the fence
never opens.

Requires the test Postgres cluster (roles + kernel schema) from
`make test-db-up`; skips (or fails under `REQUIRE_POSTGRES_TESTS=1`) when
`TEST_DATABASE_URL` is unset — see `tests/migration/conftest.py`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable, Iterator
from contextlib import contextmanager

import pytest
from sqlalchemy import Connection, create_engine, text
from sqlalchemy.exc import OperationalError

from vendor_cp.deployment.image_heads import composed_effective_heads
from vendor_cp.deployment.transition_fence import (
    fence_is_holding,
    fence_writers,
    restore_writers,
)
from vendor_cp.migrations import (
    BINDINGS_ENV_VAR,
    MODULE_PLANES_ENV_VAR,
    make_alembic_config,
)

#: A few seconds — bounded, never open-ended, matching
#: `test_transition_fence.py`'s own convention.
SESSION_WAIT_SECONDS = 3.0

FENCE_ID = "fenced-migration-test"

#: `make_alembic_config`'s own offline placeholder — no database is dialled,
#: matching `tests/unit/test_image_heads.py`'s `OFFLINE_DSN`. Used here only
#: to inspect the composed revision graph (`composed_effective_heads`), never
#: to migrate anything, so computing the expected head set never needs — and
#: never risks leaking environment state tied to — the scratch database this
#: file drops at teardown.
OFFLINE_DSN = "postgresql+psycopg://image-heads@127.0.0.1:5432/none"


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


def _offline_effective_heads(monkeypatch: pytest.MonkeyPatch) -> tuple[str, ...]:
    """`composed_effective_heads` over the OFFLINE config — never the scratch
    database's URL.

    `make_alembic_config` mutates `os.environ` directly and unconditionally
    (`MIGRATION_DATABASE_URL`, `DATABASE_URL` via `setdefault`, and the two
    prerequisite-binding variables) as a documented side effect with no
    corresponding cleanup of its own. Pre-registering each variable with
    `monkeypatch` — even though this function only ever assigns them itself —
    guarantees they are restored to whatever this test process held before the
    call, regardless of what `make_alembic_config` does to them, so nothing
    leaks past this test once `scratch_db` has dropped the database these
    variables could otherwise still be naming.
    """
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("MIGRATION_DATABASE_URL", raising=False)
    monkeypatch.delenv(BINDINGS_ENV_VAR, raising=False)
    monkeypatch.delenv(MODULE_PLANES_ENV_VAR, raising=False)
    config = make_alembic_config(OFFLINE_DSN)
    return composed_effective_heads(config)


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
    migration, `env.py`, or kernel import path, not an artifact of a fence
    that was never actually closed.
    """
    db = _dbname(scratch_db)

    # Make the scratch database production-shaped. `scratch_db` only hands
    # `public`'s SCHEMA ownership to `app_admin`; the DATABASE itself is still
    # owned by the cluster superuser that created it. `fence_writers` requires
    # `conn`'s `current_user` to be the database owner, a member of the owner,
    # or a superuser — `app_admin` (the deploy's real identity) is none of
    # those against a superuser-owned database, and would be refused
    # `CONNECTION_NOT_OWNER` before touching anything. Reassign ownership as
    # the superuser first, then fence and restore AS `app_admin` below.
    with _connect(postgres_url, autocommit=True) as conn:
        conn.execute(text(f'ALTER DATABASE "{db}" OWNER TO app_admin'))

    admin_url = url_for(postgres_url, db, user="app_admin")
    app_user_url = url_for(postgres_url, db, user="app_user")
    platform_api_url = url_for(postgres_url, db, user="platform_api")

    with _connect(admin_url, autocommit=True) as conn:
        proof = fence_writers(
            conn,
            database=db,
            fence_id=FENCE_ID,
            session_wait_seconds=SESSION_WAIT_SECONDS,
        )
    with _connect(admin_url) as conn:
        assert fence_is_holding(conn, proof) is True

    # Non-vacuity control: the fence genuinely blocks a new writer connection.
    with pytest.raises(OperationalError, match="permission denied"):
        with _connect(app_user_url):
            pass

    dotmac_platform = shutil.which("dotmac-platform")
    assert dotmac_platform is not None, (
        "the dotmac-platform console script is not on PATH; this suite must "
        "run inside the project's installed virtualenv — the same one CI's "
        "`poetry run dotmac-platform admin migrate` step uses"
    )

    # The REAL migration path, in a SUBPROCESS — not in-process — mirroring
    # `.github/workflows/ci.yml`'s `poetry run dotmac-platform admin migrate`
    # step. The subprocess gets an EXPLICIT environment built from scratch,
    # never this test process's own `os.environ`: only `PATH` (to resolve the
    # interpreter/shared libraries the console script's shebang needs) plus
    # the three ops URLs `docker-compose.production.yml`'s migrate-once
    # service sets — `DATABASE_URL`/`PLATFORM_DATABASE_URL` pointed at the
    # FENCED writer roles, `MIGRATION_DATABASE_URL` at `app_admin`. Building
    # the environment this way means this test process's own dummy
    # `DATABASE_URL`/`PLATFORM_DATABASE_URL` (set by `tests/conftest.py` for
    # the SQLite-backed unit suite) can never leak into the subprocess, and
    # the subprocess's own environment mutations can never leak back into
    # this process either — unlike an in-process call to `admin_migrate`,
    # which mutates this process's `os.environ` directly with no cleanup.
    env = {
        "PATH": os.environ.get("PATH", ""),
        "DATABASE_URL": app_user_url,
        "PLATFORM_DATABASE_URL": platform_api_url,
        "MIGRATION_DATABASE_URL": admin_url,
    }

    result = subprocess.run(  # noqa: S603 -- fixed console-script argv, no shell
        [dotmac_platform, "admin", "migrate"],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, (
        "`dotmac-platform admin migrate` failed under the fence "
        f"(exit {result.returncode}):\n"
        f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
    )

    # `alembic_version` holds the composed heads — read the same way the
    # existing migration rehearsals do (`composed_effective_heads`, not
    # `ScriptDirectory.get_heads()`, since a `depends_on` edge prunes a
    # subsumed dependency from the version table), computed OFFLINE so this
    # check never needs its own database connection or environment mutation.
    expected_heads = set(_offline_effective_heads(monkeypatch))
    assert expected_heads, (
        "composed_effective_heads returned no heads; the equality check below "
        "would otherwise pass vacuously against an empty database"
    )
    assert _versions(admin_url) == expected_heads

    # Still fenced: no writer reconnected and no grant was reopened while the
    # migration ran.
    with _connect(admin_url) as conn:
        assert fence_is_holding(conn, proof) is True

    with _connect(admin_url, autocommit=True) as conn:
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
