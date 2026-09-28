"""The REAL `scripts/lib/fence_broker.sh`, sourced and run by `bash` as a
subprocess against a real cluster — `tests/migration/test_fence_commands.py`
proves `fence_commands` and the checked-in SQL; this file is the only place
`fence_broker_serve` itself, and the exact protocol bytes it produces, are
exercised end to end.

`compose` is shimmed to turn the broker's own `compose exec -T --user
postgres db psql ...` into a real `psql` against the CI test cluster —
connection parameters come from the standard `PG*` libpq environment
variables, derived from the same `postgres_url` every other Postgres suite
in this repository uses, so this file adds no new cluster-configuration
surface.

Skips (never fails) when `psql` is not on `PATH` locally; under
`REQUIRE_POSTGRES_TESTS=1` (the CI job's own setting) a missing `psql` is a
FAILURE instead, the same two-directional discipline `postgres_url` itself
already applies to a missing `TEST_DATABASE_URL`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from sqlalchemy import Connection, create_engine, text
from sqlalchemy.exc import OperationalError

ROOT = Path(__file__).resolve().parents[2]
BROKER_PATH = ROOT / "scripts" / "lib" / "fence_broker.sh"

FENCE_ID = "test-broker-script"


@pytest.fixture(scope="module", autouse=True)
def _require_psql() -> None:
    if shutil.which("psql") is not None:
        return
    message = "psql is not on PATH — the real fence_broker_serve suite cannot run."
    if os.getenv("REQUIRE_POSTGRES_TESTS") == "1":
        pytest.fail(
            f"{message} REQUIRE_POSTGRES_TESTS=1, so this is a FAILURE: under "
            "required CI this suite must never pass by skipping.",
            pytrace=False,
        )
    pytest.skip(message)


@contextmanager
def _connect(url: str, *, autocommit: bool = False) -> Iterator[Connection]:
    engine = create_engine(url, isolation_level="AUTOCOMMIT" if autocommit else None)
    try:
        with engine.connect() as conn:
            conn.execute(text("SET lock_timeout = '5s'"))
            yield conn
    finally:
        engine.dispose()


@contextmanager
def _writer_member_role(admin_url: str) -> Iterator[str]:
    role = f"fence_broker_writer_{uuid.uuid4().hex[:10]}"
    with _connect(admin_url, autocommit=True) as conn:
        conn.execute(text(f"CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS"))
        conn.execute(text(f"GRANT app_user TO {role}"))
    try:
        yield role
    finally:
        with _connect(admin_url, autocommit=True) as conn:
            conn.execute(text(f"REVOKE app_user FROM {role}"))
            conn.execute(text(f"DROP OWNED BY {role}"))
            conn.execute(text(f"DROP ROLE IF EXISTS {role}"))


def _dbname(url: str) -> str:
    return url.rpartition("/")[2]


@pytest.fixture
def db(scratch_db: str) -> str:
    return _dbname(scratch_db)


@pytest.fixture
def admin_url(postgres_url: str, db: str, url_for: Callable[..., str]) -> str:
    return url_for(postgres_url, db)


def _libpq_env(postgres_url: str) -> dict[str, str]:
    """`PGHOST`/`PGPORT`/`PGUSER`/`PGPASSWORD` derived from `postgres_url` —
    the same DSN every other Postgres suite in this repository already
    resolves from `TEST_DATABASE_URL`/`TEST_MIGRATION_DATABASE_URL`, so this
    file introduces no new connection configuration of its own."""
    parts = urlsplit(postgres_url.replace("postgresql+psycopg", "postgresql", 1))
    env: dict[str, str] = dict(os.environ)
    if parts.hostname:
        env["PGHOST"] = parts.hostname
    if parts.port:
        env["PGPORT"] = str(parts.port)
    if parts.username:
        env["PGUSER"] = parts.username
    if parts.password:
        env["PGPASSWORD"] = parts.password
    return env


def _run_broker(
    *, postgres_url: str, database: str, fence_id: str, stdin_text: str
) -> tuple[subprocess.CompletedProcess[str], str]:
    """Run `fence_broker_serve <database> <fence_id>` as a real bash
    subprocess, with `compose` shimmed to a direct `psql` against the CI
    cluster, fd 3 wired to a temp file, and stdin/stdout carrying the exact
    protocol bytes. Returns the completed process and the fd-3 envelope
    file's contents."""
    with tempfile.TemporaryDirectory() as tmp:
        envelope_path = Path(tmp) / "envelope.txt"
        script = f"""
set -euo pipefail
source "{BROKER_PATH!s}"
compose() {{
    shift 6
    psql -d "$database" "$@"
}}
exec 3>"{envelope_path!s}"
fence_broker_serve "{database!s}" "{fence_id!s}"
"""
        proc = subprocess.run(  # noqa: S603, S607 -- fixed bash, fixed script text
            ["bash", "-c", script],  # noqa: S607 -- executable is fixed to bash
            input=stdin_text,
            capture_output=True,
            text=True,
            env=_libpq_env(postgres_url),
            timeout=60,
        )
        envelope = (
            envelope_path.read_text(encoding="utf-8") if envelope_path.exists() else ""
        )
        return proc, envelope


# ── (i) the happy path: exactly one reply line, writer/member die, others don't


def test_the_real_broker_terminates_a_live_writer_and_replies_exactly_once(
    admin_url: str, db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    with (
        _writer_member_role(admin_url) as writer_member,
        _writer_member_role(admin_url) as second_writer_member,
    ):
        bystander = f"fence_broker_bystander_{uuid.uuid4().hex[:10]}"
        with _connect(admin_url, autocommit=True) as conn:
            conn.execute(text(f"CREATE ROLE {bystander} LOGIN NOSUPERUSER NOBYPASSRLS"))
            conn.execute(text(f'GRANT CONNECT ON DATABASE "{db}" TO {bystander}'))
        try:
            writer_engine = create_engine(url_for(postgres_url, db, user=writer_member))
            member_engine = create_engine(
                url_for(postgres_url, db, user=second_writer_member)
            )
            bystander_engine = create_engine(url_for(postgres_url, db, user=bystander))
            writer_conn = writer_engine.connect()
            member_conn = member_engine.connect()
            bystander_conn = bystander_engine.connect()
            try:
                assert writer_conn.execute(text("SELECT 1")).scalar_one() == 1
                assert member_conn.execute(text("SELECT 1")).scalar_one() == 1
                assert bystander_conn.execute(text("SELECT 1")).scalar_one() == 1

                proc, envelope = _run_broker(
                    postgres_url=admin_url,
                    database=db,
                    fence_id=FENCE_ID,
                    stdin_text=f"DOTMAC-FENCE-TERMINATE v1 {FENCE_ID}\n",
                )

                assert proc.returncode == 0, proc.stderr
                assert proc.stdout == f"DOTMAC-FENCE-TERMINATED v1 {FENCE_ID}\n"
                assert envelope == ""

                with pytest.raises(OperationalError):
                    writer_conn.execute(text("SELECT 1"))
                with pytest.raises(OperationalError):
                    member_conn.execute(text("SELECT 1"))
                assert bystander_conn.execute(text("SELECT 1")).scalar_one() == 1
            finally:
                for conn, engine in (
                    (writer_conn, writer_engine),
                    (member_conn, member_engine),
                    (bystander_conn, bystander_engine),
                ):
                    conn.close()
                    engine.dispose()
        finally:
            with _connect(admin_url, autocommit=True) as conn:
                conn.execute(
                    text(f'REVOKE CONNECT ON DATABASE "{db}" FROM {bystander}')
                )
                conn.execute(text(f"DROP OWNED BY {bystander}"))
                conn.execute(text(f"DROP ROLE IF EXISTS {bystander}"))


# ── (ii) a mismatched fence_id: no SQL runs, sessions survive, exit non-zero,
#         stdout is empty ────────────────────────────────────────────────────


def test_the_real_broker_refuses_a_mismatched_fence_id_without_running_any_sql(
    admin_url: str, db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    with _writer_member_role(admin_url) as writer_member:
        writer_engine = create_engine(url_for(postgres_url, db, user=writer_member))
        writer_conn = writer_engine.connect()
        try:
            assert writer_conn.execute(text("SELECT 1")).scalar_one() == 1

            proc, envelope = _run_broker(
                postgres_url=admin_url,
                database=db,
                fence_id=FENCE_ID,
                stdin_text="DOTMAC-FENCE-TERMINATE v1 some-other-run\n",
            )

            assert proc.returncode != 0
            assert proc.stdout == ""
            assert envelope == ""
            # The writer's session was never touched.
            assert writer_conn.execute(text("SELECT 1")).scalar_one() == 1
        finally:
            writer_conn.close()
            writer_engine.dispose()


# ── (iii) a psql failure: no reply, non-zero exit ───────────────────────────


def test_the_real_broker_reports_a_psql_failure_without_replying(
    admin_url: str, db: str
) -> None:
    """Point the `compose` shim at a bad DSN (a nonexistent port) so the real
    `psql` invocation fails — the broker must not reply, and must exit
    non-zero, exactly as it does for a mismatched fence_id."""
    bad_env = _libpq_env(admin_url)
    bad_env["PGPORT"] = "1"  # a port nothing listens on

    script = f"""
set -euo pipefail
source "{BROKER_PATH!s}"
compose() {{
    shift 6
    psql -d "$database" "$@"
}}
exec 3>/dev/null
fence_broker_serve "{db!s}" "{FENCE_ID!s}"
"""
    proc = subprocess.run(  # noqa: S603, S607 -- fixed bash, fixed script text
        ["bash", "-c", script],  # noqa: S607 -- executable is fixed to bash
        input=f"DOTMAC-FENCE-TERMINATE v1 {FENCE_ID}\n",
        capture_output=True,
        text=True,
        env=bad_env,
        timeout=60,
    )

    assert proc.returncode != 0
    assert proc.stdout == ""
