"""`vendor_cp.deployment.fence_commands`, driven against a real PostgreSQL
cluster — the host-brokered wire around `transition_fence`, proven end to
end rather than trusted from its own docstring.

Mirrors `tests/migration/test_transition_fence.py`'s own fixture shapes
(`_connect`, `_writer_role`, `FENCE_ID`, `SESSION_WAIT_SECONDS`) rather than
importing them: this repository's own convention (see that file's package
docstring) keeps each Postgres suite's helpers local rather than reaching
across `tests.migration` modules for them.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from sqlalchemy import Connection, create_engine, text
from sqlalchemy.exc import OperationalError

from vendor_cp.deployment import fence_commands
from vendor_cp.deployment.transition_fence import MIGRATION_ROLE, FenceRefused

ROOT = Path(__file__).resolve().parents[2]
SQL_PATH = ROOT / "deploy" / "postgres" / "terminate_writers.sql"

SESSION_WAIT_SECONDS = 3.0
FENCE_ID = "test-fence-commands"


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
def _writer_role(admin_url: str) -> Iterator[str]:
    role = f"fence_writer_{uuid.uuid4().hex[:10]}"
    with _connect(admin_url, autocommit=True) as conn:
        conn.execute(text(f"CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS"))
    try:
        yield role
    finally:
        with _connect(admin_url, autocommit=True) as conn:
            conn.execute(text(f"DROP OWNED BY {role}"))
            conn.execute(text(f"DROP ROLE IF EXISTS {role}"))


def _dbname(url: str) -> str:
    return url.rpartition("/")[2]


@pytest.fixture
def db(scratch_db: str) -> str:
    return _dbname(scratch_db)


@pytest.fixture
def admin_url(postgres_url: str, db: str, url_for: Callable[..., str]) -> str:
    """The cluster superuser's URL against the scratch database — the
    identity that runs the checked-in termination SQL, exactly as the real
    broker's `psql -X ... --user postgres` would."""
    return url_for(postgres_url, db)


@pytest.fixture
def migration_database_url(scratch_db: str, monkeypatch: pytest.MonkeyPatch) -> str:
    """`scratch_db` is already an `app_admin`-owned URL — exactly the DSN
    `owner_runtime()` reads from `MIGRATION_DATABASE_URL`."""
    monkeypatch.setenv("MIGRATION_DATABASE_URL", scratch_db)
    return scratch_db


class _InProcessHostBroker:
    """The host side of the D16 termination protocol, in-process.

    Mirrors `scripts/lib/fence_broker.sh` exactly — checks the fence_id
    before running anything, then runs the CHECKED-IN SQL file's own text —
    but calls it over a superuser SQLAlchemy connection instead of shelling
    out to `psql`, so this test needs no subprocess or coproc. `write()` is
    the terminator's request; `readline()` is this broker's reply, matching
    the exact `TextIO` shape `StdioBrokerTerminator` expects from both
    `stdin` and `stdout` — so ONE instance of this class serves as both.
    """

    def __init__(self, admin_url: str, database: str, fence_id: str) -> None:
        self._admin_url = admin_url
        self._database = database
        self._fence_id = fence_id
        self._reply: str | None = None

    def write(self, data: str) -> int:
        line = data.rstrip("\n")
        if not line:
            return len(data)
        expected = f"DOTMAC-FENCE-TERMINATE v1 {self._fence_id}"
        assert line == expected, f"unexpected broker request: {line!r}"
        # `:'db'` is psql's quoted-literal substitution syntax, not a
        # SQLAlchemy bind parameter — rebound here to `:dbname` so the exact
        # checked-in file's text can run over a plain SQLAlchemy connection.
        sql = SQL_PATH.read_text(encoding="utf-8").replace(":'db'", ":dbname")
        with _connect(self._admin_url, autocommit=True) as conn:
            conn.execute(text(sql), {"dbname": self._database})
        self._reply = f"DOTMAC-FENCE-TERMINATED v1 {self._fence_id}\n"
        return len(data)

    def flush(self) -> None:
        return None

    def readline(self) -> str:
        assert self._reply is not None, "the broker has no reply queued yet"
        reply, self._reply = self._reply, None
        return reply


# ── (a) the checked-in SQL: writers and members die, admin and others don't ─


def test_the_checked_in_sql_kills_writers_and_members_never_admin_or_others(
    admin_url: str, db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """Run the file's own text as superuser, with `:'db'` rebound to a
    SQLAlchemy bind parameter (stated here, not hidden — psql's `:'db'`
    quoted-literal substitution has no SQLAlchemy equivalent). A writer and a
    member of it both die; `app_admin`'s own session, an unrelated
    bystander's session, and the calling superuser session itself all
    survive."""
    sql = SQL_PATH.read_text(encoding="utf-8").replace(":'db'", ":dbname")

    with _writer_role(admin_url) as writer:
        member = f"fence_member_{uuid.uuid4().hex[:10]}"
        bystander = f"fence_bystander_{uuid.uuid4().hex[:10]}"
        with _connect(admin_url, autocommit=True) as conn:
            conn.execute(text(f"CREATE ROLE {member} LOGIN NOSUPERUSER NOBYPASSRLS"))
            conn.execute(text(f"GRANT {writer} TO {member}"))
            conn.execute(text(f"CREATE ROLE {bystander} LOGIN NOSUPERUSER NOBYPASSRLS"))
            conn.execute(text(f'GRANT CONNECT ON DATABASE "{db}" TO {bystander}'))
        try:
            writer_engine = create_engine(url_for(postgres_url, db, user=writer))
            member_engine = create_engine(url_for(postgres_url, db, user=member))
            bystander_engine = create_engine(url_for(postgres_url, db, user=bystander))
            writer_conn = writer_engine.connect()
            member_conn = member_engine.connect()
            bystander_conn = bystander_engine.connect()
            try:
                assert writer_conn.execute(text("SELECT 1")).scalar_one() == 1
                assert member_conn.execute(text("SELECT 1")).scalar_one() == 1
                assert bystander_conn.execute(text("SELECT 1")).scalar_one() == 1

                with _connect(
                    url_for(postgres_url, db, user=MIGRATION_ROLE)
                ) as admin_conn:
                    assert admin_conn.execute(text("SELECT 1")).scalar_one() == 1

                    with _connect(admin_url, autocommit=True) as super_conn:
                        super_conn.execute(text(sql), {"dbname": db})
                        # The calling session's own backend is excluded by
                        # `pg_backend_pid()` — proven by continuing to use
                        # the SAME connection right after running the
                        # statement.
                        assert super_conn.execute(text("SELECT 1")).scalar_one() == 1

                    # app_admin's own session survives.
                    assert admin_conn.execute(text("SELECT 1")).scalar_one() == 1

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
                conn.execute(text(f"REVOKE {writer} FROM {member}"))
                conn.execute(text(f"DROP OWNED BY {member}"))
                conn.execute(text(f"DROP ROLE IF EXISTS {member}"))


# ── (b) close_fence, then restore_fence, end to end over the owner runtime ──


def test_close_then_restore_round_trips_the_proof_through_json(
    admin_url: str, db: str, migration_database_url: str
) -> None:
    broker = _InProcessHostBroker(admin_url, db, FENCE_ID)

    close_result = fence_commands.close_fence(
        database=db,
        fence_id=FENCE_ID,
        session_wait_seconds=SESSION_WAIT_SECONDS,
        stdin=broker,
        stdout=broker,
    )
    # The proof round-trips through JSON exactly like it would crossing a
    # real process boundary — this is the shape `close_fence`'s own return
    # value already is, so re-parsing it here proves nothing was silently
    # kept as an in-process object.
    proof_document = json.loads(json.dumps(close_result["proof"]))
    digest = close_result["digest"]
    fence_id = close_result["fence_id"]
    assert fence_id == FENCE_ID

    restore_broker = _InProcessHostBroker(admin_url, db, FENCE_ID)
    restore_result = fence_commands.restore_fence(
        database=db,
        proof_document=proof_document,
        expected_digest=digest,
        expected_fence_id=fence_id,
        session_wait_seconds=SESSION_WAIT_SECONDS,
        stdin=restore_broker,
        stdout=restore_broker,
    )
    assert restore_result["database"] == db


def test_fence_holding_reports_true_while_closed_and_false_once_restored(
    admin_url: str, db: str, migration_database_url: str
) -> None:
    broker = _InProcessHostBroker(admin_url, db, FENCE_ID)
    close_result = fence_commands.close_fence(
        database=db,
        fence_id=FENCE_ID,
        session_wait_seconds=SESSION_WAIT_SECONDS,
        stdin=broker,
        stdout=broker,
    )
    holding = fence_commands.fence_holding(
        proof_document=close_result["proof"], expected_digest=close_result["digest"]
    )
    assert holding == {"holding": True}

    restore_broker = _InProcessHostBroker(admin_url, db, FENCE_ID)
    fence_commands.restore_fence(
        database=db,
        proof_document=close_result["proof"],
        expected_digest=close_result["digest"],
        expected_fence_id=close_result["fence_id"],
        session_wait_seconds=SESSION_WAIT_SECONDS,
        stdin=restore_broker,
        stdout=restore_broker,
    )
    holding_after = fence_commands.fence_holding(
        proof_document=close_result["proof"], expected_digest=close_result["digest"]
    )
    assert holding_after == {"holding": False}


# ── (c) restore refuses a wrong digest / wrong fence_id before any GRANT ────


def test_restore_fence_refuses_a_wrong_expected_digest_before_any_grant(
    admin_url: str, db: str, migration_database_url: str
) -> None:
    broker = _InProcessHostBroker(admin_url, db, FENCE_ID)
    close_result = fence_commands.close_fence(
        database=db,
        fence_id=FENCE_ID,
        session_wait_seconds=SESSION_WAIT_SECONDS,
        stdin=broker,
        stdout=broker,
    )

    with _connect(admin_url, autocommit=True) as conn:
        before_acl = conn.execute(
            text("SELECT datacl::text FROM pg_database WHERE datname = :db"),
            {"db": db},
        ).scalar_one()

    with pytest.raises(FenceRefused):
        fence_commands.restore_fence(
            database=db,
            proof_document=close_result["proof"],
            expected_digest="sha256:" + "0" * 64,
            expected_fence_id=close_result["fence_id"],
            session_wait_seconds=SESSION_WAIT_SECONDS,
            stdin=_InProcessHostBroker(admin_url, db, FENCE_ID),
            stdout=_InProcessHostBroker(admin_url, db, FENCE_ID),
        )

    with _connect(admin_url, autocommit=True) as conn:
        after_acl = conn.execute(
            text("SELECT datacl::text FROM pg_database WHERE datname = :db"),
            {"db": db},
        ).scalar_one()
    assert after_acl == before_acl, "a refused restore must leave the ACL untouched"

    # Clean up: restore for real so the scratch database teardown does not
    # have to contend with a still-fenced ACL.
    restore_broker = _InProcessHostBroker(admin_url, db, FENCE_ID)
    fence_commands.restore_fence(
        database=db,
        proof_document=close_result["proof"],
        expected_digest=close_result["digest"],
        expected_fence_id=close_result["fence_id"],
        session_wait_seconds=SESSION_WAIT_SECONDS,
        stdin=restore_broker,
        stdout=restore_broker,
    )


def test_restore_fence_refuses_a_wrong_expected_fence_id_before_any_grant(
    admin_url: str, db: str, migration_database_url: str
) -> None:
    broker = _InProcessHostBroker(admin_url, db, FENCE_ID)
    close_result = fence_commands.close_fence(
        database=db,
        fence_id=FENCE_ID,
        session_wait_seconds=SESSION_WAIT_SECONDS,
        stdin=broker,
        stdout=broker,
    )

    with _connect(admin_url, autocommit=True) as conn:
        before_acl = conn.execute(
            text("SELECT datacl::text FROM pg_database WHERE datname = :db"),
            {"db": db},
        ).scalar_one()

    with pytest.raises(FenceRefused):
        fence_commands.restore_fence(
            database=db,
            proof_document=close_result["proof"],
            expected_digest=close_result["digest"],
            expected_fence_id="a-different-run-entirely",
            session_wait_seconds=SESSION_WAIT_SECONDS,
            stdin=_InProcessHostBroker(admin_url, db, "a-different-run-entirely"),
            stdout=_InProcessHostBroker(admin_url, db, "a-different-run-entirely"),
        )

    with _connect(admin_url, autocommit=True) as conn:
        after_acl = conn.execute(
            text("SELECT datacl::text FROM pg_database WHERE datname = :db"),
            {"db": db},
        ).scalar_one()
    assert after_acl == before_acl, "a refused restore must leave the ACL untouched"

    restore_broker = _InProcessHostBroker(admin_url, db, FENCE_ID)
    fence_commands.restore_fence(
        database=db,
        proof_document=close_result["proof"],
        expected_digest=close_result["digest"],
        expected_fence_id=close_result["fence_id"],
        session_wait_seconds=SESSION_WAIT_SECONDS,
        stdin=restore_broker,
        stdout=restore_broker,
    )
