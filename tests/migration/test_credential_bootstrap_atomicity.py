"""PostgreSQL's actual behaviour, measured — not cited from its documentation.

Every claim the bootstrap effect rests on is a claim about a PostgreSQL server,
and this file is where each one is driven against a real one on the supported
major version. The ruling is explicit: documentation of PostgreSQL's
transactional behaviour is not a measurement of it.

Five premises, and the effect is unsound if any is false:

1. `ALTER ROLE ... PASSWORD` inside a transaction that ROLLS BACK leaves the
   credential exactly as it was. Step 5 relies on this — a failure between the
   alter and the commit must leave nothing installed.
2. Committed, it changes. The control for 1: a statement that never worked
   would satisfy the rollback assertion perfectly.
3. `pg_authid.rolpassword` answers for a superuser and is REFUSED to a
   non-superuser. This is why the effect must receive a privileged session and
   cannot use any role this assembly holds.
4. `format('%I', '%L')` quotes a hostile role name and a hostile password
   safely. The statement cannot use bind parameters, so this is the whole of
   the injection argument.
5. A connection actually authenticates with the installed material. Step 6's
   proof is only a proof if this is what it measures.

The scratch database is created and dropped per test, and the roles altered here
are created inside it — nothing touches a role the rest of the suite uses.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager

import pytest
from sqlalchemy import Connection, create_engine, text

# A password shape chosen to break naive quoting: a single quote, a backslash,
# a semicolon and a comment marker. If `%L` is doing its job none of it matters.
HOSTILE = "a'b\\c;d--e"


@pytest.fixture
def superuser_url(postgres_url: str) -> str:
    """`TEST_DATABASE_URL` connects as `postgres`, which is a real superuser.

    Asserted rather than assumed: every premise below is about what a superuser
    can do, and running them as a non-superuser would fail for the wrong reason.
    """
    with _connect(postgres_url) as conn:
        assert conn.execute(
            text("SELECT usesuper FROM pg_user WHERE usename = current_user")
        ).scalar_one(), "these measurements require a superuser connection"
    return postgres_url


@contextmanager
def _connect(url: str) -> Iterator[Connection]:
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            yield conn
    finally:
        engine.dispose()


@pytest.fixture
def role(superuser_url: str) -> Iterator[str]:
    """A disposable LOGIN role with NO password, dropped afterwards."""
    name = f"bootstrap_canary_{uuid.uuid4().hex[:12]}"
    with _connect(superuser_url) as conn:
        conn.execute(text(f"CREATE ROLE {name} LOGIN NOSUPERUSER NOBYPASSRLS"))
        conn.commit()
    yield name
    with _connect(superuser_url) as conn:
        conn.execute(text(f"DROP ROLE IF EXISTS {name}"))
        conn.commit()


def _password_present(conn: Connection, role: str) -> bool:
    return bool(
        conn.execute(
            text("SELECT rolpassword IS NOT NULL FROM pg_authid WHERE rolname = :r"),
            {"r": role},
        ).scalar_one()
    )


def _install(conn: Connection, role: str, material: str) -> None:
    """Exactly what the effect does, through the same server-side quoting."""
    statement = conn.execute(
        text("SELECT format('ALTER ROLE %I PASSWORD %L', :r::text, :m::text)"),
        {"r": role, "m": material},
    ).scalar_one()
    conn.execute(text(statement))


# ── premise 1 and 2: atomicity, in both directions ──────────────────────────


def test_a_rolled_back_alter_role_leaves_the_credential_untouched(
    superuser_url: str, role: str
) -> None:
    """PREMISE 1. A failure between the alter and the commit must install
    nothing — otherwise a crash mid-effect leaves a credential nobody recorded
    and the "install once" rule is already broken on the first run."""
    with _connect(superuser_url) as conn:
        assert _password_present(conn, role) is False
        _install(conn, role, HOSTILE)
        # Visible inside the transaction...
        assert _password_present(conn, role) is True
        conn.rollback()
        # ...and gone after it.
        assert _password_present(conn, role) is False


def test_a_committed_alter_role_installs_the_credential(
    superuser_url: str, role: str
) -> None:
    """PREMISE 2, and the CONTROL for premise 1. A statement that silently did
    nothing would satisfy the rollback assertion perfectly."""
    with _connect(superuser_url) as conn:
        _install(conn, role, HOSTILE)
        conn.commit()
    with _connect(superuser_url) as conn:
        assert _password_present(conn, role) is True


# ── premise 3: the presence read needs a superuser ──────────────────────────


def test_a_non_superuser_cannot_read_credential_presence(
    superuser_url: str, role: str, url_for: Callable[..., str]
) -> None:
    """PREMISE 3, and the reason the effect receives a privileged session.

    `pg_roles` renders `rolpassword` as `********` for everyone, and `pg_authid`
    is superuser-only. A non-superuser therefore cannot answer step 3's
    question at all — it is not that the answer would be wrong, it is that
    there is no answer to be had.
    """
    with _connect(superuser_url) as conn:
        database = conn.execute(text("SELECT current_database()")).scalar_one()
        conn.execute(text(f"GRANT CONNECT ON DATABASE {database} TO {role}"))
        _install(conn, role, HOSTILE)
        conn.commit()

    with _connect(url_for(superuser_url, database, user=role)) as conn:
        with pytest.raises(Exception) as refused:
            conn.execute(text("SELECT rolpassword FROM pg_authid"))
        assert "permission denied" in str(refused.value).lower()
        conn.rollback()
        # And the view that IS readable cannot answer the question either.
        masked = conn.execute(
            text("SELECT rolpassword FROM pg_roles WHERE rolname = :r"), {"r": role}
        ).scalar_one()
        assert masked == "********"


# ── premise 4: the quoting is PostgreSQL's, and it holds ────────────────────


def test_server_side_quoting_survives_a_hostile_password(
    superuser_url: str, role: str
) -> None:
    """PREMISE 4. Neither half of the statement can be a bind parameter, so
    `format(%I, %L)` is the entire injection argument. The password below
    carries a quote, a backslash, a semicolon and a comment marker."""
    with _connect(superuser_url) as conn:
        _install(conn, role, HOSTILE)
        conn.commit()
    with _connect(superuser_url) as conn:
        assert _password_present(conn, role) is True
        # The role still exists and is unchanged in every other respect: a
        # statement that had escaped its literal would have run something else.
        assert conn.execute(
            text("SELECT rolcanlogin FROM pg_roles WHERE rolname = :r"), {"r": role}
        ).scalar_one()


def test_server_side_quoting_survives_a_hostile_role_name(
    superuser_url: str,
) -> None:
    """The identifier half of the same argument, with a name that would end the
    statement early if it were interpolated rather than quoted.

    The name is created and dropped here rather than by the fixture, because the
    fixture's own `CREATE ROLE` interpolates a name it generated itself.
    """
    hostile = 'weird"; DROP TABLE x; --'
    with _connect(superuser_url) as conn:
        created = conn.execute(
            text("SELECT format('CREATE ROLE %I LOGIN', :r::text)"),
            {"r": hostile},
        ).scalar_one()
        conn.execute(text(created))
        conn.commit()
    try:
        with _connect(superuser_url) as conn:
            _install(conn, hostile, HOSTILE)
            conn.commit()
        with _connect(superuser_url) as conn:
            assert _password_present(conn, hostile) is True
    finally:
        with _connect(superuser_url) as conn:
            dropped = conn.execute(
                text("SELECT format('DROP ROLE IF EXISTS %I', :r::text)"),
                {"r": hostile},
            ).scalar_one()
            conn.execute(text(dropped))
            conn.commit()


# ── premise 5: the installed credential actually authenticates ──────────────


def test_the_installed_credential_authenticates_and_a_wrong_one_does_not(
    superuser_url: str, role: str, url_for: Callable[..., str]
) -> None:
    """PREMISE 5, both directions.

    Step 6's proof is only a proof if authentication is what it measures. The
    negative half is what makes it one: a connection helper that succeeded
    regardless would pass the positive case and prove nothing.
    """
    with _connect(superuser_url) as conn:
        database = conn.execute(text("SELECT current_database()")).scalar_one()
        conn.execute(text(f"GRANT CONNECT ON DATABASE {database} TO {role}"))
        _install(conn, role, HOSTILE)
        conn.commit()

    base = url_for(superuser_url, database, user=role)
    scheme, _, hostpart = base.partition("://")
    host = hostpart.rpartition("@")[2]
    from urllib.parse import quote

    def _authenticates(material: str) -> bool:
        url = f"{scheme}://{role}:{quote(material, safe='')}@{host}"
        try:
            with _connect(url) as conn:
                conn.execute(text("SELECT 1"))
            return True
        except Exception:
            return False

    assert _authenticates(HOSTILE) is True
    assert _authenticates(HOSTILE + "-wrong") is False


# ── the lock the effect takes is released by the transaction ────────────────


def test_the_advisory_lock_is_transaction_scoped(superuser_url: str) -> None:
    """The effect takes `pg_advisory_xact_lock`, so a refusing executor must not
    hold it against the next one. Measured by observing `pg_locks` rather than
    by trusting the function's name."""
    from vendor_cp.deployment.credential_bootstrap import _advisory_key

    key = _advisory_key("platform_outbox_dispatcher")
    with _connect(superuser_url) as conn:
        conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": key})
        held = conn.execute(
            text(
                "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' "
                "AND pid = pg_backend_pid()"
            )
        ).scalar_one()
        assert held == 1
        conn.rollback()
        after = conn.execute(
            text(
                "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' "
                "AND pid = pg_backend_pid()"
            )
        ).scalar_one()
        assert after == 0, "a rolled back transaction must not keep the lock"
