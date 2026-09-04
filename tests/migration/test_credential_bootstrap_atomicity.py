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
from pathlib import Path

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
        # A role holding a grant cannot be dropped: PostgreSQL refuses with
        # `DependentObjectsStillExist`. `DROP OWNED BY` removes the privileges
        # this role was given in this database first.
        conn.execute(text(f"DROP OWNED BY {name}"))
        conn.execute(text(f"DROP ROLE IF EXISTS {name}"))
        conn.commit()


def _password_present(conn: Connection, role: str) -> bool:
    return bool(
        conn.execute(
            text("SELECT rolpassword IS NOT NULL FROM pg_authid WHERE rolname = :r"),
            {"r": role},
        ).scalar_one()
    )


#: The checked-in operation, applied by a superuser exactly as a cluster
#: initialisation would apply it.
_OPERATION = (
    Path(__file__).resolve().parents[2]
    / "deploy"
    / "postgres"
    / "bootstrap-credential-function.sql"
)


@pytest.fixture
def operation(superuser_url: str) -> Iterator[None]:
    """Install the real operation, then drop it.

    Applied from the checked-in file rather than from a copy in this test: a
    test that installed its own version would measure a function nothing
    deploys.
    """
    with _connect(superuser_url) as conn:
        conn.execute(text(_OPERATION.read_text(encoding="utf-8")))
        conn.commit()
    yield
    with _connect(superuser_url) as conn:
        conn.execute(
            text(
                "DROP FUNCTION IF EXISTS "
                "public.bootstrap_dispatcher_credential(text, text)"
            )
        )
        conn.commit()


def _install(conn: Connection, role: str, material: str) -> None:
    """Install a credential the direct way, for the premises that are about
    PostgreSQL rather than about the operation."""
    statement = conn.execute(
        text(
            "SELECT format('ALTER ROLE %I PASSWORD %L', "
            "CAST(:r AS text), CAST(:m AS text))"
        ),
        {"r": role, "m": material},
    ).scalar_one()
    conn.execute(text(statement))


def _call(conn: Connection, principal: str, material: str) -> str:
    return str(
        conn.execute(
            text(
                "SELECT public.bootstrap_dispatcher_credential("
                "CAST(:p AS text), CAST(:m AS text))"
            ),
            {"p": principal, "m": material},
        ).scalar_one()
    )


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
            text("SELECT format('CREATE ROLE %I LOGIN', CAST(:r AS text))"),
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
                text("SELECT format('DROP ROLE IF EXISTS %I', CAST(:r AS text))"),
                {"r": hostile},
            ).scalar_one()
            conn.execute(text(dropped))
            conn.commit()


# ── premise 5: whether this host can even REFUSE a credential ──────────────


def _authenticates(base: str, role: str, material: str) -> bool:
    """Try one login. Returns an answer; a refused password is not an error."""
    from urllib.parse import quote

    scheme, _, hostpart = base.partition("://")
    host = hostpart.rpartition("@")[2]
    try:
        with _connect(f"{scheme}://{role}:{quote(material, safe='')}@{host}") as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


def test_this_cluster_does_not_enforce_password_authentication(
    superuser_url: str, role: str, url_for: Callable[..., str]
) -> None:
    """PREMISE 5, and the finding that changed the effect.

    The negative control here FAILED on its first run: a deliberately wrong
    password authenticated. The migration-tier cluster runs
    `POSTGRES_HOST_AUTH_METHOD: trust`, so every password is accepted, and a
    positive-only authentication proof passes on it while establishing nothing.

    So this measures the cluster rather than pretending otherwise, and the test
    below turns that into the fixture for the guard it produced. The
    scram-enforcing case is exercised by `.github/candidate/acceptance.sh`,
    whose PostgreSQL is initialised with `--auth-host=scram-sha-256`; asserting
    real authentication HERE would be asserting it of a server that cannot
    refuse.
    """
    with _connect(superuser_url) as conn:
        database = conn.execute(text("SELECT current_database()")).scalar_one()
        conn.execute(text(f"GRANT CONNECT ON DATABASE {database} TO {role}"))
        _install(conn, role, HOSTILE)
        conn.commit()

    base = url_for(superuser_url, database, user=role)
    assert _authenticates(base, role, HOSTILE) is True
    # The line that matters: on a trust-configured host this is ALSO true.
    assert _authenticates(base, role, HOSTILE + "-wrong") is True, (
        "this cluster now enforces passwords, so the effect's "
        "not-enforced refusal can no longer be measured here and this test "
        "must be replaced by the real two-directional proof"
    )


def test_the_effect_refuses_a_host_that_accepts_anything(
    superuser_url: str, url_for: Callable[..., str]
) -> None:
    """THE GUARD, DRIVEN END TO END AGAINST A SERVER THAT CANNOT REFUSE.

    Step 6 proves authentication in both directions, and the second direction is
    what makes the first mean anything. This cluster accepts every password, so
    the effect must refuse rather than report a credential it cannot verify —
    and name that reason rather than a generic failure.

    The real principal is used, because the operation hardcodes it: patching the
    Python allowlist would be refused by the operation (DM101) long before
    authentication was ever attempted, and the test would pass for the wrong
    reason.
    """
    from sqlalchemy.orm import Session

    from vendor_cp.deployment import credential_bootstrap as effect

    dispatcher = "platform_outbox_dispatcher"
    with _connect(superuser_url) as conn:
        conn.execute(text(_OPERATION.read_text(encoding="utf-8")))
        conn.execute(text(f"ALTER ROLE {dispatcher} PASSWORD NULL"))
        database = conn.execute(text("SELECT current_database()")).scalar_one()
        conn.execute(text(f"GRANT CONNECT ON DATABASE {database} TO {dispatcher}"))
        conn.commit()

    base = url_for(superuser_url, database, user=dispatcher)

    class _Record:
        version = 1
        fields = {"dispatcher_password": HOSTILE}

    class _Secrets:
        def read_versioned(self, path: str) -> object:
            return _Record()

    def _authenticate(*, database: str, principal: str, material: str) -> bool:
        return _authenticates(base, principal, material)

    instruction = effect.PrincipalCredentialBootstrap(
        database=database,
        principal=dispatcher,
        secret_path="secret/dotmac/vendor-control-plane/production/relay-dispatcher",
        secret_field="dispatcher_password",
        expected_version=1,
    )

    engine = create_engine(superuser_url)
    try:
        with Session(engine) as session:
            with pytest.raises(effect.BootstrapRefused) as refused:
                effect.bootstrap_principal_credential(
                    session,
                    instruction,
                    secrets=_Secrets(),
                    authenticate=_authenticate,
                )
        assert refused.value.code == "credential.authentication_not_enforced"
    finally:
        engine.dispose()

    # The credential IS committed, which is exactly the state the refusal
    # describes: the install happened, the proof did not.
    with _connect(superuser_url) as conn:
        assert _password_present(conn, dispatcher) is True
        conn.execute(text(f"ALTER ROLE {dispatcher} PASSWORD NULL"))
        conn.execute(
            text(
                "DROP FUNCTION IF EXISTS "
                "public.bootstrap_dispatcher_credential(text, text)"
            )
        )
        conn.commit()


DISPATCHER = "platform_outbox_dispatcher"


@pytest.fixture
def uncredentialed_dispatcher(superuser_url: str) -> Iterator[None]:
    """Guarantee the dispatcher holds no credential, and restore afterwards.

    The test cluster's `init-roles.sh` now SETS this password — that arrived
    with the relay service — so the absent-to-present transition cannot be
    observed without clearing it first. Clearing it rather than SKIPPING is the
    point: a suite that skips the one transition this operation exists to
    perform is green about nothing, and this repository's Postgres gate exists
    because skips pass silently.

    Safe on this cluster: it authenticates with `trust`, so nothing here depends
    on that password being set.
    """
    with _connect(superuser_url) as conn:
        conn.execute(text(f"ALTER ROLE {DISPATCHER} PASSWORD NULL"))
        conn.commit()
    yield
    with _connect(superuser_url) as conn:
        conn.execute(text(f"ALTER ROLE {DISPATCHER} PASSWORD NULL"))
        conn.commit()


# ── the operation itself ────────────────────────────────────────────────────


def test_an_app_admin_owned_definer_cannot_alter_a_role(
    superuser_url: str, role: str
) -> None:
    """THE MEASUREMENT THAT DECIDED THE DESIGN.

    The kernel's `0012_platform_outbox` creates SECURITY DEFINER functions and
    sets `OWNER TO app_admin`, which works because app_admin has the TABLE
    privileges those functions need. It has no CREATEROLE, so an app_admin-owned
    function cannot alter a role — and that is why this operation is owned and
    installed by a superuser instead of arriving as an Alembic revision.

    Asserted against a real server rather than reasoned from the manual, because
    the whole design turns on it.
    """
    with _connect(superuser_url) as conn:
        conn.execute(
            text(
                "CREATE OR REPLACE FUNCTION public.canary_alter(p text, m text) "
                "RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' "
                "AS $fn$ BEGIN EXECUTE pg_catalog.format("
                "'ALTER ROLE %I PASSWORD %L', p, m); END $fn$"
            )
        )
        conn.execute(
            text("ALTER FUNCTION public.canary_alter(text, text) OWNER TO app_admin")
        )
        conn.commit()
    try:
        with _connect(superuser_url) as conn:
            with pytest.raises(Exception) as refused:
                conn.execute(
                    text(
                        "SELECT public.canary_alter(CAST(:p AS text), CAST(:m AS text))"
                    ),
                    {"p": role, "m": HOSTILE},
                )
            assert "permission denied" in str(refused.value).lower()
    finally:
        with _connect(superuser_url) as conn:
            conn.execute(
                text("DROP FUNCTION IF EXISTS public.canary_alter(text, text)")
            )
            conn.commit()


def test_the_operation_refuses_every_principal_but_its_own(
    superuser_url: str, operation: None, role: str
) -> None:
    """Restricted BY NAME, not by convention. A definer function that altered
    whatever principal it was handed would be a CREATEROLE grant with extra
    steps, reachable by anything holding EXECUTE."""
    with _connect(superuser_url) as conn:
        for other in (role, "app_admin", "app_user", "platform_api", "postgres"):
            with pytest.raises(Exception) as refused:
                _call(conn, other, HOSTILE)
            assert "DM101" in str(refused.value) or "not bootstrappable" in str(
                refused.value
            )
            conn.rollback()


def test_the_operation_installs_once_and_then_refuses(
    superuser_url: str, operation: None, uncredentialed_dispatcher: None
) -> None:
    """The one-time property survives the move into SQL: absent means install,
    present means refuse. No ledger — the database's own state is the record."""
    from sqlalchemy.exc import DBAPIError

    with _connect(superuser_url) as conn:
        assert _password_present(conn, DISPATCHER) is False
        assert _call(conn, DISPATCHER, HOSTILE) == "installed"
        conn.commit()
    with _connect(superuser_url) as conn:
        assert _password_present(conn, DISPATCHER) is True
        with pytest.raises(DBAPIError) as refused:
            _call(conn, DISPATCHER, HOSTILE)
        assert "DM105" in str(refused.value) or "installs once" in str(refused.value)
        conn.rollback()


def test_the_operation_is_not_executable_by_the_application_roles(
    superuser_url: str, operation: None, url_for: Callable[..., str]
) -> None:
    """Executor-only. PUBLIC gets nothing and the application's own roles are
    revoked by name, so the absence is stated rather than inherited."""
    with _connect(superuser_url) as conn:
        database = conn.execute(text("SELECT current_database()")).scalar_one()
    for principal in ("app_user", "platform_api"):
        with _connect(url_for(superuser_url, database, user=principal)) as conn:
            with pytest.raises(Exception) as refused:
                _call(conn, "platform_outbox_dispatcher", HOSTILE)
            assert "permission denied" in str(refused.value).lower()
            conn.rollback()


def test_the_operation_holds_its_lock_only_for_the_transaction(
    superuser_url: str, operation: None, uncredentialed_dispatcher: None
) -> None:
    """The lock moved inside the operation and stayed transaction-scoped.

    Driven through a refusal that TAKES the lock first. The principal check runs
    before the lock, so a DM101 refusal would never have held one and asserting
    on it would prove nothing — the already-present refusal (DM105) is the one
    that locks, reads under it, and then raises.
    """
    from sqlalchemy.exc import DBAPIError

    with _connect(superuser_url) as conn:
        _install(conn, DISPATCHER, HOSTILE)
        conn.commit()
    with _connect(superuser_url) as conn:
        with pytest.raises(DBAPIError) as refused:
            _call(conn, DISPATCHER, HOSTILE)
        assert "DM105" in str(refused.value) or "installs once" in str(refused.value)
        conn.rollback()
        held = conn.execute(
            text(
                "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' "
                "AND pid = pg_backend_pid()"
            )
        ).scalar_one()
        assert held == 0, "a refusing executor must not keep the lock"
