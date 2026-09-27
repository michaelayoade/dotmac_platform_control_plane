"""`transition_fence`, driven against a real PostgreSQL cluster.

Every claim the fence rests on is a claim about what a real server does with
`REVOKE CONNECT`, `has_database_privilege`, `pg_terminate_backend` and role
membership resolution — this file measures those rather than trusting the
module's own docstring. Disposable login roles are created and dropped inside
each test; the global `app_user`/`platform_api` roles are never touched.

Every wait is bounded: `SESSION_WAIT_SECONDS` is a few seconds, and every
connection this file opens sets a `lock_timeout` so a defect here fails fast
rather than hanging CI.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager

import pytest
from sqlalchemy import Connection, create_engine, text
from sqlalchemy.exc import OperationalError

from vendor_cp.deployment import transition_fence as fence_module
from vendor_cp.deployment.transition_fence import (
    MIGRATION_ROLE,
    FenceRefusalCode,
    FenceRefused,
    fence_writers,
    restore_writers,
)

#: A few seconds — bounded, never open-ended.
SESSION_WAIT_SECONDS = 3.0


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


@contextmanager
def _writer_role(admin_url: str, *, name: str | None = None) -> Iterator[str]:
    """A disposable LOGIN role, dropped on exit.

    No password: the migration-tier cluster runs
    `POSTGRES_HOST_AUTH_METHOD=trust` (established in
    `test_credential_bootstrap_atomicity.py`), so a new backend authenticates
    as this role without one, and a REFUSED connection here is refused on
    CONNECT privilege, never on password.
    """
    role = name or f"fence_writer_{uuid.uuid4().hex[:10]}"
    with _connect(admin_url, autocommit=True) as conn:
        conn.execute(text(f"CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS"))
    try:
        yield role
    finally:
        with _connect(admin_url, autocommit=True) as conn:
            # A role holding a grant cannot be dropped directly.
            conn.execute(text(f"DROP OWNED BY {role}"))
            conn.execute(text(f"DROP ROLE IF EXISTS {role}"))


@pytest.fixture
def db(scratch_db: str) -> str:
    return _dbname(scratch_db)


@pytest.fixture
def admin_url(postgres_url: str, db: str, url_for: Callable[..., str]) -> str:
    """The cluster superuser's URL against the scratch database — the
    identity `fence_writers` requires (owner-or-superuser) to terminate other
    roles' backends."""
    return url_for(postgres_url, db)


@pytest.fixture
def bare_db(postgres_url: str) -> Iterator[str]:
    """A scratch database with NO explicit grant ever issued against it, so
    `datacl` stays NULL — `scratch_db` already GRANTs CONNECT to
    platform_api/app_user/app_admin, which materialises a non-NULL ACL and
    cannot exercise the NULL-datacl case."""
    name = f"vcp_fence_bare_{uuid.uuid4().hex[:12]}"
    with _connect(postgres_url, autocommit=True) as conn:
        # Owned by app_admin, as production's contract requires (the deploy
        # script refuses any other owner): the migrator's CONNECT then rests
        # on ownership, not on PUBLIC, and survives the fence.
        conn.execute(text(f'CREATE DATABASE "{name}" OWNER app_admin'))
    try:
        yield name
    finally:
        with _connect(postgres_url, autocommit=True) as conn:
            conn.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :n AND pid <> pg_backend_pid()"
                ),
                {"n": name},
            )
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}"'))


# ── (a) a NEW connection as a fenced writer is refused; app_admin still can ─


def test_a_new_connection_as_a_fenced_writer_is_refused_app_admin_still_connects(
    admin_url: str, db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    with _writer_role(admin_url) as w1, _writer_role(admin_url) as w2:
        with _connect(admin_url, autocommit=True) as conn:
            fence_writers(
                conn,
                database=db,
                writer_roles=(w1, w2),
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )

        for writer in (w1, w2):
            with pytest.raises(OperationalError, match="permission denied"):
                with _connect(url_for(postgres_url, db, user=writer)):
                    pass

        with _connect(url_for(postgres_url, db, user=MIGRATION_ROLE)) as conn:
            assert conn.execute(text("SELECT 1")).scalar_one() == 1


# ── (b) an OPEN writer session is terminated and counted ────────────────────


def test_an_open_writer_session_is_terminated_and_counted(
    admin_url: str, db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    with _writer_role(admin_url) as w:
        writer_engine = create_engine(url_for(postgres_url, db, user=w))
        writer_conn = writer_engine.connect()
        try:
            assert writer_conn.execute(text("SELECT 1")).scalar_one() == 1

            with _connect(admin_url, autocommit=True) as conn:
                proof = fence_writers(
                    conn,
                    database=db,
                    writer_roles=(w,),
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                )
            assert proof.terminated_count >= 1

            with pytest.raises(Exception):  # noqa: B017 -- driver-specific
                writer_conn.execute(text("SELECT 1"))
        finally:
            writer_conn.close()
            writer_engine.dispose()


# ── (c) a NULL-datacl database: fence then restore reproduces the default ──


def test_fence_then_restore_on_a_null_datacl_database_reproduces_the_default(
    postgres_url: str, bare_db: str, url_for: Callable[..., str]
) -> None:
    bare_admin_url = url_for(postgres_url, bare_db)
    with _connect(bare_admin_url) as conn:
        acl = conn.execute(
            text("SELECT datacl FROM pg_database WHERE datname = :n"),
            {"n": bare_db},
        ).scalar_one()
        assert acl is None, "fixture must start with a NULL (default) ACL"
        default_acl = conn.execute(
            text(
                "SELECT acldefault('d', datdba)::text FROM pg_database "
                "WHERE datname = :n"
            ),
            {"n": bare_db},
        ).scalar_one()

    probe = f"fence_probe_{uuid.uuid4().hex[:10]}"
    with _writer_role(bare_admin_url) as w:
        with _connect(bare_admin_url, autocommit=True) as conn:
            conn.execute(text(f"CREATE ROLE {probe} LOGIN"))
        try:
            with _connect(bare_admin_url, autocommit=True) as conn:
                proof = fence_writers(
                    conn,
                    database=bare_db,
                    writer_roles=(w,),
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                )
                # `fence_writers` read the NULL column and materialised the
                # identical default this test computed independently.
                assert fence_module._parse_acl(
                    proof.prior_acl
                ) == fence_module._parse_acl(default_acl)

                probe_while_fenced = conn.execute(
                    text("SELECT has_database_privilege(:r, :d, 'CONNECT')"),
                    {"r": probe, "d": bare_db},
                ).scalar_one()
                assert probe_while_fenced is False

                restore_writers(conn, proof)

                probe_after_restore = conn.execute(
                    text("SELECT has_database_privilege(:r, :d, 'CONNECT')"),
                    {"r": probe, "d": bare_db},
                ).scalar_one()
                assert probe_after_restore is True

                restored_acl = fence_module._current_acl_text(conn, bare_db)
                assert fence_module._parse_acl(restored_acl) == fence_module._parse_acl(
                    default_acl
                )
        finally:
            with _connect(bare_admin_url, autocommit=True) as conn:
                conn.execute(text(f"DROP ROLE IF EXISTS {probe}"))


# ── (d) restore returns the exact prior ACL; a second restore is a no-op ───


def test_restore_returns_the_exact_prior_acl_and_a_second_restore_changes_nothing(
    admin_url: str, db: str
) -> None:
    with _writer_role(admin_url) as w:
        with _connect(admin_url, autocommit=True) as conn:
            prior_before = fence_module._current_acl_text(conn, db)

            proof = fence_writers(
                conn,
                database=db,
                writer_roles=(w,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )
            assert proof.prior_acl == prior_before

            first = restore_writers(conn, proof)
            restored_acl = fence_module._current_acl_text(conn, db)
            assert fence_module._parse_acl(restored_acl) == fence_module._parse_acl(
                prior_before
            )

            second = restore_writers(conn, proof)
            assert second.roles_restored == first.roles_restored
            assert fence_module._current_acl_text(conn, db) == restored_acl


# ── (e) re-fencing with prior= keeps the ORIGINAL prior ACL ─────────────────


def test_refencing_with_prior_keeps_the_original_prior_acl(
    admin_url: str, db: str
) -> None:
    with _writer_role(admin_url) as w:
        with _connect(admin_url, autocommit=True) as conn:
            first_proof = fence_writers(
                conn,
                database=db,
                writer_roles=(w,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )
            second_proof = fence_writers(
                conn,
                database=db,
                writer_roles=(w,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
                prior=first_proof,
            )
            assert second_proof.prior_acl == first_proof.prior_acl

            restore_writers(conn, second_proof)
            restored_acl = fence_module._current_acl_text(conn, db)
            assert fence_module._parse_acl(restored_acl) == fence_module._parse_acl(
                first_proof.prior_acl
            )


# ── (f) CONNECT inherited through an INTERMEDIATE role's own grant ─────────


def test_connect_inherited_through_an_intermediate_roles_own_grant_is_refused_first(
    admin_url: str, db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """Writer W is a member of an unrelated role R that holds its OWN CONNECT
    grant. No REVOKE this module issues removes W's inherited CONNECT, so the
    fence refuses `writer_inherits_connect` BEFORE any ACL change: the ACL is
    byte-identical afterwards, and nothing was half-fenced."""
    intermediate = f"fence_intermediate_{uuid.uuid4().hex[:10]}"
    with _connect(admin_url, autocommit=True) as conn:
        conn.execute(text(f"CREATE ROLE {intermediate} NOLOGIN"))
        conn.execute(text(f'GRANT CONNECT ON DATABASE "{db}" TO {intermediate}'))
    try:
        with _writer_role(admin_url) as w:
            with _connect(admin_url, autocommit=True) as conn:
                conn.execute(text(f"GRANT {intermediate} TO {w}"))
            try:
                with _connect(admin_url, autocommit=True) as conn:
                    prior_acl = fence_module._current_acl_text(conn, db)
                    with pytest.raises(FenceRefused) as refused:
                        fence_writers(
                            conn,
                            database=db,
                            writer_roles=(w,),
                            session_wait_seconds=SESSION_WAIT_SECONDS,
                        )
                    assert (
                        refused.value.code == FenceRefusalCode.WRITER_INHERITS_CONNECT
                    )
                    assert (
                        fence_module._current_acl_text(conn, db) == prior_acl
                    ), "a refusal must leave the ACL untouched"
            finally:
                with _connect(admin_url, autocommit=True) as conn:
                    conn.execute(text(f"REVOKE {intermediate} FROM {w}"))
    finally:
        with _connect(admin_url, autocommit=True) as conn:
            conn.execute(text(f'REVOKE CONNECT ON DATABASE "{db}" FROM {intermediate}'))
            conn.execute(text(f"DROP ROLE IF EXISTS {intermediate}"))


class _SkipWriterRevoke:
    """Test-side proxy: drops the per-writer REVOKE (but not PUBLIC's), so the
    fence MUTATES the ACL and only then fails verification."""

    def __init__(self, real: Connection, writer: str) -> None:
        self._real = real
        self._writer = writer

    def execute(self, statement: object, *args: object, **kwargs: object) -> object:
        sql = str(statement)
        if sql.startswith("REVOKE CONNECT") and self._writer in sql:
            return None
        return self._real.execute(statement, *args, **kwargs)  # type: ignore[arg-type]

    def __getattr__(self, name: str) -> object:
        return getattr(self._real, name)


def test_a_refusal_after_the_first_revoke_restores_the_starting_acl(
    admin_url: str, db: str
) -> None:
    """COMPENSATION. W holds a DIRECT grant; its own REVOKE is dropped, so
    PUBLIC is really revoked and verification then refuses. The fence must put
    the ACL back to exactly where this call started — never leave a
    half-fenced database with no proof to restore from."""
    with _writer_role(admin_url) as w:
        with _connect(admin_url, autocommit=True) as conn:
            conn.execute(text(f'GRANT CONNECT ON DATABASE "{db}" TO {w}'))
            before = fence_module._current_acl_text(conn, db)
            assert fence_module._had_connect(fence_module._parse_acl(before), "")
            with pytest.raises(FenceRefused) as refused:
                fence_writers(
                    _SkipWriterRevoke(conn, w),  # type: ignore[arg-type]
                    database=db,
                    writer_roles=(w,),
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                )
            assert refused.value.code == FenceRefusalCode.WRITER_STILL_HAS_CONNECT
            after = fence_module._current_acl_text(conn, db)
            assert fence_module._parse_acl(after) == fence_module._parse_acl(before)
            assert fence_module._had_connect(fence_module._parse_acl(after), "")
            conn.execute(text(f'REVOKE CONNECT ON DATABASE "{db}" FROM {w}'))


def test_a_superuser_writer_is_refused_first(
    admin_url: str, db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """A superuser keeps CONNECT through every REVOKE: refused before any change."""
    role = f"fence_super_{uuid.uuid4().hex[:10]}"
    with _connect(postgres_url, autocommit=True) as conn:
        conn.execute(text(f"CREATE ROLE {role} LOGIN SUPERUSER"))
    try:
        with _connect(admin_url, autocommit=True) as conn:
            prior_acl = fence_module._current_acl_text(conn, db)
            with pytest.raises(FenceRefused) as refused:
                fence_writers(
                    conn,
                    database=db,
                    writer_roles=(role,),
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                )
            assert refused.value.code == FenceRefusalCode.WRITER_INHERITS_CONNECT
            assert fence_module._current_acl_text(conn, db) == prior_acl
    finally:
        with _connect(postgres_url, autocommit=True) as conn:
            conn.execute(text(f"DROP ROLE IF EXISTS {role}"))


# ── (g) ownership: a writer that is a member of the database owner ─────────


def test_a_writer_that_is_a_member_of_the_database_owner_is_refused_before_any_change(
    admin_url: str, db: str
) -> None:
    with _connect(admin_url, autocommit=True) as conn:
        owner = conn.execute(
            text("SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = :d"),
            {"d": db},
        ).scalar_one()

    with _writer_role(admin_url) as w:
        with _connect(admin_url, autocommit=True) as conn:
            conn.execute(text(f"GRANT {owner} TO {w}"))
        try:
            with _connect(admin_url, autocommit=True) as conn:
                prior_acl = fence_module._current_acl_text(conn, db)
                with pytest.raises(FenceRefused) as refused:
                    fence_writers(
                        conn,
                        database=db,
                        writer_roles=(w,),
                        session_wait_seconds=SESSION_WAIT_SECONDS,
                    )
                assert refused.value.code == FenceRefusalCode.WRITER_INHERITS_CONNECT
                after_acl = fence_module._current_acl_text(conn, db)
                assert after_acl == prior_acl, "a refusal must leave the ACL untouched"
        finally:
            with _connect(admin_url, autocommit=True) as conn:
                conn.execute(text(f"REVOKE {owner} FROM {w}"))


# ── (h) shared role: membership with app_admin in either direction ─────────


def test_a_writer_that_app_admin_is_a_member_of_is_refused_as_shared(
    admin_url: str, db: str
) -> None:
    with _writer_role(admin_url) as w:
        with _connect(admin_url, autocommit=True) as conn:
            conn.execute(text(f"GRANT {w} TO {MIGRATION_ROLE}"))
        try:
            with _connect(admin_url, autocommit=True) as conn:
                prior_acl = fence_module._current_acl_text(conn, db)
                with pytest.raises(FenceRefused) as refused:
                    fence_writers(
                        conn,
                        database=db,
                        writer_roles=(w,),
                        session_wait_seconds=SESSION_WAIT_SECONDS,
                    )
                assert refused.value.code == FenceRefusalCode.SHARED_WRITER_ROLE
                after_acl = fence_module._current_acl_text(conn, db)
                assert after_acl == prior_acl, "a refusal must leave the ACL untouched"
        finally:
            with _connect(admin_url, autocommit=True) as conn:
                conn.execute(text(f"REVOKE {w} FROM {MIGRATION_ROLE}"))


def test_a_writer_that_is_a_member_of_app_admin_is_refused_as_shared(
    admin_url: str, db: str
) -> None:
    with _writer_role(admin_url) as w:
        with _connect(admin_url, autocommit=True) as conn:
            conn.execute(text(f"GRANT {MIGRATION_ROLE} TO {w}"))
        try:
            with _connect(admin_url, autocommit=True) as conn:
                prior_acl = fence_module._current_acl_text(conn, db)
                with pytest.raises(FenceRefused) as refused:
                    fence_writers(
                        conn,
                        database=db,
                        writer_roles=(w,),
                        session_wait_seconds=SESSION_WAIT_SECONDS,
                    )
                assert refused.value.code == FenceRefusalCode.SHARED_WRITER_ROLE
                after_acl = fence_module._current_acl_text(conn, db)
                assert after_acl == prior_acl, "a refusal must leave the ACL untouched"
        finally:
            with _connect(admin_url, autocommit=True) as conn:
                conn.execute(text(f"REVOKE {MIGRATION_ROLE} FROM {w}"))


# ── (i) SENSITIVITY: skip the PUBLIC revoke, verification must bite ────────


class _SkipPublicRevoke:
    """A test-side connection proxy — no library change.

    Delegates every statement to the real connection except one that would
    `REVOKE ... FROM PUBLIC`, which it silently drops. This is what lets the
    positive-only per-writer check be exercised: without this, PUBLIC's own
    revoke would already remove the writer's inherited CONNECT and the
    per-writer `has_database_privilege` check would never have anything left
    to catch.
    """

    def __init__(self, real: Connection) -> None:
        self._real = real

    def execute(self, statement: object, *args: object, **kwargs: object) -> object:
        if "FROM PUBLIC" in str(statement):
            return None
        return self._real.execute(statement, *args, **kwargs)  # type: ignore[arg-type]

    def __getattr__(self, name: str) -> object:
        return getattr(self._real, name)


def test_skipping_the_public_revoke_is_caught_by_writer_still_has_connect(
    admin_url: str, db: str
) -> None:
    with _writer_role(admin_url) as w:
        with _connect(admin_url, autocommit=True) as conn:
            proxy = _SkipPublicRevoke(conn)
            with pytest.raises(FenceRefused) as refused:
                fence_writers(
                    proxy,  # type: ignore[arg-type]
                    database=db,
                    writer_roles=(w,),
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                )
            assert refused.value.code == FenceRefusalCode.WRITER_STILL_HAS_CONNECT

            # The writer's own ACL entry never existed (it relied on PUBLIC),
            # so its no-op per-writer REVOKE changed nothing, and skipping
            # PUBLIC's own revoke means the ACL is exactly what it was before
            # this call — proven, not assumed.
            still_connect = conn.execute(
                text("SELECT has_database_privilege(:r, :d, 'CONNECT')"),
                {"r": w, "d": db},
            ).scalar_one()
            assert still_connect is True


def test_a_migrator_whose_connect_rests_only_on_public_is_refused_first(
    postgres_url: str,
) -> None:
    """A database app_admin does not own, with a NULL (default) ACL: the
    migrator's CONNECT rests on PUBLIC alone, so fencing would lock it out.
    Refused as `migration_role_lost_connect` BEFORE any change."""
    name = f"vcp_fence_notowned_{uuid.uuid4().hex[:12]}"
    with _connect(postgres_url, autocommit=True) as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    try:
        with _connect(postgres_url, autocommit=True) as conn:
            with pytest.raises(FenceRefused) as refused:
                fence_writers(
                    conn,
                    database=name,
                    writer_roles=("app_user",),
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                )
            assert refused.value.code == FenceRefusalCode.MIGRATION_ROLE_LOST_CONNECT
            acl = conn.execute(
                text("SELECT datacl FROM pg_database WHERE datname = :n"),
                {"n": name},
            ).scalar_one()
            assert acl is None, "a refusal must leave the ACL untouched"
    finally:
        with _connect(postgres_url, autocommit=True) as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}"'))
