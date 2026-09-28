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

import dataclasses
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime

import pytest
from sqlalchemy import Connection, create_engine, text
from sqlalchemy.exc import OperationalError

from vendor_cp.deployment import transition_fence as fence_module
from vendor_cp.deployment.transition_fence import (
    MIGRATION_ROLE,
    FenceProof,
    FenceRefusalCode,
    FenceRefused,
    fence_is_holding,
    fence_writers,
    restore_writers,
)

#: A few seconds — bounded, never open-ended.
SESSION_WAIT_SECONDS = 3.0

#: The run identifier this file's `fence_writers`/`restore_writers` calls
#: bind, and rebind, throughout — no test in this file exercises more than
#: one run at a time, so one constant is enough; the `fence_id` mismatch
#: itself is proven by the dedicated replay test below.
FENCE_ID = "test-fence"


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


def _has_connect(grants: frozenset[tuple[str, str, bool, str]], grantee: str) -> bool:
    """`grantee` (`""` for PUBLIC) holds a CONNECT grant in the decomposed
    ACL `fence_module._current_grants` returns."""
    return any(g == grantee and priv == "CONNECT" for g, priv, _, _grantor in grants)


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
                fence_id=FENCE_ID,
                writer_roles=(w1, w2),
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )

        for writer in (w1, w2):
            with pytest.raises(OperationalError, match="permission denied"):
                with _connect(url_for(postgres_url, db, user=writer)):
                    pass

        with _connect(url_for(postgres_url, db, user=MIGRATION_ROLE)) as conn:
            assert conn.execute(text("SELECT 1")).scalar_one() == 1


# ── (a2) a MEMBER of a fenced writer, with an OPEN session, is terminated ──


def test_a_member_of_a_fenced_writer_with_an_open_session_is_terminated(
    admin_url: str, db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """M is a plain LOGIN member of writer W (no grant of its own). Before the
    effective-set fix M's own session and reconnect were untouched by fencing
    W, since `_apply_fence` only ever revoked/verified/drained the NAMED
    writers — M inherits CONNECT through membership and `SET ROLE W`."""
    with _writer_role(admin_url) as w:
        member = f"fence_member_{uuid.uuid4().hex[:10]}"
        with _connect(admin_url, autocommit=True) as conn:
            conn.execute(text(f"CREATE ROLE {member} LOGIN NOSUPERUSER NOBYPASSRLS"))
            conn.execute(text(f"GRANT {w} TO {member}"))
        try:
            member_engine = create_engine(url_for(postgres_url, db, user=member))
            member_conn = member_engine.connect()
            try:
                assert member_conn.execute(text("SELECT 1")).scalar_one() == 1

                with _connect(admin_url, autocommit=True) as conn:
                    proof = fence_writers(
                        conn,
                        database=db,
                        fence_id=FENCE_ID,
                        writer_roles=(w,),
                        session_wait_seconds=SESSION_WAIT_SECONDS,
                    )
                assert member in proof.member_roles

                # The open session is terminated...
                with pytest.raises(OperationalError):
                    member_conn.execute(text("SELECT 1"))
            finally:
                member_conn.close()
                member_engine.dispose()

            # ...and a NEW connection as the member is refused too: membership
            # alone, absent this fix, would still let it through.
            with pytest.raises(OperationalError, match="permission denied"):
                with _connect(url_for(postgres_url, db, user=member)):
                    pass
        finally:
            with _connect(admin_url, autocommit=True) as conn:
                conn.execute(text(f"REVOKE {w} FROM {member}"))
                conn.execute(text(f"DROP OWNED BY {member}"))
                conn.execute(text(f"DROP ROLE IF EXISTS {member}"))


# ── (a3) a MEMBER holding its OWN direct CONNECT grant is fenced and restored


def test_a_member_with_its_own_connect_grant_is_fenced_and_restored_exactly(
    admin_url: str, db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """M is a member of writer W AND separately holds its own CONNECT grant.
    Before the effective-set fix, `_apply_fence` never revoked M's own grant
    (it only revoked the named writers), so M could reconnect on its own
    identity after the fence claimed to hold."""
    with _writer_role(admin_url) as w:
        member = f"fence_member_{uuid.uuid4().hex[:10]}"
        with _connect(admin_url, autocommit=True) as conn:
            conn.execute(text(f"CREATE ROLE {member} LOGIN NOSUPERUSER NOBYPASSRLS"))
            conn.execute(text(f"GRANT {w} TO {member}"))
            conn.execute(text(f'GRANT CONNECT ON DATABASE "{db}" TO {member}'))
        try:
            with _connect(admin_url, autocommit=True) as conn:
                before = fence_module._current_grants(conn, db)
                proof = fence_writers(
                    conn,
                    database=db,
                    fence_id=FENCE_ID,
                    writer_roles=(w,),
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                )
                assert member in proof.member_roles

            with pytest.raises(OperationalError, match="permission denied"):
                with _connect(url_for(postgres_url, db, user=member)):
                    pass

            with _connect(admin_url, autocommit=True) as conn:
                restore_writers(
                    conn,
                    proof,
                    database=db,
                    expected_fence_id=FENCE_ID,
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                )
                assert fence_module._current_grants(conn, db) == before

            with _connect(url_for(postgres_url, db, user=member)) as conn:
                assert conn.execute(text("SELECT 1")).scalar_one() == 1
        finally:
            with _connect(admin_url, autocommit=True) as conn:
                conn.execute(text(f'REVOKE CONNECT ON DATABASE "{db}" FROM {member}'))
                conn.execute(text(f"REVOKE {w} FROM {member}"))
                conn.execute(text(f"DROP OWNED BY {member}"))
                conn.execute(text(f"DROP ROLE IF EXISTS {member}"))


# ── (a4) a MEMBER sharing identity with app_admin is refused, unchanged ────


def test_a_member_of_a_fenced_writer_sharing_identity_with_app_admin_is_refused(
    admin_url: str, db: str
) -> None:
    """M is a member of writer W, and app_admin is (separately) a member of
    M. M lands in the effective set through W, and the shared-identity check
    must run over the effective set — refused before any change."""
    with _writer_role(admin_url) as w:
        member = f"fence_member_{uuid.uuid4().hex[:10]}"
        with _connect(admin_url, autocommit=True) as conn:
            conn.execute(text(f"CREATE ROLE {member} LOGIN NOSUPERUSER NOBYPASSRLS"))
            conn.execute(text(f"GRANT {w} TO {member}"))
            conn.execute(text(f"GRANT {member} TO {MIGRATION_ROLE}"))
        try:
            with _connect(admin_url, autocommit=True) as conn:
                prior_acl = fence_module._current_acl_text(conn, db)
                with pytest.raises(FenceRefused) as refused:
                    fence_writers(
                        conn,
                        database=db,
                        fence_id=FENCE_ID,
                        writer_roles=(w,),
                        session_wait_seconds=SESSION_WAIT_SECONDS,
                    )
                assert refused.value.code == FenceRefusalCode.SHARED_WRITER_ROLE
                assert (
                    fence_module._current_acl_text(conn, db) == prior_acl
                ), "a refusal must leave the ACL untouched"
        finally:
            with _connect(admin_url, autocommit=True) as conn:
                conn.execute(text(f"REVOKE {member} FROM {MIGRATION_ROLE}"))
                conn.execute(text(f"REVOKE {w} FROM {member}"))
                conn.execute(text(f"DROP OWNED BY {member}"))
                conn.execute(text(f"DROP ROLE IF EXISTS {member}"))


# ── (a5) a MEMBER inheriting CONNECT via an UNRELATED grantee X ─────────────


def test_a_member_inheriting_connect_through_an_unrelated_grantee_is_refused_first(
    admin_url: str, db: str
) -> None:
    """M is a member of writer W (landing in the effective set through W) and
    SEPARATELY a member of an unrelated role X that holds its own CONNECT
    grant. M's CONNECT inherited via X survives every REVOKE this module can
    issue, so the fence must refuse `writer_inherits_connect` for a MEMBER,
    not only for a named writer — before any change, ACL untouched."""
    grantee_x = f"fence_grantee_x_{uuid.uuid4().hex[:10]}"
    with _connect(admin_url, autocommit=True) as conn:
        conn.execute(text(f"CREATE ROLE {grantee_x} NOLOGIN"))
        conn.execute(text(f'GRANT CONNECT ON DATABASE "{db}" TO {grantee_x}'))
    try:
        with _writer_role(admin_url) as w:
            member = f"fence_member_{uuid.uuid4().hex[:10]}"
            with _connect(admin_url, autocommit=True) as conn:
                conn.execute(
                    text(f"CREATE ROLE {member} LOGIN NOSUPERUSER NOBYPASSRLS")
                )
                conn.execute(text(f"GRANT {w} TO {member}"))
                conn.execute(text(f"GRANT {grantee_x} TO {member}"))
            try:
                with _connect(admin_url, autocommit=True) as conn:
                    prior_acl = fence_module._current_acl_text(conn, db)
                    with pytest.raises(FenceRefused) as refused:
                        fence_writers(
                            conn,
                            database=db,
                            fence_id=FENCE_ID,
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
                    conn.execute(text(f"REVOKE {grantee_x} FROM {member}"))
                    conn.execute(text(f"REVOKE {w} FROM {member}"))
                    conn.execute(text(f"DROP OWNED BY {member}"))
                    conn.execute(text(f"DROP ROLE IF EXISTS {member}"))
    finally:
        with _connect(admin_url, autocommit=True) as conn:
            conn.execute(text(f'REVOKE CONNECT ON DATABASE "{db}" FROM {grantee_x}'))
            conn.execute(text(f"DROP ROLE IF EXISTS {grantee_x}"))


# ── (a6) a THREE-LEVEL chain through a NOLOGIN intermediate ─────────────────


def test_a_three_level_membership_chain_through_a_nologin_intermediate_is_fenced(
    admin_url: str, db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """login L -> NOLOGIN N -> writer W. L never appears in `WRITER_ROLES` and
    is not a DIRECT member of W, only of the intermediate N — proving
    `_member_roles`'s recursive walk, not just one hop. L's open session is
    terminated, and it cannot reconnect afterwards."""
    with _writer_role(admin_url) as w:
        intermediate = f"fence_chain_n_{uuid.uuid4().hex[:10]}"
        login_role = f"fence_chain_l_{uuid.uuid4().hex[:10]}"
        with _connect(admin_url, autocommit=True) as conn:
            conn.execute(text(f"CREATE ROLE {intermediate} NOLOGIN"))
            conn.execute(
                text(f"CREATE ROLE {login_role} LOGIN NOSUPERUSER NOBYPASSRLS")
            )
            conn.execute(text(f"GRANT {w} TO {intermediate}"))
            conn.execute(text(f"GRANT {intermediate} TO {login_role}"))
        try:
            login_engine = create_engine(url_for(postgres_url, db, user=login_role))
            login_conn = login_engine.connect()
            try:
                assert login_conn.execute(text("SELECT 1")).scalar_one() == 1

                with _connect(admin_url, autocommit=True) as conn:
                    proof = fence_writers(
                        conn,
                        database=db,
                        fence_id=FENCE_ID,
                        writer_roles=(w,),
                        session_wait_seconds=SESSION_WAIT_SECONDS,
                    )
                assert login_role in proof.member_roles
                assert intermediate in proof.member_roles

                with pytest.raises(OperationalError):
                    login_conn.execute(text("SELECT 1"))
            finally:
                login_conn.close()
                login_engine.dispose()

            with pytest.raises(OperationalError, match="permission denied"):
                with _connect(url_for(postgres_url, db, user=login_role)):
                    pass
        finally:
            with _connect(admin_url, autocommit=True) as conn:
                conn.execute(text(f"REVOKE {intermediate} FROM {login_role}"))
                conn.execute(text(f"REVOKE {w} FROM {intermediate}"))
                conn.execute(text(f"DROP OWNED BY {login_role}"))
                conn.execute(text(f"DROP ROLE IF EXISTS {login_role}"))
                conn.execute(text(f"DROP ROLE IF EXISTS {intermediate}"))


# ── (a7) a member session that `SET ROLE`s to the writer and WRITES ─────────


def test_a_member_session_using_set_role_to_write_is_terminated_by_the_fence(
    admin_url: str, db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """M is a plain member of writer W with no CONNECT grant of its own. Its
    session does `SET ROLE W` and inserts a row into a table W may write BEFORE
    the fence closes — proving the fence terminates a session that is
    actively writing under the writer's identity, not merely one that is
    idle. After the fence, the session's next statement raises, and M cannot
    reconnect."""
    with _writer_role(admin_url) as w:
        member = f"fence_setrole_member_{uuid.uuid4().hex[:10]}"
        schema = f"fence_scratch_{uuid.uuid4().hex[:8]}"
        with _connect(admin_url, autocommit=True) as conn:
            conn.execute(text(f"CREATE ROLE {member} LOGIN NOSUPERUSER NOBYPASSRLS"))
            conn.execute(text(f"GRANT {w} TO {member}"))
            conn.execute(text(f'CREATE SCHEMA "{schema}" AUTHORIZATION {w}'))
            conn.execute(text(f'CREATE TABLE "{schema}".probe (id int)'))
            # app_admin created (and owns) the table; W writes to it by grant.
            # Transferring ownership to W would need app_admin to be a member
            # of W, which the fence rightly refuses as a shared role.
            conn.execute(text(f'GRANT INSERT ON "{schema}".probe TO {w}'))
        try:
            member_engine = create_engine(
                url_for(postgres_url, db, user=member), isolation_level="AUTOCOMMIT"
            )
            member_conn = member_engine.connect()
            try:
                member_conn.execute(text(f"SET ROLE {w}"))
                # `schema` is this test's own uuid-suffixed local name, never
                # caller input; S608's premise (a value of unknown provenance
                # reaching a query) does not hold here.
                member_conn.execute(
                    text(f'INSERT INTO "{schema}".probe VALUES (1)')  # noqa: S608
                )

                with _connect(admin_url, autocommit=True) as conn:
                    proof = fence_writers(
                        conn,
                        database=db,
                        fence_id=FENCE_ID,
                        writer_roles=(w,),
                        session_wait_seconds=SESSION_WAIT_SECONDS,
                    )
                assert member in proof.member_roles

                with pytest.raises(OperationalError):
                    member_conn.execute(text("SELECT 1"))
            finally:
                member_conn.close()
                member_engine.dispose()

            with pytest.raises(OperationalError, match="permission denied"):
                with _connect(url_for(postgres_url, db, user=member)):
                    pass
        finally:
            with _connect(admin_url, autocommit=True) as conn:
                conn.execute(text(f'DROP TABLE IF EXISTS "{schema}".probe'))
                conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
                conn.execute(text(f"REVOKE {w} FROM {member}"))
                conn.execute(text(f"DROP OWNED BY {member}"))
                conn.execute(text(f"DROP ROLE IF EXISTS {member}"))


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
                    fence_id=FENCE_ID,
                    writer_roles=(w,),
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                )
            assert proof.terminated_count >= 1

            with pytest.raises(OperationalError):
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
        # The materialised default, decomposed the same way `fence_writers`
        # and `restore_writers` compare every ACL.
        default_grants = fence_module._current_grants(conn, bare_db)

    probe = f"fence_probe_{uuid.uuid4().hex[:10]}"
    with _writer_role(bare_admin_url) as w:
        with _connect(bare_admin_url, autocommit=True) as conn:
            conn.execute(text(f"CREATE ROLE {probe} LOGIN"))
        try:
            with _connect(bare_admin_url, autocommit=True) as conn:
                proof = fence_writers(
                    conn,
                    database=bare_db,
                    fence_id=FENCE_ID,
                    writer_roles=(w,),
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                )
                # `fence_writers` read the NULL column and materialised the
                # identical default this test computed independently.
                assert proof.prior_grants == default_grants

                probe_while_fenced = conn.execute(
                    text("SELECT has_database_privilege(:r, :d, 'CONNECT')"),
                    {"r": probe, "d": bare_db},
                ).scalar_one()
                assert probe_while_fenced is False

                restore_writers(
                    conn,
                    proof,
                    database=bare_db,
                    expected_fence_id=FENCE_ID,
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                )

                probe_after_restore = conn.execute(
                    text("SELECT has_database_privilege(:r, :d, 'CONNECT')"),
                    {"r": probe, "d": bare_db},
                ).scalar_one()
                assert probe_after_restore is True

                assert fence_module._current_grants(conn, bare_db) == default_grants
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
            prior_grants_before = fence_module._current_grants(conn, db)

            proof = fence_writers(
                conn,
                database=db,
                fence_id=FENCE_ID,
                writer_roles=(w,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )
            assert proof.prior_acl == prior_before
            assert proof.prior_grants == prior_grants_before

            first = restore_writers(
                conn,
                proof,
                database=db,
                expected_fence_id=FENCE_ID,
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )
            assert fence_module._current_grants(conn, db) == prior_grants_before

            # The ACL already matches prior_grants, so a second restore has
            # nothing left to grant — idempotent means "changes nothing",
            # not "re-grants the same roles again".
            second = restore_writers(
                conn,
                proof,
                database=db,
                expected_fence_id=FENCE_ID,
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )
            assert second.roles_restored == ()
            assert first.roles_restored != ()
            assert fence_module._current_grants(conn, db) == prior_grants_before


# ── (e) re-fencing with prior= keeps the ORIGINAL prior ACL ─────────────────


def test_refencing_with_prior_keeps_the_original_prior_acl(
    admin_url: str, db: str
) -> None:
    with _writer_role(admin_url) as w:
        with _connect(admin_url, autocommit=True) as conn:
            first_proof = fence_writers(
                conn,
                database=db,
                fence_id=FENCE_ID,
                writer_roles=(w,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )
            second_proof = fence_writers(
                conn,
                database=db,
                fence_id=FENCE_ID,
                writer_roles=(w,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
                prior=first_proof,
                expected_prior_fence_id=first_proof.fence_id,
            )
            assert second_proof.prior_acl == first_proof.prior_acl
            assert second_proof.prior_grants == first_proof.prior_grants

            restore_writers(
                conn,
                second_proof,
                database=db,
                expected_fence_id=FENCE_ID,
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )
            assert fence_module._current_grants(conn, db) == first_proof.prior_grants


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
                            fence_id=FENCE_ID,
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
            before = fence_module._current_grants(conn, db)
            assert _has_connect(before, "")
            with pytest.raises(FenceRefused) as refused:
                fence_writers(
                    _SkipWriterRevoke(conn, w),  # type: ignore[arg-type]
                    database=db,
                    fence_id=FENCE_ID,
                    writer_roles=(w,),
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                )
            assert refused.value.code == FenceRefusalCode.WRITER_STILL_HAS_CONNECT
            after = fence_module._current_grants(conn, db)
            assert after == before
            assert _has_connect(after, "")
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
                    fence_id=FENCE_ID,
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
                        fence_id=FENCE_ID,
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
                        fence_id=FENCE_ID,
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
                        fence_id=FENCE_ID,
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
                    fence_id=FENCE_ID,
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
                    fence_id=FENCE_ID,
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


# ── (j) a driver error mid-fence is compensated as FENCE_INTERRUPTED ────────


class _RaiseOnWriterRevoke:
    """PUBLIC's own REVOKE goes through for real; the per-writer REVOKE
    raises an `OperationalError`-shaped error, simulating a dropped
    connection or a DB error mid-fence — NOT a `FenceRefused`."""

    def __init__(self, real: Connection, writer: str) -> None:
        self._real = real
        self._writer = writer

    def execute(self, statement: object, *args: object, **kwargs: object) -> object:
        sql = str(statement)
        if sql.startswith("REVOKE CONNECT") and self._writer in sql:
            raise OperationalError("REVOKE CONNECT", {}, Exception("connection lost"))
        return self._real.execute(statement, *args, **kwargs)  # type: ignore[arg-type]

    def __getattr__(self, name: str) -> object:
        return getattr(self._real, name)


def test_a_db_error_mid_fence_is_compensated_as_fence_interrupted(
    admin_url: str, db: str
) -> None:
    with _writer_role(admin_url) as w:
        with _connect(admin_url, autocommit=True) as conn:
            before = fence_module._current_grants(conn, db)
            with pytest.raises(FenceRefused) as refused:
                fence_writers(
                    _RaiseOnWriterRevoke(conn, w),  # type: ignore[arg-type]
                    database=db,
                    fence_id=FENCE_ID,
                    writer_roles=(w,),
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                )
            assert refused.value.code == FenceRefusalCode.FENCE_INTERRUPTED
            assert refused.value.before_acl is not None
            assert isinstance(refused.value.__cause__, OperationalError)
            assert fence_module._current_grants(conn, db) == before


# ── (k) a restore that itself fails raises COMPENSATION_FAILED ─────────────


class _SkipWriterRevokeAndFailGrant:
    """Drops the per-writer REVOKE (producing the original
    `WRITER_STILL_HAS_CONNECT` refusal, exactly like `_SkipWriterRevoke`) AND
    makes every compensating GRANT raise, so the restore itself fails too."""

    def __init__(self, real: Connection, writer: str) -> None:
        self._real = real
        self._writer = writer

    def execute(self, statement: object, *args: object, **kwargs: object) -> object:
        sql = str(statement)
        if sql.startswith("REVOKE CONNECT") and self._writer in sql:
            return None
        if sql.startswith("GRANT CONNECT"):
            raise OperationalError("GRANT CONNECT", {}, Exception("grant failed"))
        return self._real.execute(statement, *args, **kwargs)  # type: ignore[arg-type]

    def __getattr__(self, name: str) -> object:
        return getattr(self._real, name)


def test_a_restore_that_itself_fails_raises_compensation_failed(
    admin_url: str, db: str
) -> None:
    """The database may still be fenced after this — cleaned up by hand in
    the `finally`, exactly what `COMPENSATION_FAILED.before_acl` exists for."""
    with _writer_role(admin_url) as w:
        with _connect(admin_url, autocommit=True) as conn:
            conn.execute(text(f'GRANT CONNECT ON DATABASE "{db}" TO {w}'))
            before = fence_module._current_grants(conn, db)
            try:
                with pytest.raises(FenceRefused) as refused:
                    fence_writers(
                        _SkipWriterRevokeAndFailGrant(conn, w),  # type: ignore[arg-type]
                        database=db,
                        fence_id=FENCE_ID,
                        writer_roles=(w,),
                        session_wait_seconds=SESSION_WAIT_SECONDS,
                    )
                assert refused.value.code == FenceRefusalCode.COMPENSATION_FAILED
                assert refused.value.before_acl is not None
                assert isinstance(refused.value.__cause__, FenceRefused)
                assert (
                    refused.value.__cause__.code
                    == FenceRefusalCode.WRITER_STILL_HAS_CONNECT
                )
            finally:
                # Manual cleanup: the compensating GRANT to PUBLIC never
                # landed, so restore it by hand.
                conn.execute(text(f'GRANT CONNECT ON DATABASE "{db}" TO PUBLIC'))
                assert fence_module._current_grants(conn, db) == before


# ── (l) a non-AUTOCOMMIT connection is refused before any change ───────────


def test_a_non_autocommit_connection_is_refused_before_any_change(
    postgres_url: str, db: str, url_for: Callable[..., str]
) -> None:
    with _connect(url_for(postgres_url, db)) as conn:  # default: NOT autocommit
        before = fence_module._current_grants(conn, db)
        with pytest.raises(FenceRefused) as refused:
            fence_writers(
                conn,
                database=db,
                fence_id=FENCE_ID,
                writer_roles=("app_user",),
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )
        assert refused.value.code == FenceRefusalCode.CONNECTION_NOT_AUTOCOMMIT
        assert fence_module._current_grants(conn, db) == before


# ── (m) a stale `prior=` is refused as PRIOR_MISMATCH ───────────────────────


def test_a_prior_naming_a_different_database_is_refused_as_prior_mismatch(
    admin_url: str, db: str
) -> None:
    stale = FenceProof(
        database=f"not_{db}",
        fence_id=FENCE_ID,
        prior_acl="",
        prior_grants=frozenset(),
        fenced_roles=("app_user",),
        member_roles=(),
        absent_roles=(),
        terminated_count=0,
        fenced_at=datetime.now(UTC),
    )
    with _connect(admin_url, autocommit=True) as conn:
        before = fence_module._current_grants(conn, db)
        with pytest.raises(FenceRefused) as refused:
            fence_writers(
                conn,
                database=db,
                fence_id=FENCE_ID,
                writer_roles=("app_user",),
                session_wait_seconds=SESSION_WAIT_SECONDS,
                prior=stale,
                expected_prior_fence_id=stale.fence_id,
            )
        assert refused.value.code == FenceRefusalCode.PRIOR_MISMATCH
        assert fence_module._current_grants(conn, db) == before


def test_a_prior_naming_a_different_writer_set_is_refused_as_prior_mismatch(
    admin_url: str, db: str
) -> None:
    with _writer_role(admin_url) as w1, _writer_role(admin_url) as w2:
        stale = FenceProof(
            database=db,
            fence_id=FENCE_ID,
            prior_acl="",
            prior_grants=frozenset(),
            fenced_roles=(w2,),
            member_roles=(),
            absent_roles=(),
            terminated_count=0,
            fenced_at=datetime.now(UTC),
        )
        with _connect(admin_url, autocommit=True) as conn:
            before = fence_module._current_grants(conn, db)
            with pytest.raises(FenceRefused) as refused:
                fence_writers(
                    conn,
                    database=db,
                    fence_id=FENCE_ID,
                    writer_roles=(w1,),
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                    prior=stale,
                    expected_prior_fence_id=stale.fence_id,
                )
            assert refused.value.code == FenceRefusalCode.PRIOR_MISMATCH
            assert fence_module._current_grants(conn, db) == before


# ── (m1) fence_writers' own required binding: expected_prior_fence_id ──────


def test_prior_without_expected_prior_fence_id_is_refused_before_any_change(
    admin_url: str, db: str
) -> None:
    """`prior=` without `expected_prior_fence_id` is refused before any
    other prior check runs — the identical out-of-band binding
    `restore_writers` requires for `expected_fence_id`, applied to the
    OTHER place this module accepts an in-process `FenceProof`."""
    with _writer_role(admin_url) as w:
        with _connect(admin_url, autocommit=True) as conn:
            first_proof = fence_writers(
                conn,
                database=db,
                fence_id=FENCE_ID,
                writer_roles=(w,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )
            before = fence_module._current_grants(conn, db)
            with pytest.raises(FenceRefused) as refused:
                fence_writers(
                    conn,
                    database=db,
                    fence_id=FENCE_ID,
                    writer_roles=(w,),
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                    prior=first_proof,
                    # expected_prior_fence_id omitted (defaults to None).
                )
            assert refused.value.code == FenceRefusalCode.PROOF_MISMATCH
            assert fence_module._current_grants(conn, db) == before

            restore_writers(
                conn,
                first_proof,
                database=db,
                expected_fence_id=FENCE_ID,
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )


def test_a_mismatched_expected_prior_fence_id_is_refused_before_any_change(
    admin_url: str, db: str
) -> None:
    """A caller that names the WRONG run — `expected_prior_fence_id` does
    not equal the given `prior.fence_id` — is refused `PROOF_MISMATCH`
    before any change, exactly as `restore_writers` refuses a mismatched
    `expected_fence_id`. This is the replay this binding exists to stop: a
    stale or misdirected `prior` proof passed to a re-fence the caller
    thinks is for a different run."""
    with _writer_role(admin_url) as w:
        with _connect(admin_url, autocommit=True) as conn:
            first_proof = fence_writers(
                conn,
                database=db,
                fence_id=FENCE_ID,
                writer_roles=(w,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )
            before = fence_module._current_grants(conn, db)
            with pytest.raises(FenceRefused) as refused:
                fence_writers(
                    conn,
                    database=db,
                    fence_id=FENCE_ID,
                    writer_roles=(w,),
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                    prior=first_proof,
                    expected_prior_fence_id="a-different-run-entirely",
                )
            assert refused.value.code == FenceRefusalCode.PROOF_MISMATCH
            assert fence_module._current_grants(conn, db) == before

            restore_writers(
                conn,
                first_proof,
                database=db,
                expected_fence_id=FENCE_ID,
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )


def test_expected_prior_fence_id_without_prior_is_refused_before_any_change(
    admin_url: str, db: str
) -> None:
    """A caller that states it is re-fencing (`expected_prior_fence_id`) but
    drops `prior=` would otherwise record the current ACL as "prior". It is
    refused `PROOF_MISMATCH` before any change: the ACL is untouched and
    PUBLIC keeps CONNECT. Removing the guard would let the fence proceed and
    revoke PUBLIC, failing both assertions."""
    with _writer_role(admin_url) as w:
        with _connect(admin_url, autocommit=True) as conn:
            before = fence_module._current_grants(conn, db)
            with pytest.raises(FenceRefused) as refused:
                fence_writers(
                    conn,
                    database=db,
                    fence_id=FENCE_ID,
                    writer_roles=(w,),
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                    expected_prior_fence_id="a-prior-run",
                )
            assert refused.value.code == FenceRefusalCode.PROOF_MISMATCH
            assert "without prior=" in str(refused.value)
            assert fence_module._current_grants(conn, db) == before


# ── (m2) restore's two required bindings: database and fence_id ────────────


class _NoQueryAllowed:
    """A connection proxy that fails any `execute()` call — proves a refusal
    happens before ANY query, not merely before a specific one. `conn` is
    forwarded for attribute access (`_require_autocommit` only reads
    `conn.connection.dbapi_connection.autocommit`, never queries it) so a
    real fenced database can back this proof without this proxy ever letting
    a query reach the server."""

    def __init__(self, real: Connection) -> None:
        self._real = real
        self.connection = real.connection

    def execute(self, *args: object, **kwargs: object) -> object:
        raise AssertionError(
            "no query should run before the database/fence_id binding check"
        )


def test_restore_refuses_a_database_mismatch_before_any_query(
    admin_url: str, db: str
) -> None:
    with _writer_role(admin_url) as w:
        with _connect(admin_url, autocommit=True) as conn:
            proof = fence_writers(
                conn,
                database=db,
                fence_id=FENCE_ID,
                writer_roles=(w,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )
            proxy = _NoQueryAllowed(conn)
            with pytest.raises(FenceRefused) as refused:
                restore_writers(
                    proxy,  # type: ignore[arg-type]
                    proof,
                    database=f"not_{db}",
                    expected_fence_id=FENCE_ID,
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                )
            assert refused.value.code == FenceRefusalCode.PROOF_MISMATCH

            # The real fence is untouched: no query ever reached it.
            restore_writers(
                conn,
                proof,
                database=db,
                expected_fence_id=FENCE_ID,
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )


def test_restore_refuses_a_replayed_proof_whose_fence_id_differs(
    admin_url: str, db: str
) -> None:
    """A proof from a superseded fencing run against the SAME database must
    not be accepted by a restore completing a DIFFERENT run — the replay this
    binding exists to catch."""
    with _writer_role(admin_url) as w:
        with _connect(admin_url, autocommit=True) as conn:
            proof = fence_writers(
                conn,
                database=db,
                fence_id=FENCE_ID,
                writer_roles=(w,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )
            with pytest.raises(FenceRefused) as refused:
                restore_writers(
                    conn,
                    proof,
                    database=db,
                    expected_fence_id="a-different-run",
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                )
            assert refused.value.code == FenceRefusalCode.PROOF_MISMATCH
            # Nothing was granted: still fully fenced.
            grants = fence_module._current_grants(conn, db)
            assert not _has_connect(grants, "")
            assert not _has_connect(grants, w)

            restore_writers(
                conn,
                proof,
                database=db,
                expected_fence_id=FENCE_ID,
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )


# ── (n) a quoted grantee fences and restores exactly ────────────────────────


def test_a_quoted_grantee_fences_and_restores_exactly(admin_url: str, db: str) -> None:
    """A writer role named with a capital letter and a space needs real
    identifier quoting — this proves `aclexplode`-based comparison (not
    naive text splitting on `,`/`=`/`/`) handles it."""
    role = "Fence Writer X"
    with _connect(admin_url, autocommit=True) as conn:
        conn.execute(text(f'CREATE ROLE "{role}" LOGIN NOSUPERUSER NOBYPASSRLS'))
    try:
        with _connect(admin_url, autocommit=True) as conn:
            before = fence_module._current_grants(conn, db)
            proof = fence_writers(
                conn,
                database=db,
                fence_id=FENCE_ID,
                writer_roles=(role,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )
            fenced_can_connect = conn.execute(
                text("SELECT has_database_privilege(:r, :d, 'CONNECT')"),
                {"r": role, "d": db},
            ).scalar_one()
            assert fenced_can_connect is False

            restore_writers(
                conn,
                proof,
                database=db,
                expected_fence_id=FENCE_ID,
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )
            assert fence_module._current_grants(conn, db) == before
    finally:
        with _connect(admin_url, autocommit=True) as conn:
            conn.execute(text(f'DROP OWNED BY "{role}"'))
            conn.execute(text(f'DROP ROLE IF EXISTS "{role}"'))


# ── (o) a grant option is restored with the grant option ────────────────────


def test_a_writer_with_grant_option_restores_with_the_grant_option(
    admin_url: str, db: str
) -> None:
    with _writer_role(admin_url) as w:
        with _connect(admin_url, autocommit=True) as conn:
            conn.execute(
                text(f'GRANT CONNECT ON DATABASE "{db}" TO {w} WITH GRANT OPTION')
            )
            before = fence_module._current_grants(conn, db)
            assert any(
                grantee == w and priv == "CONNECT" and grantable
                for grantee, priv, grantable, _grantor in before
            )

            proof = fence_writers(
                conn,
                database=db,
                fence_id=FENCE_ID,
                writer_roles=(w,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )
            restore_writers(
                conn,
                proof,
                database=db,
                expected_fence_id=FENCE_ID,
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )

            after = fence_module._current_grants(conn, db)
            assert after == before
            assert any(
                grantee == w and priv == "CONNECT" and grantable
                for grantee, priv, grantable, _grantor in after
            )


# ── (p) restore refuses an ACL that gained an unexpected extra grant ───────


def test_restore_refuses_an_unexpected_extra_grant_and_stays_fenced(
    admin_url: str, db: str
) -> None:
    with _writer_role(admin_url) as w, _writer_role(admin_url) as intruder:
        with _connect(admin_url, autocommit=True) as conn:
            proof = fence_writers(
                conn,
                database=db,
                fence_id=FENCE_ID,
                writer_roles=(w,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )
            # Something grants CONNECT to an unrelated role while fenced.
            conn.execute(text(f'GRANT CONNECT ON DATABASE "{db}" TO {intruder}'))

            with pytest.raises(FenceRefused) as refused:
                restore_writers(
                    conn,
                    proof,
                    database=db,
                    expected_fence_id=FENCE_ID,
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                )
            assert refused.value.code == FenceRefusalCode.ACL_NOT_RESTORED
            # Still fenced: PUBLIC was never re-granted by the refused restore.
            assert not _has_connect(fence_module._current_grants(conn, db), "")

            conn.execute(text(f'REVOKE CONNECT ON DATABASE "{db}" FROM {intruder}'))
            restore_writers(
                conn,
                proof,
                database=db,
                expected_fence_id=FENCE_ID,
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )


def test_restore_refuses_a_disallowed_grantee_before_regranting_public(
    admin_url: str, db: str
) -> None:
    """`bystander` was never a named writer or a member of one, so it is not
    in the effective set. It held CONNECT in the prior ACL and lost it while
    fenced (an operator revoked it by hand). The entry `restore_writers`
    would need to GRANT to put it back is therefore not a CONNECT grant to
    `{"", *effective}` — the `to_add` bound (computed, and checked, BEFORE
    `missing` or the GRANT loop even exist) refuses `PROOF_MISMATCH` before
    any GRANT is attempted at all. This is a strictly stronger guarantee than
    an older shape of this test once expected (`ACL_NOT_RESTORED` after
    PUBLIC was already re-granted and the loop failed on `bystander`
    mid-way): PUBLIC is never even reopened here."""
    with _writer_role(admin_url) as w, _writer_role(admin_url) as bystander:
        with _connect(admin_url, autocommit=True) as conn:
            conn.execute(text(f'GRANT CONNECT ON DATABASE "{db}" TO {bystander}'))
            proof = fence_writers(
                conn,
                database=db,
                fence_id=FENCE_ID,
                writer_roles=(w,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )
            # An operator revokes the bystander's CONNECT by hand while fenced.
            conn.execute(text(f'REVOKE CONNECT ON DATABASE "{db}" FROM {bystander}'))

            with pytest.raises(FenceRefused) as refused:
                restore_writers(
                    conn,
                    proof,
                    database=db,
                    expected_fence_id=FENCE_ID,
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                )
            assert refused.value.code == FenceRefusalCode.PROOF_MISMATCH
            # Still fenced: PUBLIC was never re-granted, and neither was w.
            grants = fence_module._current_grants(conn, db)
            assert not _has_connect(grants, "")
            assert not _has_connect(grants, w)

            conn.execute(text(f'GRANT CONNECT ON DATABASE "{db}" TO {bystander}'))
            restore_writers(
                conn,
                proof,
                database=db,
                expected_fence_id=FENCE_ID,
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )
            conn.execute(text(f'REVOKE CONNECT ON DATABASE "{db}" FROM {bystander}'))


# ── (q) a drain that never reaches zero survives and is compensated ────────


class _AlwaysWriterPresent:
    """The writer-backend query always reports one survivor and every
    `pg_terminate_backend` call is a no-op, so the drain can never confirm
    zero — proving `WRITER_SESSIONS_SURVIVED` fires at the deadline and the
    compensating restore runs."""

    def __init__(self, real: Connection) -> None:
        self._real = real

    def execute(self, statement: object, *args: object, **kwargs: object) -> object:
        sql = str(statement)
        if sql.startswith("SELECT pid FROM pg_stat_activity"):
            return _FakePidRows([999999999])
        if sql.startswith("SELECT pg_terminate_backend"):
            return None
        return self._real.execute(statement, *args, **kwargs)  # type: ignore[arg-type]

    def __getattr__(self, name: str) -> object:
        return getattr(self._real, name)


class _FakePidRows:
    def __init__(self, pids: list[int]) -> None:
        self._pids = pids

    def scalars(self) -> _FakePidRows:
        return self

    def all(self) -> list[int]:
        return list(self._pids)


def test_a_drain_that_never_reaches_zero_survives_and_is_compensated(
    admin_url: str, db: str
) -> None:
    with _writer_role(admin_url) as w:
        with _connect(admin_url, autocommit=True) as conn:
            before = fence_module._current_grants(conn, db)
            with pytest.raises(FenceRefused) as refused:
                fence_writers(
                    _AlwaysWriterPresent(conn),  # type: ignore[arg-type]
                    database=db,
                    fence_id=FENCE_ID,
                    writer_roles=(w,),
                    session_wait_seconds=0.3,
                )
            assert refused.value.code == FenceRefusalCode.WRITER_SESSIONS_SURVIVED
            assert refused.value.before_acl is not None
            assert fence_module._current_grants(conn, db) == before


# ── (r) a restore that reopens, a writer reconnects, then it mismatches ────


class _SkipOneGrantReconnectTheOther:
    """Drops the GRANT for `skip_role` (so the final restore verification
    genuinely mismatches proof.prior_grants), and — right after the REAL
    GRANT for `reconnect_role` lands — opens a second connection as
    `reconnect_role`, simulating a writer that reconnects during the window
    the ACL was genuinely reopened, before the final mismatch is caught."""

    def __init__(
        self,
        real: Connection,
        *,
        skip_role: str,
        reconnect_role: str,
        reconnect_url: str,
        reconnected: list[Connection],
    ) -> None:
        self._real = real
        self._skip_role = skip_role
        self._reconnect_role = reconnect_role
        self._reconnect_url = reconnect_url
        self._reconnected = reconnected

    def execute(self, statement: object, *args: object, **kwargs: object) -> object:
        sql = str(statement)
        if sql.startswith("GRANT CONNECT") and self._skip_role in sql:
            return None
        result = self._real.execute(statement, *args, **kwargs)  # type: ignore[arg-type]
        if sql.startswith("GRANT CONNECT") and self._reconnect_role in sql:
            engine = create_engine(self._reconnect_url)
            self._reconnected.append(engine.connect())
        return result

    def __getattr__(self, name: str) -> object:
        return getattr(self._real, name)


def test_a_restore_that_reopens_and_then_mismatches_redrains_before_reporting(
    admin_url: str, db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """COMPENSATION for restore itself. The final verification mismatches
    (w2's GRANT was dropped), but w1's GRANT landed for real and a second
    connection reconnects as w1 during that reopen window. `restore_writers`
    must not report `ACL_NOT_RESTORED` without re-proving the database holds
    no open writer sessions: the re-drain terminates w1's reconnected session,
    and only then is the mismatch reported."""
    with _writer_role(admin_url) as w1, _writer_role(admin_url) as w2:
        with _connect(admin_url, autocommit=True) as conn:
            # Each writer needs its OWN CONNECT grant in the prior ACL, so the
            # restore has a per-writer GRANT for the proxy to drop (w2) and to
            # react to (w1). Writers relying on PUBLIC alone would leave
            # restore only PUBLIC to re-grant, and nothing would mismatch.
            conn.execute(text(f'GRANT CONNECT ON DATABASE "{db}" TO {w1}'))
            conn.execute(text(f'GRANT CONNECT ON DATABASE "{db}" TO {w2}'))
            proof = fence_writers(
                conn,
                database=db,
                fence_id=FENCE_ID,
                writer_roles=(w1, w2),
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )

            reconnected: list[Connection] = []
            proxy = _SkipOneGrantReconnectTheOther(
                conn,
                skip_role=w2,
                reconnect_role=w1,
                reconnect_url=url_for(postgres_url, db, user=w1),
                reconnected=reconnected,
            )
            with pytest.raises(FenceRefused) as refused:
                restore_writers(
                    proxy,  # type: ignore[arg-type]
                    proof,
                    database=db,
                    expected_fence_id=FENCE_ID,
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                )
            assert refused.value.code == FenceRefusalCode.ACL_NOT_RESTORED
            assert len(reconnected) == 1

            # The writer that reconnected during the reopen window was
            # terminated by the re-drain...
            with pytest.raises(OperationalError):
                reconnected[0].execute(text("SELECT 1"))
            reconnected[0].close()

            # ...and cannot reconnect: the re-fence revoked it again.
            with pytest.raises(OperationalError, match="permission denied"):
                with _connect(url_for(postgres_url, db, user=w1)):
                    pass

            # The database is still fully fenced (both w1 and w2, plus
            # PUBLIC) — restore it for real so fixture teardown can drop the
            # roles.
            restore_writers(
                conn,
                proof,
                database=db,
                expected_fence_id=FENCE_ID,
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )


# ── (r2) the re-fence after a failed restore is ground truth, not `restored`


class _GrantLandsThenRaises:
    """The GRANT for `writer` reaches the server for real, then this raises
    `exc_factory()` — simulating an interruption AFTER the GRANT lands but
    BEFORE `restore_writers`'s own loop reaches `restored.append(...)`, so
    the re-fence cannot rely on that Python list naming `writer`."""

    def __init__(
        self, real: Connection, writer: str, exc_factory: Callable[[], BaseException]
    ) -> None:
        self._real = real
        self._writer = writer
        self._exc_factory = exc_factory

    def execute(self, statement: object, *args: object, **kwargs: object) -> object:
        sql = str(statement)
        if sql.startswith("GRANT CONNECT") and self._writer in sql:
            self._real.execute(statement, *args, **kwargs)  # type: ignore[arg-type]
            raise self._exc_factory()
        return self._real.execute(statement, *args, **kwargs)  # type: ignore[arg-type]

    def __getattr__(self, name: str) -> object:
        return getattr(self._real, name)


def test_a_keyboardinterrupt_mid_restore_propagates_and_the_writer_stays_fenced(
    admin_url: str, db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """The GRANT for W reaches the server, then `KeyboardInterrupt` is raised
    BEFORE `restore_writers`'s loop records it in `restored`. The re-fence
    must revoke W anyway (ground truth from the proof's effective set, not
    the incomplete `restored` list), and `KeyboardInterrupt` itself must
    propagate — never wrapped."""
    with _writer_role(admin_url) as w:
        with _connect(admin_url, autocommit=True) as conn:
            conn.execute(text(f'GRANT CONNECT ON DATABASE "{db}" TO {w}'))
            proof = fence_writers(
                conn,
                database=db,
                fence_id=FENCE_ID,
                writer_roles=(w,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )

            proxy = _GrantLandsThenRaises(conn, w, KeyboardInterrupt)
            with pytest.raises(KeyboardInterrupt):
                restore_writers(
                    proxy,  # type: ignore[arg-type]
                    proof,
                    database=db,
                    expected_fence_id=FENCE_ID,
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                )

            still_connect = conn.execute(
                text("SELECT has_database_privilege(:r, :d, 'CONNECT')"),
                {"r": w, "d": db},
            ).scalar_one()
            assert still_connect is False

            with pytest.raises(OperationalError, match="permission denied"):
                with _connect(url_for(postgres_url, db, user=w)):
                    pass


def test_an_operationalerror_mid_restore_stays_fenced_via_the_ground_truth_refence(
    admin_url: str, db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """Same shape as the `KeyboardInterrupt` case above, but with an
    `OperationalError` instead: this is not re-raised bare, but the fence
    must still hold afterwards."""
    with _writer_role(admin_url) as w:
        with _connect(admin_url, autocommit=True) as conn:
            conn.execute(text(f'GRANT CONNECT ON DATABASE "{db}" TO {w}'))
            proof = fence_writers(
                conn,
                database=db,
                fence_id=FENCE_ID,
                writer_roles=(w,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )

            proxy = _GrantLandsThenRaises(
                conn,
                w,
                lambda: OperationalError(
                    "GRANT CONNECT", {}, Exception("connection lost")
                ),
            )
            with pytest.raises(FenceRefused) as refused:
                restore_writers(
                    proxy,  # type: ignore[arg-type]
                    proof,
                    database=db,
                    expected_fence_id=FENCE_ID,
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                )
            assert refused.value.code in (
                FenceRefusalCode.ACL_NOT_RESTORED,
                FenceRefusalCode.WRITER_SESSIONS_SURVIVED,
            )

            still_connect = conn.execute(
                text("SELECT has_database_privilege(:r, :d, 'CONNECT')"),
                {"r": w, "d": db},
            ).scalar_one()
            assert still_connect is False

            with pytest.raises(OperationalError, match="permission denied"):
                with _connect(url_for(postgres_url, db, user=w)):
                    pass


# ── (s) a grant with a DISTINCT grantor is refused before any change ───────


def test_a_grant_with_a_distinct_grantor_is_refused_before_any_change(
    admin_url: str, db: str
) -> None:
    """G holds CONNECT WITH GRANT OPTION granted by the owner, then GRANTs
    CONNECT to writer W as ITSELF (`SET ROLE G`) — so W's CONNECT grant is
    recorded with grantor G, not the database owner. An owner/superuser
    REVOKE cannot remove a grant made by another grantor, so this must be
    refused before any change, and the ACL — grantor included — must stay
    byte-identical."""
    role_g = f"fence_grantor_{uuid.uuid4().hex[:10]}"
    with _writer_role(admin_url) as w:
        with _connect(admin_url, autocommit=True) as conn:
            conn.execute(text(f"CREATE ROLE {role_g} NOLOGIN"))
            conn.execute(
                text(f'GRANT CONNECT ON DATABASE "{db}" TO {role_g} WITH GRANT OPTION')
            )
            conn.execute(text(f"SET ROLE {role_g}"))
            conn.execute(text(f'GRANT CONNECT ON DATABASE "{db}" TO {w}'))
            conn.execute(text("RESET ROLE"))
        try:
            with _connect(admin_url, autocommit=True) as conn:
                prior_grants = fence_module._current_grants(conn, db)
                w_grant = next(
                    g for g in prior_grants if g[0] == w and g[1] == "CONNECT"
                )
                # Direct assertion on the grantor rolname: G, not the owner.
                assert w_grant[3] == role_g

                with pytest.raises(FenceRefused) as refused:
                    fence_writers(
                        conn,
                        database=db,
                        fence_id=FENCE_ID,
                        writer_roles=(w,),
                        session_wait_seconds=SESSION_WAIT_SECONDS,
                    )
                assert refused.value.code == FenceRefusalCode.GRANT_NOT_OWNER_GRANTED
                # The ACL, grantor included, is untouched by the refusal.
                assert fence_module._current_grants(conn, db) == prior_grants
        finally:
            with _connect(admin_url, autocommit=True) as conn:
                # CASCADE is required, and is itself the proof of the rule:
                # the owner's REVOKE ... FROM w does not remove G's grant to w,
                # so revoking G's grant option must cascade to it.
                conn.execute(
                    text(f'REVOKE CONNECT ON DATABASE "{db}" FROM {role_g} CASCADE')
                )
                conn.execute(text(f'REVOKE CONNECT ON DATABASE "{db}" FROM {w}'))
                conn.execute(text(f"DROP ROLE IF EXISTS {role_g}"))


# ── (t) a superuser GRANT is recorded, and restored, with the owner as grantor


def test_a_superuser_grant_is_recorded_with_the_owner_as_grantor(
    postgres_url: str, bare_db: str, url_for: Callable[..., str]
) -> None:
    """The normal path: fencing with the superuser connection (`postgres_url`)
    over a database owned by `app_admin`. Proves a superuser GRANT is
    recorded with the owner as grantor, and that `restore_writers` reproduces
    the full 4-tuple — grantor included — exactly."""
    bare_admin_url = url_for(postgres_url, bare_db)
    with _writer_role(bare_admin_url) as w:
        with _connect(bare_admin_url, autocommit=True) as conn:
            conn.execute(text(f'GRANT CONNECT ON DATABASE "{bare_db}" TO {w}'))
            prior_grants = fence_module._current_grants(conn, bare_db)
            w_grant = next(g for g in prior_grants if g[0] == w and g[1] == "CONNECT")
            # Direct assertion on the grantor rolname: the owner, app_admin —
            # not the superuser identity that actually executed the GRANT.
            assert w_grant[3] == MIGRATION_ROLE

            proof = fence_writers(
                conn,
                database=bare_db,
                fence_id=FENCE_ID,
                writer_roles=(w,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )
            restore_writers(
                conn,
                proof,
                database=bare_db,
                expected_fence_id=FENCE_ID,
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )

            after = fence_module._current_grants(conn, bare_db)
            assert after == prior_grants
            after_w_grant = next(g for g in after if g[0] == w and g[1] == "CONNECT")
            assert after_w_grant[3] == MIGRATION_ROLE


def test_an_ungranted_superuser_is_not_a_member_of_every_writer(
    admin_url: str, db: str, postgres_url: str
) -> None:
    """`pg_has_role` says every superuser is a member of every role; the
    effective set follows explicit grants only. A superuser that was never
    granted the writer role is NOT pulled into the fence, so a normal fence
    over a cluster that has superusers succeeds."""
    superuser = f"fence_bystander_super_{uuid.uuid4().hex[:8]}"
    with _connect(postgres_url, autocommit=True) as conn:
        conn.execute(text(f"CREATE ROLE {superuser} LOGIN SUPERUSER"))
    try:
        with _writer_role(admin_url) as w:
            with _connect(admin_url, autocommit=True) as conn:
                proof = fence_writers(
                    conn,
                    database=db,
                    fence_id=FENCE_ID,
                    writer_roles=(w,),
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                )
                assert superuser not in proof.member_roles
                assert "postgres" not in proof.member_roles
                restore_writers(
                    conn,
                    proof,
                    database=db,
                    expected_fence_id=FENCE_ID,
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                )
    finally:
        with _connect(postgres_url, autocommit=True) as conn:
            conn.execute(text(f"DROP ROLE IF EXISTS {superuser}"))


# ── (u) fence_is_holding really answers "is the fence holding, right now" ──


def test_fence_is_holding_returns_true_after_a_normal_fence(
    admin_url: str, db: str
) -> None:
    with _writer_role(admin_url) as w:
        with _connect(admin_url, autocommit=True) as conn:
            proof = fence_writers(
                conn,
                database=db,
                fence_id=FENCE_ID,
                writer_roles=(w,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )
            assert fence_is_holding(conn, proof) is True
            restore_writers(
                conn,
                proof,
                database=db,
                expected_fence_id=FENCE_ID,
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )


def test_fence_is_holding_returns_false_when_a_member_is_regranted_connect(
    admin_url: str, db: str
) -> None:
    """M is a member of writer W and separately held its own CONNECT grant
    before the fence. A superuser re-grants CONNECT to M mid-fence, and the
    resulting (grantee, priv, grantable, grantor) tuple is IDENTICAL to the
    one the prior ACL held (both recorded with the owner as grantor) — a
    comparison against `prior_grants` alone could not distinguish this from
    "restored". `fence_is_holding` must catch it directly via
    `has_database_privilege`, not by comparing ACLs."""
    with _writer_role(admin_url) as w:
        member = f"fence_member_{uuid.uuid4().hex[:10]}"
        with _connect(admin_url, autocommit=True) as conn:
            conn.execute(text(f"CREATE ROLE {member} LOGIN NOSUPERUSER NOBYPASSRLS"))
            conn.execute(text(f"GRANT {w} TO {member}"))
            conn.execute(text(f'GRANT CONNECT ON DATABASE "{db}" TO {member}'))
        try:
            with _connect(admin_url, autocommit=True) as conn:
                proof = fence_writers(
                    conn,
                    database=db,
                    fence_id=FENCE_ID,
                    writer_roles=(w,),
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                )
                assert member in proof.member_roles
                assert fence_is_holding(conn, proof) is True

                conn.execute(text(f'GRANT CONNECT ON DATABASE "{db}" TO {member}'))
                assert fence_is_holding(conn, proof) is False

                conn.execute(text(f'REVOKE CONNECT ON DATABASE "{db}" FROM {member}'))
                assert fence_is_holding(conn, proof) is True
                restore_writers(
                    conn,
                    proof,
                    database=db,
                    expected_fence_id=FENCE_ID,
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                )
        finally:
            with _connect(admin_url, autocommit=True) as conn:
                conn.execute(text(f'REVOKE CONNECT ON DATABASE "{db}" FROM {member}'))
                conn.execute(text(f"REVOKE {w} FROM {member}"))
                conn.execute(text(f"DROP OWNED BY {member}"))
                conn.execute(text(f"DROP ROLE IF EXISTS {member}"))


def test_fence_is_holding_returns_false_when_a_new_member_is_granted_mid_fence(
    admin_url: str, db: str
) -> None:
    """A role granted membership in W AFTER the fence closed holds no CONNECT
    of its own (so the plain `has_database_privilege` checks see nothing),
    but it IS now a member of a fenced writer — `_member_roles` re-derived
    right now must disagree with `proof.member_roles` and fail the check."""
    with _writer_role(admin_url) as w:
        with _connect(admin_url, autocommit=True) as conn:
            proof = fence_writers(
                conn,
                database=db,
                fence_id=FENCE_ID,
                writer_roles=(w,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )
            assert fence_is_holding(conn, proof) is True

            new_member = f"fence_new_member_{uuid.uuid4().hex[:10]}"
            conn.execute(
                text(f"CREATE ROLE {new_member} LOGIN NOSUPERUSER NOBYPASSRLS")
            )
            conn.execute(text(f"GRANT {w} TO {new_member}"))
            try:
                assert fence_is_holding(conn, proof) is False
            finally:
                conn.execute(text(f"REVOKE {w} FROM {new_member}"))
                conn.execute(text(f"DROP OWNED BY {new_member}"))
                conn.execute(text(f"DROP ROLE IF EXISTS {new_member}"))

            assert fence_is_holding(conn, proof) is True
            restore_writers(
                conn,
                proof,
                database=db,
                expected_fence_id=FENCE_ID,
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )


def test_fence_is_holding_returns_false_when_a_writer_backend_is_open(
    admin_url: str, db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """CONNECT stays revoked throughout, so the privilege checks alone would
    see nothing wrong; an open writer backend must still fail the check."""
    with _writer_role(admin_url) as w:
        with _connect(admin_url, autocommit=True) as conn:
            proof = fence_writers(
                conn,
                database=db,
                fence_id=FENCE_ID,
                writer_roles=(w,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )
            assert fence_is_holding(conn, proof) is True

            conn.execute(text(f'GRANT CONNECT ON DATABASE "{db}" TO PUBLIC'))
            writer_engine = create_engine(url_for(postgres_url, db, user=w))
            writer_conn = writer_engine.connect()
            try:
                assert writer_conn.execute(text("SELECT 1")).scalar_one() == 1
                conn.execute(text(f'REVOKE CONNECT ON DATABASE "{db}" FROM PUBLIC'))

                assert fence_is_holding(conn, proof) is False
            finally:
                writer_conn.close()
                writer_engine.dispose()

            assert fence_is_holding(conn, proof) is True
            restore_writers(
                conn,
                proof,
                database=db,
                expected_fence_id=FENCE_ID,
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )


# ── (v) NON-SUPERUSER OWNER: the ACL work needs no superuser privilege ──────
#
# D1 fence topology (decided 2026-09-28): the ACL work — REVOKE/GRANT
# CONNECT, aclexplode, pg_auth_members, has_database_privilege,
# pg_stat_activity reads — runs as the database OWNER, needing no new
# privilege. Only backend termination needs superuser, and that goes through
# a `terminator` seam a production broker implements over its own socket.
# These tests fence and restore over an OWNER connection that is itself
# NOSUPERUSER, proving the library never actually needs more than ownership
# for anything except signalling a backend.


@pytest.fixture
def owner_role(postgres_url: str) -> Iterator[str]:
    """A NON-SUPERUSER, NOCREATEROLE login role: the shape `app_admin` has in
    production under D1 — ownership, not superuser, is what the ACL work
    needs."""
    role = f"fence_owner_{uuid.uuid4().hex[:10]}"
    with _connect(postgres_url, autocommit=True) as conn:
        conn.execute(text(f"CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEROLE"))
    try:
        yield role
    finally:
        with _connect(postgres_url, autocommit=True) as conn:
            conn.execute(text(f"DROP OWNED BY {role}"))
            conn.execute(text(f"DROP ROLE IF EXISTS {role}"))


@pytest.fixture
def owner_db(
    postgres_url: str, owner_role: str, url_for: Callable[..., str]
) -> Iterator[str]:
    """A scratch database OWNED BY `owner_role`. `datacl` starts NULL at
    creation (so its ACL is the materialised default,
    `acldefault('d', owner_role)`, which — per PostgreSQL's own `acldefault`
    — already includes an explicit owner-granted entry for `owner_role`
    itself alongside PUBLIC's CONNECT/TEMPORARY), then becomes non-NULL the
    moment this fixture GRANTs `MIGRATION_ROLE` its own explicit CONNECT
    (executed BY the owner, so recorded with `owner_role` as grantor — the
    same "grantor is the owner" shape `_reject_grants_not_owner_granted`
    requires, and the reason `_require_migration_connect_without_public`
    passes: `MIGRATION_ROLE` is trivially a member of itself). The database
    is dropped at teardown."""
    name = f"vcp_fence_nonsuper_{uuid.uuid4().hex[:12]}"
    with _connect(postgres_url, autocommit=True) as conn:
        conn.execute(text(f'CREATE DATABASE "{name}" OWNER {owner_role}'))
    owner_url_for_grant = url_for(postgres_url, name, user=owner_role)
    with _connect(owner_url_for_grant, autocommit=True) as conn:
        conn.execute(text(f'GRANT CONNECT ON DATABASE "{name}" TO {MIGRATION_ROLE}'))
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


@pytest.fixture
def owner_url(
    postgres_url: str, owner_db: str, owner_role: str, url_for: Callable[..., str]
) -> str:
    """The OWNER's own connection URL against `owner_db` — the identity
    `fence_writers`/`restore_writers` are called with in every test below;
    never the cluster superuser."""
    return url_for(postgres_url, owner_db, user=owner_role)


def _superuser_terminator(
    postgres_url: str, database: str, writers: tuple[str, ...]
) -> Callable[[], None]:
    """A test `Terminator` backed by a SEPARATE superuser connection,
    simulating the production broker: it re-derives the writer set itself
    (via the SAME `_writer_pids` query the library uses) and terminates it —
    the fence never passes it a pid or a role name; this closure captures
    `database`/`writers` only because the TEST built it that way, standing in
    for the broker's own server-side derivation."""

    def _terminate() -> None:
        with _connect(postgres_url, autocommit=True) as super_conn:
            for pid in fence_module._writer_pids(super_conn, database, writers):
                super_conn.execute(
                    text("SELECT pg_terminate_backend(:pid)"), {"pid": pid}
                )

    return _terminate


def test_pg_stat_activity_exposes_a_writers_backend_to_the_non_superuser_owner(
    owner_url: str, owner_db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """The whole D1 topology depends on PG exposing `usename`/`datname` in
    `pg_stat_activity` to a non-superuser reader — if it does not, the owner
    can never even SEE a writer backend to know a drain has or hasn't
    converged, and the fence design in this module is unsound. This is
    measured directly, not assumed."""
    with _writer_role(postgres_url) as w:
        writer_engine = create_engine(url_for(postgres_url, owner_db, user=w))
        writer_conn = writer_engine.connect()
        try:
            assert writer_conn.execute(text("SELECT 1")).scalar_one() == 1
            with _connect(owner_url, autocommit=True) as owner_conn:
                visible = fence_module._writer_pids(owner_conn, owner_db, (w,))
            assert visible != [], (
                "PG did not expose the writer's backend to the non-superuser "
                "owner via pg_stat_activity — the D1 fence topology requires "
                "this and the design does not hold without it"
            )
        finally:
            writer_conn.close()
            writer_engine.dispose()


def test_owner_only_fence_with_a_superuser_terminator_holds_and_restores_exactly(
    owner_url: str, owner_db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    with _writer_role(postgres_url) as w:
        writer_engine = create_engine(url_for(postgres_url, owner_db, user=w))
        writer_conn = writer_engine.connect()
        try:
            assert writer_conn.execute(text("SELECT 1")).scalar_one() == 1

            with _connect(owner_url, autocommit=True) as owner_conn:
                before = fence_module._current_grants(owner_conn, owner_db)
                proof = fence_writers(
                    owner_conn,
                    database=owner_db,
                    fence_id=FENCE_ID,
                    writer_roles=(w,),
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                    terminator=_superuser_terminator(postgres_url, owner_db, (w,)),
                )
                assert proof.terminated_count >= 1
                assert fence_is_holding(owner_conn, proof) is True

            with pytest.raises(OperationalError):
                writer_conn.execute(text("SELECT 1"))

            with pytest.raises(OperationalError, match="permission denied"):
                with _connect(url_for(postgres_url, owner_db, user=w)):
                    pass

            with _connect(owner_url, autocommit=True) as owner_conn:
                restore_writers(
                    owner_conn,
                    proof,
                    database=owner_db,
                    expected_fence_id=FENCE_ID,
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                )
                after = fence_module._current_grants(owner_conn, owner_db)
                # Grantor-exact: the full 4-tuple, including the OWNER as
                # grantor, is reproduced exactly.
                assert after == before
        finally:
            writer_conn.close()
            writer_engine.dispose()


def test_owner_only_fence_without_a_terminator_cannot_signal_and_compensates(
    owner_url: str, owner_db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """No `terminator` is given, so the default adapter tries
    `pg_terminate_backend` over the OWNER connection itself — a privilege the
    owner does not have over another role's backend. `fence_writers` must
    still fail SAFE: a `FenceRefused` is raised and the ACL is restored to
    exactly its prior state; the writer's already-open session, never
    actually terminated, keeps working, exactly as the module docstring's
    "a backend already connected ... is a separate hazard REVOKE CONNECT
    does not touch" describes for a fence that fails to drain.

    Pinned to `FENCE_INTERRUPTED`: PostgreSQL does not silently ignore an
    unauthorised `pg_terminate_backend` — it raises insufficient-privilege
    on the first call, which the fence compensates as a driver error. A
    `WRITER_SESSIONS_SURVIVED` here would mean the server returned without
    signalling, which is a different failure mode this test must notice."""
    with _writer_role(postgres_url) as w:
        writer_engine = create_engine(url_for(postgres_url, owner_db, user=w))
        writer_conn = writer_engine.connect()
        try:
            assert writer_conn.execute(text("SELECT 1")).scalar_one() == 1

            with _connect(owner_url, autocommit=True) as owner_conn:
                before = fence_module._current_grants(owner_conn, owner_db)
                with pytest.raises(FenceRefused) as refused:
                    fence_writers(
                        owner_conn,
                        database=owner_db,
                        fence_id=FENCE_ID,
                        writer_roles=(w,),
                        session_wait_seconds=SESSION_WAIT_SECONDS,
                    )
                assert refused.value.code is FenceRefusalCode.FENCE_INTERRUPTED
                after = fence_module._current_grants(owner_conn, owner_db)
                assert after == before

            # The writer's session was never actually terminated (the owner
            # could not signal it), so it still works.
            assert writer_conn.execute(text("SELECT 1")).scalar_one() == 1
        finally:
            writer_conn.close()
            writer_engine.dispose()


def test_owner_only_fence_with_a_raising_terminator_compensates(
    owner_url: str, owner_db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """A `terminator` that raises is treated exactly like a failed drain: the
    existing compensation path runs and the original error propagates,
    chained, as `FENCE_INTERRUPTED` — the ACL ends up equal to its prior
    state either way."""

    def _broken_terminator() -> None:
        raise RuntimeError("broker unreachable")

    with _writer_role(postgres_url) as w:
        writer_engine = create_engine(url_for(postgres_url, owner_db, user=w))
        writer_conn = writer_engine.connect()
        try:
            assert writer_conn.execute(text("SELECT 1")).scalar_one() == 1

            with _connect(owner_url, autocommit=True) as owner_conn:
                before = fence_module._current_grants(owner_conn, owner_db)
                with pytest.raises(FenceRefused) as refused:
                    fence_writers(
                        owner_conn,
                        database=owner_db,
                        fence_id=FENCE_ID,
                        writer_roles=(w,),
                        session_wait_seconds=SESSION_WAIT_SECONDS,
                        terminator=_broken_terminator,
                    )
                assert refused.value.code == FenceRefusalCode.FENCE_INTERRUPTED
                # __cause__ is the private _TerminatorFailed wrapper (itself
                # a RuntimeError, which is why a plain isinstance check
                # against RuntimeError alone would pass without actually
                # proving the ORIGINAL exception survived) — its OWN
                # __cause__ must be the exact RuntimeError the terminator
                # raised, chained through, not swallowed.
                wrapper = refused.value.__cause__
                assert type(wrapper).__name__ == "_TerminatorFailed"
                assert isinstance(wrapper.__cause__, RuntimeError)
                assert str(wrapper.__cause__) == "broker unreachable"
                after = fence_module._current_grants(owner_conn, owner_db)
                assert after == before

            assert writer_conn.execute(text("SELECT 1")).scalar_one() == 1
        finally:
            writer_conn.close()
            writer_engine.dispose()


# ── (w) a proof cannot launder a grant: restore_writers bounds live state ──


def test_restore_refuses_a_proof_whose_member_roles_no_longer_matches_live_membership(
    owner_url: str, owner_db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """A proof's `member_roles` is a claim about membership AT FENCE TIME.
    If it no longer matches what `_member_roles` derives from
    `proof.fenced_roles` RIGHT NOW, `restore_writers` must refuse before any
    GRANT — the same "proof vs. live state" discipline `fence_is_holding`
    already applies to a proof it only reads, applied here to one this
    function is about to act on."""
    with _writer_role(postgres_url) as w:
        with _connect(owner_url, autocommit=True) as owner_conn:
            proof = fence_writers(
                owner_conn,
                database=owner_db,
                fence_id=FENCE_ID,
                writer_roles=(w,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
                terminator=_superuser_terminator(postgres_url, owner_db, (w,)),
            )
            # A role granted membership in the fenced writer AFTER the fence
            # closed: live membership now disagrees with what `proof`
            # recorded. The OWNER connection is NOCREATEROLE (see
            # `owner_role`), so this — and its cleanup — runs over a
            # SEPARATE superuser connection.
            new_member = f"fence_new_member_{uuid.uuid4().hex[:10]}"
            try:
                with _connect(postgres_url, autocommit=True) as super_conn:
                    super_conn.execute(
                        text(f"CREATE ROLE {new_member} LOGIN NOSUPERUSER NOBYPASSRLS")
                    )
                    super_conn.execute(text(f"GRANT {w} TO {new_member}"))
                with pytest.raises(FenceRefused) as refused:
                    restore_writers(
                        owner_conn,
                        proof,
                        database=owner_db,
                        expected_fence_id=FENCE_ID,
                        session_wait_seconds=SESSION_WAIT_SECONDS,
                    )
                assert refused.value.code == FenceRefusalCode.PROOF_MISMATCH
                # Nothing was granted: PUBLIC is still fenced.
                public_can_connect = owner_conn.execute(
                    text("SELECT has_database_privilege('public', :db, 'CONNECT')"),
                    {"db": owner_db},
                ).scalar_one()
                assert public_can_connect is False
            finally:
                with _connect(postgres_url, autocommit=True) as super_conn:
                    super_conn.execute(text(f"REVOKE {w} FROM {new_member}"))
                    super_conn.execute(text(f"DROP OWNED BY {new_member}"))
                    super_conn.execute(text(f"DROP ROLE IF EXISTS {new_member}"))
                restore_writers(
                    owner_conn,
                    proof,
                    database=owner_db,
                    expected_fence_id=FENCE_ID,
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                    terminator=_superuser_terminator(postgres_url, owner_db, (w,)),
                )


def test_restore_refuses_a_proof_whose_prior_grants_grantor_is_not_the_current_owner(
    owner_url: str, owner_db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """`FenceProof.from_document` cannot bound a `prior_grants` grantee
    against the owner (its name is not on the document) — this is the live
    backstop `restore_writers` applies instead: a proof recording a grantor
    other than the CURRENT owner is refused before any GRANT."""
    with _writer_role(postgres_url) as w:
        with _connect(owner_url, autocommit=True) as owner_conn:
            proof = fence_writers(
                owner_conn,
                database=owner_db,
                fence_id=FENCE_ID,
                writer_roles=(w,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
                terminator=_superuser_terminator(postgres_url, owner_db, (w,)),
            )
            forged_grants = frozenset(
                {*proof.prior_grants, ("", "TEMPORARY", False, "not_the_owner")}
            )
            forged_proof = dataclasses.replace(proof, prior_grants=forged_grants)

            before = fence_module._current_grants(owner_conn, owner_db)
            with pytest.raises(FenceRefused) as refused:
                restore_writers(
                    owner_conn,
                    forged_proof,
                    database=owner_db,
                    expected_fence_id=FENCE_ID,
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                )
            assert refused.value.code == FenceRefusalCode.PROOF_MISMATCH
            # Nothing was granted: the live ACL is byte-identical to what it
            # was before the refused call, and PUBLIC specifically still
            # lacks CONNECT.
            assert fence_module._current_grants(owner_conn, owner_db) == before
            public_can_connect = owner_conn.execute(
                text("SELECT has_database_privilege('public', :db, 'CONNECT')"),
                {"db": owner_db},
            ).scalar_one()
            assert public_can_connect is False

            # Restore for real with the genuine (unforged) proof so fixture
            # teardown can drop the role.
            restore_writers(
                owner_conn,
                proof,
                database=owner_db,
                expected_fence_id=FENCE_ID,
                session_wait_seconds=SESSION_WAIT_SECONDS,
                terminator=_superuser_terminator(postgres_url, owner_db, (w,)),
            )


def test_restore_refuses_a_grantor_only_mismatch_isolated_from_every_other_bound(
    owner_url: str, owner_db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """Every OTHER condition of the `to_add` bound is satisfied — CONNECT,
    granted to `w`, an actual effective (allowed) grantee, non-grantable —
    and ONLY the grantor is wrong. This isolates the grantor clause from the
    privilege and grantee clauses the other forgery tests exercise together
    with it, proving the grantor check alone still refuses when every other
    check would pass."""
    with _writer_role(postgres_url) as w:
        with _connect(owner_url, autocommit=True) as owner_conn:
            proof = fence_writers(
                owner_conn,
                database=owner_db,
                fence_id=FENCE_ID,
                writer_roles=(w,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
                terminator=_superuser_terminator(postgres_url, owner_db, (w,)),
            )
            forged_entry = (w, "CONNECT", False, "not_the_owner")
            assert forged_entry not in proof.prior_grants
            forged_proof = dataclasses.replace(
                proof, prior_grants=frozenset({*proof.prior_grants, forged_entry})
            )

            before = fence_module._current_grants(owner_conn, owner_db)
            with pytest.raises(FenceRefused) as refused:
                restore_writers(
                    owner_conn,
                    forged_proof,
                    database=owner_db,
                    expected_fence_id=FENCE_ID,
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                )
            assert refused.value.code == FenceRefusalCode.PROOF_MISMATCH
            assert fence_module._current_grants(owner_conn, owner_db) == before

            restore_writers(
                owner_conn,
                proof,
                database=owner_db,
                expected_fence_id=FENCE_ID,
                session_wait_seconds=SESSION_WAIT_SECONDS,
                terminator=_superuser_terminator(postgres_url, owner_db, (w,)),
            )


def test_fence_refuses_a_prior_grantor_only_mismatch_isolated(
    owner_url: str, owner_db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """The identical isolation as
    `test_restore_refuses_a_grantor_only_mismatch_isolated_from_every_other_bound`,
    against `fence_writers`'s `prior=` content bound instead: CONNECT,
    granted to `w`, non-grantable — every clause but the grantor is
    satisfied."""
    with _writer_role(postgres_url) as w:
        with _connect(owner_url, autocommit=True) as owner_conn:
            proof = fence_writers(
                owner_conn,
                database=owner_db,
                fence_id=FENCE_ID,
                writer_roles=(w,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
                terminator=_superuser_terminator(postgres_url, owner_db, (w,)),
            )
            restore_writers(
                owner_conn,
                proof,
                database=owner_db,
                expected_fence_id=FENCE_ID,
                session_wait_seconds=SESSION_WAIT_SECONDS,
                terminator=_superuser_terminator(postgres_url, owner_db, (w,)),
            )
            forged_entry = (w, "CONNECT", False, "not_the_owner")
            assert forged_entry not in proof.prior_grants
            laundered_prior = dataclasses.replace(
                proof,
                fence_id="laundered-grantor-prior",
                prior_grants=frozenset({*proof.prior_grants, forged_entry}),
            )

            before = fence_module._current_grants(owner_conn, owner_db)
            with pytest.raises(FenceRefused) as refused:
                fence_writers(
                    owner_conn,
                    database=owner_db,
                    fence_id=FENCE_ID,
                    writer_roles=(w,),
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                    prior=laundered_prior,
                    expected_prior_fence_id=laundered_prior.fence_id,
                    terminator=_superuser_terminator(postgres_url, owner_db, (w,)),
                )
            assert refused.value.code == FenceRefusalCode.PRIOR_MISMATCH
            assert fence_module._current_grants(owner_conn, owner_db) == before


def test_restore_grants_a_legally_shaped_forged_entry_the_digest_is_what_would_catch(
    owner_url: str, owner_db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """A forged `prior_grants` entry that is STRUCTURALLY indistinguishable
    from a real one — a CONNECT grant to an effective writer role, made by
    the current owner, non-grantable, the exact shape a real prior ACL has —
    passes the `to_add` bound `restore_writers` applies (that bound cannot
    tell "the real prior ACL" from "an in-memory `FenceProof` a caller
    mutated after `fence_writers` returned it": both are owner-granted
    CONNECT to an allowed grantee). `restore_writers` takes a `FenceProof`
    directly, in-process, and performs NO digest check — that defence
    belongs to `FenceProof.from_document`, for a proof that crosses a
    process boundary as untrusted JSON (PR 2). This test proves that
    boundary explicitly: restore proceeds and actually GRANTs the forged
    entry, which is exactly why an orchestrator must never hand-construct a
    `FenceProof` from something it read out of band — it must go through
    `from_document(doc, expected_digest=...)`.

    Deviation from a PUBLIC-shaped forgery: PostgreSQL's own default database
    ACL already grants PUBLIC a non-grantable CONNECT (owner-granted) the
    moment `datacl` stops being NULL — `owner_db`'s own fixture docstring
    says so — so `("", "CONNECT", False, owner)` is already a member of the
    REAL `proof.prior_grants` here, not absent from it, and forging it would
    be a silent no-op (a frozenset union with an element already present),
    proving nothing. `w` itself never receives an individual ACL entry
    (its only path to CONNECT is PUBLIC's default grant), so a forged
    `(w, "CONNECT", False, owner)` entry genuinely is absent from the real
    prior ACL, keeps the identical legal shape (CONNECT, an allowed grantee,
    owner-granted, non-grantable — so it does not trip the new
    grant-option-to-PUBLIC refusal either), and is what this test now
    forges."""
    with _writer_role(postgres_url) as w:
        with _connect(owner_url, autocommit=True) as owner_conn:
            proof = fence_writers(
                owner_conn,
                database=owner_db,
                fence_id=FENCE_ID,
                writer_roles=(w,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
                terminator=_superuser_terminator(postgres_url, owner_db, (w,)),
            )
            owner = fence_module._database_owner(owner_conn, owner_db)
            forged_entry = (w, "CONNECT", False, owner)
            assert forged_entry not in proof.prior_grants
            forged_proof = dataclasses.replace(
                proof, prior_grants=frozenset({*proof.prior_grants, forged_entry})
            )

            restored = restore_writers(
                owner_conn,
                forged_proof,
                database=owner_db,
                expected_fence_id=FENCE_ID,
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )
            assert "PUBLIC" in restored.roles_restored
            assert w in restored.roles_restored
            assert forged_entry in fence_module._current_grants(owner_conn, owner_db)


def test_restore_refuses_a_grant_option_to_public_before_any_grant(
    owner_url: str, owner_db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """PostgreSQL never allows a grant option to PUBLIC — no real
    `aclexplode` read can ever produce `("", <priv>, True, ...)`. A
    `prior_grants` entry claiming one is therefore refused by the `to_add`
    bound as `PROOF_MISMATCH`, before any GRANT — never merely left to fail
    as a raw SQL error mid-GRANT-loop (which would misreport this as
    `ACL_NOT_RESTORED`/`COMPENSATION_FAILED` instead of the precise
    proof-shape refusal it actually is)."""
    with _writer_role(postgres_url) as w:
        with _connect(owner_url, autocommit=True) as owner_conn:
            proof = fence_writers(
                owner_conn,
                database=owner_db,
                fence_id=FENCE_ID,
                writer_roles=(w,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
                terminator=_superuser_terminator(postgres_url, owner_db, (w,)),
            )
            owner = fence_module._database_owner(owner_conn, owner_db)
            forged_entry = ("", "CONNECT", True, owner)
            assert forged_entry not in proof.prior_grants
            forged_proof = dataclasses.replace(
                proof, prior_grants=frozenset({*proof.prior_grants, forged_entry})
            )

            before = fence_module._current_grants(owner_conn, owner_db)
            with pytest.raises(FenceRefused) as refused:
                restore_writers(
                    owner_conn,
                    forged_proof,
                    database=owner_db,
                    expected_fence_id=FENCE_ID,
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                )
            assert refused.value.code == FenceRefusalCode.PROOF_MISMATCH
            # Nothing was granted: still fully fenced, byte-identical to the
            # ACL right after the fence closed.
            assert fence_module._current_grants(owner_conn, owner_db) == before
            public_can_connect = owner_conn.execute(
                text("SELECT has_database_privilege('public', :db, 'CONNECT')"),
                {"db": owner_db},
            ).scalar_one()
            assert public_can_connect is False

            # Restore for real with the genuine (unforged) proof so fixture
            # teardown can drop the role.
            restore_writers(
                owner_conn,
                proof,
                database=owner_db,
                expected_fence_id=FENCE_ID,
                session_wait_seconds=SESSION_WAIT_SECONDS,
                terminator=_superuser_terminator(postgres_url, owner_db, (w,)),
            )


# ── (x) no-op terminator: survives and compensates ──────────────────────────


def test_owner_only_fence_with_a_no_op_terminator_survives_and_compensates(
    owner_url: str, owner_db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """A `terminator` that returns normally without terminating anything
    (unlike the default adapter, it never even ATTEMPTS a signal, so it
    never raises either) drains to nothing and the deadline alone catches
    it: `WRITER_SESSIONS_SURVIVED`, never `FENCE_INTERRUPTED`."""

    def _no_op() -> None:
        return None

    with _writer_role(postgres_url) as w:
        writer_engine = create_engine(url_for(postgres_url, owner_db, user=w))
        writer_conn = writer_engine.connect()
        try:
            assert writer_conn.execute(text("SELECT 1")).scalar_one() == 1

            with _connect(owner_url, autocommit=True) as owner_conn:
                before = fence_module._current_grants(owner_conn, owner_db)
                with pytest.raises(FenceRefused) as refused:
                    fence_writers(
                        owner_conn,
                        database=owner_db,
                        fence_id=FENCE_ID,
                        writer_roles=(w,),
                        session_wait_seconds=SESSION_WAIT_SECONDS,
                        terminator=_no_op,
                    )
                assert refused.value.code == FenceRefusalCode.WRITER_SESSIONS_SURVIVED
                after = fence_module._current_grants(owner_conn, owner_db)
                assert after == before

            # The writer's session was never actually terminated.
            assert writer_conn.execute(text("SELECT 1")).scalar_one() == 1
        finally:
            writer_conn.close()
            writer_engine.dispose()


def test_a_terminator_is_never_called_when_the_poll_finds_zero_backends(
    owner_url: str, owner_db: str, postgres_url: str
) -> None:
    """No writer is ever connected, so the poll sees zero backends on entry
    and the drain returns immediately — `terminator` must never be invoked
    for a database that was never holding an open writer session."""
    calls = 0

    def _counting_terminator() -> None:
        nonlocal calls
        calls += 1

    with _writer_role(postgres_url) as w:
        with _connect(owner_url, autocommit=True) as owner_conn:
            proof = fence_writers(
                owner_conn,
                database=owner_db,
                fence_id=FENCE_ID,
                writer_roles=(w,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
                terminator=_counting_terminator,
            )
            assert calls == 0
            assert proof.terminated_count == 0
            restore_writers(
                owner_conn,
                proof,
                database=owner_db,
                expected_fence_id=FENCE_ID,
                session_wait_seconds=SESSION_WAIT_SECONDS,
            )
        assert calls == 0


# ── (y) restore over the terminator seam: a mismatch re-drains via it ──────


def test_owner_only_restore_reopen_mismatch_redrains_via_the_terminator(
    owner_url: str, owner_db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """Mirrors the superuser suite's
    `test_a_restore_that_reopens_and_then_mismatches_redrains_before_reporting`
    but over the OWNER connection, with a superuser-backed `terminator` for
    the re-drain: w2's GRANT is dropped so the final comparison genuinely
    mismatches, w1's real GRANT lands and a second connection reconnects as
    w1 during that reopened window — the re-drain (going through the
    terminator, since the owner alone cannot signal it) must terminate that
    reconnected session before `ACL_NOT_RESTORED` is reported, never
    `COMPENSATION_FAILED`."""
    with _writer_role(postgres_url) as w1, _writer_role(postgres_url) as w2:
        with _connect(owner_url, autocommit=True) as owner_conn:
            owner_conn.execute(text(f'GRANT CONNECT ON DATABASE "{owner_db}" TO {w1}'))
            owner_conn.execute(text(f'GRANT CONNECT ON DATABASE "{owner_db}" TO {w2}'))
            proof = fence_writers(
                owner_conn,
                database=owner_db,
                fence_id=FENCE_ID,
                writer_roles=(w1, w2),
                session_wait_seconds=SESSION_WAIT_SECONDS,
                terminator=_superuser_terminator(postgres_url, owner_db, (w1, w2)),
            )

            reconnected: list[Connection] = []
            proxy = _SkipOneGrantReconnectTheOther(
                owner_conn,
                skip_role=w2,
                reconnect_role=w1,
                reconnect_url=url_for(postgres_url, owner_db, user=w1),
                reconnected=reconnected,
            )
            with pytest.raises(FenceRefused) as refused:
                restore_writers(
                    proxy,  # type: ignore[arg-type]
                    proof,
                    database=owner_db,
                    expected_fence_id=FENCE_ID,
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                    terminator=_superuser_terminator(postgres_url, owner_db, (w1, w2)),
                )
            assert refused.value.code == FenceRefusalCode.ACL_NOT_RESTORED
            assert len(reconnected) == 1

            with pytest.raises(OperationalError):
                reconnected[0].execute(text("SELECT 1"))
            reconnected[0].close()

            with pytest.raises(OperationalError, match="permission denied"):
                with _connect(url_for(postgres_url, owner_db, user=w1)):
                    pass

            # Still fully fenced — restore for real so teardown can drop the
            # roles.
            restore_writers(
                owner_conn,
                proof,
                database=owner_db,
                expected_fence_id=FENCE_ID,
                session_wait_seconds=SESSION_WAIT_SECONDS,
                terminator=_superuser_terminator(postgres_url, owner_db, (w1, w2)),
            )


def test_owner_only_restore_reopen_mismatch_without_a_terminator_fails_closed(
    owner_url: str, owner_db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """The same shape as the test above, but with NO `terminator` on the
    restore call: the owner cannot signal w1's reconnected backend, so the
    re-drain's default adapter cannot converge and the failure is reported
    as `COMPENSATION_FAILED`, not `ACL_NOT_RESTORED` — the re-fence's own
    drain could not be proven to hold."""
    with _writer_role(postgres_url) as w1, _writer_role(postgres_url) as w2:
        with _connect(owner_url, autocommit=True) as owner_conn:
            owner_conn.execute(text(f'GRANT CONNECT ON DATABASE "{owner_db}" TO {w1}'))
            owner_conn.execute(text(f'GRANT CONNECT ON DATABASE "{owner_db}" TO {w2}'))
            proof = fence_writers(
                owner_conn,
                database=owner_db,
                fence_id=FENCE_ID,
                writer_roles=(w1, w2),
                session_wait_seconds=SESSION_WAIT_SECONDS,
                terminator=_superuser_terminator(postgres_url, owner_db, (w1, w2)),
            )

            reconnected: list[Connection] = []
            proxy = _SkipOneGrantReconnectTheOther(
                owner_conn,
                skip_role=w2,
                reconnect_role=w1,
                reconnect_url=url_for(postgres_url, owner_db, user=w1),
                reconnected=reconnected,
            )
            with pytest.raises(FenceRefused) as refused:
                restore_writers(
                    proxy,  # type: ignore[arg-type]
                    proof,
                    database=owner_db,
                    expected_fence_id=FENCE_ID,
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                    # No terminator: the owner cannot signal w1's
                    # reconnected backend directly.
                )
            assert refused.value.code == FenceRefusalCode.COMPENSATION_FAILED
            assert len(reconnected) == 1
            reconnected[0].close()

            # Clean up for real with a working terminator so teardown can
            # drop the roles.
            restore_writers(
                owner_conn,
                proof,
                database=owner_db,
                expected_fence_id=FENCE_ID,
                session_wait_seconds=SESSION_WAIT_SECONDS,
                terminator=_superuser_terminator(postgres_url, owner_db, (w1, w2)),
            )


# ── (z) a terminator's own FenceRefused cannot spoof this module's code ────


def test_a_terminator_raising_fencerefused_cannot_spoof_the_refusal_code(
    admin_url: str, db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """A terminator is untrusted code: if it raises
    `FenceRefused(UNKNOWN_DATABASE)`, the fence must not report
    `UNKNOWN_DATABASE` — that code was never actually determined by this
    module. `_TerminatorFailed` wraps it first, so the existing compensation
    path classifies the real failure (a terminator that could not do its
    job) as `FENCE_INTERRUPTED`."""

    def _spoofing_terminator() -> None:
        raise FenceRefused(FenceRefusalCode.UNKNOWN_DATABASE, "spoofed refusal")

    with _writer_role(admin_url) as w:
        writer_engine = create_engine(url_for(postgres_url, db, user=w))
        writer_conn = writer_engine.connect()
        try:
            assert writer_conn.execute(text("SELECT 1")).scalar_one() == 1

            with _connect(admin_url, autocommit=True) as conn:
                before = fence_module._current_grants(conn, db)
                with pytest.raises(FenceRefused) as refused:
                    fence_writers(
                        conn,
                        database=db,
                        fence_id=FENCE_ID,
                        writer_roles=(w,),
                        session_wait_seconds=SESSION_WAIT_SECONDS,
                        terminator=_spoofing_terminator,
                    )
                assert refused.value.code == FenceRefusalCode.FENCE_INTERRUPTED
                assert refused.value.code != FenceRefusalCode.UNKNOWN_DATABASE
                after = fence_module._current_grants(conn, db)
                assert after == before
        finally:
            writer_conn.close()
            writer_engine.dispose()


# ── (aa) a third-party grant chain, untouched by fence/restore/compensation ─


def test_a_third_party_grant_chain_survives_fence_restore_and_compensation(
    owner_url: str, owner_db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """X and Y are neither writers nor members of one — the owner grants X
    `CONNECT WITH GRANT OPTION`, and X (not the owner, not a superuser)
    re-grants Y plain CONNECT. Nothing in this module ever names X or Y: the
    fence only ever revokes/re-grants PUBLIC and the effective writer set, so
    this whole chain — X's grantable entry AND Y's entry recording X (not
    the owner) as grantor — must survive completely untouched through a full
    fence, a real restore, and a SECOND fence that fails to drain and is
    compensated. `_current_grants` is compared as the full decomposed ACL, so
    this also proves grantor-exact preservation for a grant this module never
    itself issued."""
    with (
        _writer_role(postgres_url) as writer,
        _writer_role(postgres_url) as x,
        _writer_role(postgres_url) as y,
    ):
        # `_writer_role`'s own teardown runs `DROP OWNED BY` against
        # `postgres_url`'s database — NOT `owner_db`, a separate, per-test
        # database `DROP OWNED` never reaches (it only affects "the current
        # database"). X's and Y's grants live on `owner_db`, so this test
        # must revoke that chain itself, as the OWNER (who can revoke any
        # grant on its own database regardless of who the recorded grantor
        # was), before the roles are dropped — Y's grant first, since it is
        # the one recording X as grantor.
        try:
            with _connect(owner_url, autocommit=True) as owner_conn:
                owner_conn.execute(
                    text(
                        f'GRANT CONNECT ON DATABASE "{owner_db}" TO {x} '
                        "WITH GRANT OPTION"
                    )
                )
            with _connect(
                url_for(postgres_url, owner_db, user=x), autocommit=True
            ) as x_conn:
                x_conn.execute(text(f'GRANT CONNECT ON DATABASE "{owner_db}" TO {y}'))

            with _connect(owner_url, autocommit=True) as owner_conn:
                before = fence_module._current_grants(owner_conn, owner_db)
                assert (
                    x,
                    "CONNECT",
                    True,
                    fence_module._database_owner(owner_conn, owner_db),
                ) in before
                assert (y, "CONNECT", False, x) in before

                proof = fence_writers(
                    owner_conn,
                    database=owner_db,
                    fence_id=FENCE_ID,
                    writer_roles=(writer,),
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                    terminator=_superuser_terminator(postgres_url, owner_db, (writer,)),
                )
                # The chain survived the fence itself (never touched by a
                # REVOKE scoped to PUBLIC and the effective writer set).
                fenced_grants = fence_module._current_grants(owner_conn, owner_db)
                assert (
                    x,
                    "CONNECT",
                    True,
                    fence_module._database_owner(owner_conn, owner_db),
                ) in fenced_grants
                assert (y, "CONNECT", False, x) in fenced_grants

                restore_writers(
                    owner_conn,
                    proof,
                    database=owner_db,
                    expected_fence_id=FENCE_ID,
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                )
                after_restore = fence_module._current_grants(owner_conn, owner_db)
                assert after_restore == before

                # Force a SECOND fence to fail to drain (a no-op terminator
                # never even attempts a signal, so the deadline alone
                # catches it) with the writer connected, so it is
                # compensated — the chain must be unchanged by the
                # compensating restore too.
                writer_engine = create_engine(
                    url_for(postgres_url, owner_db, user=writer)
                )
                writer_conn = writer_engine.connect()
                try:
                    assert writer_conn.execute(text("SELECT 1")).scalar_one() == 1

                    def _no_op() -> None:
                        return None

                    with pytest.raises(FenceRefused) as refused:
                        fence_writers(
                            owner_conn,
                            database=owner_db,
                            fence_id=FENCE_ID,
                            writer_roles=(writer,),
                            session_wait_seconds=SESSION_WAIT_SECONDS,
                            terminator=_no_op,
                        )
                    assert (
                        refused.value.code == FenceRefusalCode.WRITER_SESSIONS_SURVIVED
                    )
                    after_compensation = fence_module._current_grants(
                        owner_conn, owner_db
                    )
                    assert after_compensation == before
                finally:
                    writer_conn.close()
                    writer_engine.dispose()
        finally:
            # An owner's REVOKE only removes grants the owner recorded, so a
            # plain REVOKE FROM y removes nothing (y's grant records x as
            # grantor), and a plain REVOKE FROM x fails with "dependent
            # privileges exist". CASCADE on x's grant option removes x's
            # grant and y's dependent one together, so the roles can drop.
            with _connect(owner_url, autocommit=True) as cleanup_conn:
                cleanup_conn.execute(
                    text(f'REVOKE CONNECT ON DATABASE "{owner_db}" FROM {x} CASCADE')
                )


# ── (bb) a prior= claim cannot launder a grant option to PUBLIC ────────────


def test_fence_refuses_a_prior_claiming_a_public_grant_option_absent_from_live_acl(
    owner_url: str, owner_db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """The `prior=` content bound applies the identical PostgreSQL-never-
    allows-a-grant-option-to-PUBLIC rule as `restore_writers`'s `to_add`
    bound (see the module docstring's "PostgreSQL never allows a grant
    option to PUBLIC" fix): a `prior=` proof claiming a PUBLIC CONNECT WITH
    GRANT OPTION beyond the live ACL is refused `PRIOR_MISMATCH` before any
    change, since no real `aclexplode` read could ever have produced it."""
    with _writer_role(postgres_url) as w:
        with _connect(owner_url, autocommit=True) as owner_conn:
            proof = fence_writers(
                owner_conn,
                database=owner_db,
                fence_id=FENCE_ID,
                writer_roles=(w,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
                terminator=_superuser_terminator(postgres_url, owner_db, (w,)),
            )
            restore_writers(
                owner_conn,
                proof,
                database=owner_db,
                expected_fence_id=FENCE_ID,
                session_wait_seconds=SESSION_WAIT_SECONDS,
                terminator=_superuser_terminator(postgres_url, owner_db, (w,)),
            )
            owner = fence_module._database_owner(owner_conn, owner_db)
            forged_entry = ("", "CONNECT", True, owner)
            assert forged_entry not in proof.prior_grants
            laundered_prior = dataclasses.replace(
                proof,
                fence_id="laundered-prior",
                prior_grants=frozenset({*proof.prior_grants, forged_entry}),
            )

            before = fence_module._current_grants(owner_conn, owner_db)
            with pytest.raises(FenceRefused) as refused:
                fence_writers(
                    owner_conn,
                    database=owner_db,
                    fence_id=FENCE_ID,
                    writer_roles=(w,),
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                    prior=laundered_prior,
                    expected_prior_fence_id=laundered_prior.fence_id,
                    terminator=_superuser_terminator(postgres_url, owner_db, (w,)),
                )
            assert refused.value.code == FenceRefusalCode.PRIOR_MISMATCH
            assert fence_module._current_grants(owner_conn, owner_db) == before


def test_fence_refuses_a_prior_that_does_not_account_for_a_live_grant(
    owner_url: str, owner_db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """The SUBSET layer, isolated: `before_grants <= prior.prior_grants`
    must hold, or `fence_writers` refuses `PRIOR_MISMATCH` before any
    change. A `bystander` role is granted CONNECT live, on the already
    fenced (and restored) database, and the `prior=` proof handed back is
    the ORIGINAL proof — silent about `bystander` entirely — so the live
    ACL is no longer a subset of what `prior` claims."""
    with (
        _writer_role(postgres_url) as w,
        _writer_role(postgres_url) as bystander,
    ):
        with _connect(owner_url, autocommit=True) as owner_conn:
            proof = fence_writers(
                owner_conn,
                database=owner_db,
                fence_id=FENCE_ID,
                writer_roles=(w,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
                terminator=_superuser_terminator(postgres_url, owner_db, (w,)),
            )
            restore_writers(
                owner_conn,
                proof,
                database=owner_db,
                expected_fence_id=FENCE_ID,
                session_wait_seconds=SESSION_WAIT_SECONDS,
                terminator=_superuser_terminator(postgres_url, owner_db, (w,)),
            )
            # Something grants CONNECT to an unrelated role that `proof`
            # (about to be reused as `prior=`) never accounted for.
            owner_conn.execute(
                text(f'GRANT CONNECT ON DATABASE "{owner_db}" TO {bystander}')
            )

            before = fence_module._current_grants(owner_conn, owner_db)
            with pytest.raises(FenceRefused) as refused:
                fence_writers(
                    owner_conn,
                    database=owner_db,
                    fence_id=FENCE_ID,
                    writer_roles=(w,),
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                    prior=proof,
                    expected_prior_fence_id=proof.fence_id,
                    terminator=_superuser_terminator(postgres_url, owner_db, (w,)),
                )
            assert refused.value.code == FenceRefusalCode.PRIOR_MISMATCH
            assert fence_module._current_grants(owner_conn, owner_db) == before

            owner_conn.execute(
                text(f'REVOKE CONNECT ON DATABASE "{owner_db}" FROM {bystander}')
            )


def test_fence_refuses_a_prior_claiming_an_extra_non_connect_privilege(
    owner_url: str, owner_db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """The privilege clause, isolated: the forged entry beyond the live
    subset is grantee `w` (an actual effective role), grantor the CURRENT
    owner — every clause but the privilege is satisfied — and only its
    privilege, `TEMPORARY`, is not `CONNECT`."""
    with _writer_role(postgres_url) as w:
        with _connect(owner_url, autocommit=True) as owner_conn:
            proof = fence_writers(
                owner_conn,
                database=owner_db,
                fence_id=FENCE_ID,
                writer_roles=(w,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
                terminator=_superuser_terminator(postgres_url, owner_db, (w,)),
            )
            restore_writers(
                owner_conn,
                proof,
                database=owner_db,
                expected_fence_id=FENCE_ID,
                session_wait_seconds=SESSION_WAIT_SECONDS,
                terminator=_superuser_terminator(postgres_url, owner_db, (w,)),
            )
            owner = fence_module._database_owner(owner_conn, owner_db)
            forged_entry = (w, "TEMPORARY", False, owner)
            assert forged_entry not in proof.prior_grants
            laundered_prior = dataclasses.replace(
                proof,
                fence_id="laundered-privilege-prior",
                prior_grants=frozenset({*proof.prior_grants, forged_entry}),
            )

            before = fence_module._current_grants(owner_conn, owner_db)
            with pytest.raises(FenceRefused) as refused:
                fence_writers(
                    owner_conn,
                    database=owner_db,
                    fence_id=FENCE_ID,
                    writer_roles=(w,),
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                    prior=laundered_prior,
                    expected_prior_fence_id=laundered_prior.fence_id,
                    terminator=_superuser_terminator(postgres_url, owner_db, (w,)),
                )
            assert refused.value.code == FenceRefusalCode.PRIOR_MISMATCH
            assert fence_module._current_grants(owner_conn, owner_db) == before


def test_fence_refuses_a_prior_claiming_a_grantee_outside_the_effective_set(
    owner_url: str, owner_db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """The grantee clause, isolated: the forged entry beyond the live subset
    is CONNECT, owner-granted, non-grantable — every clause but the grantee
    is satisfied — and only its grantee, `bystander`, is neither PUBLIC nor
    an effective role of THIS fence (`bystander` is a plain login role, never
    named in `writer_roles`, never a member of `w`)."""
    with (
        _writer_role(postgres_url) as w,
        _writer_role(postgres_url) as bystander,
    ):
        with _connect(owner_url, autocommit=True) as owner_conn:
            proof = fence_writers(
                owner_conn,
                database=owner_db,
                fence_id=FENCE_ID,
                writer_roles=(w,),
                session_wait_seconds=SESSION_WAIT_SECONDS,
                terminator=_superuser_terminator(postgres_url, owner_db, (w,)),
            )
            restore_writers(
                owner_conn,
                proof,
                database=owner_db,
                expected_fence_id=FENCE_ID,
                session_wait_seconds=SESSION_WAIT_SECONDS,
                terminator=_superuser_terminator(postgres_url, owner_db, (w,)),
            )
            owner = fence_module._database_owner(owner_conn, owner_db)
            forged_entry = (bystander, "CONNECT", False, owner)
            assert forged_entry not in proof.prior_grants
            laundered_prior = dataclasses.replace(
                proof,
                fence_id="laundered-grantee-prior",
                prior_grants=frozenset({*proof.prior_grants, forged_entry}),
            )

            before = fence_module._current_grants(owner_conn, owner_db)
            with pytest.raises(FenceRefused) as refused:
                fence_writers(
                    owner_conn,
                    database=owner_db,
                    fence_id=FENCE_ID,
                    writer_roles=(w,),
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                    prior=laundered_prior,
                    expected_prior_fence_id=laundered_prior.fence_id,
                    terminator=_superuser_terminator(postgres_url, owner_db, (w,)),
                )
            assert refused.value.code == FenceRefusalCode.PRIOR_MISMATCH
            assert fence_module._current_grants(owner_conn, owner_db) == before


# ── (cc) a terminator slower than the deadline never gets the benefit of the
# doubt ───────────────────────────────────────────────────────────────────


def test_a_terminator_slower_than_the_deadline_survives_and_compensates(
    owner_url: str, owner_db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """A terminator that sleeps LONGER than `session_wait_seconds` and then
    returns normally, without ever actually terminating the writer, is
    exactly what `_request_termination`'s docstring describes: Python cannot
    interrupt a blocking callable, so this is the only place that can ever
    notice — measured on return, and refused as `WRITER_SESSIONS_SURVIVED`
    regardless of what the terminator claims. A short, dedicated
    `session_wait_seconds` keeps this test itself bounded.

    Non-vacuous: `calls == 1` and the message says "exceeding" prove the
    SLOW-CALL branch in `_request_termination` is what refused — a plain
    `WRITER_SESSIONS_SURVIVED` code alone would also be produced by the
    unrelated deadline-based poll loop in `_terminate_and_drain` (e.g. if
    this terminator were simply a no-op that returned instantly and the
    writer just never got terminated), which would NOT prove the slow-call
    branch itself still refuses when it should."""
    short_wait = 0.5
    calls = 0

    def _slow_no_op() -> None:
        nonlocal calls
        calls += 1
        time.sleep(short_wait * 3)

    with _writer_role(postgres_url) as w:
        writer_engine = create_engine(url_for(postgres_url, owner_db, user=w))
        writer_conn = writer_engine.connect()
        try:
            assert writer_conn.execute(text("SELECT 1")).scalar_one() == 1

            with _connect(owner_url, autocommit=True) as owner_conn:
                before = fence_module._current_grants(owner_conn, owner_db)
                with pytest.raises(FenceRefused) as refused:
                    fence_writers(
                        owner_conn,
                        database=owner_db,
                        fence_id=FENCE_ID,
                        writer_roles=(w,),
                        session_wait_seconds=short_wait,
                        terminator=_slow_no_op,
                    )
                assert refused.value.code == FenceRefusalCode.WRITER_SESSIONS_SURVIVED
                assert "exceeding" in str(refused.value)
                assert calls == 1
                after = fence_module._current_grants(owner_conn, owner_db)
                assert after == before

            # Never actually terminated.
            assert writer_conn.execute(text("SELECT 1")).scalar_one() == 1
        finally:
            writer_conn.close()
            writer_engine.dispose()


# ── (dd) a terminator raising during restore's re-drain: COMPENSATION_FAILED


def test_a_terminator_raising_during_restores_re_drain_is_compensation_failed(
    owner_url: str, owner_db: str, postgres_url: str, url_for: Callable[..., str]
) -> None:
    """The same reopen-then-mismatch shape as
    `test_owner_only_restore_reopen_mismatch_redrains_via_the_terminator`,
    but the `terminator` handed to THIS restore call raises instead of
    terminating anything. `_refence_and_redrain` re-revokes and verifies the
    re-fence itself (never touching the terminator), so that half still
    succeeds; only the re-DRAIN, which does call the terminator, fails — and
    a terminator failure there is reported as `COMPENSATION_FAILED`,
    chained from the original mismatch, carrying `before_acl`/`prior_acl` so
    an operator has the ACL to restore by hand."""

    def _raising_terminator() -> None:
        raise RuntimeError("broker unreachable during re-drain")

    with _writer_role(postgres_url) as w1, _writer_role(postgres_url) as w2:
        with _connect(owner_url, autocommit=True) as owner_conn:
            owner_conn.execute(text(f'GRANT CONNECT ON DATABASE "{owner_db}" TO {w1}'))
            owner_conn.execute(text(f'GRANT CONNECT ON DATABASE "{owner_db}" TO {w2}'))
            proof = fence_writers(
                owner_conn,
                database=owner_db,
                fence_id=FENCE_ID,
                writer_roles=(w1, w2),
                session_wait_seconds=SESSION_WAIT_SECONDS,
                terminator=_superuser_terminator(postgres_url, owner_db, (w1, w2)),
            )

            reconnected: list[Connection] = []
            proxy = _SkipOneGrantReconnectTheOther(
                owner_conn,
                skip_role=w2,
                reconnect_role=w1,
                reconnect_url=url_for(postgres_url, owner_db, user=w1),
                reconnected=reconnected,
            )
            with pytest.raises(FenceRefused) as refused:
                restore_writers(
                    proxy,  # type: ignore[arg-type]
                    proof,
                    database=owner_db,
                    expected_fence_id=FENCE_ID,
                    session_wait_seconds=SESSION_WAIT_SECONDS,
                    terminator=_raising_terminator,
                )
            assert refused.value.code == FenceRefusalCode.COMPENSATION_FAILED
            assert refused.value.before_acl == proof.prior_acl
            # The re-fence itself (revoke + has_database_privilege verify)
            # does not depend on the terminator, so it still ran: w1's
            # reconnected session is left open (the failing re-drain never
            # got to terminate it), but it can no longer authenticate fresh.
            assert len(reconnected) == 1
            with pytest.raises(OperationalError, match="permission denied"):
                with _connect(url_for(postgres_url, owner_db, user=w1)):
                    pass
            reconnected[0].close()

            # Clean up for real with a working terminator so teardown can
            # drop the roles.
            restore_writers(
                owner_conn,
                proof,
                database=owner_db,
                expected_fence_id=FENCE_ID,
                session_wait_seconds=SESSION_WAIT_SECONDS,
                terminator=_superuser_terminator(postgres_url, owner_db, (w1, w2)),
            )
