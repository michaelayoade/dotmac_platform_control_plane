"""PostgreSQL 16 evidence for staging after an immutable original fence."""

from __future__ import annotations

import os
import secrets
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager

import pytest
from psycopg import sql
from sqlalchemy import Connection, create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError

from vendor_cp.deployment import transition_fence as fence_module
from vendor_cp.deployment.candidate_roles import (
    CandidateRoleRefused,
    CandidateRoles,
    activate,
    cleanup_before_restore,
    create_roles,
    deactivate,
    restore_after_candidate,
    verify_staged_database,
)
from vendor_cp.deployment.transition_fence import (
    FenceRefused,
    fence_is_holding,
    fence_writers,
    restore_writers,
)


@contextmanager
def _connect(url: str) -> Iterator[Connection]:
    engine = create_engine(url, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as conn:
            yield conn
    finally:
        engine.dispose()


def _install_test_password(conn: Connection, role: str) -> None:
    # This generated value is never printed or committed. Host credential
    # installation remains outside the source-only role state machine.
    password = secrets.token_urlsafe(48)
    raw = conn.connection.driver_connection
    assert raw is not None
    with raw.cursor() as cursor:
        cursor.execute(
            sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                sql.Identifier(role), sql.Literal(password)
            )
        )


def _assert_connect_denied(url: str) -> None:
    with pytest.raises(OperationalError) as refusal:
        with _connect(url):
            pass
    # libpq/psycopg can omit sqlstate for a startup FATAL, so require the
    # server's specific database-CONNECT denial, not a generic auth failure.
    detail = str(refusal.value.orig)
    assert "FATAL:" in detail and "permission denied for database" in detail
    assert "DETAIL:" in detail and "User does not have CONNECT privilege." in detail


def _roles(db: str) -> CandidateRoles:
    return CandidateRoles.for_run(database=db, run_id=uuid.uuid4().hex)


@pytest.fixture
def target_only_connect(
    scratch_db: str,
    postgres_url: str,
    url_for: Callable[..., str],
) -> Iterator[tuple[str, ...]]:
    """Temporarily close other DBs only on the disposable PG16 test service.

    The CI coordinate is the checked-in docker-compose.test.yml service.
    A different isolated loopback test container needs an explicit opt-in.
    Never run this fixture against a shared or remote database cluster.
    """
    parsed = make_url(postgres_url)
    ci_disposable = (
        parsed.host in {"localhost", "127.0.0.1"}
        and parsed.port == 5439
        and parsed.database == "vendor_cp_test"
        and parsed.username == "postgres"
    )
    explicit_disposable = (
        os.getenv("D16_DISPOSABLE_PG16") == "1"
        and parsed.host in {"localhost", "127.0.0.1"}
        and parsed.username == "postgres"
    )
    if not (ci_disposable or explicit_disposable):
        pytest.fail("candidate ACL fixture requires a disposable loopback PG16")
    target = scratch_db.rpartition("/")[2]
    with _connect(url_for(postgres_url, target)) as owner:
        databases = owner.execute(
            text(
                "SELECT datname, pg_get_userbyid(datdba) FROM pg_database "
                "WHERE datallowconn AND datname <> :target ORDER BY datname"
            ),
            {"target": target},
        ).all()
        snapshots: dict[str, frozenset[tuple[str, str, bool, str]]] = {}
        removed: dict[str, set[tuple[str, str, bool, str]]] = {}
        for name, database_owner in databases:
            grants = fence_module._current_grants(owner, str(name))
            selected = {
                grant
                for grant in grants
                if grant[1] == "CONNECT"
                and grant[0] in {"", "app_user", "platform_api"}
            }
            if any(
                grantor != database_owner or grantable
                for _, _, grantable, grantor in selected
            ):
                pytest.fail("disposable cluster has an unsupported other-DB ACL")
            snapshots[str(name)] = grants
            removed[str(name)] = selected
        try:
            for name in snapshots:
                quoted = owner.dialect.identifier_preparer.quote(name)
                owner.execute(
                    text(
                        f"REVOKE CONNECT ON DATABASE {quoted} "
                        "FROM PUBLIC, app_user, platform_api"
                    )
                )
                expected = snapshots[name] - removed[name]
                assert fence_module._current_grants(owner, name) == expected
            yield tuple(snapshots)
        finally:
            for name, selected in removed.items():
                quoted = owner.dialect.identifier_preparer.quote(name)
                for grantee, _priv, _grantable, _grantor in sorted(selected):
                    recipient = (
                        "PUBLIC"
                        if grantee == ""
                        else owner.dialect.identifier_preparer.quote(grantee)
                    )
                    owner.execute(
                        text(f"GRANT CONNECT ON DATABASE {quoted} TO {recipient}")
                    )
                assert fence_module._current_grants(owner, name) == snapshots[name]


def _fence(conn: Connection, db: str, roles: CandidateRoles):  # type: ignore[no-untyped-def]
    return fence_writers(
        conn,
        database=db,
        fence_id=f"candidate-{roles.run_id}",
        session_wait_seconds=3,
    )


def _create(conn: Connection, roles: CandidateRoles, proof) -> None:  # type: ignore[no-untyped-def]
    create_roles(
        conn,
        roles,
        proof,
        expected_digest=proof.digest(),
        expected_fence_id=proof.fence_id,
    )


def _activate(conn: Connection, roles: CandidateRoles, proof) -> None:  # type: ignore[no-untyped-def]
    for name, _ in roles.bindings():
        _install_test_password(conn, name)
    activate(
        conn,
        roles,
        proof,
        expected_digest=proof.digest(),
        expected_fence_id=proof.fence_id,
    )


def _deactivate(conn: Connection, roles: CandidateRoles, proof) -> None:  # type: ignore[no-untyped-def]
    deactivate(
        conn,
        roles,
        proof,
        expected_digest=proof.digest(),
        expected_fence_id=proof.fence_id,
    )


def _cleanup(conn: Connection, roles: CandidateRoles, proof) -> None:  # type: ignore[no-untyped-def]
    cleanup_before_restore(
        conn,
        roles,
        proof,
        expected_digest=proof.digest(),
        expected_fence_id=proof.fence_id,
    )


def _restore(conn: Connection, roles: CandidateRoles, proof) -> None:  # type: ignore[no-untyped-def]
    restore_after_candidate(
        conn,
        roles,
        proof,
        expected_digest=proof.digest(),
        expected_fence_id=proof.fence_id,
        session_wait_seconds=3,
    )


def test_original_proof_stays_immutable_and_connect_denial_is_real(
    scratch_db: str,
    postgres_url: str,
    url_for: Callable[..., str],
    target_only_connect: tuple[str, ...],
) -> None:
    db = scratch_db.rpartition("/")[2]
    roles = _roles(db)
    originals = ("app_user", "platform_api", "platform_outbox_dispatcher")
    with _connect(url_for(postgres_url, db)) as owner:
        owner.execute(text("CREATE TABLE public.d16_app_probe (value integer)"))
        owner.execute(text("CREATE TABLE public.d16_platform_probe (value integer)"))
        owner.execute(text("REVOKE ALL ON public.d16_app_probe FROM PUBLIC"))
        owner.execute(text("REVOKE ALL ON public.d16_platform_probe FROM PUBLIC"))
        owner.execute(text("GRANT SELECT ON public.d16_app_probe TO app_user"))
        owner.execute(text("GRANT SELECT ON public.d16_platform_probe TO platform_api"))
        owner.execute(
            text(
                "CREATE FUNCTION public.d16_dispatcher_probe() RETURNS integer "
                "LANGUAGE SQL AS 'SELECT 1'"
            )
        )
        owner.execute(
            text("REVOKE ALL ON FUNCTION public.d16_dispatcher_probe() FROM PUBLIC")
        )
        owner.execute(
            text(
                "GRANT EXECUTE ON FUNCTION public.d16_dispatcher_probe() "
                "TO platform_outbox_dispatcher"
            )
        )
        for original in originals:
            with _connect(url_for(postgres_url, db, user=original)) as writer:
                assert (
                    writer.execute(text("SELECT current_user")).scalar_one() == original
                )
        proof = _fence(owner, db, roles)
        original_digest = proof.digest()
        assert fence_is_holding(owner, proof)
        assert not {roles.app, roles.platform} & set(proof.member_roles)
        for original in originals:
            _assert_connect_denied(url_for(postgres_url, db, user=original))
        # Bundle/catalog and migration gates are external; the role owner must
        # never create roles until they have completed under this same fence.
        owner.execute(text("CREATE TABLE public.d16_candidate_migration_probe (n int)"))
        assert fence_is_holding(owner, proof)
        _create(owner, roles, proof)
        for candidate, app_allowed, platform_allowed in (
            (roles.app, True, False),
            (roles.platform, False, True),
        ):
            assert (
                owner.execute(
                    text(
                        "SELECT has_table_privilege("
                        ":role, 'public.d16_app_probe', 'SELECT')"
                    ),
                    {"role": candidate},
                ).scalar_one()
                is app_allowed
            )
            assert (
                owner.execute(
                    text(
                        "SELECT has_table_privilege("
                        ":role, 'public.d16_platform_probe', 'SELECT')"
                    ),
                    {"role": candidate},
                ).scalar_one()
                is platform_allowed
            )
            assert (
                owner.execute(
                    text(
                        "SELECT has_function_privilege("
                        ":role, 'public.d16_dispatcher_probe()', 'EXECUTE')"
                    ),
                    {"role": candidate},
                ).scalar_one()
                is False
            )
        assert proof.digest() == original_digest
        assert not fence_is_holding(owner, proof)
        with pytest.raises(FenceRefused, match="membership"):
            restore_writers(
                owner,
                proof,
                database=db,
                expected_fence_id=proof.fence_id,
                session_wait_seconds=3,
            )
        _activate(owner, roles, proof)
        assert verify_staged_database(
            owner,
            roles,
            proof,
            expected_digest=original_digest,
            expected_fence_id=proof.fence_id,
        )
        for original in originals:
            _assert_connect_denied(url_for(postgres_url, db, user=original))
        for name, _ in roles.bindings():
            with _connect(url_for(postgres_url, db, user=name)) as candidate_conn:
                assert (
                    candidate_conn.execute(text("SELECT current_user")).scalar_one()
                    == name
                )
        _deactivate(owner, roles, proof)
        with pytest.raises(FenceRefused, match="membership"):
            restore_writers(
                owner,
                proof,
                database=db,
                expected_fence_id=proof.fence_id,
                session_wait_seconds=3,
            )
        with pytest.raises(CandidateRoleRefused, match="roles remain"):
            _restore(owner, roles, proof)
        _cleanup(owner, roles, proof)
        assert fence_is_holding(owner, proof)
        assert proof.digest() == original_digest
        _restore(owner, roles, proof)
        for original in originals:
            with _connect(url_for(postgres_url, db, user=original)) as writer:
                assert (
                    writer.execute(text("SELECT current_user")).scalar_one() == original
                )


def test_wrong_binding_and_partial_activation_can_be_closed(
    scratch_db: str,
    postgres_url: str,
    url_for: Callable[..., str],
    target_only_connect: tuple[str, ...],
) -> None:
    db = scratch_db.rpartition("/")[2]
    roles = _roles(db)
    with _connect(url_for(postgres_url, db)) as owner:
        proof = _fence(owner, db, roles)
        with pytest.raises(CandidateRoleRefused, match="bound"):
            create_roles(
                owner,
                roles,
                proof,
                expected_digest=proof.digest(),
                expected_fence_id="wrong-run",
            )
        _create(owner, roles, proof)
        with pytest.raises(CandidateRoleRefused, match="password"):
            activate(
                owner,
                roles,
                proof,
                expected_digest=proof.digest(),
                expected_fence_id=proof.fence_id,
            )
        owner.execute(text(f'GRANT CONNECT ON DATABASE "{db}" TO "{roles.app}"'))
        owner.execute(text(f'ALTER ROLE "{roles.app}" LOGIN'))
        _deactivate(owner, roles, proof)
        _deactivate(owner, roles, proof)
        with pytest.raises(CandidateRoleRefused, match="bound"):
            cleanup_before_restore(
                owner,
                roles,
                proof,
                expected_digest=proof.digest(),
                expected_fence_id="wrong-run",
            )
        assert not verify_staged_database(
            owner,
            roles,
            proof,
            expected_digest=proof.digest(),
            expected_fence_id="wrong-run",
        )
        _cleanup(owner, roles, proof)
        _restore(owner, roles, proof)


def test_other_database_public_connect_refuses_activation(
    scratch_db: str,
    postgres_url: str,
    url_for: Callable[..., str],
) -> None:
    db = scratch_db.rpartition("/")[2]
    other = f"d16_other_{uuid.uuid4().hex[:12]}"
    roles = _roles(db)
    with _connect(url_for(postgres_url, db)) as owner:
        owner.execute(text(f'CREATE DATABASE "{other}"'))
        try:
            proof = _fence(owner, db, roles)
            _create(owner, roles, proof)
            assert owner.execute(
                text("SELECT has_database_privilege(:role, :db, 'CONNECT')"),
                {"role": roles.app, "db": other},
            ).scalar_one()
            for name, _ in roles.bindings():
                _install_test_password(owner, name)
            with pytest.raises(CandidateRoleRefused, match="another database"):
                activate(
                    owner,
                    roles,
                    proof,
                    expected_digest=proof.digest(),
                    expected_fence_id=proof.fence_id,
                )
            _cleanup(owner, roles, proof)
            _restore(owner, roles, proof)
        finally:
            owner.execute(text(f'DROP DATABASE "{other}"'))


def test_live_candidate_session_refuses_cleanup_and_restore(
    scratch_db: str,
    postgres_url: str,
    url_for: Callable[..., str],
    target_only_connect: tuple[str, ...],
) -> None:
    db = scratch_db.rpartition("/")[2]
    roles = _roles(db)
    with _connect(url_for(postgres_url, db)) as owner:
        proof = _fence(owner, db, roles)
        _create(owner, roles, proof)
        _activate(owner, roles, proof)
        with _connect(url_for(postgres_url, db, user=roles.app)):
            with pytest.raises(CandidateRoleRefused, match="sessions remain"):
                _deactivate(owner, roles, proof)
            with pytest.raises(CandidateRoleRefused, match="sessions remain"):
                _cleanup(owner, roles, proof)
            with pytest.raises(FenceRefused, match="membership"):
                restore_writers(
                    owner,
                    proof,
                    database=db,
                    expected_fence_id=proof.fence_id,
                    session_wait_seconds=3,
                )
        _deactivate(owner, roles, proof)
        _cleanup(owner, roles, proof)
        _restore(owner, roles, proof)


def test_extra_acl_membership_and_partial_cleanup_are_refused_or_recoverable(
    scratch_db: str,
    postgres_url: str,
    url_for: Callable[..., str],
    target_only_connect: tuple[str, ...],
) -> None:
    db = scratch_db.rpartition("/")[2]
    roles = _roles(db)
    rogue = f"d16_rogue_{uuid.uuid4().hex[:12]}"
    with _connect(url_for(postgres_url, db)) as owner:
        proof = _fence(owner, db, roles)
        _create(owner, roles, proof)
        _activate(owner, roles, proof)
        owner.execute(text(f'CREATE ROLE "{rogue}" NOLOGIN'))
        owner.execute(text(f'GRANT CONNECT ON DATABASE "{db}" TO "{rogue}"'))
        assert not verify_staged_database(
            owner,
            roles,
            proof,
            expected_digest=proof.digest(),
            expected_fence_id=proof.fence_id,
        )
        with pytest.raises(CandidateRoleRefused, match="ACL delta"):
            _deactivate(owner, roles, proof)
        owner.execute(text(f'REVOKE CONNECT ON DATABASE "{db}" FROM "{rogue}"'))
        owner.execute(text(f'DROP ROLE "{rogue}"'))
        owner.execute(text(f'GRANT platform_api TO "{roles.app}"'))
        assert not verify_staged_database(
            owner,
            roles,
            proof,
            expected_digest=proof.digest(),
            expected_fence_id=proof.fence_id,
        )
        with pytest.raises(CandidateRoleRefused, match="membership"):
            _deactivate(owner, roles, proof)
        owner.execute(text(f'REVOKE platform_api FROM "{roles.app}"'))
        other = target_only_connect[0]
        quoted_other = owner.dialect.identifier_preparer.quote(other)
        owner.execute(
            text(f'GRANT CONNECT ON DATABASE {quoted_other} TO "{roles.app}"')
        )
        assert not verify_staged_database(
            owner,
            roles,
            proof,
            expected_digest=proof.digest(),
            expected_fence_id=proof.fence_id,
        )
        owner.execute(
            text(f'REVOKE CONNECT ON DATABASE {quoted_other} FROM "{roles.app}"')
        )
        assert verify_staged_database(
            owner,
            roles,
            proof,
            expected_digest=proof.digest(),
            expected_fence_id=proof.fence_id,
        )
        _deactivate(owner, roles, proof)
        owner.execute(text(f'DROP ROLE "{roles.app}"'))
        with pytest.raises(FenceRefused, match="membership"):
            restore_writers(
                owner,
                proof,
                database=db,
                expected_fence_id=proof.fence_id,
                session_wait_seconds=3,
            )
        _cleanup(owner, roles, proof)
        _cleanup(owner, roles, proof)
        assert fence_is_holding(owner, proof)
        _restore(owner, roles, proof)


def test_inherited_other_parent_privilege_refuses_staged_verification(
    scratch_db: str,
    postgres_url: str,
    url_for: Callable[..., str],
    target_only_connect: tuple[str, ...],
) -> None:
    db = scratch_db.rpartition("/")[2]
    roles = _roles(db)
    with _connect(url_for(postgres_url, db)) as owner:
        owner.execute(
            text("CREATE TABLE public.d16_platform_inheritance_probe (n int)")
        )
        owner.execute(
            text("REVOKE ALL ON public.d16_platform_inheritance_probe FROM PUBLIC")
        )
        owner.execute(
            text(
                "GRANT SELECT ON public.d16_platform_inheritance_probe "
                "TO platform_api"
            )
        )
        proof = _fence(owner, db, roles)
        _create(owner, roles, proof)
        _activate(owner, roles, proof)
        assert verify_staged_database(
            owner,
            roles,
            proof,
            expected_digest=proof.digest(),
            expected_fence_id=proof.fence_id,
        )
        assert not owner.execute(
            text(
                "SELECT has_table_privilege("
                ":role, 'public.d16_platform_inheritance_probe', 'SELECT')"
            ),
            {"role": roles.app},
        ).scalar_one()
        existing_grant = owner.execute(
            text(
                "SELECT 1 FROM pg_auth_members am "
                "JOIN pg_roles parent ON parent.oid = am.roleid "
                "JOIN pg_roles member ON member.oid = am.member "
                "WHERE parent.rolname = 'platform_api' "
                "AND member.rolname = 'app_user'"
            )
        ).scalar_one_or_none()
        assert existing_grant is None
        try:
            owner.execute(text("GRANT platform_api TO app_user"))
            assert owner.execute(
                text(
                    "SELECT has_table_privilege("
                    ":role, 'public.d16_platform_inheritance_probe', 'SELECT')"
                ),
                {"role": roles.app},
            ).scalar_one()
            assert not verify_staged_database(
                owner,
                roles,
                proof,
                expected_digest=proof.digest(),
                expected_fence_id=proof.fence_id,
            )
            with pytest.raises(CandidateRoleRefused, match="forbidden role"):
                _deactivate(owner, roles, proof)
        finally:
            owner.execute(text("REVOKE platform_api FROM app_user"))
        assert verify_staged_database(
            owner,
            roles,
            proof,
            expected_digest=proof.digest(),
            expected_fence_id=proof.fence_id,
        )
        _deactivate(owner, roles, proof)
        _cleanup(owner, roles, proof)
        _restore(owner, roles, proof)
