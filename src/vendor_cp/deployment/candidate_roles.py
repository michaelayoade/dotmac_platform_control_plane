"""Run-scoped PostgreSQL identities for D16 candidate readiness.

This owner changes role connectivity only. It consumes the existing fence proof
and never creates a second fence or restores the original writer ACL. Password
installation and candidate process configuration belong to a separate host
adapter; activation refuses roles without a PostgreSQL password verifier.

The original fence and recovery bundle precede candidate role creation. The
candidate roles therefore cannot change the original proof or appear in its
globals.sql. This module verifies their temporary membership/ACL delta and
removes them before the original ACL is restored.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from sqlalchemy import Connection, text

from vendor_cp.deployment import transition_fence as fence

_RUN_ID: Final = re.compile(r"[0-9a-f]{32}\Z")
_PARENTS: Final = ("app_user", "platform_api")


class CandidateRoleRefused(RuntimeError):
    """A candidate identity transition was not proven safe."""


@dataclass(frozen=True, slots=True)
class CandidateRoles:
    database: str
    run_id: str
    app: str
    platform: str

    @classmethod
    def for_run(cls, *, database: str, run_id: str) -> CandidateRoles:
        if not database or not _RUN_ID.fullmatch(run_id):
            raise CandidateRoleRefused(
                "database and a 32-character lowercase hex run id are required"
            )
        prefix = f"vcp_d16_{run_id}"
        return cls(database, run_id, f"{prefix}_a", f"{prefix}_p")

    def bindings(self) -> tuple[tuple[str, str], ...]:
        return tuple(zip((self.app, self.platform), _PARENTS, strict=True))


def _require_canonical(roles: CandidateRoles) -> None:
    if roles != CandidateRoles.for_run(database=roles.database, run_id=roles.run_id):
        raise CandidateRoleRefused("candidate role names do not match the run")


def _identifier(conn: Connection, value: str) -> str:
    return conn.dialect.identifier_preparer.quote(value)


def _require_superuser_autocommit(conn: Connection) -> None:
    # SQLAlchemy's get_isolation_level() still reports READ COMMITTED when
    # the driver is in autocommit. The fence checks the driver flag too.
    if getattr(conn.connection.dbapi_connection, "autocommit", False) is not True:
        raise CandidateRoleRefused("candidate role changes require AUTOCOMMIT")
    if int(conn.execute(text("SHOW server_version_num")).scalar_one()) < 160000:
        raise CandidateRoleRefused("candidate membership options require PostgreSQL 16")
    if not conn.execute(
        text("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
    ).scalar_one():
        raise CandidateRoleRefused(
            "candidate role changes require the local cluster superuser"
        )


def _existing(conn: Connection, names: tuple[str, ...]) -> set[str]:
    return set(
        conn.execute(
            text(
                "SELECT rolname FROM pg_roles "
                "WHERE rolname = ANY(CAST(:names AS text[]))"
            ),
            {"names": list(names)},
        ).scalars()
    )


def _role_states(
    conn: Connection, roles: CandidateRoles
) -> dict[str, tuple[bool, ...]]:
    rows = conn.execute(
        text(
            "SELECT rolname, rolcanlogin, rolsuper, rolbypassrls, "
            "rolcreatedb, rolcreaterole, rolreplication, rolinherit, "
            "rolconnlimit FROM pg_roles "
            "WHERE rolname = ANY(CAST(:names AS text[]))"
        ),
        {"names": [name for name, _ in roles.bindings()]},
    )
    return {
        str(row[0]): (
            bool(row[1]),
            bool(row[2]),
            bool(row[3]),
            bool(row[4]),
            bool(row[5]),
            bool(row[6]),
            bool(row[7]),
            row[8] == -1,
        )
        for row in rows
    }


def _require_memberships(
    conn: Connection, roles: CandidateRoles, *, present: set[str] | None = None
) -> None:
    if present is None:
        present = {name for name, _ in roles.bindings()}
    rows = conn.execute(
        text(
            "SELECT member.rolname, parent.rolname, am.inherit_option, "
            "am.set_option, am.admin_option FROM pg_auth_members am "
            "JOIN pg_roles member ON member.oid = am.member "
            "JOIN pg_roles parent ON parent.oid = am.roleid "
            "WHERE member.rolname = ANY(CAST(:names AS text[]))"
        ),
        {"names": [name for name, _ in roles.bindings()]},
    )
    found = {
        (str(member), str(parent), bool(inherit), bool(can_set), bool(admin))
        for member, parent, inherit, can_set, admin in rows
    }
    expected = {
        (name, parent, True, False, False)
        for name, parent in roles.bindings()
        if name in present
    }
    if found != expected:
        raise CandidateRoleRefused("candidate role membership or options drifted")


def _require_parent_ancestry(
    conn: Connection, roles: CandidateRoles, proof: fence.FenceProof
) -> None:
    """Reject forbidden ancestors reached through either sole candidate parent.

    Walk actual membership rows rather than ``pg_has_role``: a superuser
    connection must not make every role appear to be a candidate ancestor.
    Direct candidate grants are checked separately by ``_require_memberships``.
    """
    forbidden = {
        *fence.WRITER_ROLES,
        *proof.fenced_roles,
        *proof.member_roles,
        fence.MIGRATION_ROLE,
        fence._database_owner(conn, roles.database),
    }
    rows = conn.execute(
        text(
            "WITH RECURSIVE ancestors(root_oid, ancestor_oid) AS ("
            "SELECT oid, oid FROM pg_roles "
            "WHERE rolname = ANY(CAST(:parents AS text[])) "
            "UNION "
            "SELECT ancestors.root_oid, memberships.roleid "
            "FROM ancestors JOIN pg_auth_members memberships "
            "ON memberships.member = ancestors.ancestor_oid"
            ") "
            "SELECT root.rolname, parent.rolname FROM ancestors "
            "JOIN pg_roles root ON root.oid = ancestors.root_oid "
            "JOIN pg_roles parent ON parent.oid = ancestors.ancestor_oid "
            "WHERE ancestors.ancestor_oid <> ancestors.root_oid"
        ),
        {"parents": list(_PARENTS)},
    )
    for parent, ancestor in rows:
        if str(ancestor) in forbidden - {str(parent)}:
            raise CandidateRoleRefused(
                "a candidate parent inherits a forbidden role through membership"
            )


def _require_role_shape(
    conn: Connection, roles: CandidateRoles, *, login: bool
) -> None:
    states = _role_states(conn, roles)
    if set(states) != {name for name, _ in roles.bindings()}:
        raise CandidateRoleRefused("one or more run-scoped candidate roles are absent")
    if any(
        state != (login, False, False, False, False, False, True, True)
        for state in states.values()
    ):
        raise CandidateRoleRefused("candidate role privilege or login state drifted")
    _require_memberships(conn, roles)


def _strict_grants(proof: fence.FenceProof) -> set[tuple[str, str, bool, str]]:
    effective = {"", *proof.fenced_roles, *proof.member_roles}
    return {
        grant
        for grant in proof.prior_grants
        if not (grant[1] == "CONNECT" and grant[0] in effective)
    }


def _require_strict_acl(conn: Connection, proof: fence.FenceProof) -> None:
    if set(fence._current_grants(conn, proof.database)) != _strict_grants(proof):
        raise CandidateRoleRefused("the original strict ACL has drifted")


def _require_membership_delta(
    conn: Connection, roles: CandidateRoles, proof: fence.FenceProof, present: set[str]
) -> None:
    live = set(fence._member_roles(conn, proof.fenced_roles))
    if live != set(proof.member_roles) | present:
        raise CandidateRoleRefused("the staged writer membership delta drifted")
    _require_memberships(conn, roles, present=present)
    _require_parent_ancestry(conn, roles, proof)


def create_roles(
    conn: Connection,
    roles: CandidateRoles,
    proof: fence.FenceProof,
    *,
    expected_digest: str,
    expected_fence_id: str,
) -> None:
    """Create NOLOGIN roles only after strict fence, bundle, and migration gates.

    The caller owns the bundle and migration gates; this function proves only
    the original fence. One PostgreSQL statement makes both creations atomic.
    """
    _require_canonical(roles)
    _require_superuser_autocommit(conn)
    _require_bound_strict_fence(
        conn,
        roles,
        proof,
        expected_digest=expected_digest,
        expected_fence_id=expected_fence_id,
    )
    _require_strict_acl(conn, proof)
    names = tuple(name for name, _ in roles.bindings())
    if _existing(conn, names):
        raise CandidateRoleRefused("a run-scoped candidate role already exists")
    if _existing(conn, _PARENTS) != set(_PARENTS):
        raise CandidateRoleRefused("a required writer parent role is absent")
    _require_parent_ancestry(conn, roles, proof)
    statements: list[str] = []
    for name, parent in roles.bindings():
        quoted = _identifier(conn, name)
        statements.extend(
            (
                f"CREATE ROLE {quoted} NOLOGIN INHERIT NOSUPERUSER "
                "NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS",
                f"GRANT {_identifier(conn, parent)} TO {quoted} "
                "WITH INHERIT TRUE, SET FALSE, ADMIN FALSE",
            )
        )
    conn.exec_driver_sql(
        "DO $candidate$ BEGIN " + "; ".join(statements) + "; END $candidate$"
    )
    _require_role_shape(conn, roles, login=False)
    _require_membership_delta(conn, roles, proof, set(names))


def _require_bound_proof(
    roles: CandidateRoles,
    proof: fence.FenceProof,
    *,
    expected_digest: str,
    expected_fence_id: str,
) -> None:
    _require_canonical(roles)
    if (
        proof.database != roles.database
        or proof.fence_id != expected_fence_id
        or proof.digest() != expected_digest
    ):
        raise CandidateRoleRefused("candidate run is not bound to this fence proof")
    if {name for name, _ in roles.bindings()} & set(
        (*proof.fenced_roles, *proof.member_roles)
    ):
        raise CandidateRoleRefused(
            "candidate roles must not be captured by the original writer fence"
        )


def _require_bound_strict_fence(
    conn: Connection,
    roles: CandidateRoles,
    proof: fence.FenceProof,
    *,
    expected_digest: str,
    expected_fence_id: str,
) -> None:
    _require_bound_proof(
        roles,
        proof,
        expected_digest=expected_digest,
        expected_fence_id=expected_fence_id,
    )
    if not fence.fence_is_holding(conn, proof):
        raise CandidateRoleRefused("the strict writer fence is not holding")


def _sessions(conn: Connection, database: str, roles: tuple[str, ...]) -> int:
    return int(
        conn.execute(
            text(
                "SELECT count(*) FROM pg_stat_activity WHERE datname = :db "
                "AND usename = ANY(CAST(:roles AS text[]))"
            ),
            {"db": database, "roles": list(roles)},
        ).scalar_one()
    )


def _candidate_sessions(conn: Connection, roles: CandidateRoles) -> int:
    """Candidate identities are cluster roles; refuse sessions in any DB."""
    return int(
        conn.execute(
            text(
                "SELECT count(*) FROM pg_stat_activity "
                "WHERE usename = ANY(CAST(:roles AS text[]))"
            ),
            {"roles": [name for name, _ in roles.bindings()]},
        ).scalar_one()
    )


def _require_originals_denied(
    conn: Connection, roles: CandidateRoles, proof: fence.FenceProof
) -> None:
    originals = tuple(sorted({*proof.fenced_roles, *proof.member_roles}))
    if _sessions(conn, roles.database, originals):
        raise CandidateRoleRefused("original writer sessions remain")
    for name in originals:
        if conn.execute(
            text("SELECT has_database_privilege(:role, :db, 'CONNECT')"),
            {"role": name, "db": roles.database},
        ).scalar_one():
            raise CandidateRoleRefused("an original writer regained CONNECT")
    if not conn.execute(
        text("SELECT has_database_privilege(:role, :db, 'CONNECT')"),
        {"role": fence.MIGRATION_ROLE, "db": roles.database},
    ).scalar_one():
        raise CandidateRoleRefused("the migration owner lost CONNECT")


def _require_candidate_acl_delta(
    conn: Connection,
    roles: CandidateRoles,
    proof: fence.FenceProof,
    *,
    connected: set[str],
) -> None:
    candidates = {name for name, _ in roles.bindings()}
    if not connected <= candidates:
        raise CandidateRoleRefused("candidate CONNECT set is not canonical")
    owner = fence._database_owner(conn, roles.database)
    expected = _strict_grants(proof) | {
        (name, "CONNECT", False, owner) for name in connected
    }
    if set(fence._current_grants(conn, roles.database)) != expected:
        raise CandidateRoleRefused("the staged database ACL delta drifted")
    _require_originals_denied(conn, roles, proof)


def _require_target_only_connect(conn: Connection, roles: CandidateRoles) -> None:
    """A PostgreSQL LOGIN is cluster-wide, so inspect every connectable DB."""
    other_database = conn.execute(
        text(
            "SELECT d.datname FROM pg_database d "
            "WHERE d.datallowconn AND d.datname <> :target "
            "AND (has_database_privilege(:app, d.datname, 'CONNECT') "
            "OR has_database_privilege(:platform, d.datname, 'CONNECT')) "
            "LIMIT 1"
        ),
        {"target": roles.database, "app": roles.app, "platform": roles.platform},
    ).scalar_one_or_none()
    if other_database is not None:
        raise CandidateRoleRefused(
            "a candidate identity can CONNECT to another database"
        )


def deactivate(
    conn: Connection,
    roles: CandidateRoles,
    proof: fence.FenceProof,
    *,
    expected_digest: str,
    expected_fence_id: str,
) -> None:
    """Idempotently close a fully or partially activated candidate pair."""
    _require_superuser_autocommit(conn)
    _require_bound_proof(
        roles,
        proof,
        expected_digest=expected_digest,
        expected_fence_id=expected_fence_id,
    )
    names = {name for name, _ in roles.bindings()}
    states = _role_states(conn, roles)
    if set(states) != names or any(
        state[1:] != (False, False, False, False, False, True, True)
        for state in states.values()
    ):
        raise CandidateRoleRefused("candidate role privilege state drifted")
    _require_membership_delta(conn, roles, proof, names)
    owner = fence._database_owner(conn, roles.database)
    current = set(fence._current_grants(conn, roles.database))
    connected = {name for name in names if (name, "CONNECT", False, owner) in current}
    _require_candidate_acl_delta(conn, roles, proof, connected=connected)
    for name in names:
        conn.execute(text(f"ALTER ROLE {_identifier(conn, name)} NOLOGIN"))
        conn.execute(
            text(
                f"REVOKE CONNECT ON DATABASE {_identifier(conn, roles.database)} "
                f"FROM {_identifier(conn, name)}"
            )
        )
    if _candidate_sessions(conn, roles):
        raise CandidateRoleRefused("candidate sessions remain after entry closed")
    _require_role_shape(conn, roles, login=False)
    _require_candidate_acl_delta(conn, roles, proof, connected=set())


def activate(
    conn: Connection,
    roles: CandidateRoles,
    proof: fence.FenceProof,
    *,
    expected_digest: str,
    expected_fence_id: str,
) -> None:
    """Open only candidate connectivity after strict original ACL proof.

    A separate credential installer must have set both password verifiers
    while these roles were NOLOGIN. This function reads only verifier presence.
    """
    _require_canonical(roles)
    _require_superuser_autocommit(conn)
    _require_role_shape(conn, roles, login=False)
    _require_bound_proof(
        roles,
        proof,
        expected_digest=expected_digest,
        expected_fence_id=expected_fence_id,
    )
    names = tuple(name for name, _ in roles.bindings())
    _require_membership_delta(conn, roles, proof, set(names))
    _require_candidate_acl_delta(conn, roles, proof, connected=set())
    _require_target_only_connect(conn, roles)
    present = set(
        conn.execute(
            text(
                "SELECT rolname FROM pg_authid "
                "WHERE rolname = ANY(CAST(:names AS text[])) "
                "AND rolpassword IS NOT NULL"
            ),
            {"names": list(names)},
        ).scalars()
    )
    if present != set(names):
        raise CandidateRoleRefused(
            "every candidate app role needs a held password before LOGIN"
        )
    try:
        for name in names:
            conn.execute(
                text(
                    f"GRANT CONNECT ON DATABASE {_identifier(conn, roles.database)} "
                    f"TO {_identifier(conn, name)}"
                )
            )
            conn.execute(text(f"ALTER ROLE {_identifier(conn, name)} LOGIN"))
        _require_role_shape(conn, roles, login=True)
        _require_candidate_acl_delta(conn, roles, proof, connected=set(names))
    except BaseException:
        for name in names:
            conn.execute(text(f"ALTER ROLE {_identifier(conn, name)} NOLOGIN"))
            conn.execute(
                text(
                    f"REVOKE CONNECT ON DATABASE {_identifier(conn, roles.database)} "
                    f"FROM {_identifier(conn, name)}"
                )
            )
        raise


def verify_staged_database(
    conn: Connection,
    roles: CandidateRoles,
    proof: fence.FenceProof,
    *,
    expected_digest: str,
    expected_fence_id: str,
) -> bool:
    """Database-only staged verdict; image, heads and URL checks remain external.

    Strict ``fence_is_holding`` is expected to be false while candidates have
    CONNECT. This checks the precise ACL delta from the original strict fence.
    """
    try:
        _require_canonical(roles)
        _require_bound_proof(
            roles,
            proof,
            expected_digest=expected_digest,
            expected_fence_id=expected_fence_id,
        )
        _require_role_shape(conn, roles, login=True)
        candidates = {name for name, _ in roles.bindings()}
        _require_membership_delta(conn, roles, proof, candidates)
        _require_candidate_acl_delta(conn, roles, proof, connected=candidates)
        _require_target_only_connect(conn, roles)
        for name in candidates:
            if not conn.execute(
                text("SELECT has_database_privilege(:role, :db, 'CONNECT')"),
                {"role": name, "db": roles.database},
            ).scalar_one():
                return False
        return True
    except (CandidateRoleRefused, TypeError):
        return False


def restore_after_candidate(
    conn: Connection,
    roles: CandidateRoles,
    proof: fence.FenceProof,
    *,
    expected_digest: str,
    expected_fence_id: str,
    session_wait_seconds: float,
    terminator: fence.Terminator | None = None,
) -> fence.UnfenceProof:
    """Restore only after candidates are gone and strict proof holds again.

    The generic fence restore has no candidate lifecycle. The deployment
    adapter must use this wrapper, never call it directly after staging.
    """
    _require_canonical(roles)
    _require_bound_proof(
        roles,
        proof,
        expected_digest=expected_digest,
        expected_fence_id=expected_fence_id,
    )
    if _existing(conn, tuple(name for name, _ in roles.bindings())):
        raise CandidateRoleRefused("candidate roles remain before ACL restore")
    _require_bound_strict_fence(
        conn,
        roles,
        proof,
        expected_digest=expected_digest,
        expected_fence_id=expected_fence_id,
    )
    _require_strict_acl(conn, proof)
    return fence.restore_writers(
        conn,
        proof,
        database=roles.database,
        expected_fence_id=expected_fence_id,
        session_wait_seconds=session_wait_seconds,
        terminator=terminator,
    )


def cleanup_before_restore(
    conn: Connection,
    roles: CandidateRoles,
    proof: fence.FenceProof,
    *,
    expected_digest: str,
    expected_fence_id: str,
) -> None:
    """Atomically revoke membership and drop candidates before ACL restore.

    A retry accepts one already-absent role, but no shape or ACL drift. The
    surviving role stays a writer member until the transactional DROP commits,
    so generic restore still refuses while any candidate remains.
    """
    _require_canonical(roles)
    _require_superuser_autocommit(conn)
    _require_bound_proof(
        roles,
        proof,
        expected_digest=expected_digest,
        expected_fence_id=expected_fence_id,
    )
    names = tuple(name for name, _ in roles.bindings())
    present = _existing(conn, names)
    states = _role_states(conn, roles)
    if set(states) != present or any(
        state != (False, False, False, False, False, False, True, True)
        for state in states.values()
    ):
        raise CandidateRoleRefused("candidate role privilege or login state drifted")
    _require_membership_delta(conn, roles, proof, present)
    _require_candidate_acl_delta(conn, roles, proof, connected=set())
    if _candidate_sessions(conn, roles):
        raise CandidateRoleRefused("candidate sessions remain")
    if present:
        statements: list[str] = []
        for name, parent in roles.bindings():
            if name in present:
                statements.extend(
                    (
                        f"REVOKE {_identifier(conn, parent)} "
                        f"FROM {_identifier(conn, name)}",
                        f"DROP ROLE {_identifier(conn, name)}",
                    )
                )
        conn.exec_driver_sql(
            "DO $candidate$ BEGIN " + "; ".join(statements) + "; END $candidate$"
        )
    if _existing(conn, names) or not fence.fence_is_holding(conn, proof):
        raise CandidateRoleRefused("original strict fence was not recovered")
    _require_strict_acl(conn, proof)
