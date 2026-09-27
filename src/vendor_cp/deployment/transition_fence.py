"""Fence every writer role off a database, hold the fence, then release it.

Today `scripts/deploy_production.sh` backs up, migrates, then replaces the
relay and the app WHILE the old writers stay connected (deploy_production.sh
lines 438, 446-447). A backend that opens between the backup and the schema
change observes a database mid-migration and can write through it. D16 fences
every writer role for the whole transition; PR 2 wires that fence into the
deploy script's maintenance window. This module is that fence, on its own: a
pure library over a caller-supplied connection, no process and no environment
access.

## Why REVOKE CONNECT rather than a lock or a flag

A row-level flag only stops writers that check it. `REVOKE CONNECT ON
DATABASE ... FROM <role>` stops a NEW backend from authenticating as that role
against this database at all, independently of what the application does or
does not check, and `has_database_privilege` lets the fence PROVE the revoke
took rather than merely issuing it and hoping. A backend already connected
when the fence closes is a separate hazard REVOKE CONNECT does not touch,
which is why `fence_writers` also terminates and waits for every open writer
session.

## The connection must be AUTOCOMMIT

On a transactional connection the REVOKE is invisible to every OTHER backend
until this connection commits, and a rollback silently erases the fence while
a `FenceProof` claiming otherwise still exists. `fence_writers` and
`restore_writers` both refuse (`connection_not_autocommit`) before touching
anything unless the DRIVER connection's own `autocommit` flag is True
(`Connection.get_isolation_level()` is not used: it reports the server's
isolation level, which still reads "read committed" under autocommit).

## The prior ACL is the thing being protected, not the fence's own state

`restore_writers` puts the database back to EXACTLY the ACL that was there
before the fence closed — never a hardcoded default, and never "whatever
GRANT CONNECT TO PUBLIC would produce" — because a database's prior ACL can
carry privileges (CREATE, TEMPORARY, a narrower grant to a third role) this
module never touched and has no business re-deriving. Re-fencing an
already-fenced database (`fence_writers(..., prior=proof)`) keeps that same
original ACL rather than recording the already-revoked one as "prior",
because the second call's own view of `pg_database.datacl` is the fence's own
handiwork, not evidence about what the database looked like before anyone
fenced it. A `prior=` a caller passes is bound: it must name the same
database and the same fenced-role set this call resolved, or `fence_writers`
refuses (`prior_mismatch`) before any change — a mismatched `prior` would let
one database's proof restore a different one's ACL.

## The ACL is compared as decomposed grants, never as text

`pg_database.datacl::text` is PostgreSQL's own rendering, and a grantee that
needs quoting (a capital letter, a space, a literal `,` `=` or `/`) renders
quoted in ways that are easy to mis-parse by hand. Every comparison in this
module instead reads `aclexplode()` — the server's own decomposition of the
ACL into `(grantee, privilege_type, is_grantable)` rows, with PUBLIC's
grantee oid (0) resolved to `""` — and compares frozensets of that tuple.
`FenceProof.prior_acl` keeps the raw text for the human record, but nothing
compares it. Grantors are dropped from the comparison entirely; a role that
re-grants the identical privilege under a different grantor is not a
disagreement this module is in a position to police.

## Unknown is not absent

A writer role named in `WRITER_ROLES` that does not exist in this cluster is
recorded in `FenceProof.absent_roles`, never silently dropped from the roles
the fence reports on. A role that exists and keeps CONNECT is a fence that did
not hold; a role that was never there is a different fact, and collapsing the
two would let a typo'd role name pass as "fenced" when nothing was ever
checked.

## The effective set: a writer's own members are fenced too

`WRITER_ROLES` names login roles, but PostgreSQL role membership is
transitive: a role M that is a member of a fenced writer W can `SET ROLE W`
from an already-open session and keep writing, and if M holds its own CONNECT
grant it can reconnect on its own identity regardless of what happens to W's.
Ruled 2026-09-27: `fence_writers` resolves the EFFECTIVE set once, after the
named writers are resolved against the cluster — `effective = fenced ∪ {r :
r != w, pg_has_role(r, w, 'MEMBER') for some fenced writer w}` — and records
the members on `FenceProof.member_roles` (never silently dropped, the same
`absent_roles` discipline as unknown roles). Every pre-check (superuser,
shared identity with `MIGRATION_ROLE`, inherited CONNECT), the REVOKE, the
`has_database_privilege` verification and the drain all run over this
effective set, not only the named writers. `restore_writers` re-derives the
same effective set from `fenced_roles + member_roles` on the proof, so
`allowed_grantees` and a `prior=` binding both cover it too.

## Inherited CONNECT cannot be revoked away, so it is refused up front

`REVOKE CONNECT ON DATABASE ... FROM <role>` only ever touches that role's own
ACL entry. `has_database_privilege` still resolves role membership and
ownership when it answers "can this role connect" — PostgreSQL grants a
database's owner (and every member of the owner) an implicit CONNECT that no
`REVOKE` on the database's ACL removes, and a role that is a member of another
role holding CONNECT keeps it through that membership regardless of what its
own ACL entry says. Ruled 2026-09-26: a writer that is the database owner, a
member of the owner, or a member of `MIGRATION_ROLE` cannot be fenced by
revoking, so `fence_writers` REFUSES (`writer_inherits_connect`) before
touching the ACL at all, rather than revoking, "verifying" against a
privilege check that was never going to change, and returning a proof that
lies.

## A writer role sharing identity with the migrator is refused, not fenced

Fencing "the migrator" would defeat the migration it is meant to protect. If a
role named in `WRITER_ROLES` IS `MIGRATION_ROLE`, or the two share role
membership in either direction (`pg_has_role` both ways), there is no ACL
state that fences one without the other — so `fence_writers` refuses
(`shared_writer_role`) before any change, the same as the inherited-CONNECT
case above. The identical check also catches one login role appearing twice
in the writer set after resolution, which is the same hazard by a different
route: revoking and re-granting the same role under two names would race with
itself.

## Every exception after the first ACL change is compensated

Once `_apply_fence` has issued its first REVOKE, any exception at all —
another `FenceRefused`, a driver error, a timeout, `KeyboardInterrupt` — is
caught, the ACL is restored to what this call started from, and only then is
the failure reported. If the compensating restore itself fails, the caller
gets `FenceRefused(COMPENSATION_FAILED)` chained from the original exception,
with `before_acl` set on it, so an operator always holds the exact ACL to
restore by hand rather than a stack trace alone.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final

from sqlalchemy import text
from sqlalchemy.engine import Connection

__all__ = [
    "MIGRATION_ROLE",
    "WRITER_ROLES",
    "FenceProof",
    "FenceRefusalCode",
    "FenceRefused",
    "UnfenceProof",
    "fence_is_holding",
    "fence_writers",
    "restore_writers",
]

#: The long-running application, relay and dispatcher identities (see
#: `docker-compose.production.yml` and the deploy script's role list). Every
#: one of these is a role that can hold an open session against the database
#: while a migration runs.
WRITER_ROLES: Final[tuple[str, ...]] = (
    "app_user",
    "platform_api",
    "platform_outbox_dispatcher",
    "outbox_dispatcher",
)

#: The migrator. Never fenced, and its CONNECT privilege is part of what
#: `fence_writers` verifies rather than merely assumes.
MIGRATION_ROLE: Final = "app_admin"

#: How often to re-poll `pg_stat_activity` while waiting for terminated writer
#: backends to actually disappear.
_POLL_INTERVAL_SECONDS: Final = 0.05


class FenceRefusalCode(StrEnum):
    """A closed set. Exception messages carry one of these plus role names —
    never a DSN, never a query result beyond a role or database name."""

    WRITER_STILL_HAS_CONNECT = "writer_still_has_connect"
    MIGRATION_ROLE_LOST_CONNECT = "migration_role_lost_connect"
    WRITER_SESSIONS_SURVIVED = "writer_sessions_survived"
    ACL_NOT_RESTORED = "acl_not_restored"
    UNKNOWN_DATABASE = "unknown_database"
    #: A writer owns the database, or is a member of its owner or of
    #: `MIGRATION_ROLE`: CONNECT it holds through that path survives every
    #: REVOKE this module can issue, so nothing is changed and this is raised
    #: instead.
    WRITER_INHERITS_CONNECT = "writer_inherits_connect"
    #: A writer role is `MIGRATION_ROLE` itself, shares role membership with
    #: it in either direction, or the same login role was named twice in the
    #: writer set.
    SHARED_WRITER_ROLE = "shared_writer_role"
    #: `conn` is not AUTOCOMMIT. Checked before any change.
    CONNECTION_NOT_AUTOCOMMIT = "connection_not_autocommit"
    #: A `prior=` proof named a different database, or a different fenced-role
    #: set, than this call resolved. Checked before any change.
    PRIOR_MISMATCH = "prior_mismatch"
    #: An exception (not itself a `FenceRefused`) interrupted fencing after the
    #: first ACL change; the ACL was successfully restored.
    FENCE_INTERRUPTED = "fence_interrupted"
    #: The compensating restore after an interrupted fence itself failed. The
    #: database may still be fenced; `before_acl` is the ACL to restore by
    #: hand.
    COMPENSATION_FAILED = "compensation_failed"


class FenceRefused(Exception):
    """Raised instead of returning a proof that lies about the fence state.

    `before_acl` is set on every refusal raised after the pre-checks (i.e.
    once `fence_writers` has read the database's starting ACL) — an operator
    who sees this exception always has the exact ACL to restore to, even when
    the automatic compensation itself failed.
    """

    def __init__(
        self,
        code: FenceRefusalCode,
        detail: str,
        *,
        before_acl: str | None = None,
    ) -> None:
        self.code = code
        self.detail = detail
        self.before_acl = before_acl
        super().__init__(f"{code}: {detail}")


#: A decomposed ACL: `(grantee, privilege_type, is_grantable)`. PUBLIC's
#: grantee is `""`. Grantors are never part of this comparison.
_Grants = frozenset[tuple[str, str, bool]]


@dataclass(frozen=True, slots=True)
class FenceProof:
    """What the fence did, verified rather than assumed.

    `prior_acl` is the database's ACL exactly as `pg_database.datacl::text`
    read it (or the materialised `acldefault('d', datdba)` when that was
    NULL) before this fence's first REVOKE — kept for the human record, but
    `prior_grants` (the identical ACL decomposed into `(grantee,
    privilege_type, is_grantable)` tuples via `aclexplode`) is what
    `restore_writers` actually compares against; see the module docstring for
    why text comparison is refused."""

    database: str
    prior_acl: str
    prior_grants: _Grants
    fenced_roles: tuple[str, ...]
    #: Every role, other than a named writer itself, that transitively holds
    #: membership in a named writer (`pg_has_role(role, writer, 'MEMBER')`).
    #: These roles can `SET ROLE` to a fenced writer and keep writing, or
    #: reconnect under their own CONNECT grant, so every pre-check and the
    #: revoke/verify/drain all run over `fenced_roles + member_roles`
    #: together (see the module docstring's "effective set" section).
    member_roles: tuple[str, ...]
    absent_roles: tuple[str, ...]
    terminated_count: int
    fenced_at: datetime


@dataclass(frozen=True, slots=True)
class UnfenceProof:
    """The result of `restore_writers`: the ACL is back, verified equal."""

    database: str
    restored_at: datetime
    roles_restored: tuple[str, ...]


def _quote_ident(conn: Connection, name: str) -> str:
    """Delegate quoting to PostgreSQL itself rather than reimplementing it.

    `quote_ident` is the server's own answer to "how do I write this
    identifier back into SQL safely" — no format-string interpolation of a
    role or database name ever happens in this module."""
    return str(
        conn.execute(text("SELECT quote_ident(:name)"), {"name": name}).scalar_one()
    )


def _role_ref_sql(conn: Connection, grantee: str) -> str:
    """`""` (PUBLIC, from `aclexplode`) or a quoted role identifier."""
    return "PUBLIC" if grantee == "" else _quote_ident(conn, grantee)


def _require_autocommit(conn: Connection) -> None:
    """`connection_not_autocommit`, checked before any change.

    On a transactional connection the REVOKE is invisible to every other
    backend until this connection commits, and a rollback would erase the
    fence while a `FenceProof` claiming otherwise still exists."""
    # The DRIVER connection's own autocommit flag, not
    # `Connection.get_isolation_level()`: that queries the server's isolation
    # level, which still reads "read committed" under autocommit.
    dbapi_connection = conn.connection.dbapi_connection
    if getattr(dbapi_connection, "autocommit", False) is not True:
        raise FenceRefused(
            FenceRefusalCode.CONNECTION_NOT_AUTOCOMMIT,
            "the connection is not AUTOCOMMIT; a REVOKE issued on it is "
            "invisible to other backends until commit, and a rollback would "
            "erase the fence while a proof of it exists",
        )


def _database_exists(conn: Connection, database: str) -> bool:
    return (
        conn.execute(
            text("SELECT 1 FROM pg_database WHERE datname = :db"), {"db": database}
        ).first()
        is not None
    )


def _existing_roles(conn: Connection, roles: tuple[str, ...]) -> set[str]:
    if not roles:
        return set()
    rows = conn.execute(
        text("SELECT rolname FROM pg_roles WHERE rolname = ANY(:roles)"),
        {"roles": list(roles)},
    )
    return {row[0] for row in rows}


def _duplicates(values: tuple[str, ...]) -> tuple[str, ...]:
    seen: set[str] = set()
    dupes: set[str] = set()
    for value in values:
        if value in seen:
            dupes.add(value)
        seen.add(value)
    return tuple(sorted(dupes))


_MEMBER_ROLES_QUERY: Final = text(
    "SELECT DISTINCT r.rolname FROM pg_roles r "
    "JOIN unnest(CAST(:writers AS text[])) AS w(rolname) ON true "
    "WHERE r.rolname <> ALL(CAST(:writers AS text[])) "
    "AND pg_has_role(r.rolname, w.rolname, 'MEMBER')"
)


def _member_roles(conn: Connection, fenced: tuple[str, ...]) -> tuple[str, ...]:
    """Every role, other than a fenced writer itself, that is a (transitive)
    member of any fenced writer — the roles that inherit a writer's CONNECT
    through `SET ROLE` and are therefore part of the effective set (see the
    module docstring)."""
    if not fenced:
        return ()
    rows = conn.execute(_MEMBER_ROLES_QUERY, {"writers": list(fenced)})
    return tuple(sorted({str(row[0]) for row in rows}))


def _database_owner(conn: Connection, database: str) -> str:
    """The database owner's role name, resolved from `pg_database.datdba`."""
    return str(
        conn.execute(
            text("SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = :db"),
            {"db": database},
        ).scalar_one()
    )


def _is_member_of(conn: Connection, member: str, role: str) -> bool:
    """`pg_has_role(member, role, 'MEMBER')` — resolves the full membership
    chain, not only a direct GRANT."""
    return bool(
        conn.execute(
            text("SELECT pg_has_role(:member, :role, 'MEMBER')"),
            {"member": member, "role": role},
        ).scalar_one()
    )


def _reject_shared_writer_roles(
    conn: Connection, effective: tuple[str, ...], writer_roles: tuple[str, ...]
) -> None:
    """`shared_writer_role`, checked before any ACL change, against every
    EFFECTIVE role (named writers plus every role that is a member of one —
    see the module docstring's "effective set" section).

    Fencing a role that IS the migrator, or that shares membership with it in
    either direction, would fence the migration it exists to protect. The
    identical hazard shows up as one login role named twice in the writer set,
    so that is checked here too.
    """
    duplicates = _duplicates(writer_roles)
    if duplicates:
        raise FenceRefused(
            FenceRefusalCode.SHARED_WRITER_ROLE,
            f"{duplicates} named more than once in the writer set — the same "
            "login role fenced under two names would race with itself",
        )
    for role in effective:
        if role == MIGRATION_ROLE:
            raise FenceRefused(
                FenceRefusalCode.SHARED_WRITER_ROLE,
                f"effective writer role {role!r} IS the migration role "
                f"{MIGRATION_ROLE!r}",
            )
        if _is_member_of(conn, MIGRATION_ROLE, role) or _is_member_of(
            conn, role, MIGRATION_ROLE
        ):
            raise FenceRefused(
                FenceRefusalCode.SHARED_WRITER_ROLE,
                f"effective writer role {role!r} shares role membership with "
                f"the migration role {MIGRATION_ROLE!r}",
            )


def _reject_superuser_writers(conn: Connection, effective: tuple[str, ...]) -> None:
    """A superuser keeps CONNECT through every REVOKE (and is a member of every
    role, so it would otherwise surface as a shared role): refused first.

    Runs over the EFFECTIVE role set (named writers plus every role that is a
    member of one), not only the named writers.
    """
    for role in effective:
        is_superuser = conn.execute(
            text("SELECT rolsuper FROM pg_roles WHERE rolname = :role"),
            {"role": role},
        ).scalar_one()
        if is_superuser:
            raise FenceRefused(
                FenceRefusalCode.WRITER_INHERITS_CONNECT,
                f"effective writer role {role!r} is a superuser; no REVOKE "
                "removes its CONNECT",
            )


def _require_migration_connect_without_public(
    conn: Connection, database: str, grants: _Grants
) -> None:
    """`migration_role_lost_connect`, checked before any ACL change.

    The fence revokes PUBLIC. If the migration role's CONNECT rests only on
    PUBLIC (it neither owns the database, nor is a member of the owner, nor is
    a member of any explicit non-PUBLIC grantee), the fence would lock the
    migrator out with the writers. Production's contract is that `app_admin`
    owns the database, so this refuses anything else up front."""
    owner = _database_owner(conn, database)
    if MIGRATION_ROLE == owner or _is_member_of(conn, MIGRATION_ROLE, owner):
        return
    grantees = (grantee for grantee, priv, _ in grants if priv == "CONNECT" and grantee)
    if any(_is_member_of(conn, MIGRATION_ROLE, grantee) for grantee in grantees):
        return
    raise FenceRefused(
        FenceRefusalCode.MIGRATION_ROLE_LOST_CONNECT,
        f"migration role {MIGRATION_ROLE!r} holds CONNECT on {database!r} only "
        "through PUBLIC; fencing would lock the migrator out too",
    )


def _reject_inherited_connect(
    conn: Connection, effective: tuple[str, ...], database: str, grants: _Grants
) -> None:
    """`writer_inherits_connect`, checked before any ACL change, against every
    EFFECTIVE role (named writers plus every role that is a member of one —
    see the module docstring's "effective set" section).

    `REVOKE CONNECT ON DATABASE ... FROM <role>` only ever edits that role's
    own ACL entry. A database owner (and every member of the owner) holds an
    implicit CONNECT no such REVOKE removes, and a member of `MIGRATION_ROLE`
    inherits that role's CONNECT the same way — so this cannot be fenced by
    revoking, and is refused instead of revoked, "verified", and returned as a
    proof that lies.
    """
    owner = _database_owner(conn, database)
    # Every explicit CONNECT grantee in the ACL this call starts from, other
    # than PUBLIC (revoked) and every effective role itself (each revoked). An
    # effective role that is a member of ANY such grantee keeps CONNECT
    # through that membership after every REVOKE this module issues.
    other_grantees = tuple(
        grantee
        for grantee, priv, _ in grants
        if priv == "CONNECT" and grantee and grantee not in effective
    )
    for role in effective:
        for grantee in other_grantees:
            if _is_member_of(conn, role, grantee):
                raise FenceRefused(
                    FenceRefusalCode.WRITER_INHERITS_CONNECT,
                    f"writer role {role!r} is a member of {grantee!r}, which "
                    f"holds its own CONNECT on {database!r}; that inherited "
                    "CONNECT survives every REVOKE this module can issue",
                )
        if role == owner:
            raise FenceRefused(
                FenceRefusalCode.WRITER_INHERITS_CONNECT,
                f"writer role {role!r} owns database {database!r}; CONNECT "
                "through ownership survives every REVOKE this module can issue",
            )
        if _is_member_of(conn, role, owner):
            raise FenceRefused(
                FenceRefusalCode.WRITER_INHERITS_CONNECT,
                f"writer role {role!r} is a member of database owner "
                f"{owner!r}; CONNECT inherited through membership survives "
                "every REVOKE this module can issue",
            )
        if _is_member_of(conn, role, MIGRATION_ROLE):
            raise FenceRefused(
                FenceRefusalCode.WRITER_INHERITS_CONNECT,
                f"writer role {role!r} is a member of the migration role "
                f"{MIGRATION_ROLE!r}; CONNECT inherited through membership "
                "survives every REVOKE this module can issue",
            )


def _current_acl_text(conn: Connection, database: str) -> str:
    """`pg_database.datacl::text`, or the materialised default when NULL.

    NULL `datacl` means "nobody has ever explicitly GRANTed or REVOKEd" —
    PostgreSQL answers privilege checks against the implicit default in that
    case, and `acldefault('d', datdba)` is that default made explicit so the
    prior state this module restores to is never a guess. Kept for the human
    record on `FenceProof.prior_acl`; see `_current_grants` for the form
    every comparison in this module actually uses."""
    row = conn.execute(
        text("SELECT datacl::text, datdba FROM pg_database WHERE datname = :db"),
        {"db": database},
    ).one()
    acl_text, owner_oid = row
    if acl_text is not None:
        return str(acl_text)
    return str(
        conn.execute(
            text("SELECT acldefault('d', :owner)::text"), {"owner": owner_oid}
        ).scalar_one()
    )


_GRANTS_QUERY: Final = text(
    "SELECT COALESCE(r.rolname, '') AS grantee, a.privilege_type, a.is_grantable "
    "FROM pg_database d, "
    "aclexplode(COALESCE(d.datacl, acldefault('d', d.datdba))) a "
    "LEFT JOIN pg_roles r ON r.oid = a.grantee "
    "WHERE d.datname = :db"
)


def _current_grants(conn: Connection, database: str) -> _Grants:
    """The database's ACL, decomposed by the server itself via `aclexplode`.

    PUBLIC's grantee oid is 0, which `pg_roles` never matches, so
    `COALESCE(r.rolname, '')` resolves it to `""` — the same sentinel used
    throughout this module. Grantors are discarded: nothing here compares
    them."""
    rows = conn.execute(_GRANTS_QUERY, {"db": database})
    return frozenset((str(row[0]), str(row[1]), bool(row[2])) for row in rows)


def fence_writers(
    conn: Connection,
    *,
    database: str,
    writer_roles: tuple[str, ...] = WRITER_ROLES,
    session_wait_seconds: float,
    prior: FenceProof | None = None,
) -> FenceProof:
    """Revoke CONNECT from every existing writer role, verify it, then drain.

    `conn` must be held by a superuser (or a role with `pg_signal_backend`):
    terminating another role's backends needs that, and database ownership
    alone does not grant it. Without it the drain times out and the fence is
    compensated, so it fails safe. Production holds this over the cluster
    superuser's socket connection, the same identity `pg_dumpall` already
    uses.
    """
    _require_autocommit(conn)

    if not _database_exists(conn, database):
        raise FenceRefused(
            FenceRefusalCode.UNKNOWN_DATABASE,
            f"no database named {database!r} exists in this cluster",
        )

    existing = _existing_roles(conn, writer_roles)
    absent = tuple(role for role in writer_roles if role not in existing)
    fenced = tuple(role for role in writer_roles if role in existing)
    # The EFFECTIVE set: every named writer, plus every role that is a
    # (transitive) member of one. A login role that is a member of a fenced
    # writer can `SET ROLE` to it and keep writing, or hold its own CONNECT
    # grant and reconnect — so every pre-check, the revoke, the verification
    # and the drain below all run over this set, not just `fenced`. See the
    # module docstring's "effective set" section.
    member_roles = _member_roles(conn, fenced)
    effective = tuple(dict.fromkeys((*fenced, *member_roles)))

    if prior is not None and (
        prior.database != database
        or set(prior.fenced_roles) != set(fenced)
        or set(prior.member_roles) != set(member_roles)
    ):
        raise FenceRefused(
            FenceRefusalCode.PRIOR_MISMATCH,
            f"prior proof names database {prior.database!r}, fenced roles "
            f"{sorted(prior.fenced_roles)} and member roles "
            f"{sorted(prior.member_roles)}, but this call resolved "
            f"{database!r}, {sorted(fenced)} and {sorted(member_roles)} — a "
            "mismatched prior would restore the wrong ACL",
        )

    # Every check below runs before any ACL change, and over the EFFECTIVE
    # role set. None of these hazards can be repaired by revoking — a role
    # that inherits CONNECT through ownership or membership keeps it
    # regardless, and a role sharing identity with the migrator would fence
    # the migration along with it — so all are refused rather than revoked
    # and then "verified" against a privilege check that was never going to
    # move.
    before_acl = _current_acl_text(conn, database)
    before_grants = _current_grants(conn, database)
    _reject_superuser_writers(conn, effective)
    _require_migration_connect_without_public(conn, database, before_grants)
    _reject_shared_writer_roles(conn, effective, writer_roles)
    _reject_inherited_connect(conn, effective, database, before_grants)

    prior_acl = prior.prior_acl if prior is not None else before_acl
    prior_grants = prior.prior_grants if prior is not None else before_grants

    try:
        return _apply_fence(
            conn,
            database=database,
            fenced=fenced,
            member_roles=member_roles,
            effective=effective,
            absent=absent,
            prior_acl=prior_acl,
            prior_grants=prior_grants,
            session_wait_seconds=session_wait_seconds,
        )
    except BaseException as exc:
        # Any exception at all after the first REVOKE — another refusal, a
        # driver error, a timeout, KeyboardInterrupt — puts the ACL back to
        # what THIS call started from, never leaves a half-fenced database
        # with no proof to restore from. On a re-fence that is the
        # still-holding fence, not the original prior ACL.
        compensating = FenceProof(
            database=database,
            prior_acl=before_acl,
            prior_grants=before_grants,
            member_roles=member_roles,
            fenced_roles=fenced,
            absent_roles=absent,
            terminated_count=0,
            # A local timestamp, never a query: on a dropped connection a
            # `SELECT now()` here would raise raw and lose `before_acl` on the
            # very path that guarantee exists for.
            fenced_at=datetime.now(UTC),
        )
        try:
            restore_writers(conn, compensating)
        except BaseException as restore_exc:
            failure = FenceRefused(
                FenceRefusalCode.COMPENSATION_FAILED,
                f"restoring the ACL for {database!r} after {exc!r} itself "
                f"failed: {restore_exc!r}; the database may still be fenced "
                "— restore to before_acl by hand",
                before_acl=before_acl,
            )
            raise failure from exc
        if isinstance(exc, KeyboardInterrupt | SystemExit):
            raise
        if isinstance(exc, FenceRefused):
            exc.before_acl = before_acl
            raise
        raise FenceRefused(
            FenceRefusalCode.FENCE_INTERRUPTED,
            f"fencing {database!r} was interrupted after the first ACL "
            f"change: {exc!r}",
            before_acl=before_acl,
        ) from exc


def _writer_pids(
    conn: Connection, database: str, writers: tuple[str, ...]
) -> list[int]:
    return list(
        conn.execute(
            text(
                "SELECT pid FROM pg_stat_activity WHERE datname = :db "
                "AND usename = ANY(:writers) AND pid <> pg_backend_pid()"
            ),
            {"db": database, "writers": list(writers)},
        )
        .scalars()
        .all()
    )


def _terminate_and_drain(
    conn: Connection,
    database: str,
    roles: tuple[str, ...],
    session_wait_seconds: float,
) -> int:
    """Terminate every open backend for `roles` and block until TWO
    CONSECUTIVE polls, a full `_POLL_INTERVAL_SECONDS` apart, both find zero
    remaining — `pg_terminate_backend` merely requests termination, and a
    single zero reading can race a backend that is mid-termination and about
    to be replaced by a reconnect. Raises `WRITER_SESSIONS_SURVIVED` if the
    drain does not converge within `session_wait_seconds` (the deadline
    bounds the whole drain, not the two-poll confirmation). Returns the
    number of backends terminated on entry."""
    if not roles:
        return 0
    backends = _writer_pids(conn, database, roles)
    terminated_count = len(backends)
    for pid in backends:
        conn.execute(text("SELECT pg_terminate_backend(:pid)"), {"pid": pid})

    deadline = time.monotonic() + session_wait_seconds
    while True:
        remaining = _writer_pids(conn, database, roles)
        if not remaining:
            time.sleep(_POLL_INTERVAL_SECONDS)
            confirm = _writer_pids(conn, database, roles)
            if not confirm:
                return terminated_count
            remaining = confirm
        if time.monotonic() >= deadline:
            raise FenceRefused(
                FenceRefusalCode.WRITER_SESSIONS_SURVIVED,
                f"{len(remaining)} writer backend(s) on {database!r} "
                f"survived {session_wait_seconds}s of draining",
            )
        for pid in remaining:
            conn.execute(text("SELECT pg_terminate_backend(:pid)"), {"pid": pid})
        time.sleep(_POLL_INTERVAL_SECONDS)


def _apply_fence(
    conn: Connection,
    *,
    database: str,
    fenced: tuple[str, ...],
    member_roles: tuple[str, ...],
    effective: tuple[str, ...],
    absent: tuple[str, ...],
    prior_acl: str,
    prior_grants: _Grants,
    session_wait_seconds: float,
) -> FenceProof:
    """The mutating half of `fence_writers`; its caller compensates a refusal.

    Every revoke, verification and drain below runs over the EFFECTIVE role
    set (`fenced` plus `member_roles`) — see the module docstring's
    "effective set" section.
    """
    quoted_db = _quote_ident(conn, database)
    conn.execute(text(f"REVOKE CONNECT ON DATABASE {quoted_db} FROM PUBLIC"))
    for role in effective:
        quoted_role = _quote_ident(conn, role)
        conn.execute(text(f"REVOKE CONNECT ON DATABASE {quoted_db} FROM {quoted_role}"))

    for role in effective:
        still_connect = conn.execute(
            text("SELECT has_database_privilege(:role, :db, 'CONNECT')"),
            {"role": role, "db": database},
        ).scalar_one()
        if still_connect:
            raise FenceRefused(
                FenceRefusalCode.WRITER_STILL_HAS_CONNECT,
                f"role {role!r} still has CONNECT on {database!r} after revoke",
            )

    if not _existing_roles(conn, (MIGRATION_ROLE,)):
        raise FenceRefused(
            FenceRefusalCode.MIGRATION_ROLE_LOST_CONNECT,
            f"migration role {MIGRATION_ROLE!r} does not exist in this cluster",
        )
    migration_can_connect = conn.execute(
        text("SELECT has_database_privilege(:role, :db, 'CONNECT')"),
        {"role": MIGRATION_ROLE, "db": database},
    ).scalar_one()
    if not migration_can_connect:
        raise FenceRefused(
            FenceRefusalCode.MIGRATION_ROLE_LOST_CONNECT,
            f"migration role {MIGRATION_ROLE!r} lost CONNECT on {database!r}",
        )

    terminated_count = _terminate_and_drain(
        conn, database, effective, session_wait_seconds
    )

    fenced_at = conn.execute(text("SELECT now()")).scalar_one()
    return FenceProof(
        database=database,
        prior_acl=prior_acl,
        prior_grants=prior_grants,
        fenced_roles=fenced,
        member_roles=member_roles,
        absent_roles=absent,
        terminated_count=terminated_count,
        fenced_at=fenced_at,
    )


def _refence(conn: Connection, quoted_db: str, restored: list[str]) -> None:
    """Re-revoke CONNECT from PUBLIC and every role a failed restore granted."""
    revoke_grantees = dict.fromkeys(
        ["", *(role for role in restored if role != "PUBLIC")]
    )
    for grantee in revoke_grantees:
        conn.execute(
            text(
                f"REVOKE CONNECT ON DATABASE {quoted_db} FROM "
                f"{_role_ref_sql(conn, grantee)}"
            )
        )


def restore_writers(conn: Connection, proof: FenceProof) -> UnfenceProof:
    """Put the ACL back to exactly `proof.prior_grants`. Idempotent.

    Only re-grants CONNECT to a grantee the prior ACL actually held it for —
    never PUBLIC, never a fenced role, unless `prior_grants` says so — and
    then verifies the restored ACL exactly matches the prior one (compared as
    decomposed grants, never as raw text; see the module docstring) before
    returning. Refuses, before granting anything, if the current ACL holds a
    grant the prior ACL never had — something changed the ACL while it was
    fenced — and, if the restored ACL still does not match afterwards,
    re-revokes everything it just granted (plus PUBLIC) so the database stays
    fenced rather than silently half-open.
    """
    _require_autocommit(conn)

    quoted_db = _quote_ident(conn, proof.database)
    current = _current_grants(conn, proof.database)

    unexpected = current - proof.prior_grants
    if unexpected:
        raise FenceRefused(
            FenceRefusalCode.ACL_NOT_RESTORED,
            f"the ACL for {proof.database!r} holds grant(s) {sorted(unexpected)} "
            "absent from the fence's recorded prior ACL; something changed "
            "the ACL while it was fenced, so nothing was granted",
        )

    # The EFFECTIVE set this proof fenced: named writers plus every role that
    # was a member of one at fence time (see the module docstring's
    # "effective set" section) — the only grantees `fence_writers` could ever
    # have revoked, and so the only ones `restore_writers` may re-grant.
    effective = tuple(dict.fromkeys((*proof.fenced_roles, *proof.member_roles)))
    allowed_grantees = {"", *effective}
    missing = sorted(
        grant for grant in (proof.prior_grants - current) if grant[1] == "CONNECT"
    )
    # Every grantee is validated BEFORE the first GRANT. `missing` sorts
    # PUBLIC first, so a refusal found mid-loop would already have reopened
    # the database to every writer.
    disallowed = [
        grantee for grantee, _p, _g in missing if grantee not in allowed_grantees
    ]
    if disallowed:
        raise FenceRefused(
            FenceRefusalCode.ACL_NOT_RESTORED,
            f"the prior ACL for {proof.database!r} granted CONNECT to "
            f"{sorted(disallowed)}, which this fence never revoked and will not "
            "re-grant; nothing was granted, so the database stays fenced",
        )

    restored: list[str] = []
    try:
        for grantee, _priv, is_grantable in missing:
            option_sql = " WITH GRANT OPTION" if is_grantable else ""
            conn.execute(
                text(
                    f"GRANT CONNECT ON DATABASE {quoted_db} TO "
                    f"{_role_ref_sql(conn, grantee)}{option_sql}"
                )
            )
            restored.append("PUBLIC" if grantee == "" else grantee)
        final = _current_grants(conn, proof.database)
    except BaseException as exc:
        _refence(conn, quoted_db, restored)
        raise FenceRefused(
            FenceRefusalCode.ACL_NOT_RESTORED,
            f"restoring the ACL for {proof.database!r} failed part-way "
            f"({exc!r}); re-revoked what was granted to stay fenced",
        ) from exc

    if final != proof.prior_grants:
        # Stay fenced: re-revoke PUBLIC and every role just granted, rather
        # than returning a proof claiming the restore worked.
        _refence(conn, quoted_db, restored)
        raise FenceRefused(
            FenceRefusalCode.ACL_NOT_RESTORED,
            f"restored ACL for {proof.database!r} does not equal the prior "
            "ACL recorded in the fence proof; re-revoked to stay fenced",
        )

    restored_at = conn.execute(text("SELECT now()")).scalar_one()
    return UnfenceProof(
        database=proof.database,
        restored_at=restored_at,
        roles_restored=tuple(restored),
    )


def fence_is_holding(conn: Connection, proof: FenceProof) -> bool:
    """Read-only: is the fence this proof describes still in effect?

    True only when every fenced role still lacks CONNECT and the migration
    role still has it — never merely "the ACL looks different from prior"."""
    for role in proof.fenced_roles:
        still_connect = conn.execute(
            text("SELECT has_database_privilege(:role, :db, 'CONNECT')"),
            {"role": role, "db": proof.database},
        ).scalar_one()
        if still_connect:
            return False
    migration_can_connect = conn.execute(
        text("SELECT has_database_privilege(:role, :db, 'CONNECT')"),
        {"role": MIGRATION_ROLE, "db": proof.database},
    ).scalar_one()
    return bool(migration_can_connect)
