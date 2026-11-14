"""The scoped dispatch-consumption database credential (E3-Q1 ruling, E6).

For Gate 2 a2 the target consumes Control's dispatch through a short-lived
database role limited to the dispatch-consumption records. This module is the
CP side of that ruling and creates nothing: it accepts a SEPARATELY supplied
DSN, refuses anything that is not plausibly that role, and PROVES the role it
is actually connected as is narrow, by asking the database about its own
privileges (never by trusting a name).

Two layers, deliberately:

1. `scoped_consumption_dsn` - cheap, static, no connection. The scoped DSN must
   be present, well-formed, and must not be (or sit beside) a general CP
   platform DSN. A host that is carrying `DATABASE_URL` or
   `PLATFORM_DATABASE_URL` is refused outright: those are the write-capable
   credentials W1 names, and "an unused general DSN" on a target is exactly the
   widening the ruling exists to remove. A role name that reads as an owner or
   administrator is refused too. The name test is a tripwire, not the control.
2. `prove_scoped_role` - the control. It queries the catalogue as the
   connected role and refuses unless that role is not a superuser or creator of
   roles/databases, has no replication/bypass-RLS attribute, has a bounded
   `VALID UNTIL`, cannot CREATE in any schema, owns no relation, and holds on
   every table only the privileges `docs/design/scoped-consumption-role.md`
   lists. DELETE, TRUNCATE, REFERENCES and TRIGGER are never held anywhere.

The grant sets below ARE the contract the doc states; a test pins the doc to
them so the two cannot drift. They are derived statically from Deployment
Control's consumption path and are the thing the later ceremony's conformance
run must confirm (see the doc, "Open points").

TODO(before D3): a CP consumption API replaces this role. The target's provider
becomes a client; CP performs resolve/finalize and no database credential is
placed on any target. This module is then deleted, not extended.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Final

from sqlalchemy import text
from sqlalchemy.engine import make_url

from vendor_cp.deployment.target_refusals import (
    FoundationBindingsUnavailable,
    TargetRefusal,
)

if TYPE_CHECKING:  # pragma: no cover
    from dotmac_kernel.session_runtime import DatabaseRuntime
    from sqlalchemy.orm import Session

__all__ = [
    "CONSUMPTION_DSN_ENV",
    "GENERAL_DSN_ENVS",
    "LOCK_ONLY_TABLES",
    "MAX_ROLE_TTL",
    "READ_ONLY_TABLES",
    "WRITE_TABLES",
    "consumption_sessions",
    "prove_scoped_role",
    "scoped_consumption_dsn",
]

#: The one environment name the scoped DSN is supplied under. A value, never
#: echoed. Distinct from every general platform DSN name below.
CONSUMPTION_DSN_ENV: Final = "DISPATCH_CONSUMPTION_DATABASE_URL"

#: General CP platform DSNs: write-capable, owner-shaped. None may be on a target.
GENERAL_DSN_ENVS: Final = ("DATABASE_URL", "PLATFORM_DATABASE_URL")

#: A role must expire. "No longer than the run" is the ruling; twelve hours is
#: the hard ceiling this proof will accept for a run's role, not a target.
MAX_ROLE_TTL: Final = timedelta(hours=12)

#: Role names that read as a general or privileged role. A tripwire only.
_FORBIDDEN_NAME_PARTS: Final = ("owner", "admin", "superuser", "migrat", "root")
_FORBIDDEN_NAMES: Final = frozenset({"postgres", "app", "vendor_cp"})

#: SELECT only. Tables Control's resolve/admit path reads to verify the pair and
#: the standing it consumes. Names only; schemas `mod_deploy`, `mod_approvals`.
READ_ONLY_TABLES: Final[frozenset[str]] = frozenset(
    {
        "attestation_current_roots",
        "attestation_enrolments",
        "attestation_fingerprint_closures",
        "attestation_root_descriptors",
        "target_host_associations",
        "target_host_association_closures",
        "target_current_hosts",
        "target_admission_policies",
        "target_admission_policy_closures",
        "target_current_admission_policies",
        "platform_approval_requests",
    }
)

#: SELECT plus the UPDATE privilege that `SELECT ... FOR UPDATE` requires. The
#: consumption path takes row locks on these in a fixed order. Postgres demands
#: UPDATE (table or column level) for a row lock, so this is the widest part of
#: the contract and is flagged in the doc as an open point: a lock-only grant
#: should be column-level on one column no consumption path writes.
LOCK_ONLY_TABLES: Final[frozenset[str]] = frozenset(
    {
        "attestation_subject_locks",
        "deployment_targets",
        "target_credentials",
        "deployment_plans",
        "rollouts",
        "rollout_attempts",
    }
)

#: INSERT and UPDATE: the single permanent replay marker, written once per
#: dispatch by Kernel's `execute_once_platform`.
WRITE_TABLES: Final[frozenset[str]] = frozenset({"platform_idempotency_records"})

#: Privileges never held on any relation by this role.
_NEVER: Final = ("DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")

# Catalogue questions, asked of the connected role. Module constants so a test
# fake can answer each by identity rather than by parsing SQL.
_ROLE_SQL: Final = (
    "SELECT r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication, "
    "r.rolbypassrls, r.rolvaliduntil, "
    "EXTRACT(EPOCH FROM (r.rolvaliduntil - clock_timestamp())) "
    "FROM pg_roles r WHERE r.rolname = current_user"
)
_CREATE_SCHEMAS_SQL: Final = (
    "SELECT count(*) FROM pg_namespace n "
    "WHERE n.nspname NOT LIKE 'pg\\_%' AND n.nspname <> 'information_schema' "
    "AND has_schema_privilege(current_user, n.oid, 'CREATE')"
)
_OWNED_SQL: Final = (
    "SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner "
    "WHERE r.rolname = current_user AND c.relkind IN ('r','p','v','m','S','f')"
)
_PRIVILEGES_SQL: Final = (
    "SELECT n.nspname, c.relname, "
    "has_table_privilege(current_user, c.oid, 'SELECT'), "
    "has_any_column_privilege(current_user, c.oid, 'INSERT'), "
    "has_any_column_privilege(current_user, c.oid, 'UPDATE'), "
    "has_table_privilege(current_user, c.oid, 'DELETE'), "
    "has_table_privilege(current_user, c.oid, 'TRUNCATE'), "
    "has_table_privilege(current_user, c.oid, 'REFERENCES'), "
    "has_table_privilege(current_user, c.oid, 'TRIGGER') "
    "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
    "WHERE c.relkind IN ('r','p','v','m','f') "
    "AND n.nspname NOT LIKE 'pg\\_%' AND n.nspname <> 'information_schema'"
)


def _refuse(message: str, code: TargetRefusal) -> FoundationBindingsUnavailable:
    return FoundationBindingsUnavailable(message, code=code)


def scoped_consumption_dsn(env: Mapping[str, str]) -> str:
    """The scoped consumption DSN from `env`, or a typed refusal naming a thing.

    No connection is opened. The returned text is a deployment secret: callers
    pass it to the kernel runtime and never log or echo it.
    """
    present = [name for name in GENERAL_DSN_ENVS if env.get(name, "").strip()]
    if present:
        raise _refuse(
            "a target must not carry a general CP platform database credential; "
            f"present: {', '.join(present)}",
            TargetRefusal.GENERAL_DSN_PRESENT,
        )
    raw = env.get(CONSUMPTION_DSN_ENV, "").strip()
    if not raw:
        raise _refuse(
            f"the scoped dispatch-consumption database credential "
            f"({CONSUMPTION_DSN_ENV}) is not supplied",
            TargetRefusal.CONSUMPTION_DSN_MISSING,
        )
    try:
        url = make_url(raw)
    except Exception:
        raise _refuse(
            f"{CONSUMPTION_DSN_ENV} is not a database URL",
            TargetRefusal.CONSUMPTION_DSN_MALFORMED,
        ) from None
    if not url.drivername.startswith("postgresql"):
        raise _refuse(
            f"{CONSUMPTION_DSN_ENV} is not a PostgreSQL URL",
            TargetRefusal.CONSUMPTION_DSN_MALFORMED,
        )
    if not url.username or not url.database or not url.host:
        raise _refuse(
            f"{CONSUMPTION_DSN_ENV} lacks a role, host or database",
            TargetRefusal.CONSUMPTION_DSN_MALFORMED,
        )
    if any(key in url.query for key in ("options", "role", "service", "passfile")):
        raise _refuse(
            f"{CONSUMPTION_DSN_ENV} carries a connection option that can change "
            "the effective role or load further credentials",
            TargetRefusal.CONSUMPTION_DSN_NOT_SCOPED,
        )
    role = url.username.lower()
    if role in _FORBIDDEN_NAMES or any(p in role for p in _FORBIDDEN_NAME_PARTS):
        raise _refuse(
            f"{CONSUMPTION_DSN_ENV} names a general or privileged role, not a "
            "scoped consumption role",
            TargetRefusal.CONSUMPTION_DSN_NOT_SCOPED,
        )
    return raw


#: The kernel runtime built from the scoped DSN, held for the life of the
#: process: its engine backs the session factory every consumer uses.
_RUNTIME: DatabaseRuntime | None = None


def consumption_sessions(dsn: str) -> Callable[[], Session]:
    """The kernel runtime's raw session factory over the SCOPED consumption DSN.

    The kernel owns the engine (D1); vendor code never builds one. Both the
    kernel's database and platform URLs are the one scoped DSN: a target holds
    no general platform credential, so there is no other URL to supply. The
    factory yields the fresh raw Session the adapter contract requires (the
    adapter commits each phase and closes it itself). Engine construction is
    lazy; no connection opens here.
    """
    global _RUNTIME
    if _RUNTIME is None:
        from dotmac_kernel.session_runtime import DatabaseRuntime

        _RUNTIME = DatabaseRuntime.from_urls(
            database_url=dsn, platform_database_url=dsn
        )
    return _RUNTIME.platform_session_factory


@dataclass(frozen=True, slots=True)
class _Table:
    schema: str
    name: str
    select: bool
    insert: bool
    update: bool
    never: tuple[bool, ...]


def prove_scoped_role(session_factory: Callable[[], Session]) -> None:
    """Refuse unless the connected role is the narrow consumption role.

    A privilege answer that is not exactly False (NULL included) counts as held.
    Queries only the catalogue, as the role itself, in one read transaction
    that is rolled back. A database that cannot answer refuses: unprovable is
    over-broad, never "assumed fine".
    """
    session = session_factory()
    try:
        role = session.execute(text(_ROLE_SQL)).one_or_none()
        create_schemas = session.execute(text(_CREATE_SCHEMAS_SQL)).scalar()
        owned = session.execute(text(_OWNED_SQL)).scalar()
        rows = session.execute(text(_PRIVILEGES_SQL)).all()
    except Exception:
        raise _refuse(
            "the consumption role's privileges could not be read from the database",
            TargetRefusal.CONSUMPTION_ROLE_UNVERIFIABLE,
        ) from None
    finally:
        try:
            session.rollback()
        finally:
            session.close()

    over = TargetRefusal.CONSUMPTION_ROLE_OVERBROAD
    if role is None:
        raise _refuse(
            "the connected role is not visible in the catalogue",
            TargetRefusal.CONSUMPTION_ROLE_UNVERIFIABLE,
        )
    superuser, createrole, createdb, replication, bypassrls, valid_until, ttl = role
    for held, attribute in (
        (superuser, "superuser"),
        (createrole, "createrole"),
        (createdb, "createdb"),
        (replication, "replication"),
        (bypassrls, "bypassrls"),
    ):
        if held is not False:
            raise _refuse(f"the consumption role holds the {attribute} attribute", over)
    if valid_until is None or ttl is None:
        raise _refuse("the consumption role has no expiry (VALID UNTIL)", over)
    if ttl <= 0 or timedelta(seconds=float(ttl)) > MAX_ROLE_TTL:
        raise _refuse(
            "the consumption role's remaining lifetime is outside the bound", over
        )
    if create_schemas != 0:
        raise _refuse("the consumption role can create objects in a schema", over)
    if owned != 0:
        raise _refuse("the consumption role owns a relation", over)

    readable = READ_ONLY_TABLES | LOCK_ONLY_TABLES | WRITE_TABLES
    for row in rows:
        table = _Table(
            schema=str(row[0]),
            name=str(row[1]),
            select=row[2] is not False,
            insert=row[3] is not False,
            update=row[4] is not False,
            never=tuple(value is not False for value in row[5:]),
        )
        if any(table.never):
            raise _refuse(
                f"the consumption role holds a never-granted privilege "
                f"({'/'.join(_NEVER)}) on {table.name}",
                over,
            )
        if table.select and table.name not in readable:
            raise _refuse(f"the consumption role can read {table.name}", over)
        if table.insert and table.name not in WRITE_TABLES:
            raise _refuse(f"the consumption role can insert into {table.name}", over)
        if table.update and table.name not in (LOCK_ONLY_TABLES | WRITE_TABLES):
            raise _refuse(f"the consumption role can update {table.name}", over)
