"""The scoped dispatch-consumption database credential (E3-Q1 ruling, E6).

For Gate 2 a2 the target consumes Control's dispatch through a short-lived
database role. Michael's 2026-11-15 ruling fixes the model: the role connects to
the PRODUCTION CP database and is held to four limits, because the role's reach
is that database's reach:

1. lock tables carry column-level `UPDATE (updated_at)` and nothing wider;
2. no UPDATE on the replay ledger (insert-only);
3. every statement the role runs is logged (`log_statement = 'all'`, a role
   setting; no Kernel schema change), so ledger inserts are reviewable;
4. a connection limit and statement / lock / idle-in-transaction timeouts.

This module is the CP side and creates nothing. It accepts a SEPARATELY supplied
DSN, refuses anything that is not plausibly that role, and PROVES the role from
the catalogue (never by trusting a name).

IMPORTANT (R5): the startup proof runs ON the target, so a compromised target can
simply skip it. It is a tripwire for ceremony mistakes, not a bound on an
attacker. The control is the creation statements (`consumption_role_spec`) plus
an INDEPENDENT read-back of this same proof by the ceremony before the
credential is handed over (`python -m vendor_cp.deployment.consumption_role_check`).

Layers:

1. `scoped_consumption_dsn` - static, no connection. The DSN must be present,
   well-formed, TLS with certificate verification (`sslmode=verify-full` and a
   pinned `sslrootcert`), and carry no option that changes the effective role.
   A host carrying `DATABASE_URL`, `PLATFORM_DATABASE_URL` or ANY libpq `PG*`
   environment variable refuses: those can redirect or re-credential the
   connection around the DSN that was checked. A role name that reads as an owner
   or administrator refuses (tripwire).
2. `prove_scoped_role` - the catalogue proof, for the connected role or, from an
   administrative read-only connection, for a named role. It refuses on role
   attributes, any role membership, database/schema CREATE, owned objects,
   privileges beyond the contract (schema-qualified, table AND column level,
   sequences), executable SECURITY DEFINER functions, a missing expiry beyond
   4 hours, and missing connection/timeout/logging limits.

The grant sets below ARE the contract `docs/design/scoped-consumption-role.md`
states and `consumption_role_spec` renders; tests pin all three together and a
real-PostgreSQL conformance test runs Control's actual consumption path as the
role the rendered SQL creates.

TODO(before D3): a CP consumption API replaces this role. The target's provider
becomes a client; CP performs resolve/finalize and no database credential is
placed on any target. This module is then deleted, not extended.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from datetime import timedelta
from typing import TYPE_CHECKING, Any, Final

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
    "CONNECTION_LIMIT",
    "CONSUMPTION_DSN_ENV",
    "GENERAL_DSN_ENVS",
    "IDLE_IN_TRANSACTION_TIMEOUT",
    "LEDGER_TABLES",
    "LOCK_COLUMN",
    "LOCK_TABLES",
    "LOCK_TIMEOUT",
    "MAX_ROLE_TTL",
    "READ_ONLY_TABLES",
    "STATEMENT_TIMEOUT",
    "consumption_sessions",
    "prove_scoped_role",
    "scoped_consumption_dsn",
]

#: The one environment name the scoped DSN is supplied under. A value, never
#: echoed. Distinct from every general platform DSN name below.
CONSUMPTION_DSN_ENV: Final = "DISPATCH_CONSUMPTION_DATABASE_URL"

#: General CP platform DSNs: write-capable, owner-shaped. None may be on a target.
GENERAL_DSN_ENVS: Final = ("DATABASE_URL", "PLATFORM_DATABASE_URL")

#: A role must expire, and the lifetime is the run's, hard-capped (ruling
#: 2026-11-15). `VALID UNTIL` is checked only at login, so revocation also
#: terminates sessions (see `consumption_role_spec`).
MAX_ROLE_TTL: Final = timedelta(hours=4)

#: The four limits, as the spec SQL sets them. The proof accepts these or
#: tighter, never looser.
CONNECTION_LIMIT: Final = 4
STATEMENT_TIMEOUT: Final = "30s"
LOCK_TIMEOUT: Final = "5s"
IDLE_IN_TRANSACTION_TIMEOUT: Final = "30s"
_MAX_TIMEOUT_MS: Final = {
    "statement_timeout": 60_000,
    "lock_timeout": 10_000,
    "idle_in_transaction_session_timeout": 60_000,
}

#: Role names that read as a general or privileged role. A tripwire only.
_FORBIDDEN_NAME_PARTS: Final = ("owner", "admin", "superuser", "migrat", "root")
_FORBIDDEN_NAMES: Final = frozenset({"postgres", "app", "vendor_cp"})

Table = tuple[str, str]

#: SELECT only. What Control's resolve/admit path reads to verify the pair and
#: the standing it consumes (Control `ad95f4e1`, Approvals a8), as
#: `(schema, table)`.
READ_ONLY_TABLES: Final[frozenset[Table]] = frozenset(
    {
        ("mod_deploy", "attestation_current_roots"),
        ("mod_deploy", "attestation_enrolments"),
        ("mod_deploy", "attestation_fingerprint_closures"),
        ("mod_deploy", "attestation_root_descriptors"),
        ("mod_deploy", "target_host_associations"),
        ("mod_deploy", "target_host_association_closures"),
        ("mod_deploy", "target_admission_policies"),
        ("mod_deploy", "target_admission_policy_closures"),
        ("mod_deploy", "rollout_attempts"),
        ("mod_deploy", "rollout_attempt_settlements"),
        ("mod_approvals", "platform_approval_decisions"),
    }
)

#: The only column a lock table may be updated through.
LOCK_COLUMN: Final = "updated_at"

#: SELECT plus `UPDATE (updated_at)`, nothing wider. PostgreSQL requires UPDATE
#: privilege (column level suffices) for `SELECT ... FOR UPDATE` and, equally,
#: for `FOR SHARE`. `updated_at` is not read as authority on the admission or
#: consumption path.
LOCK_TABLES: Final[frozenset[Table]] = frozenset(
    {
        ("mod_deploy", "attestation_subject_locks"),
        ("mod_deploy", "deployment_targets"),
        ("mod_deploy", "target_credentials"),
        ("mod_deploy", "deployment_plans"),
        ("mod_deploy", "rollouts"),
        ("mod_deploy", "target_current_hosts"),
        ("mod_deploy", "target_current_admission_policies"),
        ("mod_approvals", "platform_approval_requests"),
    }
)

#: SELECT and INSERT, no UPDATE: Kernel `execute_once_platform` only reads and
#: inserts the permanent dispatch replay marker. Insert scope (which scope key)
#: is NOT restrictable without a Kernel schema change; the residual is bounded
#: by statement logging (ruling 2026-11-15).
LEDGER_TABLES: Final[frozenset[Table]] = frozenset(
    {("public", "platform_idempotency_records")}
)

_SYSTEM_SCHEMA_PREDICATE: Final = (
    "n.nspname NOT LIKE 'pg\\_%' AND n.nspname <> 'information_schema'"
)

# Catalogue questions about ONE role (`:role`). Module constants so a test fake
# can answer each by identity rather than by parsing SQL.
_CURRENT_SQL: Final = "SELECT current_user, session_user"
_ROLE_SQL: Final = (
    "SELECT r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication, "
    "r.rolbypassrls, r.rolinherit, r.rolcanlogin, r.rolconnlimit, "
    "r.rolvaliduntil, "
    "EXTRACT(EPOCH FROM (r.rolvaliduntil - clock_timestamp())), r.rolconfig "
    "FROM pg_roles r WHERE r.rolname = :role"
)
_MEMBERSHIP_SQL: Final = (
    "SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.member "
    "WHERE r.rolname = :role"
)
_DATABASE_CREATE_SQL: Final = (
    "SELECT has_database_privilege(:role, current_database(), 'CREATE')"
)
_CREATE_SCHEMAS_SQL: Final = (
    "SELECT count(*) FROM pg_namespace n WHERE "  # noqa: S608 - constants only
    + _SYSTEM_SCHEMA_PREDICATE
    + " AND has_schema_privilege(:role, n.oid, 'CREATE')"
)
_OWNED_SQL: Final = (
    "SELECT (SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner "
    "WHERE r.rolname = :role) + "
    "(SELECT count(*) FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner "
    "WHERE r.rolname = :role) + "
    "(SELECT count(*) FROM pg_namespace s JOIN pg_roles r ON r.oid = s.nspowner "
    "WHERE r.rolname = :role)"
)
_TABLES_SQL: Final = (
    "SELECT n.nspname, c.relname, "
    "has_table_privilege(:role, c.oid, 'SELECT'), "
    "has_table_privilege(:role, c.oid, 'INSERT'), "
    "has_table_privilege(:role, c.oid, 'UPDATE'), "
    "has_table_privilege(:role, c.oid, 'DELETE'), "
    "has_table_privilege(:role, c.oid, 'TRUNCATE'), "
    "has_table_privilege(:role, c.oid, 'REFERENCES'), "
    "has_table_privilege(:role, c.oid, 'TRIGGER') "
    "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
    "WHERE c.relkind IN ('r','p','v','m','f') AND " + _SYSTEM_SCHEMA_PREDICATE
)
#: Column-level grants that the table-level flags above cannot show. Rows are
#: `(schema, table, column, select, insert, update, references)`, limited to
#: columns where any write-class privilege holds, or SELECT holds on a column
#: whose table-level SELECT does not.
_COLUMNS_SQL: Final = (
    "SELECT n.nspname, c.relname, a.attname, "
    "has_column_privilege(:role, c.oid, a.attnum, 'SELECT'), "
    "has_column_privilege(:role, c.oid, a.attnum, 'INSERT'), "
    "has_column_privilege(:role, c.oid, a.attnum, 'UPDATE'), "
    "has_column_privilege(:role, c.oid, a.attnum, 'REFERENCES') "
    "FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid "
    "JOIN pg_namespace n ON n.oid = c.relnamespace "
    "WHERE a.attnum > 0 AND NOT a.attisdropped "
    "AND c.relkind IN ('r','p','v','m','f') AND "
    + _SYSTEM_SCHEMA_PREDICATE
    + " AND (has_column_privilege(:role, c.oid, a.attnum, 'INSERT') "
    "OR has_column_privilege(:role, c.oid, a.attnum, 'UPDATE') "
    "OR has_column_privilege(:role, c.oid, a.attnum, 'REFERENCES') "
    "OR (has_column_privilege(:role, c.oid, a.attnum, 'SELECT') "
    "AND NOT has_table_privilege(:role, c.oid, 'SELECT')))"
)
_SEQUENCES_SQL: Final = (
    "SELECT n.nspname, c.relname, "
    "has_sequence_privilege(:role, c.oid, 'USAGE'), "
    "has_sequence_privilege(:role, c.oid, 'SELECT'), "
    "has_sequence_privilege(:role, c.oid, 'UPDATE') "
    "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
    "WHERE c.relkind = 'S' AND " + _SYSTEM_SCHEMA_PREDICATE
)
_FUNCTIONS_SQL: Final = (
    "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "  # noqa: S608 - constants only
    "WHERE p.prosecdef AND "
    + _SYSTEM_SCHEMA_PREDICATE
    + " AND has_function_privilege(:role, p.oid, 'EXECUTE')"
)

_DURATION: Final = re.compile(r"^(\d{1,9})(ms|s|min)?$")
_PG_ENV_PREFIX: Final = "PG"


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
    libpq = sorted(name for name in env if name.startswith(_PG_ENV_PREFIX))
    if libpq:
        raise _refuse(
            "libpq PG* environment variables can redirect or re-credential the "
            "connection around the checked DSN; present: " + ", ".join(libpq),
            TargetRefusal.CONSUMPTION_DSN_NOT_SCOPED,
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
    query = {key: value for key, value in url.query.items()}
    if any(key in query for key in ("options", "role", "service", "passfile")):
        raise _refuse(
            f"{CONSUMPTION_DSN_ENV} carries a connection option that can change "
            "the effective role or load further credentials",
            TargetRefusal.CONSUMPTION_DSN_NOT_SCOPED,
        )
    if query.get("sslmode") != "verify-full":
        raise _refuse(
            f"{CONSUMPTION_DSN_ENV} must require TLS with certificate and host "
            "verification (sslmode=verify-full)",
            TargetRefusal.CONSUMPTION_DSN_NOT_SCOPED,
        )
    root = query.get("sslrootcert")
    if not isinstance(root, str) or not root.startswith("/"):
        raise _refuse(
            f"{CONSUMPTION_DSN_ENV} must pin its CA (an absolute sslrootcert)",
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


def _timeout_ms(value: str) -> int | None:
    match = _DURATION.match(value.strip())
    if match is None:
        return None
    number, unit = int(match.group(1)), match.group(2) or "ms"
    return number * {"ms": 1, "s": 1_000, "min": 60_000}[unit]


def prove_scoped_role(
    session_factory: Callable[[], Session], *, role: str | None = None
) -> None:
    """Refuse unless the role is the narrow consumption role.

    With `role=None` the proof is about the connected role (the startup
    tripwire). With a name it is about that role, from any read-only connection
    (the ceremony's independent read-back before the credential is handed over).
    Queries only the catalogue, in one read transaction that is rolled back. A
    privilege answer that is not exactly False (NULL included) counts as held.
    A database that cannot answer refuses: unprovable is over-broad, never
    "assumed fine".
    """
    session = session_factory()
    try:
        current = session.execute(text(_CURRENT_SQL)).one_or_none()
        subject = role if role is not None else (current[0] if current else None)
        if not isinstance(subject, str) or not subject:
            raise RuntimeError("no role")
        if role is None and current is not None and current[0] != current[1]:
            raise _refuse(
                "the session is acting through a switched role",
                TargetRefusal.CONSUMPTION_ROLE_OVERBROAD,
            )
        params: dict[str, Any] = {"role": subject}

        def ask(sql: str) -> Any:
            return session.execute(text(sql), params)

        role_row = ask(_ROLE_SQL).one_or_none()
        memberships = ask(_MEMBERSHIP_SQL).scalar()
        database_create = ask(_DATABASE_CREATE_SQL).scalar()
        create_schemas = ask(_CREATE_SCHEMAS_SQL).scalar()
        owned = ask(_OWNED_SQL).scalar()
        tables = ask(_TABLES_SQL).all()
        columns = ask(_COLUMNS_SQL).all()
        sequences = ask(_SEQUENCES_SQL).all()
        definers = ask(_FUNCTIONS_SQL).scalar()
    except FoundationBindingsUnavailable:
        raise
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
    if role_row is None:
        raise _refuse(
            "the role is not visible in the catalogue",
            TargetRefusal.CONSUMPTION_ROLE_UNVERIFIABLE,
        )
    (
        superuser,
        createrole,
        createdb,
        replication,
        bypassrls,
        inherit,
        can_login,
        conn_limit,
        valid_until,
        ttl,
        config,
    ) = role_row
    for held, attribute in (
        (superuser, "superuser"),
        (createrole, "createrole"),
        (createdb, "createdb"),
        (replication, "replication"),
        (bypassrls, "bypassrls"),
        (inherit, "inherit"),
    ):
        if held is not False:
            raise _refuse(f"the consumption role holds the {attribute} attribute", over)
    if can_login is not True:
        raise _refuse("the consumption role cannot log in", over)
    if memberships != 0:
        raise _refuse(
            "the consumption role is a member of another role (reachable by "
            "SET ROLE whatever its inherit setting)",
            over,
        )
    if valid_until is None or ttl is None:
        raise _refuse("the consumption role has no expiry (VALID UNTIL)", over)
    if ttl <= 0 or timedelta(seconds=float(ttl)) > MAX_ROLE_TTL:
        raise _refuse(
            "the consumption role's remaining lifetime is outside the 4 hour bound",
            over,
        )
    if not isinstance(conn_limit, int) or not 1 <= conn_limit <= CONNECTION_LIMIT:
        raise _refuse("the consumption role has no bounded connection limit", over)
    settings = dict(
        item.split("=", 1)
        for item in (config or ())
        if isinstance(item, str) and "=" in item
    )
    if settings.get("log_statement", "").strip("'\" ") != "all":
        raise _refuse("the consumption role's statements are not all logged", over)
    for name, limit_ms in _MAX_TIMEOUT_MS.items():
        parsed = _timeout_ms(settings.get(name, "").strip("'\" "))
        if parsed is None or not 0 < parsed <= limit_ms:
            raise _refuse(f"the consumption role has no bounded {name}", over)
    if database_create is not False:
        raise _refuse("the consumption role can create objects in the database", over)
    if create_schemas != 0:
        raise _refuse("the consumption role can create objects in a schema", over)
    if owned != 0:
        raise _refuse("the consumption role owns a database object", over)
    if definers != 0:
        raise _refuse(
            "the consumption role can execute a SECURITY DEFINER function", over
        )

    for name, use, select, update in ((str(r[1]), r[2], r[3], r[4]) for r in sequences):
        if select is not False or update is not False or use is not False:
            raise _refuse(
                f"the consumption role holds a privilege on sequence {name}", over
            )

    readable = READ_ONLY_TABLES | LOCK_TABLES | LEDGER_TABLES
    for row in tables:
        key = (str(row[0]), str(row[1]))
        select, insert, update = (
            row[2] is not False,
            row[3] is not False,
            row[4] is not False,
        )
        if any(value is not False for value in row[5:]):
            raise _refuse(
                f"the consumption role holds a never-granted privilege "
                f"(DELETE/TRUNCATE/REFERENCES/TRIGGER) on {key[1]}",
                over,
            )
        if select and key not in readable:
            raise _refuse(f"the consumption role can read {key[1]}", over)
        if insert and key not in LEDGER_TABLES:
            raise _refuse(f"the consumption role can insert into {key[1]}", over)
        if update:
            raise _refuse(
                f"the consumption role holds table-level UPDATE on {key[1]}", over
            )

    lock_columns: dict[Table, set[str]] = {}
    for schema, name, column, select, insert, update, references in (
        (str(r[0]), str(r[1]), str(r[2]), r[3], r[4], r[5], r[6]) for r in columns
    ):
        key = (schema, name)
        if references is not False:
            raise _refuse(
                f"the consumption role holds REFERENCES on a column of {name}", over
            )
        if select is not False and key not in readable:
            raise _refuse(f"the consumption role can read a column of {name}", over)
        if insert is not False and key not in LEDGER_TABLES:
            raise _refuse(f"the consumption role can insert a column of {name}", over)
        if update is not False:
            if key not in LOCK_TABLES:
                raise _refuse(
                    f"the consumption role can update a column of {name}", over
                )
            lock_columns.setdefault(key, set()).add(column)
    for key, held_columns in lock_columns.items():
        if held_columns != {LOCK_COLUMN}:
            raise _refuse(
                f"the consumption role can update more than {LOCK_COLUMN} on {key[1]}",
                over,
            )
