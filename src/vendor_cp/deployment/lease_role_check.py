"""Standalone, read-only check of the per-run LEASE role (CP-4, design 3.1/3.5).

The mirror of `consumption_role_check`: it opens one read-only transaction over an
administrative connection, runs catalogue queries only, and prints a single line
naming a typed code, never a value. The ceremony runs it independently, BEFORE the
tunnel is opened, and records the result as evidence.

It refuses unless the named role is exactly the lease role `lease_role_spec`
renders:

* the same attribute, expiry, connection and timeout limits as the consumption
  role (`NOINHERIT`, no membership, no CREATE anywhere, owns nothing, at most four
  hours, `log_statement = 'all'`), with a connection limit of at most two;
* **no** table, column or sequence privilege in ANY schema (every write is a
  `SECURITY DEFINER` function, so a table grant is never needed and never held);
* `USAGE` on `cp_lane3` and `EXECUTE` on EXACTLY the lease-store functions
  (`lease_role_spec.LEASE_FUNCTIONS`), no more and no fewer;
* no executable `SECURITY DEFINER` function outside `cp_lane3`, and no `USAGE` on
  any module schema (the platform plane the consumption role reads);
* one live `run_bindings` row naming this role, this host and this run.

    LEASE_ROLE_CHECK_DATABASE_URL=... \\
        python -m vendor_cp.deployment.lease_role_check --role NAME \\
        --host-id HOST --authorization-run RUN

Exit 0 only when the role is proven; 2 on any refusal.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from datetime import timedelta
from typing import Any, Final

from sqlalchemy import text

from vendor_cp.deployment import consumption_scope as scope
from vendor_cp.deployment.lease_role_spec import (
    LEASE_CONNECTION_LIMIT,
    LEASE_FUNCTIONS,
    LEASE_SCHEMA,
    MAX_LEASE_ROLE_TTL_HOURS,
)

__all__ = [
    "ADMIN_DSN_ENV",
    "LeaseRoleRefused",
    "main",
    "prove_lease_role",
]

ADMIN_DSN_ENV: Final = "LEASE_ROLE_CHECK_DATABASE_URL"

#: Non-system schemas the role can USE. Only the lease-store schema (and the
#: ordinary `public`, which PostgreSQL grants to PUBLIC and which holds nothing the
#: role can reach: no table privilege, no executable definer function) may appear.
_SCHEMA_USAGE_SQL: Final = (
    "SELECT n.nspname FROM pg_namespace n WHERE "  # noqa: S608 - constants only
    + scope._SYSTEM_SCHEMA_PREDICATE
    + " AND has_schema_privilege(:role, n.oid, 'USAGE')"
)
#: Every function in the lease-store schema the role can execute, as
#: `name(argument types)`, so the set is compared exactly.
_LEASE_EXECUTE_SQL: Final = (
    "SELECT p.proname || '(' || oidvectortypes(p.proargtypes) || ')' "
    "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
    "WHERE n.nspname = 'cp_lane3' AND has_function_privilege(:role, p.oid, 'EXECUTE')"
)
#: SECURITY DEFINER functions OUTSIDE the lease schema that the role can execute.
_DEFINERS_OUTSIDE_SQL: Final = (
    "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "  # noqa: S608
    "WHERE p.prosecdef AND n.nspname <> 'cp_lane3' AND "
    + scope._SYSTEM_SCHEMA_PREDICATE
    + " AND has_function_privilege(:role, p.oid, 'EXECUTE')"
)
#: Live bindings naming exactly this role, host and run, judged on the store clock.
_BINDING_SQL: Final = (
    "SELECT count(*) FROM cp_lane3.run_bindings b WHERE b.role_name = :role "
    "AND b.host_id = :host AND b.authorization_run = :run "
    "AND b.valid_until > cp_lane3.store_now()"
)
#: Bindings naming this role for ANY other host or run: a lease role is bound to
#: one host and one run, so a second binding is over-broad.
_OTHER_BINDINGS_SQL: Final = (
    "SELECT count(*) FROM cp_lane3.run_bindings b WHERE b.role_name = :role "
    "AND (b.host_id <> :host OR b.authorization_run <> :run) "
    "AND b.valid_until > cp_lane3.store_now()"
)

_MAX_ROLE_TTL: Final = timedelta(hours=MAX_LEASE_ROLE_TTL_HOURS)


class LeaseRoleRefused(Exception):
    """The role is not the lease role. A code that names a thing, never a value."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _refuse(code: str) -> LeaseRoleRefused:
    return LeaseRoleRefused(code)


def prove_lease_role(
    session_factory: Callable[[], Any],
    *,
    role: str,
    host_id: str,
    authorization_run: str,
) -> None:
    """Refuse unless `role` is the lease role bound to `host_id` and `run`.

    One read transaction, rolled back. A privilege answer that is not exactly
    False (NULL included) counts as held; a database that cannot answer refuses.
    """
    session = session_factory()
    try:
        params = {"role": role}

        def ask(sql: str, extra: Mapping[str, Any] | None = None) -> Any:
            return session.execute(text(sql), {**params, **(extra or {})})

        role_row = ask(scope._ROLE_SQL).one_or_none()
        memberships = ask(scope._MEMBERSHIP_SQL).scalar()
        database_create = ask(scope._DATABASE_CREATE_SQL).scalar()
        create_schemas = ask(scope._CREATE_SCHEMAS_SQL).scalar()
        owned = ask(scope._OWNED_SQL).scalar()
        tables = ask(scope._TABLES_SQL).all()
        columns = ask(scope._COLUMNS_SQL).all()
        sequences = ask(scope._SEQUENCES_SQL).all()
        usable = {str(row[0]) for row in ask(_SCHEMA_USAGE_SQL).all()}
        executable = {str(row[0]) for row in ask(_LEASE_EXECUTE_SQL).all()}
        definers = ask(_DEFINERS_OUTSIDE_SQL).scalar()
        binding = {"host": host_id, "run": authorization_run}
        live = ask(_BINDING_SQL, binding).scalar()
        elsewhere = ask(_OTHER_BINDINGS_SQL, binding).scalar()
    except LeaseRoleRefused:
        raise
    except Exception:
        raise _refuse("lease-role-unverifiable") from None
    finally:
        try:
            session.rollback()
        finally:
            session.close()

    if role_row is None:
        raise _refuse("lease-role-unverifiable")
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
            raise _refuse(f"lease-role-{attribute}")
    if can_login is not True:
        raise _refuse("lease-role-cannot-login")
    if memberships != 0:
        raise _refuse("lease-role-membership")
    if valid_until is None or ttl is None:
        raise _refuse("lease-role-no-expiry")
    if ttl <= 0 or timedelta(seconds=float(ttl)) > _MAX_ROLE_TTL:
        raise _refuse("lease-role-expiry-bound")
    if not isinstance(conn_limit, int) or not 1 <= conn_limit <= LEASE_CONNECTION_LIMIT:
        raise _refuse("lease-role-connection-limit")
    settings = dict(
        item.split("=", 1)
        for item in (config or ())
        if isinstance(item, str) and "=" in item
    )
    if settings.get("log_statement", "").strip("'\" ") != "all":
        raise _refuse("lease-role-not-logged")
    for name, limit_ms in scope._MAX_TIMEOUT_MS.items():
        parsed = scope._timeout_ms(settings.get(name, "").strip("'\" "))
        if parsed is None or not 0 < parsed <= limit_ms:
            raise _refuse(f"lease-role-{name}")
    temp = scope._SIZE.fullmatch(settings.get("temp_file_limit", "").strip("'\" "))
    temp_kb = (
        int(temp.group(1))
        * {None: 1, "kB": 1, "MB": 1024, "GB": 1024 * 1024}[temp.group(2)]
        if temp
        else None
    )
    if temp_kb is None or not 0 < temp_kb <= scope._MAX_TEMP_FILE_KB:
        raise _refuse("lease-role-temp-file-limit")
    if database_create is not False or create_schemas != 0:
        raise _refuse("lease-role-can-create")
    if owned != 0:
        raise _refuse("lease-role-owns-an-object")

    # No table, column or sequence privilege ANYWHERE: the functions are the only
    # door, and they run as their owner.
    for row in tables:
        if any(value is not False for value in row[2:]):
            raise _refuse("lease-role-table-privilege")
    if columns:
        raise _refuse("lease-role-column-privilege")
    for row in sequences:
        if any(value is not False for value in row[2:]):
            raise _refuse("lease-role-sequence-privilege")

    if LEASE_SCHEMA not in usable:
        raise _refuse("lease-role-no-schema-usage")
    if usable - {LEASE_SCHEMA, "public"}:
        raise _refuse("lease-role-other-schema-usage")
    expected = {_normalise(signature) for signature in LEASE_FUNCTIONS}
    if {_normalise(item) for item in executable} != expected:
        raise _refuse("lease-role-function-set")
    if definers != 0:
        raise _refuse("lease-role-other-definer")
    if live != 1:
        raise _refuse("lease-role-not-bound")
    if elsewhere != 0:
        raise _refuse("lease-role-bound-elsewhere")


def _normalise(signature: str) -> str:
    """`name(arg, arg)` with the catalogue's spelling of each argument type."""
    name, _, rest = signature.partition("(")
    arguments = [
        part.strip().replace("timestamp with time zone", "timestamptz")
        for part in rest.rstrip(")").split(",")
        if part.strip()
    ]
    return f"{name}({', '.join(arguments)})"


def main(
    argv: Sequence[str] | None = None, environ: Mapping[str, str] | None = None
) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--role", required=True)
    parser.add_argument("--host-id", required=True)
    parser.add_argument("--authorization-run", required=True)
    args = parser.parse_args(argv)
    env = os.environ if environ is None else environ
    dsn = env.get(ADMIN_DSN_ENV, "").strip()
    if not dsn:
        print(
            f"lease role check refused: {ADMIN_DSN_ENV} is not supplied",
            file=sys.stderr,
        )
        return 2
    try:
        from dotmac_kernel.session_runtime import DatabaseRuntime

        factory = DatabaseRuntime.from_urls(
            database_url=dsn, platform_database_url=dsn
        ).platform_session_factory
        prove_lease_role(
            factory,
            role=args.role,
            host_id=args.host_id,
            authorization_run=args.authorization_run,
        )
    except LeaseRoleRefused as refusal:
        print(f"lease role check refused: {refusal.code}", file=sys.stderr)
        return 2
    print("lease role check passed")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
