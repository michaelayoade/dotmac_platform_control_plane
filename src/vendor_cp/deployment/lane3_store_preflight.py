"""Read-only preflight for `v023_lane3_store` (CP-1, F-G read-back, ruling d).

The migration refuses, before any DDL, unless its design preconditions hold. This
command runs the same checks (the SQL is READ FROM the migration, one source)
against an EXISTING database that does not yet have `cp_lane3`, so the answer is
known before the deploy:

    LANE3_STORE_PREFLIGHT_DATABASE_URL=... \\
        python -m vendor_cp.deployment.lane3_store_preflight [--role app_admin]

It issues SELECTs and `SHOW` only, in a read-only transaction (read back: refused
unless the server says `on`) with `search_path` pinned to `pg_catalog, pg_temp`,
and prints ONLY check names, booleans and role/schema names (`ok <check>`,
`FAIL <check>`, `info <name>=<role>`), never a value of any kind. Exit 0 only
when every check holds, 2 on any failure, 4 when the database cannot be asked.

Checks (`--role` is the migration role, `app_admin` on production):

* the server is PostgreSQL 16;
* the role exists, is NOSUPERUSER and NOCREATEROLE, and may CREATE in the database;
* the role is a member of no role and has no members (either direction);
* no event trigger exists;
* no default-privilege rule would apply to what the migration creates;
* `cp_lane3` does not exist yet;
* `public.forbid_mutation_of_append_only_table()` exists exactly once and its
  definition digest equals the pin;
* the owner of `mod_deploy` is the role (the owner the integrity check will
  demand afterwards). The guard's owner and the role's attributes are reported.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Final

from vendor_cp.deployment.lane3_store_integrity import (
    PUBLIC_FUNCTIONS,
    SessionRefused,
    begin_read_only,
    migration_module,
    pin_search_path,
    session_execute,
)

__all__ = ["ADMIN_DSN_ENV", "main", "run_preflight"]

ADMIN_DSN_ENV: Final = "LANE3_STORE_PREFLIGHT_DATABASE_URL"
_GUARD_KEY: Final = "public.forbid_mutation_of_append_only_table()"

_ROLE_SQL: Final = (
    "SELECT rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls, "
    "rolcanlogin, rolinherit FROM pg_catalog.pg_roles WHERE rolname = :role"
)
_ATTRIBUTES: Final = (
    "superuser",
    "createrole",
    "createdb",
    "replication",
    "bypassrls",
    "login",
    "inherit",
)
_DB_CREATE_SQL: Final = (
    "SELECT has_database_privilege(:role, current_database(), 'CREATE')"
)
_MEMBERSHIP_COUNT_SQL: Final = (
    "SELECT count(*) FROM pg_catalog.pg_auth_members m WHERE m.roleid = "
    "(SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = :role) OR "
    "m.member = (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = :role)"
)
_MOD_DEPLOY_OWNER_SQL: Final = (
    "SELECT pg_catalog.pg_get_userbyid(nspowner) FROM pg_catalog.pg_namespace "
    "WHERE nspname = 'mod_deploy'"
)
_GUARD_OWNER_SQL: Final = (
    "SELECT pg_catalog.pg_get_userbyid(p.proowner) FROM pg_catalog.pg_proc p "
    "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
    "WHERE n.nspname = 'public' "
    "AND p.proname = 'forbid_mutation_of_append_only_table'"
)


def run_preflight(
    execute: Callable[..., Any],
    *,
    role: str = "app_admin",
    migration_path: Path | None = None,
) -> list[tuple[str, bool]]:
    """`(check name, held)` pairs, in order, plus `info` pairs are not included:
    see `info_lines`. Read-only: `execute(sql, params=None)` returns rows."""
    pin_search_path(execute)
    source = migration_module(migration_path)
    results: list[tuple[str, bool]] = []

    def check(name: str, held: bool) -> None:
        results.append((name, bool(held)))

    major = int(str(execute(source.PREFLIGHT_VERSION_SQL)[0][0])) // 10000
    check("server-major-16", major == source.PREFLIGHT_MAJOR)
    params = {"role": role}
    row = execute(_ROLE_SQL, params)
    check("migration-role-exists", bool(row))
    attributes = dict(zip(_ATTRIBUTES, row[0], strict=True)) if row else {}
    check("migration-role-nosuperuser", attributes.get("superuser") is False)
    check("migration-role-nocreaterole", attributes.get("createrole") is False)
    check(
        "migration-role-can-create-in-database",
        bool(row) and execute(_DB_CREATE_SQL, params)[0][0] is True,
    )
    check(
        "no-event-triggers",
        int(execute(source.PREFLIGHT_EVENT_TRIGGERS_SQL)[0][0]) == 0,
    )
    for name, template in (
        ("migration-role-not-a-member", source.PREFLIGHT_MEMBER_OF_TEMPLATE),
        ("migration-role-has-no-members", source.PREFLIGHT_HAS_MEMBERS_TEMPLATE),
        ("no-default-privileges-apply", source.PREFLIGHT_DEFAULT_ACL_TEMPLATE),
    ):
        check(
            name,
            bool(row)
            and int(execute(template.replace("{role}", ":role"), params)[0][0]) == 0,
        )
    check(
        "schema-cp_lane3-absent", int(execute(source.PREFLIGHT_SCHEMA_SQL)[0][0]) == 0
    )
    guard = execute(source.PREFLIGHT_GUARD_SQL)
    check("append-only-guard-exists", len(guard) >= 1)
    check("append-only-guard-exactly-one", len(guard) == 1)
    digest = (
        hashlib.sha256(str(guard[0][0]).encode()).hexdigest() if len(guard) == 1 else ""
    )
    check(
        "append-only-guard-digest-matches-pin", digest == PUBLIC_FUNCTIONS[_GUARD_KEY]
    )
    check(
        "migration-pin-equals-integrity-pin",
        source.PUBLIC_GUARD_SHA256 == PUBLIC_FUNCTIONS[_GUARD_KEY],
    )
    owner = execute(_MOD_DEPLOY_OWNER_SQL)
    check("mod_deploy-owner-is-the-role", bool(owner) and str(owner[0][0]) == role)
    return results


def info_lines(execute: Callable[..., Any], *, role: str) -> list[str]:
    """Names and booleans only: owners, and the role's attributes."""
    lines = []
    for label, sql in (
        ("mod_deploy_owner", _MOD_DEPLOY_OWNER_SQL),
        ("append_only_guard_owner", _GUARD_OWNER_SQL),
    ):
        rows = execute(sql)
        lines.append(f"info {label}={rows[0][0] if rows else 'absent'}")
    row = execute(_ROLE_SQL, {"role": role})
    if row:
        # a number only: how many membership rows involve the role, either way
        count = int(execute(_MEMBERSHIP_COUNT_SQL, {"role": role})[0][0])
        lines.append(f"info role_memberships={count}")
        for name, value in zip(_ATTRIBUTES, row[0], strict=True):
            lines.append(f"info role_{name}={str(value).lower()}")
    return lines


def main(
    argv: Sequence[str] | None = None,
    environ: Mapping[str, str] | None = None,
    *,
    migration_path: Path | None = None,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--role", default="app_admin")
    args = parser.parse_args(argv)
    env = os.environ if environ is None else environ
    dsn = env.get(ADMIN_DSN_ENV, "").strip()
    if not dsn:
        print(f"preflight refused: {ADMIN_DSN_ENV} is not supplied", file=sys.stderr)
        return 2
    try:
        from dotmac_kernel.session_runtime import DatabaseRuntime

        session = DatabaseRuntime.from_urls(
            database_url=dsn, platform_database_url=dsn
        ).platform_session_factory()
        try:
            execute = session_execute(session)
            begin_read_only(execute)

            results = run_preflight(
                execute, role=args.role, migration_path=migration_path
            )
            lines = info_lines(execute, role=args.role)
        finally:
            session.rollback()
            session.close()
    except SessionRefused as refusal:
        print(f"preflight refused: {refusal.code}", file=sys.stderr)
        return 2
    except Exception as error:  # noqa: BLE001 - class name only, never the text
        print(f"preflight unverifiable: {type(error).__name__}", file=sys.stderr)
        return 4
    for name, held in results:
        print(("ok " if held else "FAIL ") + name)
    for line in lines:
        print(line)
    return 0 if all(held for _, held in results) else 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
