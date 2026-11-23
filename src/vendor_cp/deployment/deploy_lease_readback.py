"""Read-only F-G read-back for `v024_deploy_lease` (WP5c, names and booleans only).

Two phases, both SELECT/`SHOW` only, in a read-only transaction with `search_path`
pinned to `pg_catalog, pg_temp`. The SQL is READ FROM the migration (one source):

    DEPLOY_LEASE_READBACK_DATABASE_URL=... \\
        python -m vendor_cp.deployment.deploy_lease_readback --phase before|after

`before` (U16: is the CP runtime role stable for the grant?; run it as the
migrating role, as the migration does):
  * the migration role and `platform_api` exist; `platform_api` is NOSUPERUSER;
  * `cp_lane3` and `mod_deploy` exist (v023 is applied) and `cp_deploy_lease` does
    not; no default-privilege rule would apply; no event trigger;
  * `info` lines: `platform_api`'s attributes (superuser, createrole, createdb,
    replication, bypassrls, login, inherit) and how many membership rows involve
    it, either direction. A number or a boolean, never a value.

`after` (the grant, as built):
  * the schema carries no ACL entry but the owner's and `platform_api` USAGE;
  * no table, sequence or column ACL entry; no default-privilege rule;
  * exactly the five `deploy_*` functions carry `platform_api` EXECUTE and no
    other function ACL entry exists; every object is owned by one role;
  * `platform_api` has no USAGE on `cp_lane3` (nothing in it is reachable).

Output: `ok <check>` / `FAIL <check>` / `info <name>=<value>`. Exit 0 only when
every check holds, 2 on any failure or refusal, 4 when the database cannot be
asked. Nothing here changes the database, and nothing prints a secret.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Final

from vendor_cp.deployment.lane3_store_integrity import (
    SessionRefused,
    begin_read_only,
    session_execute,
)

__all__ = ["READBACK_DSN_ENV", "main", "migration", "run_after", "run_before"]

READBACK_DSN_ENV: Final = "DEPLOY_LEASE_READBACK_DATABASE_URL"
_MIGRATION_FILE: Final = "v024_deploy_lease.py"

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
_MEMBERSHIP_COUNT_SQL: Final = (
    "SELECT count(*) FROM pg_catalog.pg_auth_members m WHERE m.roleid = "
    "(SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = :role) OR "
    "m.member = (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = :role)"
)
_SCHEMA_PRESENT_SQL: Final = (
    "SELECT count(*) FROM pg_catalog.pg_namespace WHERE nspname = :schema"
)
_CURRENT_ROLE_SQL: Final = "SELECT current_user"


def migration(path: Path | None = None) -> Any:
    """`v024_deploy_lease` loaded as a module: the one source of the SQL."""
    if path is None:
        from vendor_cp.migrations import vendor_versions_dir

        path = vendor_versions_dir() / _MIGRATION_FILE
    spec = importlib.util.spec_from_file_location("v024_deploy_lease_source", path)
    if spec is None or spec.loader is None:
        raise FileNotFoundError(_MIGRATION_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _count(execute: Callable[..., Any], sql: str, params: Any = None) -> int:
    return int(execute(sql, params)[0][0])


def run_before(
    execute: Callable[..., Any], *, source: Any
) -> tuple[list[tuple[str, bool]], list[str]]:
    """`(checks, info lines)` for the state BEFORE the migration."""
    role = source.RUNTIME_ROLE
    params = {"role": role}
    row = execute(_ROLE_SQL, params)
    attributes = dict(zip(_ATTRIBUTES, row[0], strict=True)) if row else {}
    migrator = execute(
        source.PREFLIGHT_ROLE_SQL.replace("current_user", ":me"),
        {"me": execute(_CURRENT_ROLE_SQL)[0][0]},
    )
    checks = [
        ("migration-role-nosuperuser-nocreaterole", migrator == [(False, False)]),
        ("runtime-role-exists", bool(row)),
        ("runtime-role-nosuperuser", attributes.get("superuser") is False),
        (
            "no-event-triggers",
            _count(execute, source.PREFLIGHT_EVENT_TRIGGERS_SQL) == 0,
        ),
        (
            "no-default-privileges-apply",
            _count(execute, source.PREFLIGHT_DEFAULT_ACL_SQL) == 0,
        ),
        (
            "schema-cp_deploy_lease-absent",
            _count(execute, _SCHEMA_PRESENT_SQL, {"schema": source.SCHEMA}) == 0,
        ),
        (
            "rehearsal-lease-store-present",
            _count(execute, source.PREFLIGHT_V023_SQL) == 2,
        ),
    ]
    info = [f"info runtime_role={role}"]
    for name, value in attributes.items():
        info.append(f"info role_{name}={str(value).lower()}")
    if row:
        info.append(
            f"info role_memberships={_count(execute, _MEMBERSHIP_COUNT_SQL, params)}"
        )
    return checks, info


def run_after(
    execute: Callable[..., Any], *, source: Any, owner: str = "app_admin"
) -> list[tuple[str, bool]]:
    """The grant as built: every query is the migration's own text. `owner` is the
    migrating role (`app_admin` on production), which the read-back session need
    not be."""
    return [
        (
            "schema-acl-only-owner-and-runtime-usage",
            _count(execute, source.SCHEMA_ACL_SQL) == 0,
        ),
        (
            "schema-usage-granted-to-runtime-role",
            _count(execute, source.SCHEMA_GRANT_PRESENT_SQL) == 1,
        ),
        ("no-table-or-sequence-acl", _count(execute, source.RELATION_ACL_SQL) == 0),
        ("no-column-acl", _count(execute, source.COLUMN_ACL_SQL) == 0),
        (
            "no-function-acl-beyond-the-five",
            _count(execute, source.FUNCTION_ACL_SQL) == 0,
        ),
        (
            "five-functions-granted-to-runtime-role",
            _count(execute, source.FUNCTION_GRANT_COUNT_SQL)
            == len(source.RUNTIME_ROLE_FUNCTIONS),
        ),
        (
            "no-default-privileges-on-schema",
            _count(execute, source.DEFAULT_ACL_SQL) == 0,
        ),
        (
            "one-owner-the-migrating-role",
            _count(
                execute,
                source.OWNER_NOT_MIGRATOR_SQL.replace("current_user", ":owner"),
                {"owner": owner},
            )
            == 0,
        ),
        (
            "runtime-role-has-no-cp_lane3-usage",
            execute(source.LANE3_REACH_SQL)[0][0] is False,
        ),
    ]


def main(
    argv: Sequence[str] | None = None,
    environ: Mapping[str, str] | None = None,
    *,
    migration_path: Path | None = None,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--phase", choices=("before", "after"), required=True)
    parser.add_argument("--owner", default="app_admin", help="the migrating role")
    args = parser.parse_args(argv)
    env = os.environ if environ is None else environ
    dsn = env.get(READBACK_DSN_ENV, "").strip()
    if not dsn:
        print(f"read-back refused: {READBACK_DSN_ENV} is not supplied", file=sys.stderr)
        return 2
    try:
        from dotmac_kernel.session_runtime import DatabaseRuntime

        session = DatabaseRuntime.from_urls(
            database_url=dsn, platform_database_url=dsn
        ).platform_session_factory()
        try:
            execute = session_execute(session)
            begin_read_only(execute)
            source = migration(migration_path)
            info: list[str] = []
            if args.phase == "before":
                results, info = run_before(execute, source=source)
            else:
                results = run_after(execute, source=source, owner=args.owner)
        finally:
            session.rollback()
            session.close()
    except SessionRefused as refusal:
        print(f"read-back refused: {refusal.code}", file=sys.stderr)
        return 2
    except Exception as error:  # noqa: BLE001 - class name only, never the text
        print(f"read-back unverifiable: {type(error).__name__}", file=sys.stderr)
        return 4
    for name, held in results:
        print(("ok " if held else "FAIL ") + name)
    for line in info:
        print(line)
    return 0 if all(held for _, held in results) else 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
