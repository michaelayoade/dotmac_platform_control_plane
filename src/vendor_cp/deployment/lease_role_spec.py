"""Renders the per-run LEASE role's SQL as TEXT, and its pg_hba block. Executes nothing.

CP-4, pre-E11 design sections 3.1 and 3.6. The launcher reaches the lease store
(`cp_lane3`) as a second per-run role, created by the same E6 ceremony as the
target's consumption role and with the same lifecycle: a client-computed SCRAM
verifier (no plaintext password in SQL), `NOINHERIT`, no membership, a bounded
connection limit and `VALID UNTIL` (4 hours at most), `log_statement = 'all'`,
the watchdog's tripwires, and an ordered revocation with a read-back of zeros.

What it holds is the MIRROR of the consumption role's reach:

* `USAGE` on schema `cp_lane3` and `EXECUTE` on the lease-store functions, and
  NOTHING else. No table, column or sequence privilege anywhere, and nothing on
  any other schema. Every write goes through a `SECURITY DEFINER` function that
  first demands a live `run_bindings` row for `session_user`.
* A `run_bindings` row (written here, in the creating transaction) binding the
  role to ONE host and ONE authorization run until the same deadline as the
  role. The functions refuse every call without one.

The consumption role holds NOTHING in `cp_lane3` (`consumption_scope` proves it
and `consumption_role_spec` never names the schema), so a compromised target can
neither read, extend nor clear a lease.

## pg_hba (Q1-B)

The lease role's only `hostssl` line admits it from the CP-HOST end of the
ceremony tunnel: PostgreSQL sees the forwarded connection from the address of the
CP host on the database container's network, never from the launcher
(`pg_hba_block`). The source is a typed value read back at E10a. Everything else
for the role is rejected, so the role is useless from anywhere else.

    python -m vendor_cp.deployment.lease_role_spec create --role NAME \\
        --host-id HOST --authorization-run RUN --scram-verifier V --valid-until T
    python -m vendor_cp.deployment.lease_role_spec revoke --role NAME
    python -m vendor_cp.deployment.lease_role_spec verify --role NAME
    python -m vendor_cp.deployment.lease_role_spec pg-hba --role NAME \\
        --database DB --cp-bridge-addr ADDR
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Final

from vendor_cp.deployment.consumption_role_spec import scram_verifier

__all__ = [
    "LEASE_CONNECTION_LIMIT",
    "LEASE_FUNCTIONS",
    "LEASE_IDLE_IN_TRANSACTION_TIMEOUT",
    "LEASE_LOCK_TIMEOUT",
    "LEASE_SCHEMA",
    "LEASE_STATEMENT_TIMEOUT",
    "LEASE_TEMP_FILE_LIMIT",
    "MAX_LEASE_ROLE_TTL_HOURS",
    "creation_sql",
    "executable_creation_sql",
    "pg_hba_block",
    "revocation_sql",
    "scram_verifier",
    "verification_sql",
]

LEASE_SCHEMA: Final = "cp_lane3"
#: Two connections: one is the launcher's, the second covers its own reconnect
#: after a dropped tunnel read as a fresh handle.
LEASE_CONNECTION_LIMIT: Final = 2
LEASE_STATEMENT_TIMEOUT: Final = "30s"
LEASE_LOCK_TIMEOUT: Final = "5s"
LEASE_IDLE_IN_TRANSACTION_TIMEOUT: Final = "30s"
LEASE_TEMP_FILE_LIMIT: Final = "256MB"
MAX_LEASE_ROLE_TTL_HOURS: Final = 4

#: Exactly the functions the migration creates for the lease role. A real
#: PostgreSQL test compares this set with the catalogue in both directions.
LEASE_FUNCTIONS: Final = (
    "acquire(text, text, text, text, integer, jsonb, text, jsonb)",
    "bind_document(uuid, bytea, text)",
    "covers(uuid, text)",
    "database_time()",
    "e10_receipt(text, text, text)",
    "release(uuid, bytea, text, text, text, text, timestamptz, boolean)",
    "released_at(text)",
    "standing(text)",
)

ROLE_PLACEHOLDER: Final = "<lease_role>"
_ROLE: Final = re.compile(r"[a-z][a-z0-9_]{2,53}")
_HOST: Final = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
#: A run id is quoted into SQL, so the alphabet excludes every quote and escape.
_RUN: Final = re.compile(r"[A-Za-z0-9._:/@-]{1,255}")
_VERIFIER: Final = re.compile(
    r"SCRAM-SHA-256\$\d{4,7}:[A-Za-z0-9+/]+=*\$[A-Za-z0-9+/]+=*:[A-Za-z0-9+/]+=*"
)
_DATABASE: Final = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}")
_RECORDED_BY: Final = "lane3-ceremony"
_GUARD_LOCK_TIMEOUT: Final = "3s"


def _role(role: str) -> str:
    if role != ROLE_PLACEHOLDER and not _ROLE.fullmatch(role):
        raise ValueError("role must be a lowercase identifier of 3 to 54 characters")
    return role


def _quoted(role: str) -> str:
    return f'"{_role(role)}"'


def _host(value: str) -> str:
    if not _HOST.fullmatch(value) or len(value) > 63:
        raise ValueError("host id must be a Fleet-shaped identifier")
    return value


def _run(value: str) -> str:
    if not _RUN.fullmatch(value):
        raise ValueError("authorization run id has an unsupported character")
    return value


def _valid_until(value: datetime, *, now: datetime | None) -> str:
    if value.tzinfo is None:
        raise ValueError("valid_until must be timezone-aware")
    reference = now or datetime.now(UTC)
    if not reference < value <= reference + timedelta(hours=MAX_LEASE_ROLE_TTL_HOURS):
        raise ValueError("valid_until must be within the 4 hour cap")
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S+00")


def creation_sql(
    role: str,
    *,
    host_id: str,
    authorization_run: str,
    scram_verifier_value: str,
    valid_until: datetime,
    now: datetime | None = None,
) -> tuple[str, ...]:
    """One transaction: the role, its limits, exactly the grants, and its binding.

    `SET LOCAL log_statement = 'none'` keeps even the verifier out of the log.
    The binding row and the role end at the same instant.
    """
    name = _quoted(role)
    if not _VERIFIER.fullmatch(scram_verifier_value):
        raise ValueError("the password must be supplied as a SCRAM-SHA-256 verifier")
    until = _valid_until(valid_until, now=now)
    host = _host(host_id)
    run = _run(authorization_run)
    functions = ", ".join(f"{LEASE_SCHEMA}.{sig}" for sig in LEASE_FUNCTIONS)
    return (
        "BEGIN",
        "SET LOCAL log_statement = 'none'",
        f"SET LOCAL lock_timeout = '{_GUARD_LOCK_TIMEOUT}'",
        f"CREATE ROLE {name} LOGIN PASSWORD '{scram_verifier_value}' NOSUPERUSER "
        "NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT "
        f"CONNECTION LIMIT {LEASE_CONNECTION_LIMIT} VALID UNTIL '{until}'",
        f"ALTER ROLE {name} SET statement_timeout = '{LEASE_STATEMENT_TIMEOUT}'",
        f"ALTER ROLE {name} SET lock_timeout = '{LEASE_LOCK_TIMEOUT}'",
        f"ALTER ROLE {name} SET idle_in_transaction_session_timeout = "
        f"'{LEASE_IDLE_IN_TRANSACTION_TIMEOUT}'",
        # Superuser-only GUCs: the role cannot raise or clear them.
        f"ALTER ROLE {name} SET temp_file_limit = '{LEASE_TEMP_FILE_LIMIT}'",
        f"ALTER ROLE {name} SET log_statement = 'all'",
        f"GRANT USAGE ON SCHEMA {LEASE_SCHEMA} TO {name}",
        f"GRANT EXECUTE ON FUNCTION {functions} TO {name}",
        f"INSERT INTO {LEASE_SCHEMA}.run_bindings (role_name, host_id, "  # noqa: S608
        f"authorization_run, valid_until, recorded_by) VALUES ('{_role(role)}', "
        f"'{host}', '{run}', '{until}', '{_RECORDED_BY}')",
        "COMMIT",
    )


def executable_creation_sql(
    role: str,
    *,
    host_id: str,
    authorization_run: str,
    scram_verifier_value: str,
    valid_until: datetime,
    now: datetime | None = None,
) -> tuple[str, ...]:
    """`creation_sql` with every value supplied, or a refusal. Runs as written."""
    if role == ROLE_PLACEHOLDER or not scram_verifier_value:
        raise ValueError("role and verifier are both required")
    statements = creation_sql(
        role,
        host_id=host_id,
        authorization_run=authorization_run,
        scram_verifier_value=scram_verifier_value,
        valid_until=valid_until,
        now=now,
    )
    for statement in statements:
        if "<" in statement:
            raise ValueError("the rendered SQL still carries a placeholder")
    return statements


def revocation_sql(role: str) -> tuple[str, ...]:
    """Ordered revocation: no login, kill sessions, drop the grants, drop the role."""
    name = _quoted(role)
    literal = f"'{_role(role)}'"
    return (
        f"ALTER ROLE {name} NOLOGIN CONNECTION LIMIT 0",
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "  # noqa: S608
        f"WHERE usename = {literal}",
        f"DROP OWNED BY {name}",
        f"DROP ROLE {name}",
    )


def verification_sql(role: str) -> str:
    """Read-back after revocation: all three counts must be 0.

    `roles_remaining`, `sessions_remaining` and `grants_remaining` (every ACL entry
    in the lease schema that still names the role). The binding row is append-only
    evidence and stays; it is inert once the role is gone, and role names are
    unique per run.
    """
    literal = f"'{_role(role)}'"
    return (
        f"SELECT (SELECT count(*) FROM pg_roles WHERE rolname = {literal}) "  # noqa: S608
        "AS roles_remaining, "
        f"(SELECT count(*) FROM pg_stat_activity WHERE usename = {literal}) "
        "AS sessions_remaining, "
        "((SELECT count(*) FROM pg_namespace n, "
        "LATERAL aclexplode(coalesce(n.nspacl, '{}')) a "
        "JOIN pg_roles r ON r.oid = a.grantee "
        f"WHERE n.nspname = '{LEASE_SCHEMA}' AND r.rolname = {literal}) + "
        "(SELECT count(*) FROM pg_proc p JOIN pg_namespace n "
        "ON n.oid = p.pronamespace, "
        "LATERAL aclexplode(coalesce(p.proacl, '{}')) a "
        "JOIN pg_roles r ON r.oid = a.grantee "
        f"WHERE n.nspname = '{LEASE_SCHEMA}' AND r.rolname = {literal})) "
        "AS grants_remaining"
    )


def pg_hba_block(role: str, *, database: str, cp_bridge_addr: str) -> tuple[str, ...]:
    """The managed pg_hba lines for the lease role (Q1-B).

    `cp_bridge_addr` is the CP host's address on the database container's docker
    network: where the forwarded connection appears to come from. It must be one
    literal address (rendered `/32` or `/128`), never a range, a hostname or the
    launcher's address. Order matters: the only `hostssl` accept line comes first
    and the rejects follow, so no other source or transport reaches the role.
    """
    name = _role(role)
    if not _DATABASE.fullmatch(database):
        raise ValueError("database must be a plain identifier")
    try:
        address = ipaddress.ip_address(cp_bridge_addr)
    except ValueError:
        raise ValueError("cp_bridge_addr must be one literal IP address") from None
    if address.is_unspecified or address.is_multicast:
        raise ValueError("cp_bridge_addr must be a host address")
    width = 32 if address.version == 4 else 128
    return (
        f"hostssl {database} {name} {address}/{width} scram-sha-256",
        f"host    all {name} all reject",
        f"local   all {name} reject",
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Print the lease role SQL as text. Executes nothing."
    )
    parser.add_argument("action", choices=("create", "revoke", "verify", "pg-hba"))
    parser.add_argument("--role", required=True)
    parser.add_argument("--host-id")
    parser.add_argument("--authorization-run")
    parser.add_argument("--scram-verifier")
    parser.add_argument("--valid-until")
    parser.add_argument("--database")
    parser.add_argument("--cp-bridge-addr")
    args = parser.parse_args(argv)
    try:
        if args.action == "create":
            if not (
                args.host_id
                and args.authorization_run
                and args.scram_verifier
                and args.valid_until
            ):
                raise ValueError(
                    "create requires --host-id, --authorization-run, "
                    "--scram-verifier and --valid-until"
                )
            statements: Sequence[str] = executable_creation_sql(
                args.role,
                host_id=args.host_id,
                authorization_run=args.authorization_run,
                scram_verifier_value=args.scram_verifier,
                valid_until=datetime.fromisoformat(args.valid_until),
            )
        elif args.action == "revoke":
            statements = revocation_sql(args.role)
        elif args.action == "verify":
            statements = (verification_sql(args.role),)
        else:
            if not (args.database and args.cp_bridge_addr):
                raise ValueError("pg-hba requires --database and --cp-bridge-addr")
            statements = pg_hba_block(
                args.role, database=args.database, cp_bridge_addr=args.cp_bridge_addr
            )
    except ValueError as refusal:
        print(f"refused: {refusal}", file=sys.stderr)
        return 2
    for statement in statements:
        print(statement if args.action == "pg-hba" else statement + ";")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
