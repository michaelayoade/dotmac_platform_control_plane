"""Renders the scoped consumption role's SQL as TEXT. Never executes it.

The ceremony reviews this text, then (a separately approved act) runs it. This
module holds no connection, creates no role and prints no secret: the password
is a placeholder the ceremony fills from its own generator. The same statements
are what the real-PostgreSQL conformance test runs against a disposable
database, so the specification is exactly what is proven.

The grant set and the four limits come from `consumption_scope`, the single
place the proof reads them, so the specification, the proof and the document
cannot drift (a test pins all three).

Revocation (`revocation_sql`) is ordered because each step closes a gap the
previous one leaves: `VALID UNTIL` is checked only at login, so pooled sessions
outlive it; `DROP ROLE` fails while the role still holds privileges; a role can
reconnect between terminate and drop. So: stop new logins, terminate the
sessions, `DROP OWNED BY`, `DROP ROLE`, then read back that no role and no
session remain (`verification_sql`).

    python -m vendor_cp.deployment.consumption_role_spec create --role NAME
    python -m vendor_cp.deployment.consumption_role_spec revoke --role NAME
    python -m vendor_cp.deployment.consumption_role_spec verify --role NAME
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Final

from vendor_cp.deployment.consumption_scope import (
    CONNECTION_LIMIT,
    IDLE_IN_TRANSACTION_TIMEOUT,
    LEDGER_TABLES,
    LOCK_COLUMN,
    LOCK_TABLES,
    LOCK_TIMEOUT,
    MAX_ROLE_TTL,
    READ_ONLY_TABLES,
    STATEMENT_TIMEOUT,
)

__all__ = [
    "PASSWORD_PLACEHOLDER",
    "ROLE_PLACEHOLDER",
    "VALID_UNTIL_PLACEHOLDER",
    "creation_sql",
    "revocation_sql",
    "verification_sql",
]

ROLE_PLACEHOLDER: Final = "<run_role>"
PASSWORD_PLACEHOLDER: Final = "<generated>"  # noqa: S105 - a placeholder
VALID_UNTIL_PLACEHOLDER: Final = "<run end UTC, at most 4 hours after creation>"
_ROLE: Final = re.compile(r"^[a-z][a-z0-9_]{2,62}$")


def _role(role: str) -> str:
    if role != ROLE_PLACEHOLDER and not _ROLE.match(role):
        raise ValueError("role must be a lowercase identifier of 3 to 63 characters")
    return role


def _quoted(role: str) -> str:
    return role if role == ROLE_PLACEHOLDER else f'"{role}"'


def _tables(tables: frozenset[tuple[str, str]]) -> str:
    return ", ".join(f"{schema}.{name}" for schema, name in sorted(tables))


def _valid_until(value: datetime | str, *, now: datetime | None) -> str:
    if isinstance(value, str):
        if value != VALID_UNTIL_PLACEHOLDER:
            raise ValueError("valid_until must be a datetime or the placeholder")
        return value
    if value.tzinfo is None:
        raise ValueError("valid_until must be timezone-aware")
    reference = now or datetime.now(UTC)
    if not reference < value <= reference + MAX_ROLE_TTL:
        raise ValueError("valid_until must be within the 4 hour cap")
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S+00")


def creation_sql(
    role: str,
    *,
    password: str = PASSWORD_PLACEHOLDER,
    valid_until: datetime | str = VALID_UNTIL_PLACEHOLDER,
    now: datetime | None = None,
) -> tuple[str, ...]:
    """The statements that create the role and grant exactly the contract."""
    name = _quoted(_role(role))
    if "'" in password:
        raise ValueError("password must not contain a quote")
    until = _valid_until(valid_until, now=now)
    # `CONNECTION LIMIT`, `VALID UNTIL` and the NO* attributes are the role's
    # shape. `NOINHERIT` is belt-and-braces: the proof also refuses ANY
    # membership, because SET ROLE reaches a member role whatever inherit says.
    create = (
        f"CREATE ROLE {name} LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB "
        f"NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT "
        f"CONNECTION LIMIT {CONNECTION_LIMIT} VALID UNTIL '{until}'"
    )
    return (
        create,
        f"ALTER ROLE {name} SET statement_timeout = '{STATEMENT_TIMEOUT}'",
        f"ALTER ROLE {name} SET lock_timeout = '{LOCK_TIMEOUT}'",
        f"ALTER ROLE {name} SET idle_in_transaction_session_timeout = "
        f"'{IDLE_IN_TRANSACTION_TIMEOUT}'",
        # Superuser-only GUC: every statement the role runs is logged, which is
        # the control over ledger inserts (no Kernel schema change).
        f"ALTER ROLE {name} SET log_statement = 'all'",
        "GRANT USAGE ON SCHEMA mod_deploy, mod_approvals, public TO " + name,
        "GRANT SELECT ON "
        + _tables(READ_ONLY_TABLES | LOCK_TABLES | LEDGER_TABLES)
        + " TO "
        + name,
        f"GRANT UPDATE ({LOCK_COLUMN}) ON {_tables(LOCK_TABLES)} TO {name}",
        f"GRANT INSERT ON {_tables(LEDGER_TABLES)} TO {name}",
    )


def revocation_sql(role: str) -> tuple[str, ...]:
    """Ordered revocation. Run all of it, then `verification_sql`."""
    name = _quoted(_role(role))
    literal = f"'{_role(role)}'"
    return (
        f"ALTER ROLE {name} NOLOGIN CONNECTION LIMIT 0",
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "  # noqa: S608
        f"WHERE usename = {literal}",
        f"DROP OWNED BY {name}",
        f"DROP ROLE {name}",
    )


def verification_sql(role: str) -> str:
    """Read-back after revocation: both counts must be 0."""
    literal = f"'{_role(role)}'"
    return (
        f"SELECT (SELECT count(*) FROM pg_roles WHERE rolname = {literal}) "  # noqa: S608
        "AS roles_remaining, "
        f"(SELECT count(*) FROM pg_stat_activity WHERE usename = {literal}) "
        "AS sessions_remaining"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Print the scoped consumption role SQL as text. Executes nothing."
    )
    parser.add_argument("action", choices=("create", "revoke", "verify"))
    parser.add_argument("--role", default=ROLE_PLACEHOLDER)
    args = parser.parse_args(argv)
    try:
        if args.action == "create":
            statements: Sequence[str] = creation_sql(args.role)
        elif args.action == "revoke":
            statements = revocation_sql(args.role)
        else:
            statements = (verification_sql(args.role),)
    except ValueError as refusal:
        print(f"refused: {refusal}", file=sys.stderr)
        return 2
    for statement in statements:
        print(statement + ";")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
