"""Renders the scoped consumption role's SQL as TEXT. Never executes it.

The ceremony reviews this text, then (a separately approved act) runs it. This
module holds no connection, creates no role and prints no secret. The role has
NO plaintext password anywhere in SQL: creation takes a client-computed
`SCRAM-SHA-256$` verifier (`scram_verifier`), so a failed CREATE or a statement
logger can leak only a value that cannot log in. The same statements are what the
real-PostgreSQL conformance test runs against a disposable database, so the
specification is exactly what is proven.

The grant set, the limits and the ledger scope come from `consumption_scope`, the
single place the proof reads them, so specification, proof and document cannot
drift (a test pins all three).

Ledger guard (E6 design, Michael's 2026-11-15 ruling). Row level security is
installed per run, by this ceremony, and removed with it:

* once per rehearsal (`guard_enable_sql`): enable RLS on the replay ledger
  (without FORCE, so the owner and superusers are unaffected) and add a
  permissive `TO PUBLIC USING (true)` policy, so every other role sees exactly
  what it saw before;
* per run role, in the same transaction as the role (`creation_sql`): a
  RESTRICTIVE INSERT policy and a RESTRICTIVE SELECT policy for that role only,
  binding scope, the dispatch id being consumed and `created_at = now()` (which
  also closes "the inserter chooses created_at"). PostgreSQL refuses COPY FROM on
  a table where RLS applies to the user, so the COPY bypass is closed, not merely
  logged;
* at teardown (`revocation_sql`): the policies are dropped, then the role;
* last (`guard_disable_sql`): refuses while any restrictive policy remains, then
  removes the permissive policy and disables RLS. Kernel's ledger verifier refuses
  the next requiring migration while the guard is on, so a forgotten teardown is
  loud, never silent.

Revocation is ordered because each step closes a gap the previous leaves:
`VALID UNTIL` is checked only at login; `DROP ROLE` fails while the role holds
privileges; a role can reconnect between terminate and drop.

    python -m vendor_cp.deployment.consumption_role_spec guard-enable
    python -m vendor_cp.deployment.consumption_role_spec create --role NAME \
        --dispatch-id UUID --scram-verifier VERIFIER
    python -m vendor_cp.deployment.consumption_role_spec revoke --role NAME
    python -m vendor_cp.deployment.consumption_role_spec verify --role NAME
    python -m vendor_cp.deployment.consumption_role_spec guard-disable
    printf %s "$PASSWORD" | python -m vendor_cp.deployment.consumption_role_spec scram
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import re
import secrets
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Final
from uuid import UUID

from vendor_cp.deployment.consumption_scope import (
    CONNECTION_LIMIT,
    GUARD_POLICY,
    IDLE_IN_TRANSACTION_TIMEOUT,
    LEDGER_SCOPE,
    LEDGER_TABLE_NAME,
    LEDGER_TABLES,
    LOCK_COLUMN,
    LOCK_TABLES,
    LOCK_TIMEOUT,
    MAX_ROLE_TTL,
    READ_ONLY_TABLES,
    STATEMENT_TIMEOUT,
    TEMP_FILE_LIMIT,
)

__all__ = [
    "DISPATCH_PLACEHOLDER",
    "ROLE_PLACEHOLDER",
    "VALID_UNTIL_PLACEHOLDER",
    "VERIFIER_PLACEHOLDER",
    "creation_sql",
    "executable_creation_sql",
    "guard_disable_sql",
    "guard_enable_sql",
    "revocation_sql",
    "scram_verifier",
    "verification_sql",
]

ROLE_PLACEHOLDER: Final = "<run_role>"
#: A psql variable reference, NOT a quoted string: executed as written it is a
#: syntax error, so the template can never create a role with a known plaintext
#: password. Only `template` output carries it; `create` refuses it.
VERIFIER_PLACEHOLDER: Final = ":'scram_verifier'"
VALID_UNTIL_PLACEHOLDER: Final = "<run end UTC, at most 4 hours after creation>"
DISPATCH_PLACEHOLDER: Final = "<dispatch uuid>"
_ROLE: Final = re.compile(r"[a-z][a-z0-9_]{2,53}")
_VERIFIER: Final = re.compile(
    r"SCRAM-SHA-256\$\d{4,7}:[A-Za-z0-9+/]+=*\$[A-Za-z0-9+/]+=*:[A-Za-z0-9+/]+=*"
)
_LEDGER: Final = f"public.{LEDGER_TABLE_NAME}"
_GUARD_LOCK_TIMEOUT: Final = "3s"


def scram_verifier(
    password: str, *, salt: bytes | None = None, iterations: int = 4096
) -> str:
    """PostgreSQL `SCRAM-SHA-256` verifier, computed on the client (RFC 5802).

    The server stores a well-formed verifier as given, so the plaintext never
    reaches the server or its logs. Callers generate a 256-bit random password,
    deliver it only inside the target's DSN, and hand this value to the ceremony.
    """
    if not password or iterations < 4096:
        raise ValueError("a password and at least 4096 iterations are required")
    chosen = salt if salt is not None else secrets.token_bytes(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), chosen, iterations)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored = hashlib.sha256(client_key).digest()
    server = hmac.new(salted, b"Server Key", hashlib.sha256).digest()

    def b64(raw: bytes) -> str:
        return base64.b64encode(raw).decode("ascii")

    return f"SCRAM-SHA-256${iterations}:{b64(chosen)}${b64(stored)}:{b64(server)}"


def _role(role: str) -> str:
    if role != ROLE_PLACEHOLDER and not _ROLE.fullmatch(role):
        raise ValueError("role must be a lowercase identifier of 3 to 54 characters")
    return role


def _quoted(role: str, suffix: str = "") -> str:
    return f'"{role}{suffix}"'


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


def _dispatch(value: str) -> str:
    if value == DISPATCH_PLACEHOLDER:
        return value
    try:
        canonical = str(UUID(value))
    except (TypeError, ValueError, AttributeError):
        raise ValueError("dispatch id must be a UUID") from None
    if canonical != value:
        raise ValueError("dispatch id must be a canonical lowercase UUID")
    return canonical


def guard_enable_sql() -> tuple[str, ...]:
    """Once per rehearsal: RLS on (no FORCE), unrestricted for everyone else."""
    return (
        "BEGIN",
        f"SET LOCAL lock_timeout = '{_GUARD_LOCK_TIMEOUT}'",
        f"ALTER TABLE {_LEDGER} ENABLE ROW LEVEL SECURITY",
        f"CREATE POLICY {GUARD_POLICY} ON {_LEDGER} AS PERMISSIVE FOR ALL "
        "TO PUBLIC USING (true) WITH CHECK (true)",
        "COMMIT",
    )


def guard_disable_sql() -> tuple[str, ...]:
    """Refuses while any restrictive policy remains; then RLS off."""
    return (
        "BEGIN",
        f"SET LOCAL lock_timeout = '{_GUARD_LOCK_TIMEOUT}'",
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = "  # noqa: S608
        f"'public' AND tablename = '{LEDGER_TABLE_NAME}' AND permissive = "
        "'RESTRICTIVE') THEN RAISE EXCEPTION 'restrictive ledger policies "
        "remain'; END IF; END $$",
        f"DROP POLICY {GUARD_POLICY} ON {_LEDGER}",
        f"ALTER TABLE {_LEDGER} DISABLE ROW LEVEL SECURITY",
        "COMMIT",
    )


def creation_sql(
    role: str,
    *,
    dispatch_id: str = DISPATCH_PLACEHOLDER,
    scram_verifier: str = VERIFIER_PLACEHOLDER,
    valid_until: datetime | str = VALID_UNTIL_PLACEHOLDER,
    now: datetime | None = None,
) -> tuple[str, ...]:
    """One transaction: the role, its limits, exactly the grants, and its policies.

    `SET LOCAL log_statement = 'none'` keeps even the verifier out of the log; the
    evidence is the independent read-back, not the server log.
    """
    name = _quoted(_role(role))
    if scram_verifier != VERIFIER_PLACEHOLDER and not _VERIFIER.fullmatch(
        scram_verifier
    ):
        raise ValueError("the password must be supplied as a SCRAM-SHA-256 verifier")
    password = (
        VERIFIER_PLACEHOLDER
        if scram_verifier == VERIFIER_PLACEHOLDER
        else f"'{scram_verifier}'"
    )
    until = _valid_until(valid_until, now=now)
    dispatch = _dispatch(dispatch_id)
    scope = f"'{LEDGER_SCOPE}'"
    insert_check = (
        f"scope = {scope} AND \"key\" = '{dispatch}' AND operation = scope "
        "AND status = 'executed' AND expires_at IS NULL AND correlation_id IS NULL "
        "AND fingerprint ~ '^[0-9a-f]{64}$' AND created_at = now() "
        "AND updated_at = now()"
    )
    select_using = f"scope = {scope} AND \"key\" = '{dispatch}'"
    return (
        "BEGIN",
        "SET LOCAL log_statement = 'none'",
        f"SET LOCAL lock_timeout = '{_GUARD_LOCK_TIMEOUT}'",
        f"CREATE ROLE {name} LOGIN PASSWORD {password} NOSUPERUSER "
        "NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT "
        f"CONNECTION LIMIT {CONNECTION_LIMIT} VALID UNTIL '{until}'",
        f"ALTER ROLE {name} SET statement_timeout = '{STATEMENT_TIMEOUT}'",
        f"ALTER ROLE {name} SET lock_timeout = '{LOCK_TIMEOUT}'",
        f"ALTER ROLE {name} SET idle_in_transaction_session_timeout = "
        f"'{IDLE_IN_TRANSACTION_TIMEOUT}'",
        # Superuser-only GUCs: the role cannot raise or clear them. The three
        # timeouts above are USERSET (only defaults); the watchdog is their bound.
        f"ALTER ROLE {name} SET temp_file_limit = '{TEMP_FILE_LIMIT}'",
        f"ALTER ROLE {name} SET log_statement = 'all'",
        "GRANT USAGE ON SCHEMA mod_deploy, mod_approvals, public TO " + name,
        "GRANT SELECT ON "
        + _tables(READ_ONLY_TABLES | LOCK_TABLES | LEDGER_TABLES)
        + " TO "
        + name,
        f"GRANT UPDATE ({LOCK_COLUMN}) ON {_tables(LOCK_TABLES)} TO {name}",
        f"GRANT INSERT ON {_tables(LEDGER_TABLES)} TO {name}",
        f"CREATE POLICY {_quoted(role, '_insert')} ON {_LEDGER} AS RESTRICTIVE "
        f"FOR INSERT TO {name} WITH CHECK ({insert_check})",
        f"CREATE POLICY {_quoted(role, '_select')} ON {_LEDGER} AS RESTRICTIVE "
        f"FOR SELECT TO {name} USING ({select_using})",
        "COMMIT",
    )


def executable_creation_sql(
    role: str,
    *,
    dispatch_id: str,
    scram_verifier: str,
    valid_until: datetime,
    now: datetime | None = None,
) -> tuple[str, ...]:
    """The creation transaction with EVERY value supplied, or a refusal.

    No placeholder, empty value or template variable can reach this output, so it
    runs as written. `valid_until` is a timezone-aware instant within the 4 hour
    cap. Verified: no statement contains `<` (a leftover placeholder) or a psql
    variable.
    """
    if not isinstance(valid_until, datetime):
        raise ValueError("valid_until is required")
    if role == ROLE_PLACEHOLDER or not scram_verifier or not dispatch_id:
        raise ValueError("role, dispatch id and verifier are all required")
    if scram_verifier == VERIFIER_PLACEHOLDER or dispatch_id == DISPATCH_PLACEHOLDER:
        raise ValueError("a placeholder is not a value")
    statements = creation_sql(
        role,
        dispatch_id=dispatch_id,
        scram_verifier=scram_verifier,
        valid_until=valid_until,
        now=now,
    )
    for statement in statements:
        if "<" in statement or VERIFIER_PLACEHOLDER in statement:
            raise ValueError("the rendered SQL still carries a placeholder")
    return statements


def revocation_sql(role: str) -> tuple[str, ...]:
    """Ordered revocation. Run all of it, then `verification_sql`."""
    name = _quoted(_role(role))
    literal = f"'{_role(role)}'"
    return (
        f"ALTER ROLE {name} NOLOGIN CONNECTION LIMIT 0",
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "  # noqa: S608
        f"WHERE usename = {literal}",
        f"DROP POLICY IF EXISTS {_quoted(role, '_insert')} ON {_LEDGER}",
        f"DROP POLICY IF EXISTS {_quoted(role, '_select')} ON {_LEDGER}",
        f"DROP OWNED BY {name}",
        f"DROP ROLE {name}",
    )


def verification_sql(role: str) -> str:
    """Read-back after revocation: all three counts must be 0."""
    literal = f"'{_role(role)}'"
    return (
        f"SELECT (SELECT count(*) FROM pg_roles WHERE rolname = {literal}) "  # noqa: S608
        "AS roles_remaining, "
        f"(SELECT count(*) FROM pg_stat_activity WHERE usename = {literal}) "
        "AS sessions_remaining, "
        "(SELECT count(*) FROM pg_policies WHERE schemaname = 'public' AND "
        f"tablename = '{LEDGER_TABLE_NAME}' AND roles @> ARRAY[{literal}]::name[]) "
        "AS policies_remaining"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Print the scoped consumption role SQL as text. Executes nothing."
    )
    parser.add_argument(
        "action",
        choices=(
            "template",
            "create",
            "revoke",
            "verify",
            "guard-enable",
            "guard-disable",
            "scram",
        ),
    )
    parser.add_argument("--role")
    parser.add_argument("--dispatch-id")
    parser.add_argument("--scram-verifier")
    parser.add_argument(
        "--valid-until", help="ISO-8601 instant with a zone, at most 4 hours ahead"
    )
    args = parser.parse_args(argv)
    try:
        if args.action == "scram":
            # The password arrives on stdin and is never echoed or stored.
            print(scram_verifier(sys.stdin.read().strip()))
            return 0
        if args.action == "template":
            # Documentation form only: placeholders, and a verifier that is a psql
            # variable (a syntax error if executed), never a password.
            statements: Sequence[str] = creation_sql(ROLE_PLACEHOLDER)
        elif args.action == "create":
            # Every value is required: the output runs as written.
            if not (
                args.role
                and args.dispatch_id
                and args.scram_verifier
                and args.valid_until
            ):
                raise ValueError(
                    "create requires --role, --dispatch-id, --scram-verifier "
                    "and --valid-until"
                )
            statements = executable_creation_sql(
                args.role,
                dispatch_id=args.dispatch_id,
                scram_verifier=args.scram_verifier,
                valid_until=datetime.fromisoformat(args.valid_until),
            )
        elif args.action in ("revoke", "verify"):
            if not args.role or args.role == ROLE_PLACEHOLDER:
                raise ValueError(f"{args.action} requires --role")
            statements = (
                revocation_sql(args.role)
                if args.action == "revoke"
                else (verification_sql(args.role),)
            )
        elif args.action == "guard-enable":
            statements = guard_enable_sql()
        else:
            statements = guard_disable_sql()
    except ValueError as refusal:
        print(f"refused: {refusal}", file=sys.stderr)
        return 2
    for statement in statements:
        print(statement + ";")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
