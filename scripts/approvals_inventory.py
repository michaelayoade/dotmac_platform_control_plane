#!/usr/bin/env python
"""Read-only legacy approvals inventory — emits deterministic evidence.

Usage:

    poetry run python scripts/approvals_inventory.py --dsn postgresql+psycopg://...
    VENDOR_INVENTORY_DSN=postgresql+psycopg://... poetry run python \
        scripts/approvals_inventory.py

## The target is NAMED, never inferred

This is the whole reason the flag exists. The script refuses to fall back to
`DATABASE_URL`, `MIGRATION_DATABASE_URL`, `PLATFORM_DATABASE_URL` or anything
else already in the environment, and reads no compose file, no `.env`, and no
deployment config. Those are exactly the channels through which a tool "helpfully"
discovers a production database nobody asked it to touch.

An operator names the target for this run, or the script does nothing. If the DSN
is absent it exits non-zero and says so; it never guesses.

## Read-only, enforced by the database

The connection opens a `READ ONLY` transaction before any statement runs, so a
write is refused by PostgreSQL rather than by this file's good intentions. It
writes to neither system — not the legacy tables, not the module's, not a log
table, not a run record.

## Deterministic output

The document is a pure function of database state. The same database produces
byte-identical bytes twice: sorted keys, sorted lists, no run timestamp anywhere,
and a payload digest over the canonical body. Diff two runs and any difference is
a change in the database, never in the tool.

Exit codes: 0 inventory emitted; 2 no DSN named; 3 the shadow-phase readiness
check failed (the module tables are not empty, or the online role is not
SELECT-only) — the inventory is still printed, because a failed readiness check
is itself evidence worth keeping.
"""

from __future__ import annotations

import argparse
import os
import sys

# D1 ALLOWLIST — see `tests/architecture/test_deny_cases.py`. This entrypoint
# constructs an engine because the whole point is to connect to a DSN an operator
# names for one run, which is the opposite of the "one control-plane database the
# kernel owns" that D1 protects. The enforceable premises are: the DSN is
# supplied explicitly and never read from the app's own environment variables;
# the transaction is READ ONLY; and nothing here writes.
from sqlalchemy import create_engine, text  # noqa: E402

from vendor_cp.approvals_inventory import (  # noqa: E402
    collect_legacy_estate,
    collect_module_readiness,
    render_evidence,
)

#: The ONLY environment variable this script will read a target from.
DSN_ENV_VAR = "VENDOR_INVENTORY_DSN"

#: Variables it deliberately ignores, because reading any of them would let the
#: script discover a database from ambient configuration instead of being told.
REFUSED_ENV_VARS = (
    "DATABASE_URL",
    "MIGRATION_DATABASE_URL",
    "PLATFORM_DATABASE_URL",
    "TEST_DATABASE_URL",
)


def resolve_dsn(argument: str | None, environ: dict[str, str]) -> str | None:
    """The named target, or `None`. Never a guess.

    Pure and injected, so the refusal is testable without setting real
    environment variables — and so the list of variables it will NOT read is a
    checked fact rather than a claim in a docstring.
    """
    if argument:
        return argument
    return environ.get(DSN_ENV_VAR) or None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only inventory of the legacy approvals tables.",
    )
    parser.add_argument(
        "--dsn",
        default=None,
        help=(
            "SQLAlchemy DSN of the database to inventory. Required unless "
            f"{DSN_ENV_VAR} is set. Never inferred from deployment config."
        ),
    )
    arguments = parser.parse_args(argv)

    dsn = resolve_dsn(arguments.dsn, dict(os.environ))
    if not dsn:
        print(
            f"no target named: pass --dsn or set {DSN_ENV_VAR}.\n"
            "This script deliberately does NOT fall back to "
            f"{', '.join(REFUSED_ENV_VARS)} or read any deployment config — a "
            "target is named for this run or the inventory does not happen.",
            file=sys.stderr,
        )
        return 2

    engine = create_engine(dsn)
    try:
        with engine.connect() as connection:
            # Enforced by PostgreSQL, not by intent: any write in this
            # transaction is refused regardless of what the code below does.
            connection.execute(text("SET TRANSACTION READ ONLY"))
            estate = collect_legacy_estate(connection)
            readiness = collect_module_readiness(connection)
    finally:
        engine.dispose()

    print(render_evidence(estate, readiness))
    return 0 if readiness.ok else 3


if __name__ == "__main__":
    raise SystemExit(main())
