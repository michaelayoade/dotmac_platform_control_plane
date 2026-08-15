#!/usr/bin/env python
"""Deploy entrypoint for vendor migrations — composes every lineage, upgrades heads.

Runs as the `app_admin` role (RLS-bypass migrator). The URL comes from
`MIGRATION_DATABASE_URL` (falling back to `DATABASE_URL`). Using the shared
`vendor_cp.migrations.make_alembic_config` guarantees the deploy path composes the
kernel base lineage, the module lineages and the vendor lineage identically to the
rehearsals.

## Why this refuses a partial target

`ap_0001_approvals` grants `platform_api` full DML on the approvals module's
tables; vendor `v012` takes it away. Both run inside ONE transaction
(`transaction_per_migration=False`, stated in `alembic/env.py`), so the grant is
never a committed state — the database moves straight from "no module tables" to
"module tables, SELECT-only".

That guarantee has one reachable hole, and it is not exotic: an ordinary
`alembic upgrade ap_0001_approvals` stops after the module's own migration and
COMMITS the DML grant. Nothing about that command looks dangerous, which is
exactly why the production entrypoint refuses it rather than documenting it.

So this script upgrades to composed `heads` and nothing else. Rehearsals and
tests still drive intermediate targets directly through
`vendor_cp.migrations.make_alembic_config` — they need to, and they are not the
deploy path.

Usage: `MIGRATION_DATABASE_URL=postgresql+psycopg://app_admin:...@host/db \
        poetry run python scripts/migrate.py`
"""

from __future__ import annotations

import os
import sys

# Importing dotmac_kernel instantiates its Settings (and, via messaging, its
# engine) from DATABASE_URL at import time — so DATABASE_URL must be set BEFORE
# any kernel-touching import below. It is never connected to here; migrations use
# MIGRATION_DATABASE_URL.
_URL = os.getenv("MIGRATION_DATABASE_URL") or os.getenv("DATABASE_URL") or ""
if _URL:
    os.environ.setdefault("DATABASE_URL", _URL)
    os.environ.setdefault("MIGRATION_DATABASE_URL", _URL)

from alembic import command  # noqa: E402

from vendor_cp.migrations import (  # noqa: E402
    COMPOSED_TARGET,
    deploy_config,
    deploy_target_refusal,
)


def main(target: str = COMPOSED_TARGET) -> int:
    """Validate, then delegate. The decisions live in `vendor_cp.migrations`."""
    if not _URL:
        print("set MIGRATION_DATABASE_URL (or DATABASE_URL)", file=sys.stderr)
        return 2

    refusal = deploy_target_refusal(target)
    if refusal is not None:
        print(refusal, file=sys.stderr)
        return 3

    command.upgrade(deploy_config(_URL), COMPOSED_TARGET)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(*sys.argv[1:2]))
