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

from vendor_cp.migrations import make_alembic_config  # noqa: E402

#: The ONLY target this entrypoint accepts. See the module docstring.
COMPOSED_TARGET = "heads"


def main(target: str = COMPOSED_TARGET) -> int:
    if not _URL:
        print("set MIGRATION_DATABASE_URL (or DATABASE_URL)", file=sys.stderr)
        return 2

    if target != COMPOSED_TARGET:
        print(
            f"refusing to upgrade to {target!r}: the deploy path applies composed "
            f"{COMPOSED_TARGET!r} only.\n"
            "A partial upgrade can stop after `ap_0001_approvals` and COMMIT the "
            "module DML grant that vendor `v012` exists to remove — the shadow "
            "composition is read-only only because both run in one transaction.\n"
            "Drive an intermediate target through vendor_cp.migrations "
            "make_alembic_config (rehearsals do) if that is genuinely what you "
            "want.",
            file=sys.stderr,
        )
        return 3

    config = make_alembic_config(_URL)
    # Assert the OUTCOME, not the action, and assert it INSIDE the migration
    # transaction: `upgrade("heads")` returning does not by itself say the
    # database reached every composed head — a lineage missing from
    # `version_locations` is simply never applied, and the command reports
    # success for the lineages it did know about. `env.py` performs the check on
    # the live connection, so a shortfall rolls the whole composition back
    # rather than leaving a half-composed database committed.
    config.attributes["require_composed_heads"] = True
    command.upgrade(config, COMPOSED_TARGET)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(*sys.argv[1:2]))
