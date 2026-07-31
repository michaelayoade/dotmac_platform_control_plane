#!/usr/bin/env python
"""Deploy entrypoint for vendor migrations — composes both lineages, upgrades heads.

Runs as the `app_admin` role (RLS-bypass migrator). The URL comes from
`MIGRATION_DATABASE_URL` (falling back to `DATABASE_URL`). Using the shared
`vendor_cp.migrations.make_alembic_config` guarantees the deploy path composes the
kernel base lineage + the vendor lineage identically to the rehearsals.

Usage: `MIGRATION_DATABASE_URL=postgresql+psycopg://app_admin:...@host/db \
        poetry run python scripts/migrate.py [target]`  (target defaults to heads)
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


def main(target: str = "heads") -> int:
    if not _URL:
        print("set MIGRATION_DATABASE_URL (or DATABASE_URL)", file=sys.stderr)
        return 2
    command.upgrade(make_alembic_config(_URL), target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(*sys.argv[1:2]))
