"""Compose the vendor migration lineage with the kernel's shipped base lineage.

The vendor control-plane database runs the KERNEL base migrations (shipped as
`dotmac_kernel` package data, located via the public `versions_dir()`), the
installed Release Catalog module lineage, PLUS this repo's own
`alembic/versions` — one revision graph, three separately-owned lineages.
Because both shared packages are installed dependencies (not fixed repo paths),
`version_locations` is composed programmatically rather than hard-coded in
`alembic.ini`.

Import-safe: builds an Alembic `Config` only — it constructs no engine (deny-case
D1) and imports only the kernel's PUBLIC `migrations` surface (deny-case D5).
"""

from __future__ import annotations

import os
from pathlib import Path

from alembic.config import Config
from dotmac_kernel.migrations import versions_dir as kernel_versions_dir
from dotmac_release_catalog import versions_dir as release_catalog_versions_dir

REPO_ROOT = Path(__file__).resolve().parents[2]
ALEMBIC_DIR = REPO_ROOT / "alembic"
VENDOR_VERSIONS = ALEMBIC_DIR / "versions"


def composed_version_locations() -> str:
    """Kernel, Release Catalog and vendor assembly migration lineages."""
    return (
        f"{kernel_versions_dir()} "
        f"{release_catalog_versions_dir()} "
        f"{VENDOR_VERSIONS}"
    )


def make_alembic_config(url: str) -> Config:
    """An Alembic `Config` wired to both lineages and the given database URL.

    Used by both the deploy entrypoint (`scripts/migrate.py`) and the migration
    rehearsals, so CLI-vs-test composition can never diverge.
    """
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ALEMBIC_DIR))
    cfg.set_main_option("version_locations", composed_version_locations())
    # env.py reads the migration URL from the environment. DATABASE_URL is set too
    # because env.py imports `dotmac_kernel.messaging`, which eagerly constructs the
    # kernel engine from DATABASE_URL at import (it never connects here).
    os.environ["MIGRATION_DATABASE_URL"] = url
    os.environ.setdefault("DATABASE_URL", url)
    return cfg


__all__ = [
    "REPO_ROOT",
    "ALEMBIC_DIR",
    "VENDOR_VERSIONS",
    "composed_version_locations",
    "make_alembic_config",
]
