"""Compose the vendor migration lineage with the kernel's shipped base lineage.

The vendor control-plane database runs the KERNEL base migrations (shipped as
`dotmac_kernel` package data, located via the public `versions_dir()`), the
installed Release Catalog module lineage, the installed Entitlement Allocation
module lineage, PLUS this repo's own `alembic/versions` — one revision graph,
four separately-owned lineages. Because all shared packages are installed
dependencies (not fixed repo paths),
`version_locations` is composed programmatically rather than hard-coded in
`alembic.ini`.

Import-safe: builds an Alembic `Config` only — it constructs no engine (deny-case
D1) and imports only the kernel's PUBLIC `migrations` surface (deny-case D5).
"""

from __future__ import annotations

import os
from pathlib import Path

import dotmac_approvals.migrations as approvals_migrations
from alembic.config import Config
from dotmac_entitlement_allocation import (
    versions_dir as entitlement_allocation_versions_dir,
)
from dotmac_kernel.migrations import versions_dir as kernel_versions_dir
from dotmac_kernel.planes import MODULE_PLANES_ENV_VAR
from dotmac_kernel.prerequisites import BINDINGS_ENV_VAR
from dotmac_release_catalog import versions_dir as release_catalog_versions_dir

REPO_ROOT = Path(__file__).resolve().parents[2]
ALEMBIC_DIR = REPO_ROOT / "alembic"
VENDOR_VERSIONS = ALEMBIC_DIR / "versions"


def approvals_versions_dir() -> Path:
    """Locate the `dotmac-approvals` lineage — a SHIM, pending its own locator.

    Every other installable module in the fleet ships a public
    `versions_dir()`; `dotmac-release-catalog`'s says why in as many words:
    "This public locator keeps the package layout owned here instead of making
    every consumer reconstruct it from `__file__`." `dotmac-approvals` 0.1.0a3
    ships the lineage as package data and exposes no such locator, so this is
    the one consumer in the repository reconstructing a foreign package's
    layout — precisely the thing the convention exists to prevent.

    It is confined to this function on purpose, and
    `tests/architecture/test_release_catalog_composition.py
    ::test_the_approvals_locator_shim_is_still_needed` FAILS the moment the
    upstream locator appears. A shim that nobody is told to delete is how a
    workaround becomes the architecture.
    """
    return Path(approvals_migrations.__file__).resolve().parent / "versions"


def composed_version_locations() -> str:
    """Kernel, three independent modules and vendor migration lineages."""
    return (
        f"{kernel_versions_dir()} "
        f"{release_catalog_versions_dir()} "
        f"{entitlement_allocation_versions_dir()} "
        f"{approvals_versions_dir()} "
        f"{VENDOR_VERSIONS}"
    )


def make_alembic_config(url: str) -> Config:
    """An Alembic `Config` wired to all lineages and the given database URL.

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
    # `alembic heads`, `history` and `show` build the revision map WITHOUT
    # running `env.py`, so a lineage that resolves its `depends_on` from the
    # installed bindings and plane selections would see neither. These two
    # variables are the one channel both entry points share; setting them here
    # keeps an INSPECTED graph identical to the one an upgrade applies.
    os.environ.setdefault(
        BINDINGS_ENV_VAR, "vendor_cp.migration_bindings:ASSEMBLY_PREREQUISITE_BINDINGS"
    )
    os.environ.setdefault(
        MODULE_PLANES_ENV_VAR, "vendor_cp.migration_bindings:ASSEMBLY_MODULE_PLANES"
    )
    return cfg


__all__ = [
    "REPO_ROOT",
    "ALEMBIC_DIR",
    "VENDOR_VERSIONS",
    "composed_version_locations",
    "make_alembic_config",
]
