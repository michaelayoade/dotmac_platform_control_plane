"""Compose the vendor migration lineage with the kernel's shipped base lineage.

The vendor control-plane database runs the KERNEL base migrations (shipped as
`dotmac_kernel` package data, located via the public `versions_dir()`) PLUS this
repo's own `alembic/versions` — one revision graph, two separately-owned
lineages, exactly the pattern the reference assembly uses. Because the kernel is
an installed dependency (not a fixed repo path), `version_locations` is composed
programmatically here rather than hard-coded in `alembic.ini`.

Import-safe: builds an Alembic `Config` only — it constructs no engine (deny-case
D1) and imports only the kernel's PUBLIC `migrations` surface (deny-case D5).
"""

from __future__ import annotations

import os
from pathlib import Path

import dotmac_entitlement_allocation
import dotmac_release_catalog
from alembic.config import Config
from dotmac_kernel.migrations import versions_dir as kernel_versions_dir

REPO_ROOT = Path(__file__).resolve().parents[2]
ALEMBIC_DIR = REPO_ROOT / "alembic"
VENDOR_VERSIONS = ALEMBIC_DIR / "versions"


def _module_versions_dir(module) -> Path:
    """Locate an installed module's Alembic lineage.

    The kernel publishes `dotmac_kernel.migrations.versions_dir()` for exactly
    this, and `dotmac-application-directory` followed it. `dotmac-release-catalog`
    and `dotmac-entitlement-allocation` 0.1.0a1 do NOT — they were released
    before a cross-repository consumer existed, and this assembly is the first,
    so the gap surfaced here.

    Deriving the path from `__file__` is a workaround, not the pattern: it
    depends on the package's internal layout, which is the module's to change.
    The fix belongs upstream — a `versions_dir()` on each module, shipped in
    0.1.0a2 — and this helper is deleted when both expose one. Until then a
    consumer cannot compose their lineages at all, which is worse.
    """
    package_root = Path(module.__file__).resolve().parent
    location = package_root / "migrations" / "versions"
    if not location.is_dir():
        raise RuntimeError(
            f"{module.__name__} ships no migrations/versions directory at "
            f"{location} — the wheel is not the one the release allowlist "
            "describes."
        )
    return location


def composed_version_locations() -> str:
    """The four composed lineages, each located through its OWNER's locator.

    Kernel, release catalog, entitlement allocation, then this repository's own.
    The two module paths are resolved by the modules themselves rather than
    hard-coded: they are installed packages whose location is environment
    specific — a virtualenv, a wheel, a container layer — and guessing at
    `__file__` would break the first time one is installed differently.

    Order is not significance: each lineage carries its own branch label and
    cross-lineage ordering is `depends_on`, never position.
    """
    return " ".join(
        str(location)
        for location in (
            kernel_versions_dir(),
            _module_versions_dir(dotmac_release_catalog),
            _module_versions_dir(dotmac_entitlement_allocation),
            VENDOR_VERSIONS,
        )
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
