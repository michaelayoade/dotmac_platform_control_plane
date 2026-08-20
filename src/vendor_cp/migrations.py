"""Compose the vendor migration lineage with the kernel's shipped base lineage.

The vendor control-plane database runs the KERNEL base migrations (shipped as
`dotmac_kernel` package data, located via the public `versions_dir()`), the
installed Release Catalog, Entitlement Allocation, Approvals and Commercial
Agreements module lineages, PLUS this repo's own `alembic/versions` — one
revision graph, six separately-owned lineages. Because all shared packages are
installed dependencies (not fixed repo paths),
`version_locations` is composed programmatically rather than hard-coded in
`alembic.ini`.

Import-safe: builds an Alembic `Config` only — it constructs no engine (deny-case
D1) and imports only the kernel's PUBLIC `migrations` surface (deny-case D5).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final

from alembic.config import Config
from dotmac_approvals.migrations import versions_dir as approvals_versions_dir
from dotmac_commercial_agreements import (
    versions_dir as commercial_agreements_versions_dir,
)
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


def composed_version_locations() -> str:
    """Kernel, four independent modules and Vendor migration lineages."""
    return (
        f"{kernel_versions_dir()} "
        f"{release_catalog_versions_dir()} "
        f"{entitlement_allocation_versions_dir()} "
        f"{approvals_versions_dir()} "
        f"{commercial_agreements_versions_dir()} "
        f"{VENDOR_VERSIONS}"
    )


#: The ONLY target the deploy path applies.
#:
#: `ap_0001_approvals` grants `platform_api` full DML on the approvals module's
#: tables and vendor `v012` takes it away; both run in ONE transaction, so the
#: grant is never a committed state. That guarantee has one reachable hole, and
#: it is an ordinary command rather than an exotic one: `alembic upgrade
#: ap_0001_approvals` stops after the module's own migration and COMMITS the
#: grant. Nothing about it looks dangerous, which is why the deploy path refuses
#: it rather than documenting it.
COMPOSED_TARGET: Final[str] = "heads"


def deploy_target_refusal(target: str) -> str | None:
    """Why the deploy path will not apply `target`, or `None` if it will.

    A function rather than a check inside the script, because the script is a
    thin adapter and this is the decision.
    """
    if target == COMPOSED_TARGET:
        return None
    return (
        f"refusing to upgrade to {target!r}: the deploy path applies composed "
        f"{COMPOSED_TARGET!r} only.\n"
        "A partial upgrade can stop after `ap_0001_approvals` and COMMIT the "
        "module DML grant that vendor `v012` exists to remove — the shadow "
        "composition is read-only only because both run in one transaction.\n"
        "Drive an intermediate target through `make_alembic_config` (the "
        "rehearsals do) if that is genuinely what you want."
    )


def deploy_config(url: str) -> Config:
    """`make_alembic_config`, plus the deploy path's in-transaction post-condition.

    `env.py` reads `require_composed_heads` and asserts, on the live connection,
    that every composed lineage reached its head — so a half-composed database
    rolls back instead of committing. Rehearsals deliberately do not set it: a
    partial upgrade is the whole point there.
    """
    config = make_alembic_config(url)
    config.attributes["require_composed_heads"] = True
    return config


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
    #
    # ASSIGNED, never `setdefault`. These name THIS assembly's declarations, and
    # the assembly is authoritative for them — so a value already exported into
    # the process must lose, not win. `setdefault` had it exactly backwards: a
    # stale or foreign `DOTMAC_MIGRATION_BINDINGS` left over from another
    # assembly, a test, or a shell would survive, and `make_alembic_config`
    # would then inspect a different graph from the one it applies. That is the
    # precise failure the comment above claims to prevent.
    #
    # `DATABASE_URL` above is deliberately NOT in this group: it is the
    # deployment's own runtime DSN, which this function does not own and must
    # not overwrite — it only supplies a fallback so importing the kernel does
    # not fail. `MIGRATION_DATABASE_URL` is owned here and is assigned.
    os.environ[BINDINGS_ENV_VAR] = (
        "vendor_cp.migration_bindings:ASSEMBLY_PREREQUISITE_BINDINGS"
    )
    os.environ[MODULE_PLANES_ENV_VAR] = (
        "vendor_cp.migration_bindings:ASSEMBLY_MODULE_PLANES"
    )
    return cfg


__all__ = [
    "COMPOSED_TARGET",
    "deploy_config",
    "deploy_target_refusal",
    "REPO_ROOT",
    "ALEMBIC_DIR",
    "VENDOR_VERSIONS",
    "composed_version_locations",
    "make_alembic_config",
]
