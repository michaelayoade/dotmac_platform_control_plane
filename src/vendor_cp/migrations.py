"""Compose the vendor migration lineage with the kernel's shipped base lineage.

The vendor control-plane database runs the KERNEL base migrations (shipped as
`dotmac_kernel` package data, located via the public `versions_dir()`), the
installed Release Catalog, Entitlement Allocation, Approvals, Commercial
Agreements, Licensing and Deployment Control module lineages, PLUS this repo's
own `alembic/versions` — one revision graph, eight separately-owned lineages.
Because all shared packages are installed dependencies (not fixed repo paths),
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
from dotmac_deployment_control import versions_dir as deployment_control_versions_dir
from dotmac_entitlement_allocation import (
    versions_dir as entitlement_allocation_versions_dir,
)
from dotmac_kernel.migrations import versions_dir as kernel_versions_dir
from dotmac_kernel.planes import MODULE_PLANES_ENV_VAR
from dotmac_kernel.prerequisites import BINDINGS_ENV_VAR
from dotmac_licensing import versions_dir as licensing_versions_dir
from dotmac_release_catalog import versions_dir as release_catalog_versions_dir

#: Where the Vendor lineage and `alembic.ini` live, when they are not beside a
#: checkout. An overridable knob with a documented default, per the repository's
#: "everything by config" rule.
#:
#: This exists because the assembly is INSTALLED AS A WHEEL now. The three paths
#: below used to be derived from `__file__` with `parents[2]`, which silently
#: assumed `src/vendor_cp/migrations.py` inside a source tree; from
#: `site-packages/vendor_cp/migrations.py` that expression resolves to the
#: interpreter's library directory and the lineage is simply not there.
#:
#: The migration lineage is deliberately NOT packaged into the wheel. Poetry
#: would place a top-level `alembic` directory at the wheel root, colliding with
#: the Alembic distribution's own import name — a name collision is a worse
#: failure than a configured path. So the image copies the lineage as DATA and
#: names where it put it.
MIGRATION_ROOT_ENV_VAR: Final[str] = "VENDOR_MIGRATION_ROOT"


class MigrationRootNotFound(RuntimeError):
    """The migration lineage is not where this process was told to look."""


#: The checkout layout, used when the environment says nothing. Correct for
#: development, tests and CI, all of which run from a source tree.
_CHECKOUT_ROOT: Final[Path] = Path(__file__).resolve().parents[2]


def migration_root() -> Path:
    """The directory holding `alembic.ini` and `alembic/versions`.

    Resolved on every call rather than frozen at import, so a process that sets
    the variable before running a migration gets the directory it named — and so
    a test can point it somewhere without reloading the module.

    Refuses rather than guessing: a root with no `alembic.ini` in it is reported
    with the variable to set, because the alternative is Alembic failing later
    with a message about a missing revision that says nothing about the cause.
    """
    configured = os.environ.get(MIGRATION_ROOT_ENV_VAR, "").strip()
    root = Path(configured).resolve() if configured else _CHECKOUT_ROOT
    if not (root / "alembic.ini").is_file():
        raise MigrationRootNotFound(
            f"no alembic.ini under {root}. This assembly is installed as a "
            "wheel and the migration lineage travels beside the deployment as "
            f"data, so set {MIGRATION_ROOT_ENV_VAR} to the directory holding "
            "`alembic.ini` and `alembic/versions`."
        )
    return root


def alembic_dir() -> Path:
    """The Alembic script location."""
    return migration_root() / "alembic"


def vendor_versions_dir() -> Path:
    """This assembly's own revision directory."""
    return alembic_dir() / "versions"


def composed_version_locations() -> str:
    """Kernel, six independent modules and Vendor migration lineages."""
    return (
        f"{kernel_versions_dir()} "
        f"{release_catalog_versions_dir()} "
        f"{entitlement_allocation_versions_dir()} "
        f"{approvals_versions_dir()} "
        f"{commercial_agreements_versions_dir()} "
        f"{licensing_versions_dir()} "
        f"{deployment_control_versions_dir()} "
        f"{vendor_versions_dir()}"
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

    Used by both the deploy entrypoint (`dotmac-platform admin migrate`) and the
    migration rehearsals, so CLI-vs-test composition can never diverge.
    """
    root = migration_root()
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "alembic"))
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
    "MIGRATION_ROOT_ENV_VAR",
    "MigrationRootNotFound",
    "alembic_dir",
    "composed_version_locations",
    "deploy_config",
    "deploy_target_refusal",
    "make_alembic_config",
    "migration_root",
    "vendor_versions_dir",
]
