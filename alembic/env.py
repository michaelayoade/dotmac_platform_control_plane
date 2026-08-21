"""Alembic environment — the vendor control plane's migration environment.

Connects as `app_admin` (the RLS-bypass migration role) — set
`MIGRATION_DATABASE_URL` or `DATABASE_URL`. `target_metadata` is the kernel
`Base` (all kernel models), the installed modules and the vendor's own models,
so autogenerate sees the whole composed schema. The seven lineages' directories
are composed programmatically (`vendor_cp.migrations`), not in `alembic.ini`,
because the shared owners are installed packages with environment-specific
paths.
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context

# Register the kernel models so the shared Base.metadata is fully populated.
from dotmac_kernel import (  # noqa: F401
    audit,
    models_platform,
    settings_models,
)
from dotmac_kernel.messaging import models as messaging_models  # noqa: F401
from dotmac_kernel.models import Base
from dotmac_kernel.planes import install_module_plane_selections
from dotmac_kernel.prerequisites import install_prerequisite_bindings
from sqlalchemy import engine_from_config, pool

# Register the vendor's own models. Importing `vendor_cp.migrations` below also
# loads all installed modules through their public top-level migration locators,
# registering their models on the same shared Base metadata.
# Shared authority models are registered by importing their packages via
# `vendor_cp.migrations`; only retained Vendor models are imported explicitly.
import vendor_cp.accounts.models  # noqa: F401
import vendor_cp.licensing.delivery_models  # noqa: F401
import vendor_cp.offers.models  # noqa: F401
from vendor_cp.migration_bindings import (
    ASSEMBLY_MODULE_PLANES,
    ASSEMBLY_PREREQUISITE_BINDINGS,
)
from vendor_cp.migrations import composed_version_locations

# Both installed BEFORE Alembic builds the revision map: a composed module
# lineage resolves its `depends_on` from them at script-load time, so an
# assembly that composes a module without answering what it requires — or
# without saying which of its planes it wants — fails loudly here rather than
# ordering wrongly or emitting DDL nobody chose.
#
# They are two declarations because they answer two questions. The bindings say
# where an effect comes from; the plane selection says what this product
# installs. See `vendor_cp/migration_bindings.py` for why conflating them
# breaks precisely this assembly (ADR-0028).
install_prerequisite_bindings(ASSEMBLY_PREREQUISITE_BINDINGS)
install_module_plane_selections(ASSEMBLY_MODULE_PLANES)

config = context.config

# Ensure every lineage is composed even if alembic is invoked without the
# programmatic Config (belt-and-suspenders for the online run).
if not config.get_main_option("version_locations"):
    config.set_main_option("version_locations", composed_version_locations())

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def get_url() -> str:
    return os.getenv("MIGRATION_DATABASE_URL") or os.getenv("DATABASE_URL") or ""


def run_migrations_offline() -> None:
    context.configure(
        url=get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def _require_composed_heads(connection: object) -> None:
    """Every composed lineage actually reached its head — checked in-transaction.

    The deploy entrypoint sets `require_composed_heads`; rehearsals driving an
    intermediate target deliberately do not, because a partial upgrade is the
    whole point there.

    Raising here rolls back the ENTIRE composition, which matters for more than
    tidiness: a database that stopped after `ap_0001_approvals` would have
    committed the module DML grant that vendor `v012` exists to remove.

    ## Why this compares ANCESTRY, not the version rows

    `alembic_version` holds current heads, not every applied revision — and a
    `depends_on` edge makes its target an ANCESTOR of the depending revision
    rather than a separate head. `ap_0001_approvals` is a static head of its own
    lineage, but once `v012` depends on it and both are applied, it is no longer
    a head ROW. Comparing static heads against version rows therefore reports it
    missing on a perfectly complete database — which is exactly what CI caught
    on the first run of this check.

    So the question is "is every static head REACHED", answered over the ancestor
    closure of what is applied.
    """
    from alembic.script import ScriptDirectory
    from sqlalchemy import text

    script = ScriptDirectory.from_config(config)
    applied = set(
        connection.execute(  # type: ignore[attr-defined]
            text("SELECT version_num FROM alembic_version")
        ).scalars()
    )

    reached: set[str] = set()
    pending = list(applied)
    while pending:
        revision_id = pending.pop()
        if revision_id in reached:
            continue
        reached.add(revision_id)
        revision = script.get_revision(revision_id)
        for edge in (revision.down_revision, revision.dependencies):
            if edge is None:
                continue
            pending.extend((edge,) if isinstance(edge, str) else tuple(edge))

    missing = set(script.get_heads()) - reached
    if missing:
        raise RuntimeError(
            "upgrade did not reach composed heads; missing "
            f"{sorted(missing)} — refusing to commit a half-composed database"
        )


def run_migrations_online() -> None:
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = get_url()
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            # STATED, not inherited. This is Alembic's default, and the shadow
            # composition's central guarantee rests entirely on it: the WHOLE
            # composed upgrade runs in ONE transaction, so `ap_0001_approvals`
            # granting `platform_api` full DML on the module tables and vendor
            # `v012` taking it away again are never separately visible. The
            # COMMITTED database moves straight from "no module tables" to
            # "module tables, SELECT-only".
            #
            # Flip this to True and that guarantee silently disappears — each
            # migration would commit on its own and the DML grant would be a
            # real, observable, committed state. A default nobody wrote down is
            # a default nobody notices changing, so it is written down.
            transaction_per_migration=False,
        )
        with context.begin_transaction():
            context.run_migrations()
            if config.attributes.get("require_composed_heads"):
                _require_composed_heads(connection)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
