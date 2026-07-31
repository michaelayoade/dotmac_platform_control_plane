"""Alembic environment — the vendor control plane's migration environment.

Connects as `app_admin` (the RLS-bypass migration role) — set
`MIGRATION_DATABASE_URL` or `DATABASE_URL`. `target_metadata` is the kernel
`Base` (all kernel models) PLUS the vendor's own models, so autogenerate sees the
whole composed schema. The two lineages' directories are composed programmatically
(`vendor_cp.migrations`), not in `alembic.ini`, because the kernel is an installed
package with an environment-specific path.
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
from sqlalchemy import engine_from_config, pool

# Register the vendor's own models (VendorAccount).
import vendor_cp.accounts.models  # noqa: F401
import vendor_cp.allocations.models  # noqa: F401
import vendor_cp.approvals.models  # noqa: F401
import vendor_cp.contracts.models  # noqa: F401
import vendor_cp.offers.models  # noqa: F401
from vendor_cp.migrations import composed_version_locations

config = context.config

# Ensure both lineages are composed even if alembic is invoked without the
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


def run_migrations_online() -> None:
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = get_url()
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
