"""Compose only installed Kernel a100 and Control a14 migrations."""

from __future__ import annotations

import os

from alembic import context
from dotmac_kernel.prerequisites import (
    IDEMPOTENCY_LEDGER_V1,
    PLATFORM_AUDIT_LOG_V1,
    PrerequisiteBinding,
    install_prerequisite_bindings,
)
from sqlalchemy import engine_from_config, pool

install_prerequisite_bindings(
    (
        PrerequisiteBinding(
            IDEMPOTENCY_LEDGER_V1.name, "0018_idempotency_one_owner", "kernel"
        ),
        PrerequisiteBinding(
            PLATFORM_AUDIT_LOG_V1.name, "0026_platform_audit_log", "kernel"
        ),
    )
)


def run_migrations_online() -> None:
    url = os.environ.get("REHEARSAL_ISSUER_MIGRATION_DATABASE_URL")
    if not url:
        raise RuntimeError("REHEARSAL_ISSUER_MIGRATION_DATABASE_URL is required")
    section = context.config.get_section(context.config.config_ini_section) or {}
    section["sqlalchemy.url"] = url
    engine = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    try:
        with engine.connect() as connection:
            context.configure(connection=connection, target_metadata=None)
            with context.begin_transaction():
                context.run_migrations()
    finally:
        engine.dispose()


if context.is_offline_mode():
    raise RuntimeError("offline migration is not a rehearsal")
run_migrations_online()
