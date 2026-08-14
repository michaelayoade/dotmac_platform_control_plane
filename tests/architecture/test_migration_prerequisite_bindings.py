"""Vendor declares only the migration effects its platform plane can supply.

The control plane composes the kernel lineage, whose root creates the database
roles needed by installable modules. It deliberately does not bind the tenant
catalogue: doing so would let a dual-plane module create tenant-owned state in
an assembly that must never become a product data plane.
"""

from __future__ import annotations

from pathlib import Path

from dotmac_kernel.prerequisites import (
    MODULE_DATABASE_ROLES_V1,
    TENANT_SCOPE_CATALOG_V1,
)

from vendor_cp.migration_bindings import ASSEMBLY_PREREQUISITE_BINDINGS

ROOT = Path(__file__).resolve().parents[2]


def test_vendor_binds_only_the_platform_database_roles() -> None:
    assert tuple(
        (
            binding.prerequisite,
            binding.provider_revision,
            binding.provider_owner,
        )
        for binding in ASSEMBLY_PREREQUISITE_BINDINGS
    ) == (
        (
            MODULE_DATABASE_ROLES_V1.name,
            "0001_initial_tenant_schema",
            "kernel",
        ),
    )
    assert all(
        binding.prerequisite != TENANT_SCOPE_CATALOG_V1.name
        for binding in ASSEMBLY_PREREQUISITE_BINDINGS
    )


def test_alembic_installs_bindings_before_building_the_revision_map() -> None:
    env_source = (ROOT / "alembic" / "env.py").read_text()

    install_at = env_source.index(
        "install_prerequisite_bindings(ASSEMBLY_PREREQUISITE_BINDINGS)"
    )
    configure_at = env_source.index("config = context.config")

    assert install_at < configure_at
