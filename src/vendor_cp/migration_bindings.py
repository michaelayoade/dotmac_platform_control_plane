"""Vendor's answers to which composed revision supplies required DB effects.

The Vendor Control Plane operates the platform plane only. Kernel revision
``0001_initial_tenant_schema`` creates the shared database roles required by
installable module migrations, so Vendor binds that effect to the kernel
lineage. It deliberately does not bind ``tenant_scope_catalog.v1``: a missing
tenant binding is the enforceable premise that makes dual-plane modules omit
their tenant tables when composed here.
"""

from __future__ import annotations

from typing import Final

from dotmac_kernel.prerequisites import (
    MODULE_DATABASE_ROLES_V1,
    PrerequisiteBinding,
)

ASSEMBLY_PREREQUISITE_BINDINGS: Final[tuple[PrerequisiteBinding, ...]] = (
    PrerequisiteBinding(
        prerequisite=MODULE_DATABASE_ROLES_V1.name,
        provider_revision="0001_initial_tenant_schema",
        provider_owner="kernel",
    ),
)

__all__ = ["ASSEMBLY_PREREQUISITE_BINDINGS"]
