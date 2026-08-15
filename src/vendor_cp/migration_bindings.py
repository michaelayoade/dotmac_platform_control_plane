"""This assembly's two independent composition declarations.

They answer different questions and must never be collapsed into one:

- **`ASSEMBLY_PREREQUISITE_BINDINGS`** — *where does an effect come from?* A
  binding names the composed revision whose effects satisfy a logical
  prerequisite. It is a statement of fact about this database.
- **`ASSEMBLY_MODULE_PLANES`** — *which part of a module do we intend to
  install?* A selection is a statement of intent about this product.

## Why they are separate (ADR-0028)

Kernel `0.1.0a60` briefly let the first answer imply the second: a dual-plane
module built its tenant plane if, and only if, the assembly happened to bind
`tenant_scope_catalog.v1`. That reads plausibly and is wrong here, because the
Vendor Control Plane is the exact case it fails on.

This assembly runs the whole kernel base lineage, and kernel
`0001_initial_tenant_schema` creates `public.tenants`, `public.tenant_domains`
and `public.app_current_tenant_id()` unconditionally. The tenant catalogue
genuinely EXISTS here, so binding it is simply truthful. Under the a60 model
that truthful binding would have switched on tenant approval tables in a
control plane with no tenants to scope them to, and the only way to avoid that
was to lie by withholding a binding whose effect the database plainly provides.

a61 separates the two. We bind what we have, and we select what we want: the
Vendor Control Plane is not a product data plane, so it selects `PLATFORM`
approvals and nothing else. The tenant plane's prerequisites are never
resolved and its DDL is never emitted because of the SELECTION — never because
of an absent binding.

Both declarations are installed from `alembic/env.py` before Alembic builds the
revision map, and both are mirrored into the graph-command environment
variables (`DOTMAC_MIGRATION_BINDINGS`, `DOTMAC_MODULE_PLANE_SELECTIONS`) by
`vendor_cp.migrations.make_alembic_config`, because `alembic heads`, `history`
and `show` build a revision map without ever running `env.py`.
"""

from __future__ import annotations

from typing import Final

from dotmac_kernel.planes import ModulePlane, ModulePlaneSelection
from dotmac_kernel.prerequisites import (
    MODULE_DATABASE_ROLES_V1,
    TENANT_SCOPE_CATALOG_V1,
    PrerequisiteBinding,
)

#: The kernel lineage root provides both effects this assembly can supply.
KERNEL_ROOT_REVISION: Final[str] = "0001_initial_tenant_schema"

ASSEMBLY_PREREQUISITE_BINDINGS: Final[tuple[PrerequisiteBinding, ...]] = (
    PrerequisiteBinding(
        prerequisite=MODULE_DATABASE_ROLES_V1.name,
        provider_revision=KERNEL_ROOT_REVISION,
        provider_owner="kernel",
    ),
    # Bound because it is TRUE, not because anything here wants a tenant plane.
    # Kernel 0001 creates the catalogue and the RLS function, so a reviewer
    # reading only this list sees the database as it actually is. What this
    # assembly INSTALLS is decided one declaration below.
    PrerequisiteBinding(
        prerequisite=TENANT_SCOPE_CATALOG_V1.name,
        provider_revision=KERNEL_ROOT_REVISION,
        provider_owner="kernel",
    ),
)

ASSEMBLY_MODULE_PLANES: Final[tuple[ModulePlaneSelection, ...]] = (
    # The vendor control plane holds approval state for VENDOR decisions —
    # offers, contracts, releases. No tenant exists here whose approvals could
    # be scoped, so the tenant plane is not installed. ERP selects the tenant
    # plane from this same lineage and the starter selects both, which is
    # exactly why the choice has to be declared per assembly rather than
    # inferred from any property the module or the database could observe.
    ModulePlaneSelection(module="approvals", planes=(ModulePlane.PLATFORM,)),
)

__all__ = [
    "ASSEMBLY_MODULE_PLANES",
    "ASSEMBLY_PREREQUISITE_BINDINGS",
    "KERNEL_ROOT_REVISION",
]
