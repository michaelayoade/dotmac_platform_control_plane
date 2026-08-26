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

a61 separates the two: we bind what we HAVE, and we select what we INSTALL.
Both bindings below are therefore present and truthful, and the tenant plane of
any dual-plane module stays out because it was never SELECTED — never because a
binding was withheld.

`dotmac-approvals` is the one selectable module composed here, and the selection
below installs its PLATFORM plane only. Note what that does NOT say: selecting a
plane chooses STORAGE SHAPE, never WRITE AUTHORITY. Vendor `v013`, authorised by
ADR-0005, is the completed authority switch; `v012` is historical shadow state.

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

#: The assembly's INSTALLATION INTENT, now that a selectable module is composed.
#:
#: `dotmac-approvals` ships tenant AND platform planes. This assembly installs
#: only the platform one: vendor approvals are control-plane state, and there is
#: no tenant here whose approvals could be scoped. ERP selects the tenant plane
#: from this same lineage and the starter selects both — which is exactly why the
#: choice must be declared per assembly rather than inferred from any property
#: the module or the database could observe.
#:
#: `ModulePlane.PLATFORM` selects STORAGE SHAPE. It says nothing about whether
#: this assembly has acquired WRITE AUTHORITY over those tables — that is a
#: migration-state question, and Vendor owns it. See vendor migration `v013`.
ASSEMBLY_MODULE_PLANES: Final[tuple[ModulePlaneSelection, ...]] = (
    ModulePlaneSelection(module="approvals", planes=(ModulePlane.PLATFORM,)),
)


__all__ = [
    "ASSEMBLY_MODULE_PLANES",
    "ASSEMBLY_PREREQUISITE_BINDINGS",
    "KERNEL_ROOT_REVISION",
]
