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

The separation introduced in a61 remains the contract at the a77 pin: we bind
what we HAVE, and we select what we INSTALL. Every binding below is therefore
present and truthful, and the tenant plane of any dual-plane module stays out
because it was never SELECTED — never because a binding was withheld.

`outbox_relay.v1` joined the list at the approvals a5 repin rather than at
composition, and that ordering is the interesting part: the module had written
the relay tables since a1 without declaring the effect, so for three releases
this assembly satisfied a dependency it had never been asked to name. Binding it
is not new capability; it is the same database, finally described.

`dotmac-approvals` is the one selectable module composed here, and the selection
below installs its PLATFORM plane only. Note what that does NOT say: selecting a
plane chooses STORAGE SHAPE, never WRITE AUTHORITY. Vendor `v012` imposed the
bounded shadow restriction; `v013` later restored DML and transferred authority
under ADR-0005.

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
    IDEMPOTENCY_LEDGER_V1,
    MODULE_DATABASE_ROLES_V1,
    OUTBOX_RELAY_V1,
    PLATFORM_AUDIT_LOG_V1,
    TENANT_SCOPE_CATALOG_V1,
    PrerequisiteBinding,
)

#: The kernel lineage root provides both effects this assembly can supply.
KERNEL_ROOT_REVISION: Final[str] = "0001_initial_tenant_schema"

ASSEMBLY_PREREQUISITE_BINDINGS: Final[tuple[PrerequisiteBinding, ...]] = (
    # Keep the declaration in the canonical prerequisite-name order returned by
    # `installed_bindings()`. Order is not semantic, but one stable order makes
    # the installed graph and this checked-in declaration directly comparable.
    PrerequisiteBinding(
        prerequisite=IDEMPOTENCY_LEDGER_V1.name,
        provider_revision="0018_idempotency_one_owner",
        provider_owner="kernel",
    ),
    PrerequisiteBinding(
        prerequisite=MODULE_DATABASE_ROLES_V1.name,
        provider_revision=KERNEL_ROOT_REVISION,
        provider_owner="kernel",
    ),
    # Bound at the approvals a5 repin. The module always wrote both relay
    # tables — `emit_platform_events` calls the kernel's `enqueue_platform_event`
    # at request time — and through a4 declared nothing, so nothing here had to
    # name a provider. a5 declares the effect and `ap_0002_outbox_relay` verifies
    # it at deploy, which is what turns a dependency that lived inside a function
    # body into one this assembly must answer for.
    #
    # `0012_platform_outbox` rather than `0008_outbox_inbox`, and the difference
    # matters: the effect spans BOTH planes plus the lease/retry columns and the
    # claim/settle pair. 0008 creates the tenant table, 0011 adds leasing, and
    # 0012 is the descendant that completes it. Binding the root would name a
    # revision that supplies part of an effect — the same class of error as
    # binding a lineage root for the idempotency ledger instead of 0018. The
    # starter reference assembly binds the same revision.
    PrerequisiteBinding(
        prerequisite=OUTBOX_RELAY_V1.name,
        provider_revision="0012_platform_outbox",
        provider_owner="kernel",
    ),
    PrerequisiteBinding(
        prerequisite=PLATFORM_AUDIT_LOG_V1.name,
        provider_revision="0026_platform_audit_log",
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
#: migration-state question, and Vendor owns it. See vendor migrations `v012`
#: and `v013`.
ASSEMBLY_MODULE_PLANES: Final[tuple[ModulePlaneSelection, ...]] = (
    ModulePlaneSelection(module="approvals", planes=(ModulePlane.PLATFORM,)),
)


__all__ = [
    "ASSEMBLY_MODULE_PLANES",
    "ASSEMBLY_PREREQUISITE_BINDINGS",
    "KERNEL_ROOT_REVISION",
]
