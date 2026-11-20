"""Installed composition declarations shared by web and non-web processes.

Vendor declarations carry no routes or runtime configuration. The web assembly
adds surfaces to these same manifests; audit startup consumes every installed
owner regardless of a deployment profile's surface choices.
"""

from __future__ import annotations

from dotmac_approvals import module as approvals_module
from dotmac_commercial_agreements import module as commercial_agreements_module
from dotmac_deployment_control import module as deployment_control_module
from dotmac_entitlement_allocation import module as entitlement_allocation_module
from dotmac_kernel import (
    AuditActionRegistry,
    FeatureManifest,
    ModuleManifest,
    install_audit_actions,
)
from dotmac_licensing import module as licensing_module
from dotmac_release_catalog import module as release_catalog_module

from vendor_cp.accounts.declaration import declaration as accounts_declaration
from vendor_cp.allocations.declaration import declaration as allocations_declaration
from vendor_cp.approvals.declaration import declaration as approvals_declaration
from vendor_cp.console.declaration import declaration as console_declaration
from vendor_cp.contracts.declaration import declaration as contracts_declaration
from vendor_cp.deploy_agent.declaration import declaration as deploy_agent_declaration
from vendor_cp.licensing.declaration import declaration as licensing_declaration
from vendor_cp.offers.declaration import declaration as offers_declaration
from vendor_cp.provisioning.declaration import declaration as provisioning_declaration
from vendor_cp.readiness.declaration import declaration as readiness_declaration
from vendor_cp.relay.withdrawal_conflicts_declaration import (
    declaration as withdrawal_conflicts_declaration,
)
from vendor_cp.release_evidence.declaration import (
    declaration as release_evidence_declaration,
)

# The persistence owners. Present under EVERY profile, because each one carries
# a migration lineage and a schema this database already contains: an assembly
# missing one would no longer describe its own tables, and the composed
# live-catalogue audit would be walking schemas nobody declared.
# `test_deployment_profile.py` derives its assertion from this tuple and proves
# both halves per profile: the manifest is still registered, and the lineage's
# head revision is still reachable in the composed revision graph.
#
# Present is not the same as unfiltered. Since ADR-0019 a profile may withhold a
# stateful module's ROUTES — `_profiled_surface` clears route fields and nothing
# else, so the manifest, its tables and its lineage are exactly as composed —
# and it must be able to, or a module that ships an operator screen would
# force-publish it into every production profile.
STATEFUL_MODULES = (
    release_catalog_module,
    entitlement_allocation_module,
    # Dual-plane and therefore SELECTABLE: composing it without an explicit
    # `module_planes` entry fails `ProductAssemblySpec` construction. It is the
    # approval authority under ADR-0005; vendor migration `v013` restored online
    # DML after the bounded v012 shadow phase and retired the local writer.
    approvals_module,
    # Platform-only and atomic: Vendor v015 checks the empty legacy premise,
    # retires the local owner and makes this module the sole agreement writer.
    commercial_agreements_module,
    # Platform-only and atomic: Vendor v016 retires the empty local issuer;
    # delivery and product-held key custody remain Vendor responsibilities.
    licensing_module,
    # Platform-only and atomic. A module that decides what a fleet of
    # deployments should run cannot live inside one of them, so there is no
    # tenant plane to select and `ASSEMBLY_MODULE_PLANES` gains nothing.
    #
    # Composed as a GREENFIELD owner for plans, rollouts, credentials and
    # observations — no revision in this lineage ever created one. The
    # deployment-TARGET half was an authority cutover: `v017` sealed the
    # independent registration path, and `vendor_cp.deployment.adapter` is the
    # only seam (ADR-0011).
    deployment_control_module,
)

# Canonical installed order, shared by route composition and audit startup.
VENDOR_DECLARATIONS: tuple[FeatureManifest | ModuleManifest, ...] = (
    release_evidence_declaration,
    readiness_declaration,
    console_declaration,
    accounts_declaration,
    offers_declaration,
    approvals_declaration,
    contracts_declaration,
    allocations_declaration,
    licensing_declaration,
    provisioning_declaration,
    withdrawal_conflicts_declaration,
    deploy_agent_declaration,
)

COMPOSED_DECLARATIONS: tuple[FeatureManifest | ModuleManifest, ...] = (
    *STATEFUL_MODULES,
    *VENDOR_DECLARATIONS,
)


def install_process_audit_actions() -> None:
    """Install all declared actions without starting the web or DB runtime."""
    install_audit_actions(AuditActionRegistry.from_manifests(COMPOSED_DECLARATIONS))


# Retain the stateful module aliases re-exported by the web assembly, as well
# as the declaration/bootstrap surface shared with non-web process owners.
__all__ = [
    "COMPOSED_DECLARATIONS",
    "STATEFUL_MODULES",
    "VENDOR_DECLARATIONS",
    "approvals_module",
    "commercial_agreements_module",
    "deployment_control_module",
    "entitlement_allocation_module",
    "install_process_audit_actions",
    "licensing_module",
    "release_catalog_module",
]
