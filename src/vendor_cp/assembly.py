"""The vendor `ProductAssemblySpec` — how this product composes the kernel.

`build_spec()` declares the vendor control plane as a `dotmac_kernel.assembly.
ProductAssemblySpec` and `main.py` boots it via `dotmac_kernel.create_app`. The
kernel provides config, the single RLS database, platform-admin auth, middleware,
and feature mounting; the vendor supplies only its own feature modules. No copied
kernel code, no private kernel imports (deny-case D5).
"""

from __future__ import annotations

import os
from dataclasses import replace

from dotmac_kernel import (
    FeatureManifest,
    ModuleManifest,
    ProductAssemblySpec,
)
from dotmac_kernel.api_documentation import environment_api_documentation_policy

from vendor_cp.accounts.feature import feature as accounts_feature
from vendor_cp.allocations.feature import feature as allocations_feature
from vendor_cp.approvals.feature import feature as approvals_feature
from vendor_cp.composition import STATEFUL_MODULES as STATEFUL_MODULES
from vendor_cp.composition import VENDOR_DECLARATIONS
from vendor_cp.composition import approvals_module as approvals_module
from vendor_cp.composition import (
    commercial_agreements_module as commercial_agreements_module,
)
from vendor_cp.composition import deployment_control_module as deployment_control_module
from vendor_cp.composition import (
    entitlement_allocation_module as entitlement_allocation_module,
)
from vendor_cp.composition import licensing_module as licensing_module
from vendor_cp.composition import release_catalog_module as release_catalog_module
from vendor_cp.config import validate_runtime_configuration, vendor_settings
from vendor_cp.console.feature import feature as console_feature
from vendor_cp.contracts.feature import feature as contracts_feature
from vendor_cp.deploy_agent.feature import feature as deploy_agent_feature
from vendor_cp.deploy_agent.runtime import (
    install_runtime as install_deploy_agent_runtime,
)
from vendor_cp.deployment_profile import (
    VendorDeploymentProfile,
    admit_surfaces,
    load_deployment_profile,
    validate_profile_for_environment,
)
from vendor_cp.licensing.feature import feature as licensing_feature
from vendor_cp.licensing.signing_adapter import install_runtime_licence_signers
from vendor_cp.migration_bindings import ASSEMBLY_MODULE_PLANES
from vendor_cp.offers.feature import feature as offers_feature
from vendor_cp.provisioning.feature import feature as provisioning_feature
from vendor_cp.readiness.feature import feature as readiness_feature
from vendor_cp.relay.withdrawal_conflicts_feature import (
    feature as withdrawal_conflicts_feature,
)
from vendor_cp.release_evidence.feature import feature as release_evidence_feature

ASSEMBLY_NAME = "dotmac-vendor-control-plane"

# The vendor's own features, in mount order. A profile may strip a feature's
# route/nav SURFACE; it may not remove its manifest declarations, reorder the
# features or add one.
#
# Not the only route-bearing manifests this assembly composes, and the tuple's
# name is the last place that reading survives: every manifest in
# `COMPOSED_MANIFESTS` goes through the profile, because a composed module that
# ships an operator surface publishes routes exactly as a vendor adapter does
# (ADR-0019).
_VENDOR_SURFACE_BINDINGS = (
    release_evidence_feature,
    # Composed first among the route-bearing surfaces and withheld by none. A
    # deployment that cannot say whether it is ready is one an orchestrator will
    # assume is — which is the failure `/health/ready` exists to end, so the ability
    # to turn it off would reintroduce it.
    readiness_feature,
    console_feature,
    accounts_feature,
    offers_feature,
    approvals_feature,
    contracts_feature,
    allocations_feature,
    licensing_feature,
    provisioning_feature,
    withdrawal_conflicts_feature,
    deploy_agent_feature,
)


# Bind routes by identity; the declaration owner alone defines installed order.
_surface_by_name = {manifest.name: manifest for manifest in _VENDOR_SURFACE_BINDINGS}
if len(_VENDOR_SURFACE_BINDINGS) != len(
    VENDOR_DECLARATIONS
) or _surface_by_name.keys() != {manifest.name for manifest in VENDOR_DECLARATIONS}:
    raise ValueError("vendor surface bindings do not match installed declarations")
VENDOR_SURFACES = tuple(
    _surface_by_name[manifest.name] for manifest in VENDOR_DECLARATIONS
)


def _profiled_surface(
    feature: FeatureManifest | ModuleManifest, profile: VendorDeploymentProfile
) -> FeatureManifest | ModuleManifest:
    """Keep a manifest's declarations installed while withholding its routes.

    Two manifest shapes travel through here, and every composed manifest does —
    vendor adapter and composed module alike. A legacy `FeatureManifest`
    withholds `routers`/`web_routers`/`nav`; a contract-v2 `ModuleManifest`
    withholds `api_routers`/`web_surfaces` AND the legacy pair a contract-1
    module may still carry. The distinction is not cosmetic — clearing the wrong
    field names would leave the routes MOUNTED under a profile that withholds
    them, which is a surface appearing where the profile says it does not exist,
    and the earlier version cleared two of the four names it warned about.

    Declarations are untouched in both shapes, and that is the invariant a
    profile is allowed to rely on: tables, prerequisites, audit vocabulary,
    migration prefix and branch label survive withholding, because this clears
    ROUTE FIELDS and only route fields. It is what makes withholding a stateful
    module's surface safe (`dotmac_starter_mt` ADR-0003; ADR-0019).
    """
    if profile.exposes(feature.name):
        return feature
    if isinstance(feature, ModuleManifest):
        return replace(feature, api_routers=(), web_surfaces=(), web_routers=(), nav=())
    return replace(feature, routers=(), web_routers=(), nav=())


#: Every manifest this assembly composes, in mount order — the persistence
#: owners first, then the vendor surfaces. This is the set admission is measured
#: against and the set the profile filters, and there is one of it precisely so
#: those two cannot diverge again.
COMPOSED_MANIFESTS: tuple[FeatureManifest | ModuleManifest, ...] = (
    *STATEFUL_MODULES,
    *VENDOR_SURFACES,
)


def build_spec(profile: VendorDeploymentProfile | None = None) -> ProductAssemblySpec:
    """Compose the vendor control-plane assembly.

    Slice 2: the platform-admin surface + the console shell. Slice 3 adds the
    vendor `accounts` feature (platform-level, option A). Slice 4 adds the
    `provisioning` contract laboratory (fake-only).

    `profile` is the ONE place a deployment profile is read (see
    `vendor_cp.deployment_profile`). It selects which composed surfaces are
    mounted and nothing else — no behaviour, no persistence, no decision. Tests
    pass one explicitly; the process reads it from the environment.

    Three refusals guard the boot and they are separate checks:
    `validate_runtime_configuration` rejects a production-unsafe MODE,
    `validate_profile_for_environment` rejects a production-unsafe SURFACE SET
    — chiefly a profile mounting the simulated provisioning laboratory, and an
    absent profile that would otherwise inherit the `full` fallback (ADR-0015)
    — and `admit_surfaces` rejects, in every environment, a profile whose
    inventory does not describe the surfaces this composition actually bears
    (ADR-0019).
    """
    environment = os.getenv("ENVIRONMENT", "development")
    validate_runtime_configuration(vendor_settings, environment=environment)

    effective = (
        profile
        if profile is not None
        else load_deployment_profile(environment=environment)
    )
    # The surface half of the boot refusal, and it runs BEFORE key custody is
    # installed: a production process composing the provisioning laboratory
    # must not get as far as holding a signing key. ADR-0015.
    validate_profile_for_environment(
        effective, environment=environment, provider_mode=vendor_settings.provider_mode
    )
    # And the profile must DESCRIBE this composition. Measured against the
    # UNPROFILED manifests: after filtering, a withheld module bears no routes
    # and would read as one that publishes nothing, which is the one conclusion
    # admission must not reach from its own output. Before key custody for the
    # same reason as the check above (ADR-0019).
    admit_surfaces(effective, COMPOSED_MANIFESTS)

    # Key custody is a boot dependency, not a first-issuance surprise. The
    # installed signer objects hold their key material for this process — and
    # deliberately still do under a profile that withholds the licensing
    # ROUTES, because a withheld surface is not a disabled subsystem.
    install_runtime_licence_signers(vendor_settings)
    install_deploy_agent_runtime()

    return ProductAssemblySpec(
        name=ASSEMBLY_NAME,
        # The INTENT half of the composition (`dotmac_starter_mt` ADR-0028):
        # which plane of a selectable module this product installs. Not
        # implied by the
        # prerequisite bindings, which truthfully record that kernel 0001
        # supplies a tenant catalogue this assembly declines to build on.
        module_planes=ASSEMBLY_MODULE_PLANES,
        # EVERY composed manifest goes through the profile. Until ADR-0019 the
        # stateful modules were spliced in raw, so a composed module's operator
        # surface mounted under every profile and appeared in no inventory.
        modules=tuple(
            _profiled_surface(manifest, effective) for manifest in COMPOSED_MANIFESTS
        ),
        # Declared before the app exists, so the kernel gives FastAPI its
        # documentation coordinates at construction rather than this assembly
        # deleting mounted routes afterwards (ADR-0016).
        api_documentation=environment_api_documentation_policy(),
        web_enabled=True,
    )
