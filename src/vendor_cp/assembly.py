"""The vendor `ProductAssemblySpec` — how this product composes the kernel.

`build_spec()` declares the vendor control plane as a `dotmac_kernel.assembly.
ProductAssemblySpec` and `main.py` boots it via `dotmac_kernel.create_app`. The
kernel provides config, the single RLS database, platform-admin auth, middleware,
and feature mounting; the vendor supplies only its own feature modules. No copied
kernel code, no private kernel imports (deny-case D5).
"""

from __future__ import annotations

import os

from dotmac_approvals import module as approvals_module
from dotmac_entitlement_allocation import module as entitlement_allocation_module
from dotmac_kernel import ProductAssemblySpec
from dotmac_release_catalog import module as release_catalog_module

from vendor_cp.accounts.feature import feature as accounts_feature
from vendor_cp.allocations.feature import feature as allocations_feature
from vendor_cp.approvals.feature import feature as approvals_feature
from vendor_cp.config import validate_runtime_configuration, vendor_settings
from vendor_cp.console.feature import feature as console_feature
from vendor_cp.contracts.feature import feature as contracts_feature
from vendor_cp.migration_bindings import ASSEMBLY_MODULE_PLANES
from vendor_cp.deployment_profile import (
    VendorDeploymentProfile,
    load_deployment_profile,
)
from vendor_cp.licensing.feature import feature as licensing_feature
from vendor_cp.licensing.signer import install_runtime_licence_signers
from vendor_cp.offers.feature import feature as offers_feature
from vendor_cp.provisioning.feature import feature as provisioning_feature
from vendor_cp.release_evidence.feature import feature as release_evidence_feature

ASSEMBLY_NAME = "dotmac-vendor-control-plane"

# The persistence owners. Composed under EVERY profile, because each one carries
# a migration lineage and a schema this database already contains: withholding
# one would leave the assembly no longer describing its own tables, and the
# composed live-catalogue audit would be walking schemas nobody declared.
STATEFUL_MODULES = (
    release_catalog_module,
    entitlement_allocation_module,
    # Dual-plane, and therefore SELECTABLE: composing it without an explicit
    # `module_planes` entry fails `ProductAssemblySpec` construction. That is
    # the point — a control plane and a product data plane install different
    # halves of this one lineage, and neither is a default.
    approvals_module,
)

# The vendor's own features, in mount order. A profile may withhold a SURFACE
# from this sequence; it may not reorder or add to it.
VENDOR_SURFACES = (
    release_evidence_feature,
    console_feature,
    accounts_feature,
    offers_feature,
    approvals_feature,
    contracts_feature,
    allocations_feature,
    licensing_feature,
    provisioning_feature,
)


def build_spec(profile: VendorDeploymentProfile | None = None) -> ProductAssemblySpec:
    """Compose the vendor control-plane assembly.

    Slice 2: the platform-admin surface + the console shell. Slice 3 adds the
    vendor `accounts` feature (platform-level, option A). Slice 4 adds the
    `provisioning` contract laboratory (fake-only).

    `profile` is the ONE place a deployment profile is read (see
    `vendor_cp.deployment_profile`). It selects which vendor surfaces are
    mounted and nothing else — no behaviour, no persistence, no decision. Tests
    pass one explicitly; the process reads it from the environment.
    """
    validate_runtime_configuration(
        vendor_settings,
        environment=os.getenv("ENVIRONMENT", "development"),
    )
    # Key custody is a boot dependency, not a first-issuance surprise. The
    # installed signer objects hold their key material for this process — and
    # deliberately still do under a profile that withholds the licensing
    # ROUTES, because a withheld surface is not a disabled subsystem.
    install_runtime_licence_signers(vendor_settings)

    effective = profile if profile is not None else load_deployment_profile()

    return ProductAssemblySpec(
        name=ASSEMBLY_NAME,
        # The intent half of the composition (ADR-0028). `dotmac-approvals`
        # ships tenant AND platform planes; this assembly installs only the
        # platform one, because there is no tenant here whose approvals could
        # be scoped. Note this is NOT implied by the prerequisite bindings,
        # which truthfully record that kernel 0001 supplies a tenant catalogue.
        module_planes=ASSEMBLY_MODULE_PLANES,
        modules=(
            *STATEFUL_MODULES,
            *(
                feature
                for feature in VENDOR_SURFACES
                if effective.exposes(feature.name)
            ),
        ),
        web_enabled=True,
    )
