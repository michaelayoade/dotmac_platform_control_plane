"""The vendor `ProductAssemblySpec` — how this product composes the kernel.

`build_spec()` declares the vendor control plane as a `dotmac_kernel.assembly.
ProductAssemblySpec` and `main.py` boots it via `dotmac_kernel.create_app`. The
kernel provides config, the single RLS database, platform-admin auth, middleware,
and feature mounting; the vendor supplies only its own feature modules. No copied
kernel code, no private kernel imports (deny-case D5).
"""

from __future__ import annotations

import os

from dotmac_entitlement_allocation import module as entitlement_allocation_module
from dotmac_kernel import ProductAssemblySpec
from dotmac_release_catalog import module as release_catalog_module

from vendor_cp.accounts.feature import feature as accounts_feature
from vendor_cp.allocations.feature import feature as allocations_feature
from vendor_cp.approvals.feature import feature as approvals_feature
from vendor_cp.config import validate_runtime_configuration, vendor_settings
from vendor_cp.console.feature import feature as console_feature
from vendor_cp.contracts.feature import feature as contracts_feature
from vendor_cp.licensing.feature import feature as licensing_feature
from vendor_cp.licensing.signer import install_runtime_licence_signers
from vendor_cp.offers.feature import feature as offers_feature
from vendor_cp.provisioning.feature import feature as provisioning_feature
from vendor_cp.release_evidence.feature import feature as release_evidence_feature

ASSEMBLY_NAME = "dotmac-vendor-control-plane"


def build_spec() -> ProductAssemblySpec:
    """Compose the vendor control-plane assembly.

    Slice 2: the platform-admin surface + the console shell. Slice 3 adds the
    vendor `accounts` feature (platform-level, option A). Slice 4 adds the
    `provisioning` contract laboratory (fake-only).
    """
    validate_runtime_configuration(
        vendor_settings,
        environment=os.getenv("ENVIRONMENT", "development"),
    )
    # Key custody is a boot dependency, not a first-issuance surprise. The
    # installed signer objects hold their key material for this process.
    install_runtime_licence_signers(vendor_settings)

    return ProductAssemblySpec(
        name=ASSEMBLY_NAME,
        modules=(
            release_catalog_module,
            entitlement_allocation_module,
            release_evidence_feature,
            console_feature,
            accounts_feature,
            offers_feature,
            approvals_feature,
            contracts_feature,
            allocations_feature,
            licensing_feature,
            provisioning_feature,
        ),
        web_enabled=True,
    )
