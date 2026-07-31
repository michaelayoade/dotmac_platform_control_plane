"""The vendor `ProductAssemblySpec` — how this product composes the kernel.

`build_spec()` declares the vendor control plane as a `dotmac_kernel.assembly.
ProductAssemblySpec` and `main.py` boots it via `dotmac_kernel.create_app`. The
kernel provides config, the single RLS database, platform-admin auth, middleware,
and feature mounting; the vendor supplies only its own feature modules. No copied
kernel code, no private kernel imports (deny-case D5).
"""

from __future__ import annotations

from dotmac_kernel import ProductAssemblySpec

from vendor_cp.accounts.feature import feature as accounts_feature
from vendor_cp.approvals.feature import feature as approvals_feature
from vendor_cp.console.feature import feature as console_feature
from vendor_cp.offers.feature import feature as offers_feature
from vendor_cp.provisioning.feature import feature as provisioning_feature

ASSEMBLY_NAME = "dotmac-vendor-control-plane"


def build_spec() -> ProductAssemblySpec:
    """Compose the vendor control-plane assembly.

    Slice 2: the platform-admin surface + the console shell. Slice 3 adds the
    vendor `accounts` feature (platform-level, option A). Slice 4 adds the
    `provisioning` contract laboratory (fake-only).
    """
    return ProductAssemblySpec(
        name=ASSEMBLY_NAME,
        modules=(
            console_feature,
            accounts_feature,
            offers_feature,
            approvals_feature,
            provisioning_feature,
        ),
        web_enabled=True,
    )
