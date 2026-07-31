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
from vendor_cp.console.feature import feature as console_feature

ASSEMBLY_NAME = "dotmac-vendor-control-plane"


def build_spec() -> ProductAssemblySpec:
    """Compose the vendor control-plane assembly.

    Slice 2: the platform-admin surface + the console shell. Slice 3 (this spike
    branch) adds the TENANT-scoped `accounts` feature (option C). The
    provisioning laboratory is a later slice's own feature module.
    """
    return ProductAssemblySpec(
        name=ASSEMBLY_NAME,
        modules=(console_feature, accounts_feature),
        web_enabled=True,
    )
