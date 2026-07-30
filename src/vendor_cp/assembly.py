"""The vendor `ProductAssemblySpec` — how this product composes the kernel.

`build_spec()` declares the vendor control plane as a `dotmac_kernel.assembly.
ProductAssemblySpec` and `main.py` boots it via `dotmac_kernel.create_app`. The
kernel provides config, the single RLS database, platform-admin auth, middleware,
and feature mounting; the vendor supplies only its own feature modules. No copied
kernel code, no private kernel imports (deny-case D5).
"""

from __future__ import annotations

from dotmac_kernel import ProductAssemblySpec

from vendor_cp.console.feature import feature as console_feature

ASSEMBLY_NAME = "dotmac-vendor-control-plane"


def build_spec() -> ProductAssemblySpec:
    """Compose the vendor control-plane assembly.

    Slice 1/2: the platform-admin surface + the console shell. Accounts and the
    provisioning laboratory are added as their own feature modules in later
    slices.
    """
    return ProductAssemblySpec(
        name=ASSEMBLY_NAME,
        modules=(console_feature,),
        web_enabled=True,
    )
