"""The `console` feature manifest — the vendor admin shell.

Registered in the vendor `ProductAssemblySpec.modules`. Declares its web surface
(`web_routers`) and sidebar entry (`nav`) the kernel mounts; carries no JSON
`routers` yet. `core=False` — it is a deletable surface, not part of the
control-plane's minimum viable core.
"""

from __future__ import annotations

from dotmac_kernel.features import FeatureManifest, NavItem

from vendor_cp.console.web import router

feature = FeatureManifest(
    name="console",
    web_routers=[router],
    nav=(NavItem(label="Vendor Console", path="/admin"),),
    core=False,
    enabled_by_default=True,
)
