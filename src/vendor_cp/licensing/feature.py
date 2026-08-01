"""The `licensing` feature manifest — WS8 licence issuance (vendor side).

`core=True`: signed delivery is the contracted hand-off from the vendor control
plane to a product data plane, not an optional add-on.
"""

from __future__ import annotations

from dotmac_kernel.features import FeatureManifest

from vendor_cp.licensing.router import router

feature = FeatureManifest(
    name="licensing",
    routers=[router],
    core=True,
    enabled_by_default=True,
)
