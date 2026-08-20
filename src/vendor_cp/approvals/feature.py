"""The Vendor approval adapter surface over the composed approvals module.

`dotmac-approvals` is the ONLY approval owner in this assembly. Vendor's routes
delegate through the typed adapter; the retired local models, writer and tables
are gone under ADR-0005.

## Why it is named `vendor_approvals`

`dotmac-approvals` holds the module code `approvals`. A module registry has one
owner per code, so this adapter package cannot also be called that.

The HTTP surface is unchanged: routes still live under
`/platform/vendor/approvals`. A manifest name is a composition identifier, not a
URL.
"""

from __future__ import annotations

from dotmac_kernel.features import FeatureManifest

from vendor_cp.approvals.router import router

feature = FeatureManifest(
    name="vendor_approvals",
    routers=[router],
    core=True,
    enabled_by_default=True,
)
