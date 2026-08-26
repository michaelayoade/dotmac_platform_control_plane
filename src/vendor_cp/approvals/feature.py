"""Vendor approval routes over authoritative ``dotmac-approvals`` state.

ADR-0005 and migration ``v013`` transferred approval authority to the module.
This package owns no approval persistence and makes no approval decision; its
routes are platform-admin adapters over :mod:`vendor_cp.approvals.adapter`, the
one typed seam to the authority.

## Why it is named `vendor_approvals`

`dotmac-approvals` holds the module code ``approvals``. A module registry has one
owner per code, so this route feature remains named ``vendor_approvals`` even
after the authority switch; the different name is composition identity, not a
second owner.

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
