"""Vendor's HTTP surface over the Commercial Agreements module authority."""

from __future__ import annotations

from dotmac_kernel.features import FeatureManifest

from vendor_cp.contracts.router import router

feature = FeatureManifest(
    name="contracts",
    routers=[router],
    core=True,
    enabled_by_default=True,
)
