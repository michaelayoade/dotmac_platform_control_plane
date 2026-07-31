"""The `approvals` feature manifest — versioned approval policy + approvals."""

from __future__ import annotations

from dotmac_kernel.features import FeatureManifest

from vendor_cp.approvals.router import router

feature = FeatureManifest(
    name="approvals",
    routers=[router],
    core=True,
    enabled_by_default=True,
)
