"""The tenant-scoped `accounts` feature manifest (option C spike)."""

from __future__ import annotations

from dotmac_kernel.features import FeatureManifest

from vendor_cp.accounts.router import router

feature = FeatureManifest(
    name="accounts",
    routers=[router],
    core=True,
    enabled_by_default=True,
)
