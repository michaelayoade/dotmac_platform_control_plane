"""The `offers` feature manifest — immutable priced offer versions.

JSON API only (`routers`). `core=True`: offer versions are foundational to the
commercial domain (ContractService pins them).
"""

from __future__ import annotations

from dotmac_kernel.features import FeatureManifest

from vendor_cp.offers.router import router

feature = FeatureManifest(
    name="offers",
    routers=[router],
    core=True,
    enabled_by_default=True,
    audit_actions=("vendor.offer_version.published",),
)
