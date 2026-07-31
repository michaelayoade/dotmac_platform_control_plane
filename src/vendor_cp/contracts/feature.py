"""The `contracts` feature manifest — commercial-contract lifecycle.

JSON API only (`routers`). `core=True`: ContractService is the owner of the
commercial decision that AllocationService (and, later, fleet) project from.
"""

from __future__ import annotations

from dotmac_kernel.features import FeatureManifest

from vendor_cp.contracts.router import router

feature = FeatureManifest(
    name="contracts",
    routers=[router],
    core=True,
    enabled_by_default=True,
)
