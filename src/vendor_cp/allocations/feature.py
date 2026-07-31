"""The `allocations` feature manifest — staged allocation projection (read API).

The staging itself is event-driven (`ContractEventConsumer`), not route-driven; the
router is read-only. `core=True`: allocation is the projection the WS8 signed
delivery will later consume.
"""

from __future__ import annotations

from dotmac_kernel.features import FeatureManifest

from vendor_cp.allocations.router import router

feature = FeatureManifest(
    name="allocations",
    routers=[router],
    core=True,
    enabled_by_default=True,
)
