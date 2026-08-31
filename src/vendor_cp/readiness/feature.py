"""The `readiness` manifest — composed under every profile, withheld by none.

The route answers on `/health/ready`, which the kernel reserves as a
tenant-resolution-exempt probe path — see `router.py` for why that is not a
cosmetic choice.

It appears in `deployment_profile.VENDOR_SURFACE_CODES` so every profile's
inventory has to name it, and is deliberately absent from
`WITHHOLDABLE_SURFACES`: a readiness probe a deployment can switch off is not a
readiness probe, it is a readiness probe plus a way to go back to the failure
this feature exists to end.

`core=True` — a mount failure here is a boot failure. A process that cannot
answer whether it is ready should not quietly start and let an orchestrator
assume it is.
"""

from __future__ import annotations

from dotmac_kernel.features import FeatureManifest

from vendor_cp.readiness.router import router

feature = FeatureManifest(
    name="readiness",
    routers=[router],
    core=True,
    enabled_by_default=True,
)
