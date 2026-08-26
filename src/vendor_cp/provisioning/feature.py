"""The `provisioning` feature manifest — the provisioning contract laboratory.

Contributes a JSON API (`routers`) only. `core=False`: the lab is a deletable
surface for exercising the provider contract, not part of the minimum viable
control plane.
"""

from __future__ import annotations

from dotmac_kernel.features import FeatureManifest

from vendor_cp.provisioning.router import router
from vendor_cp.provisioning.service import LAB_PARTICIPANT_CODE

feature = FeatureManifest(
    name="provisioning",
    routers=[router],
    provisioning_participants=(LAB_PARTICIPANT_CODE,),
    core=False,
    enabled_by_default=True,
)
