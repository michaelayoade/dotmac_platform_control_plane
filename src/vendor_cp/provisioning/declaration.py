"""Pure provisioning feature declaration, without route bindings."""

from __future__ import annotations

from dotmac_kernel.features import FeatureManifest

declaration = FeatureManifest(
    name="provisioning",
    core=False,
    enabled_by_default=True,
)
