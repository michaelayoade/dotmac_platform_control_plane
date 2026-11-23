"""Pure withdrawal-conflicts feature declaration, without route bindings."""

from __future__ import annotations

from dotmac_kernel.features import FeatureManifest

declaration = FeatureManifest(
    name="withdrawal_conflicts",
    core=True,
    enabled_by_default=True,
)
