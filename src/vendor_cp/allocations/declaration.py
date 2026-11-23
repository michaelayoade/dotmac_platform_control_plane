"""Pure allocations feature declaration, without route bindings."""

from __future__ import annotations

from dotmac_kernel.features import FeatureManifest

declaration = FeatureManifest(
    name="allocations",
    core=True,
    enabled_by_default=True,
)
