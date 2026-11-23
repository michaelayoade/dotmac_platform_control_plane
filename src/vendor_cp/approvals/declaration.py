"""Pure approvals feature declaration, without route bindings."""

from __future__ import annotations

from dotmac_kernel.features import FeatureManifest

declaration = FeatureManifest(
    name="vendor_approvals",
    core=True,
    enabled_by_default=True,
)
