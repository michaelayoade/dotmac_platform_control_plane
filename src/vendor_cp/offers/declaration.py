"""Pure offers feature declaration, without route bindings."""

from __future__ import annotations

from dotmac_kernel.features import FeatureManifest

declaration = FeatureManifest(
    name="offers",
    audit_actions=("vendor.offer_version.published",),
    core=True,
    enabled_by_default=True,
)
