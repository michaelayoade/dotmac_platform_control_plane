"""Pure accounts feature declaration, without route bindings."""

from __future__ import annotations

from dotmac_kernel.features import FeatureManifest

declaration = FeatureManifest(
    name="accounts",
    audit_actions=("vendor.account.created",),
    core=True,
    enabled_by_default=True,
)
