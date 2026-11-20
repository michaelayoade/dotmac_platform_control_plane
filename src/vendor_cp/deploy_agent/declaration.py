"""Pure deploy_agent feature declaration, without route bindings."""

from __future__ import annotations

from dotmac_kernel.features import FeatureManifest

declaration = FeatureManifest(
    name="deploy_agent",
    core=True,
    enabled_by_default=True,
    audit_actions=("vendor.deploy_agent.recorded",),
)
