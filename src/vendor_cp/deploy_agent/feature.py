"""Retained signed deployment evidence, without a second fleet owner."""

from dotmac_kernel import FeatureManifest

from .router import router

feature = FeatureManifest(
    name="deploy_agent",
    routers=[router],
    core=True,
    enabled_by_default=True,
    audit_actions=("vendor.deploy_agent.recorded",),
)
