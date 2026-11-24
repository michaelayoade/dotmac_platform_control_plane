"""Retained signed deployment evidence, without a second fleet owner."""

from dotmac_kernel import FeatureManifest

from .router import router

feature = FeatureManifest(
    name="deploy_agent",
    routers=[router],
    core=True,
    enabled_by_default=True,
    audit_actions=(
        "vendor.deploy_agent.recorded",
        # The target API (lane 5b) has no manifest of its own: composing one
        # would change the product manifest. Its one audit action is declared
        # here until lane 5a composes the M4 profile.
        "vendor.deploy_target_api.observation_principal_mismatch",
    ),
)
