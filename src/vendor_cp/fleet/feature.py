"""Fleet desired-state feature manifest."""

from dotmac_kernel.features import FeatureManifest

from vendor_cp.fleet.router import router

feature = FeatureManifest(
    name="fleet",
    routers=[router],
    core=True,
    enabled_by_default=True,
    audit_actions=(
        "vendor.deployment_target.created",
        "vendor.deployment.intent_recorded",
    ),
)

__all__ = ["feature"]
