"""Managed-profile catalogue feature manifest."""

from dotmac_kernel.features import FeatureManifest

from vendor_cp.managed_profiles.router import router

feature = FeatureManifest(
    name="managed_profiles",
    routers=[router],
    core=True,
    enabled_by_default=True,
    audit_actions=("vendor.managed_profile.published",),
)

__all__ = ["feature"]
