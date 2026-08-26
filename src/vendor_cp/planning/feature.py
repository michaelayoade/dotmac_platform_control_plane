"""Deterministic planning and exact approval feature manifest."""

from dotmac_kernel.features import FeatureManifest

from vendor_cp.planning.router import router

feature = FeatureManifest(
    name="planning",
    routers=[router],
    core=True,
    enabled_by_default=True,
    audit_actions=(
        "vendor.deployment_bundle.published",
        "vendor.deployment_plan.created",
        "vendor.deployment_plan.approval_requested",
        "vendor.deployment_plan.approval_granted",
        "vendor.integrator_command.dispatched",
        "vendor.integrator_receipt.ingested",
    ),
)

__all__ = ["feature"]
