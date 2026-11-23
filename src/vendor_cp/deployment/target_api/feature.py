"""Declarations owned by the target API (no routes; lane 5a mounts the router)."""

from __future__ import annotations

from dotmac_kernel import FeatureManifest

feature = FeatureManifest(
    name="deploy_target_api",
    core=True,
    enabled_by_default=True,
    audit_actions=("vendor.deploy_target_api.observation_principal_mismatch",),
)
