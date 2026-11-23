"""Declarations owned by the release-evidence ingestion adapter."""

from __future__ import annotations

from dotmac_kernel import FeatureManifest

feature = FeatureManifest(
    name="release_evidence",
    core=True,
    enabled_by_default=True,
    audit_actions=(
        "vendor.release_evidence.catalogued",
        # The target API (lane 5b) has no manifest of its own: composing one
        # would change the product manifest. Its one audit action is declared on
        # this route-less manifest until lane 5a composes the M4 profile.
        "vendor.deploy_target_api.observation_principal_mismatch",
    ),
)
