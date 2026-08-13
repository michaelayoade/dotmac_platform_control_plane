"""Declarations owned by the release-evidence ingestion adapter."""

from __future__ import annotations

from dotmac_kernel import FeatureManifest

feature = FeatureManifest(
    name="release_evidence",
    core=True,
    enabled_by_default=True,
    audit_actions=("vendor.release_evidence.catalogued",),
)
