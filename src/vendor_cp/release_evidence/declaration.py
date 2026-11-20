"""Pure release-evidence feature declaration, without route bindings."""

from __future__ import annotations

from dotmac_kernel import FeatureManifest

declaration = FeatureManifest(
    name="release_evidence",
    core=True,
    enabled_by_default=True,
    audit_actions=("vendor.release_evidence.catalogued",),
)
