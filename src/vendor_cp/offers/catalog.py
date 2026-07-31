"""The capability catalogue an offer version is validated against.

Built from the vendor's configured `offered_capabilities` (a checked-in mirror of
the target product's manifest catalogue, reconciled via the product contract). An
offer version may only grant a code declared here — it never invents one (WS1).
"""

from __future__ import annotations

from dotmac_kernel import CapabilityCatalogue, FeatureManifest

from vendor_cp.config import vendor_settings


def offered_capability_catalogue() -> CapabilityCatalogue:
    return CapabilityCatalogue.from_manifests(
        [
            FeatureManifest(
                name="vendor-offered",
                capabilities=vendor_settings.offered_capabilities,
            )
        ]
    )


__all__ = ["offered_capability_catalogue"]
