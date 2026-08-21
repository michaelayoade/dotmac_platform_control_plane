"""Vendor's retained WS8 licence route and delivery surface.

`core=True`: signed delivery is the contracted hand-off from the vendor control
plane to a product data plane, not an optional add-on. Issuer persistence and
lifecycle declarations belong to the separately composed `licensing` module.
"""

from __future__ import annotations

from dotmac_kernel.features import FeatureManifest

from vendor_cp.licensing.router import router

feature = FeatureManifest(
    # Distinct from the composed module manifest named `licensing`: this is
    # Vendor's retained route/delivery surface, not a second issuer module.
    name="licence_delivery",
    routers=[router],
    audit_actions=(
        # One code replaced two at the ADR-0011 cutover. `registered` and
        # `updated` distinguished create from update on a caller's claim; a
        # reconciliation is one operation against an authority that already
        # decided, so splitting it would name a difference that no longer means
        # anything.
        "vendor.licence.delivery_target_reconciled",
        "vendor.licence.delivery_mapped",
        "vendor.licence.delivered",
        "vendor.licence.ack_received",
        "vendor.licence.ack_quarantined",
        "vendor.licence.delivery_parked",
        "vendor.licence.delivery_resumed",
        "vendor.licence.delivery_attempt_failed",
        "vendor.licence.bundle_exported",
    ),
    core=True,
    enabled_by_default=True,
)
