"""The `licensing` feature manifest — WS8 licence issuance (vendor side).

`core=True`: signed delivery is the contracted hand-off from the vendor control
plane to a product data plane, not an optional add-on.
"""

from __future__ import annotations

from dotmac_kernel.features import FeatureManifest

from vendor_cp.licensing.router import router

feature = FeatureManifest(
    name="licensing",
    routers=[router],
    audit_actions=(
        "vendor.licence.delivery_target_registered",
        "vendor.licence.delivery_target_updated",
        "vendor.licence.delivery_mapped",
        "vendor.licence.delivered",
        "vendor.licence.ack_received",
        "vendor.licence.ack_quarantined",
        "vendor.licence.delivery_parked",
        "vendor.licence.delivery_resumed",
        "vendor.licence.delivery_attempt_failed",
        "vendor.licence.bundle_exported",
        "vendor.licence.revoked",
        "vendor.licence.revocation_list_published",
        "vendor.licence.issued",
    ),
    core=True,
    enabled_by_default=True,
)
