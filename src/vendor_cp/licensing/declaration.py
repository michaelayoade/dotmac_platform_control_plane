"""Pure licensing feature declaration, without route bindings."""

from __future__ import annotations

from dotmac_kernel.features import FeatureManifest

declaration = FeatureManifest(
    # Distinct from the composed module manifest named `licensing`: this is
    # Vendor's retained route/delivery surface, not a second issuer module.
    name="licence_delivery",
    audit_actions=(
        # One code replaced two at the ADR-0011 cutover. `registered` and
        # `updated` distinguished create from update on a caller's claim; a
        # reconciliation is one operation against an authority that already
        # decided, so splitting it would name a difference that no longer means
        # anything.
        "vendor.licence.delivery_target_reconciled",
        # ADR-0010 s3 source ports (gate 2a). Declared with their writers in the
        # same change, because ADR-0008 fails the boot on a declared code with
        # no consumer and fails the write on an undeclared one.
        "vendor.licence.delivery_intent_opened",
        "vendor.licence.source_artifact_read",
        "vendor.licence.delivery_intent_acknowledged",
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
