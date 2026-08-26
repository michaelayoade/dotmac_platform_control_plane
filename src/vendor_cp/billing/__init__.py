"""Vendor-owned adapter declarations for the shared Billing owner."""

from vendor_cp.billing.authority import (
    PlatformBillingRepository,
    install_billing_authority,
)

__all__ = ["PlatformBillingRepository", "install_billing_authority"]
