"""Bind Vendor CP to Billing's internal platform authority exactly once."""

from __future__ import annotations

from dataclasses import dataclass, field

from dotmac_billing import (
    AuthorityBinding,
    BillingPlane,
    CommercialAuthority,
    bind_commercial_authority,
)


@dataclass(frozen=True, slots=True)
class PlatformBillingRepository:
    """Typed declaration that Vendor routes Billing through its platform DB."""

    plane: BillingPlane = field(default=BillingPlane.PLATFORM, init=False)


_binding: AuthorityBinding | None = None


def install_billing_authority() -> AuthorityBinding:
    """Install or return Vendor CP's sole commercial-authority binding."""
    global _binding
    if _binding is None:
        _binding = bind_commercial_authority(
            CommercialAuthority.INTERNAL,
            platform_repository_factory=PlatformBillingRepository,
        )
    return _binding


__all__ = ["PlatformBillingRepository", "install_billing_authority"]
