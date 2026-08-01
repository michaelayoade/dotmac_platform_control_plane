"""Vendor-control-plane settings.

The DATABASE lives with the kernel (`dotmac_kernel.config.settings.database_url`):
there is exactly ONE control-plane database and the kernel owns the engine
(deny-case D1). This module adds only the vendor-specific knobs — chiefly the
provider mode, which is `fake` in this phase and FAILS STARTUP for anything else
(deny-case D3).
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class VendorSettings:
    """Vendor-only configuration (the kernel owns DB / auth / security config)."""

    provider_mode: str  # only "fake" is permitted in this phase
    # Capability codes the vendor is authorised to OFFER — a checked-in/configured
    # mirror of the target product's manifest catalogue (reconciled via the product
    # contract, never by inventing codes). An offer version may only grant these.
    offered_capabilities: tuple[str, ...] = ()
    # WS8 licence signing (see vendor_cp.licensing.signer). Only "ephemeral" is
    # permitted in this phase — an in-memory keypair, never persisted. Real key
    # custody (OpenBao-referenced) is a later, design-gated slice, so anything
    # else fails loudly rather than silently signing with a throwaway key.
    licence_signing_mode: str = "ephemeral"


def load_vendor_settings() -> VendorSettings:
    """Read vendor settings from the environment with safe defaults."""
    mode = os.getenv("VENDOR_PROVIDER_MODE", "fake").strip().lower()
    raw = os.getenv("VENDOR_OFFERED_CAPABILITIES", "")
    offered = tuple(c.strip() for c in raw.split(",") if c.strip())
    signing = os.getenv("VENDOR_LICENCE_SIGNING_MODE", "ephemeral").strip().lower()
    return VendorSettings(
        provider_mode=mode,
        offered_capabilities=offered,
        licence_signing_mode=signing,
    )


vendor_settings = load_vendor_settings()
