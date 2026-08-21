"""Licensing ownership and the one permitted Vendor assembly seam."""

from __future__ import annotations

from typing import Final

AUTHORITY: Final[str] = "dotmac_licensing"
ADAPTER_MODULE: Final[str] = "vendor_cp.licensing.adapter"
# Old paths stay absent. Four were issuer implementation; the signer and
# delivery-ops paths were renamed so retained product responsibilities cannot
# be mistaken for a second issuer owner.
RETIRED_LOCAL_MODULES: Final[tuple[str, ...]] = (
    "vendor_cp.licensing.service",
    "vendor_cp.licensing.models",
    "vendor_cp.licensing.revocation",
    "vendor_cp.licensing.revocation_models",
    "vendor_cp.licensing.signer",
    "vendor_cp.licensing.ops",
)

__all__ = ["ADAPTER_MODULE", "AUTHORITY", "RETIRED_LOCAL_MODULES"]
