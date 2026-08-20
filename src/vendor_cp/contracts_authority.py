"""Commercial-agreement ownership and the one permitted assembly seam."""

from __future__ import annotations

from typing import Final

AUTHORITY: Final[str] = "dotmac_commercial_agreements"
ADAPTER_MODULE: Final[str] = "vendor_cp.contracts.adapter"
RETIRED_LOCAL_WRITER: Final[str] = "vendor_cp.contracts.service"
RETIRED_LOCAL_MODELS: Final[str] = "vendor_cp.contracts.models"

# The subject vocabulary belongs to the agreement owner. Vendor uses this one
# spelling whenever it asks Approvals to decide on an accepted snapshot.
APPROVAL_SUBJECT_TYPE: Final[str] = "commercial_agreement"

__all__ = [
    "ADAPTER_MODULE",
    "APPROVAL_SUBJECT_TYPE",
    "AUTHORITY",
    "RETIRED_LOCAL_MODELS",
    "RETIRED_LOCAL_WRITER",
]
