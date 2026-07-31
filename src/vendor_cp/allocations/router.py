"""Allocations JSON API — READ-ONLY, platform-admin-only.

There is deliberately NO create/mutate endpoint: an allocation is a projection of an
activated contract, staged by the `contract.activated` consumer — never created by
hand. This route only lets an operator inspect what was staged.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from dotmac_kernel import PlatformAdmin
from dotmac_kernel.db import get_platform_db
from dotmac_kernel.platform_auth import require_platform_admin
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from vendor_cp.allocations import service
from vendor_cp.allocations.schemas import AllocationResponse

router = APIRouter(prefix="/platform/vendor/allocations", tags=["allocations"])

Admin = Annotated[PlatformAdmin, Depends(require_platform_admin)]
Db = Annotated[Session, Depends(get_platform_db)]


@router.get("/{contract_id}", response_model=list[AllocationResponse])
def list_for_contract(
    contract_id: UUID, _admin: Admin, db: Db
) -> list[AllocationResponse]:
    return [
        AllocationResponse.of(v) for v in service.list_for_contract(db, contract_id)
    ]


__all__ = ["router"]
