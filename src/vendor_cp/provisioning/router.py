"""Provisioning-lab JSON API — a thin, platform-admin-only adapter.

Exposes the four kernel `ProvisioningProvider` contract operations so a platform
admin can drive plan → apply → observe → cancel against the Vendor-owned
laboratory simulation. Every route depends on `require_platform_admin`
(deny-case D4). NO database (there is no persistence — the only state is the
simulation's in-memory ledger, deny-case D1/D3). The route builds no
infrastructure; it invokes one contract method and maps the typed result.
"""

from __future__ import annotations

from typing import Annotated

from dotmac_kernel import PlatformAdmin
from dotmac_kernel.platform_auth import require_platform_admin
from fastapi import APIRouter, Depends

from vendor_cp.provisioning import service
from vendor_cp.provisioning.schemas import (
    ApplyRequest,
    ApplyResponse,
    ObserveResponse,
    PlanRequest,
    PlanResponse,
)

router = APIRouter(prefix="/platform/vendor/provisioning", tags=["provisioning-lab"])

Admin = Annotated[PlatformAdmin, Depends(require_platform_admin)]


@router.post("/plan", response_model=PlanResponse)
def plan(body: PlanRequest, _admin: Admin) -> PlanResponse:
    return PlanResponse.of(service.plan(body.intent_id, body.spec))


@router.post("/apply", response_model=ApplyResponse)
def apply(body: ApplyRequest, _admin: Admin) -> ApplyResponse:
    return ApplyResponse.of(
        service.apply(body.intent_id, body.spec, operation_id=body.operation_id)
    )


@router.get("/operations/{operation_id}", response_model=ObserveResponse)
def observe(operation_id: str, _admin: Admin) -> ObserveResponse:
    return ObserveResponse.of(service.observe(operation_id))


@router.post("/operations/{operation_id}/cancel", response_model=ObserveResponse)
def cancel(operation_id: str, _admin: Admin) -> ObserveResponse:
    return ObserveResponse.of(service.cancel(operation_id))


__all__ = ["router"]
