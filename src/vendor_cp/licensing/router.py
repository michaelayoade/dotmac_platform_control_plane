"""Licence issuance JSON API — platform-admin-only, thin adapter.

Issuance is a deliberate commercial act, so unlike allocation staging it IS
route-driven; the route only validates/authorises/delegates. The keyring
endpoint publishes PUBLIC verification material for deployments to import —
there is no route that can expose private key material, by construction.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from dotmac_kernel import PlatformAdmin
from dotmac_kernel.db import get_platform_db
from dotmac_kernel.platform_auth import require_platform_admin
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from vendor_cp.licensing import service
from vendor_cp.licensing.models import LicenceSigningKey
from vendor_cp.licensing.schemas import (
    IssueLicenceRequest,
    LicenceIssuanceResponse,
    SigningKeyResponse,
)

router = APIRouter(prefix="/platform/vendor/licences", tags=["licensing"])

Admin = Annotated[PlatformAdmin, Depends(require_platform_admin)]
Db = Annotated[Session, Depends(get_platform_db)]


@router.post("/issue", response_model=LicenceIssuanceResponse)
def issue(
    payload: IssueLicenceRequest, admin: Admin, db: Db
) -> LicenceIssuanceResponse:
    view = service.issue_licence(
        db,
        service.IssueLicenceCommand(
            allocation_id=payload.allocation_id,
            product=payload.product,
            edition=payload.edition,
            not_before=payload.not_before,
            expires_at=payload.expires_at,
            grace_days=payload.grace_days,
            deployment_id=payload.deployment_id,
            constraints=payload.constraints,
            actor_admin_id=admin.id,
        ),
    )
    return LicenceIssuanceResponse.of(view)


@router.get("/{licence_id}/issuances", response_model=list[LicenceIssuanceResponse])
def list_issuances(
    licence_id: UUID, _admin: Admin, db: Db
) -> list[LicenceIssuanceResponse]:
    return [
        LicenceIssuanceResponse.of(v) for v in service.list_issuances(db, licence_id)
    ]


@router.get("/keyring", response_model=list[SigningKeyResponse])
def keyring(_admin: Admin, db: Db) -> list[SigningKeyResponse]:
    rows = db.execute(select(LicenceSigningKey)).scalars().all()
    return [
        SigningKeyResponse(
            key_id=r.key_id, public_key_b64=r.public_key_b64, status=r.status
        )
        for r in rows
    ]


__all__ = ["router"]
