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

from vendor_cp.licensing import projection, service
from vendor_cp.licensing.models import LicenceSigningKey
from vendor_cp.licensing.schemas import (
    AcknowledgementRequest,
    AckOutcomeResponse,
    DeliveryResponse,
    IssueLicenceRequest,
    LicenceIssuanceResponse,
    SigningKeyResponse,
    StageDeliveryRequest,
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


@router.post("/deliveries", response_model=DeliveryResponse)
def stage_delivery(
    payload: StageDeliveryRequest, admin: Admin, db: Db
) -> DeliveryResponse:
    view = projection.stage_delivery(
        db,
        projection.StageDeliveryCommand(
            issuance_id=payload.issuance_id,
            target_ref=payload.target_ref,
            actor_admin_id=admin.id,
        ),
    )
    return _delivery_response(view)


@router.get("/deliveries/{delivery_id}", response_model=DeliveryResponse)
def delivery_status(delivery_id: UUID, _admin: Admin, db: Db) -> DeliveryResponse:
    return _delivery_response(projection.delivery_status(db, delivery_id))


@router.post("/acknowledgements", response_model=AckOutcomeResponse)
def ingest_acknowledgement(
    payload: AcknowledgementRequest, admin: Admin, db: Db
) -> AckOutcomeResponse:
    """Ingest a data-plane acknowledgement. Always 200 with a verdict: a
    quarantined ack is a recorded FACT the vendor needs, not a client error."""
    outcome = projection.ingest_acknowledgement(
        db,
        projection.AcknowledgementInput(
            licence_id=payload.licence_id,
            licence_version=payload.licence_version,
            digest=payload.digest,
            status=payload.status,
            reason=payload.reason,
            deployment_id=payload.deployment_id,
        ),
        actor_admin_id=admin.id,
    )
    return AckOutcomeResponse(
        ack_id=outcome.ack_id,
        disposition=outcome.disposition,
        activated=outcome.activated,
        quarantined=outcome.quarantined,
        delivery_id=outcome.delivery_id,
    )


def _delivery_response(view: projection.DeliveryView) -> DeliveryResponse:
    return DeliveryResponse(
        id=view.id,
        issuance_id=view.issuance_id,
        target_ref=view.target_ref,
        state=view.state,
        activating_ack_id=view.activating_ack_id,
    )


__all__ = ["router"]
