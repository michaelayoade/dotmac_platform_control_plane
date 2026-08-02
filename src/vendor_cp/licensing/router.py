"""Licence issuance JSON API — platform-admin-only, thin adapter.

Issuance is a deliberate commercial act, so unlike allocation staging it IS
route-driven; the route only validates/authorises/delegates. The keyring
endpoint publishes PUBLIC verification material for deployments to import —
there is no route that can expose private key material, by construction.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from dotmac_kernel import BadRequestError, PlatformAdmin
from dotmac_kernel.db import get_platform_db
from dotmac_kernel.platform_auth import require_platform_admin
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from vendor_cp.licensing import ops, projection, revocation, service, transport
from vendor_cp.licensing.delivery_models import LicenceDeliveryTarget, TargetStatus
from vendor_cp.licensing.models import LicenceSigningKey
from vendor_cp.licensing.schemas import (
    AcknowledgementRequest,
    AckOutcomeResponse,
    DeliveryResponse,
    DeliveryTargetResponse,
    DispatchReportResponse,
    DispatchRequest,
    IssueLicenceRequest,
    LicenceIssuanceResponse,
    MapLegacyDeliveryRequest,
    PipelineHealthResponse,
    RegisterTargetRequest,
    RevocationEntryResponse,
    RevocationListResponse,
    RevokeLicenceRequest,
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
            deployment_ref=payload.deployment_ref,
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
        # Identity must be PROVEN, not claimed. A platform admin is not a
        # deployment, so bound licences fail closed here until
        # deployment-authenticated ingestion lands.
        authenticated_deployment_ref=None,
        actor_admin_id=admin.id,
    )
    return AckOutcomeResponse(
        ack_id=outcome.ack_id,
        disposition=outcome.disposition,
        activated=outcome.activated,
        quarantined=outcome.quarantined,
        delivery_id=outcome.delivery_id,
    )


@router.post("/revocations", response_model=RevocationEntryResponse)
def revoke(
    payload: RevokeLicenceRequest, admin: Admin, db: Db
) -> RevocationEntryResponse:
    """Append a revocation entry. It reaches deployments only when the next
    list snapshot is published and imported — revoking is not delivery."""
    entry = revocation.revoke_licence(
        db,
        revocation.RevokeLicenceCommand(
            licence_id=payload.licence_id,
            reason=payload.reason,
            actor_admin_id=admin.id,
        ),
    )
    return RevocationEntryResponse(licence_id=entry.licence_id, reason=entry.reason)


@router.post("/revocations/publish", response_model=RevocationListResponse)
def publish_revocation_list(admin: Admin, db: Db) -> RevocationListResponse:
    """Sign and record a FULL cumulative snapshot at the next list version."""
    view = revocation.publish_revocation_list(db, actor_admin_id=admin.id)
    return RevocationListResponse(
        id=view.id,
        list_version=view.list_version,
        digest=view.digest,
        key_id=view.key_id,
        entry_count=view.entry_count,
        envelope=view.envelope,
        revoked_licence_ids=list(view.revoked_licence_ids),
    )


@router.get("/revocations/latest", response_model=RevocationListResponse | None)
def latest_revocation_list(_admin: Admin, db: Db) -> RevocationListResponse | None:
    """What a deployment should be importing right now."""
    row = revocation.latest_list(db)
    if row is None:
        return None
    return RevocationListResponse(
        id=row.id,
        list_version=row.list_version,
        digest=row.digest,
        key_id=row.key_id,
        entry_count=row.entry_count,
        envelope=dict(row.envelope),
        revoked_licence_ids=list(revocation.revoked_licence_ids(db)),
    )


@router.get("/health", response_model=PipelineHealthResponse)
def pipeline_health(_admin: Admin, db: Db) -> PipelineHealthResponse:
    """Operational signals for alerting. Read-only; injects the clock so a
    report is reproducible."""
    health = ops.pipeline_health(db, now=datetime.now(UTC))
    return PipelineHealthResponse(
        never_attempted=health.never_attempted,
        attempted_never_sent=health.attempted_never_sent,
        sent_unacknowledged=health.sent_unacknowledged,
        oldest_unacknowledged_age_seconds=health.oldest_unacknowledged_age_seconds,
        parked_total=health.parked_total,
        rejected_by_reason=dict(health.rejected_by_reason),
        unknown_digest_acks=health.unknown_digest_acks,
        unknown_licence_acks=health.unknown_licence_acks,
        deployment_mismatch_acks=health.deployment_mismatch_acks,
        unverified_identity_acks=health.unverified_identity_acks,
        critical_acks=health.critical_acks,
        latest_revocation_list_version=health.latest_revocation_list_version,
        keyring_uptake_lag_measurable=health.keyring_uptake_lag_measurable,
        revocation_application_lag_measurable=(
            health.revocation_application_lag_measurable
        ),
    )


@router.post("/targets", response_model=DeliveryTargetResponse)
def register_target(
    payload: RegisterTargetRequest, admin: Admin, db: Db
) -> DeliveryTargetResponse:
    """Register/synchronise a delivery target — the ONE writer for the target
    projection. Without this endpoint a clean deployment could never stage a
    delivery at all, because staging requires a registered destination."""
    try:
        status = TargetStatus(payload.status)
    except ValueError as exc:
        raise BadRequestError(
            f"unknown target status {payload.status!r} — expected one of "
            f"{[s.value for s in TargetStatus]}"
        ) from exc
    row = projection.register_delivery_target(
        db,
        projection.RegisterTargetCommand(
            target_ref=payload.target_ref,
            customer_ref=payload.customer_ref,
            connection_ref=payload.connection_ref,
            status=status,
            actor_admin_id=admin.id,
        ),
    )
    return DeliveryTargetResponse(
        id=row.id,
        target_ref=row.target_ref,
        customer_ref=row.customer_ref,
        connection_ref=row.connection_ref,
        status=row.status,
    )


@router.get("/targets", response_model=list[DeliveryTargetResponse])
def list_targets(_admin: Admin, db: Db) -> list[DeliveryTargetResponse]:
    rows = db.execute(select(LicenceDeliveryTarget)).scalars().all()
    return [
        DeliveryTargetResponse(
            id=r.id,
            target_ref=r.target_ref,
            customer_ref=r.customer_ref,
            connection_ref=r.connection_ref,
            status=r.status,
        )
        for r in rows
    ]


@router.post("/deliveries/{delivery_id}/map", response_model=DeliveryResponse)
def map_legacy_delivery(
    delivery_id: UUID, payload: MapLegacyDeliveryRequest, admin: Admin, db: Db
) -> DeliveryResponse:
    """Attach a destination to a delivery quarantined by migration `v010`.
    Applies the same authorisation as staging, so this is not a back door."""
    return _delivery_response(
        projection.map_legacy_delivery(
            db,
            delivery_id=delivery_id,
            target_ref=payload.target_ref,
            actor_admin_id=admin.id,
        )
    )


@router.post("/deliveries/{delivery_id}/resume", response_model=DeliveryResponse)
def resume_delivery(delivery_id: UUID, admin: Admin, db: Db) -> DeliveryResponse:
    """Un-park a delivery once its cause is fixed; the retry budget resets to a
    new replay generation. Refuses an unmapped delivery, which would otherwise
    leave replay silently."""
    transport.resume_delivery(db, delivery_id, actor_admin_id=admin.id)
    return _delivery_response(projection.delivery_status(db, delivery_id))


@router.post("/replay", response_model=DispatchReportResponse)
def run_replay(
    payload: DispatchRequest, admin: Admin, db: Db
) -> DispatchReportResponse:
    """Execute one bounded replay pass.

    Exposed as an endpoint so a scheduler (or an operator) can actually drive
    delivery: until this existed, `dispatch_pending` had no runtime caller and
    nothing was ever sent outside tests. Intentionally a pull, not a daemon —
    a background loop inside the API process would replay from every replica.
    """
    report = transport.dispatch_pending(
        db,
        limit=payload.limit,
        max_attempts=payload.max_attempts,
        actor_admin_id=admin.id,
    )
    return DispatchReportResponse(
        attempted=report.attempted,
        sent=report.sent,
        failed=report.failed,
        parked_terminal=report.parked_terminal,
        parked_exhausted=report.parked_exhausted,
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
