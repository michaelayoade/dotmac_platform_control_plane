"""Licence issuance JSON API — platform-admin-only, thin adapter.

Issuance is a deliberate commercial act, so unlike allocation staging it IS
route-driven; the route only validates/authorises/delegates. The keyring
endpoint publishes PUBLIC verification material for deployments to import —
there is no route that can expose private key material, by construction.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from dotmac_kernel import PlatformAdmin
from dotmac_kernel.db import get_platform_db
from dotmac_kernel.platform_auth import require_platform_admin
from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from vendor_cp.deployment import adapter as deployment_adapter
from vendor_cp.licensing import adapter as licensing
from vendor_cp.licensing import (
    delivery_ops,
    projection,
    source_contract,
    source_ports,
    transport,
)
from vendor_cp.licensing.schemas import (
    AcknowledgeIntentRequest,
    AcknowledgementRequest,
    AckOutcomeResponse,
    DeliveryIntentResponse,
    DeliveryResponse,
    DeliveryTargetResponse,
    ExactArtifactResponse,
    IssueLicenceRequest,
    LicenceIssuanceResponse,
    MapLegacyDeliveryRequest,
    OpenDeliveryIntentRequest,
    PipelineHealthResponse,
    ReconcileTargetRequest,
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
    view = licensing.issue_licence(
        db,
        licensing.IssueLicenceCommand(
            allocation_id=payload.allocation_id,
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
        LicenceIssuanceResponse.of(v) for v in licensing.list_issuances(db, licence_id)
    ]


@router.get("/keyring", response_model=list[SigningKeyResponse])
def keyring(_admin: Admin, db: Db) -> list[SigningKeyResponse]:
    rows = licensing.list_signing_keys(db)
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
    entry = licensing.revoke_licence(
        db,
        licensing.RevokeLicenceCommand(
            licence_id=payload.licence_id,
            reason=payload.reason,
            actor_admin_id=admin.id,
        ),
    )
    return RevocationEntryResponse(licence_id=entry.licence_id, reason=entry.reason)


@router.post("/revocations/publish", response_model=RevocationListResponse)
def publish_revocation_list(admin: Admin, db: Db) -> RevocationListResponse:
    """Sign and record a FULL cumulative snapshot at the next list version."""
    view = licensing.publish_revocation_list(db, actor_admin_id=admin.id)
    return RevocationListResponse(
        id=view.id,
        list_version=view.list_version,
        digest=view.digest,
        key_id=view.key_id,
        entry_count=view.entry_count,
        envelope=dict(view.envelope),
        revoked_licence_ids=list(view.revoked_licence_ids),
    )


@router.get("/revocations/latest", response_model=RevocationListResponse | None)
def latest_revocation_list(_admin: Admin, db: Db) -> RevocationListResponse | None:
    """What a deployment should be importing right now."""
    view = licensing.latest_revocation_list(db)
    if view is None:
        return None
    return RevocationListResponse(
        id=view.id,
        list_version=view.list_version,
        digest=view.digest,
        key_id=view.key_id,
        entry_count=view.entry_count,
        envelope=dict(view.envelope),
        revoked_licence_ids=list(view.revoked_licence_ids),
    )


@router.get("/health", response_model=PipelineHealthResponse)
def pipeline_health(_admin: Admin, db: Db) -> PipelineHealthResponse:
    """Operational signals for alerting. Read-only; injects the clock so a
    report is reproducible."""
    health = delivery_ops.pipeline_health(db, now=datetime.now(UTC))
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
def reconcile_target(
    payload: ReconcileTargetRequest, admin: Admin, db: Db
) -> DeliveryTargetResponse:
    """Project a deployment target from `mod_deploy` into the delivery
    projection.

    Same path and method as the registration endpoint it replaces, because the
    operation is still "make this destination available for staging" — but the
    body now names a target the fleet owner owns instead of describing one. Two
    calls, and neither decides anything: the adapter reads the authoritative
    record, the projection writes what it returned.
    """
    facts = deployment_adapter.resolve_target(db, payload.deployment_target_id)
    row = projection.reconcile_delivery_target(db, facts, actor_admin_id=admin.id)
    return DeliveryTargetResponse(
        id=row.id,
        target_ref=row.target_ref,
        customer_ref=row.customer_ref,
        connection_ref=row.connection_ref,
        status=row.status,
    )


@router.get("/targets", response_model=list[DeliveryTargetResponse])
def list_targets(_admin: Admin, db: Db) -> list[DeliveryTargetResponse]:
    rows = projection.list_delivery_targets(db)
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


@router.post("/deliveries/{delivery_id}/export")
def export_delivery_bundle(delivery_id: UUID, admin: Admin, db: Db) -> Response:
    """Export a delivery's envelope bundle for an air-gapped site.

    This is the only delivery path enabled in this phase, and it is a REAL
    handoff: the bytes are returned to an authenticated operator, so the
    artifact actually leaves the process and an `exported` attempt is recorded.

    There is deliberately NO generic replay endpoint yet. Both reference
    transports are in-process — they accept a packet and discard it — so a
    replay pass would have recorded deliveries as `sent` while nothing crossed
    a boundary, manufacturing evidence and eventually parking licences that
    were never carried anywhere. Connected replay returns when a transport
    performs a genuine external handoff.
    """
    bundle = transport.export_delivery_bundle(
        db, delivery_id=delivery_id, actor_admin_id=admin.id
    )
    return Response(
        content=bundle,
        media_type="application/json",
        headers={
            "Content-Disposition": (
                f'attachment; filename="licence-bundle-{delivery_id}.json"'
            )
        },
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


# ── ADR-0010 § 3 source ports (gate 2a) ─────────────────────────────────────
#
# Checked in and authenticated, driving nothing. There is no `dotmac-integration`
# pin, no connector and no mirror mode in this change, and the frozen
# logging/offline-bundle paths above remain the only thing that moves bytes.
#
# Thin, like every route here: each one validates, authorises and delegates. The
# correlation rules that make an acknowledgement safe live in
# `vendor_cp.licensing.source_ports`, not in these handlers.


@router.get("/source/contract", response_model=dict)
def licence_source_contract(_admin: Admin) -> dict[str, object]:
    """The digest-pinned contract an Integrator pins and refuses drift against.

    Deliberately NOT a `ProductPortDescriptorV1`: that answers "where does this
    land?", and the destination here is the DEPLOYMENT, whose own descriptor and
    binding to the Deployment Control `target_ref` are gate 2b in another
    repository. This says only what Vendor offers.
    """
    return {
        **source_contract.declaration(),
        "digest": source_contract.contract_digest(),
    }


@router.post("/source/intents", response_model=DeliveryIntentResponse)
def open_delivery_intent(
    payload: OpenDeliveryIntentRequest, admin: Admin, db: Db
) -> DeliveryIntentResponse:
    intent = source_ports.open_delivery_intent(
        db,
        issuance_id=payload.issuance_id,
        deployment_target_id=payload.deployment_target_id,
        actor_admin_id=admin.id,
    )
    return DeliveryIntentResponse(**asdict(intent))


@router.get(
    "/source/intents/{delivery_intent_id}/artifact",
    response_model=ExactArtifactResponse,
)
def read_exact_artifact(
    delivery_intent_id: UUID, admin: Admin, db: Db
) -> ExactArtifactResponse:
    artifact = source_ports.read_exact_artifact(
        db, delivery_intent_id=delivery_intent_id, actor_admin_id=admin.id
    )
    return ExactArtifactResponse(
        delivery_intent_id=artifact.delivery_intent_id,
        artifact_digest=artifact.artifact_digest,
        envelope=dict(artifact.envelope),
    )


@router.post(
    "/source/intents/{delivery_intent_id}/acknowledgement",
    response_model=DeliveryIntentResponse,
)
def acknowledge_delivery_intent(
    delivery_intent_id: UUID,
    payload: AcknowledgeIntentRequest,
    admin: Admin,
    db: Db,
) -> DeliveryIntentResponse:
    intent = source_ports.acknowledge_delivery_intent(
        db,
        source_ports.AcknowledgeIntentCommand(
            delivery_intent_id=delivery_intent_id,
            deployment_target_ref=payload.deployment_target_ref,
            licence_version=payload.licence_version,
            artifact_digest=payload.artifact_digest,
            integrator_receipt_ref=payload.integrator_receipt_ref,
            authenticated_deployment_ref=payload.authenticated_deployment_ref,
            outcome=payload.outcome,
            reason=payload.reason,
            reported_at=payload.reported_at,
            actor_admin_id=admin.id,
        ),
    )
    return DeliveryIntentResponse(**asdict(intent))
