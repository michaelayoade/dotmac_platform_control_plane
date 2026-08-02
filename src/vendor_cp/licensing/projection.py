"""`EntitlementProjectionService` — delivery staging + acknowledgement truth.

The second WS8 vendor owner (`docs/design/licence-service.md`). It owns
**delivery and acknowledgement state, and nothing else**: it never signs, never
builds documents (that is `LicenceIssuanceService`), and never writes a product
data plane's WS2 grants (ruling C4).

Its one hard rule: **`active` means the data plane committed a local projection
of this exact version and digest — not that a call succeeded.** Everything here
follows from that:

- Staging a delivery records an immutable fact and emits `licence.delivered`
  atomically with it; delivery is at-least-once, so re-staging is a no-op.
- Only an `applied` acknowledgement matching the licence id, version, digest,
  and — when the document is deployment-bound — the deployment id, advances
  `delivered → active`.
- Anything else is recorded and QUARANTINED, never acted on. An ack naming a
  digest we never issued is the mis-issue/tamper tripwire; deleting it would
  destroy the evidence.
- A late acknowledgement for an older version can never regress a newer active
  one.

Transaction-authority contract: receives a `Session` and only add/flush. State
+ platform audit + platform outbox event commit in ONE transaction.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from uuid import UUID

from dotmac_kernel import NotFoundError, write_platform_audit_event
from dotmac_kernel.messaging import enqueue_platform_event
from sqlalchemy import select
from sqlalchemy.orm import Session

from vendor_cp.licensing.delivery_models import (
    AckDisposition,
    AckStatus,
    DeliveryState,
    Deployment,
    LicenceAckRecord,
    LicenceDelivery,
    LicenceDeliveryState,
)
from vendor_cp.licensing.models import Licence, LicenceIssuance

_EVENT_DELIVERED = "licence.delivered"
_EVENT_ACTIVATED = "licence.activated"


@dataclass(frozen=True, slots=True)
class StageDeliveryCommand:
    """Stage an issued version for delivery to a REGISTERED deployment.

    `deployment_ref` is resolved against the deployment registry — a caller can
    never name an arbitrary destination, so an issued licence only ever goes
    somewhere the vendor deliberately registered.
    """

    issuance_id: UUID
    deployment_ref: str
    actor_admin_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class AcknowledgementInput:
    """An inbound acknowledgement, in the kernel's cross-plane vocabulary
    (`dotmac_kernel.licensing.LicenceAcknowledgement`). These are CLAIMS from a
    deployment — nothing here is trusted until it is matched against what we
    actually issued."""

    licence_id: str
    licence_version: int
    digest: str
    status: str
    reason: str | None = None
    deployment_id: str | None = None


@dataclass(frozen=True, slots=True)
class DeliveryView:
    id: UUID
    issuance_id: UUID
    target_ref: str
    state: str
    activating_ack_id: UUID | None


@dataclass(frozen=True, slots=True)
class AckOutcome:
    """What the vendor did with an acknowledgement. `disposition` is the
    machine-readable verdict; `activated` says whether a projection advanced."""

    ack_id: UUID
    disposition: str
    activated: bool
    delivery_id: UUID | None = None

    @property
    def quarantined(self) -> bool:
        return AckDisposition(self.disposition).is_quarantined


# ── Delivery staging ────────────────────────────────────────────────────────


def _state_of(db: Session, delivery_id: UUID) -> LicenceDeliveryState:
    row = db.execute(
        select(LicenceDeliveryState).where(
            LicenceDeliveryState.delivery_id == delivery_id
        )
    ).scalar_one_or_none()
    if row is None:  # unreachable: staging always creates the state row
        raise RuntimeError(f"delivery {delivery_id} has no projection state")
    return row


def _view(db: Session, delivery: LicenceDelivery) -> DeliveryView:
    state = _state_of(db, delivery.id)
    return DeliveryView(
        id=delivery.id,
        issuance_id=delivery.issuance_id,
        target_ref=delivery.target_ref,
        state=state.state,
        activating_ack_id=state.activating_ack_id,
    )


def stage_delivery(db: Session, command: StageDeliveryCommand) -> DeliveryView:
    """Record the immutable delivery fact, its `delivered` projection, the audit
    entry, and the `licence.delivered` outbox event — in one transaction.

    Idempotent per `(issuance_id, target_ref)`: delivery is at-least-once, so a
    repeat is the SAME fact, never a second one.
    """
    issuance = db.get(LicenceIssuance, command.issuance_id)
    if issuance is None:
        raise NotFoundError(f"licence issuance {command.issuance_id} not found")

    deployment = db.execute(
        select(Deployment).where(Deployment.deployment_ref == command.deployment_ref)
    ).scalar_one_or_none()
    if deployment is None:
        raise NotFoundError(
            f"deployment {command.deployment_ref!r} is not registered — a "
            "licence may only be delivered to a registered destination"
        )

    existing = db.execute(
        select(LicenceDelivery).where(
            LicenceDelivery.issuance_id == command.issuance_id,
            LicenceDelivery.target_ref == command.deployment_ref,
        )
    ).scalar_one_or_none()
    if existing is not None:
        return _view(db, existing)

    delivery = LicenceDelivery(
        issuance_id=issuance.id,
        target_ref=command.deployment_ref,
        deployment_id=deployment.id,
    )
    db.add(delivery)
    db.flush()
    db.add(
        LicenceDeliveryState(
            delivery_id=delivery.id, state=DeliveryState.DELIVERED.value
        )
    )
    db.flush()

    write_platform_audit_event(
        db,
        actor_admin_id=command.actor_admin_id,
        action="vendor.licence.delivered",
        entity_type="licence_delivery",
        entity_id=str(delivery.id),
        details={
            "issuance_id": str(issuance.id),
            "licence_id": str(issuance.licence_id),
            "licence_version": issuance.version,
            "digest": issuance.digest,
            "target_ref": command.deployment_ref,
        },
    )
    enqueue_platform_event(
        db,
        event_type=_EVENT_DELIVERED,
        payload={
            "delivery_id": str(delivery.id),
            "issuance_id": str(issuance.id),
            "licence_id": str(issuance.licence_id),
            "licence_version": issuance.version,
            "digest": issuance.digest,
            "target_ref": command.deployment_ref,
        },
    )
    return _view(db, delivery)


# ── Acknowledgement ingestion ───────────────────────────────────────────────


def _record(
    db: Session,
    ack: AcknowledgementInput,
    disposition: AckDisposition,
    *,
    delivery_id: UUID | None = None,
) -> LicenceAckRecord:
    row = LicenceAckRecord(
        delivery_id=delivery_id,
        licence_id=ack.licence_id,
        licence_version=ack.licence_version,
        digest=ack.digest,
        status=ack.status,
        reason=ack.reason,
        deployment_id=ack.deployment_id,
        disposition=disposition.value,
    )
    db.add(row)
    db.flush()
    return row


def _audit_ack(
    db: Session,
    ack: AcknowledgementInput,
    record: LicenceAckRecord,
    disposition: AckDisposition,
    actor_admin_id: UUID | None,
) -> None:
    write_platform_audit_event(
        db,
        actor_admin_id=actor_admin_id,
        action=(
            "vendor.licence.ack_quarantined"
            if disposition.is_quarantined
            else "vendor.licence.ack_received"
        ),
        entity_type="licence_ack",
        entity_id=str(record.id),
        details={
            "licence_id": ack.licence_id,
            "licence_version": ack.licence_version,
            "digest": ack.digest,
            "status": ack.status,
            "reason": ack.reason,
            "deployment_id": ack.deployment_id,
            "disposition": disposition.value,
        },
    )


def _highest_active_version(db: Session, licence_id: UUID) -> int:
    """The newest version of this lineage already acknowledged as applied."""
    rows = db.execute(
        select(LicenceIssuance.version)
        .join(LicenceDelivery, LicenceDelivery.issuance_id == LicenceIssuance.id)
        .join(
            LicenceDeliveryState,
            LicenceDeliveryState.delivery_id == LicenceDelivery.id,
        )
        .where(
            LicenceIssuance.licence_id == licence_id,
            LicenceDeliveryState.state == DeliveryState.ACTIVE.value,
        )
    ).scalars()
    return max((int(v) for v in rows), default=0)


def _issued_deployment_id(issuance: LicenceIssuance) -> str | None:
    """The deployment the document was BOUND to, read back from the frozen
    envelope's payload — the issued fact, not a caller's claim."""
    import base64
    import json

    payload_b64 = issuance.envelope.get("payload_b64")
    if not isinstance(payload_b64, str):
        return None
    try:
        payload = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
        document = json.loads(payload)
    except (ValueError, TypeError):
        return None
    if not isinstance(document, dict):
        return None
    subject = document.get("subject")
    if not isinstance(subject, dict):
        return None
    bound = subject.get("deployment_id")
    return bound if isinstance(bound, str) else None


def ingest_acknowledgement(
    db: Session,
    ack: AcknowledgementInput,
    *,
    authenticated_deployment_ref: str | None = None,
    actor_admin_id: UUID | None = None,
) -> AckOutcome:
    """Record an acknowledgement and, only if it genuinely matches something we
    issued, advance that delivery to `active`.

    `authenticated_deployment_ref` is the identity the CALLER PROVED, derived
    from its authentication — never from the request body. `ack.deployment_id`
    is only a claim, and a claim that disagrees with the proven identity is a
    mismatch. For a deployment-BOUND licence, an unauthenticated caller cannot
    activate anything: without a proven identity there is nothing to check the
    binding against, and accepting the body's word would make binding
    decorative. That is fail-closed by design until deployment authentication
    lands; platform-admin callers can still ingest acks for unbound licences.

    Every inbound ack is written to the append-only log first — including the
    ones we refuse — so the decision is always auditable.
    """
    # 1. Does it name a lineage we own?
    try:
        licence_uuid = UUID(ack.licence_id)
    except (ValueError, AttributeError):
        licence_uuid = None
    licence = db.get(Licence, licence_uuid) if licence_uuid is not None else None
    if licence is None:
        record = _record(db, ack, AckDisposition.UNKNOWN_LICENCE)
        _audit_ack(db, ack, record, AckDisposition.UNKNOWN_LICENCE, actor_admin_id)
        return AckOutcome(record.id, AckDisposition.UNKNOWN_LICENCE.value, False)

    # 2. …at a version we actually issued?
    issuance = db.execute(
        select(LicenceIssuance).where(
            LicenceIssuance.licence_id == licence.id,
            LicenceIssuance.version == ack.licence_version,
        )
    ).scalar_one_or_none()
    if issuance is None:
        record = _record(db, ack, AckDisposition.UNKNOWN_LICENCE)
        _audit_ack(db, ack, record, AckDisposition.UNKNOWN_LICENCE, actor_admin_id)
        return AckOutcome(record.id, AckDisposition.UNKNOWN_LICENCE.value, False)

    # 3. …with the digest WE issued? A mismatch means the deployment applied a
    #    document we did not produce (or produced a claim about one).
    if ack.digest != issuance.digest:
        record = _record(db, ack, AckDisposition.UNKNOWN_DIGEST)
        _audit_ack(db, ack, record, AckDisposition.UNKNOWN_DIGEST, actor_admin_id)
        return AckOutcome(record.id, AckDisposition.UNKNOWN_DIGEST.value, False)

    # 4. …from the deployment it was bound to (when it was bound at all)?
    # A claimed identity that contradicts the proven one is itself a mismatch.
    if (
        authenticated_deployment_ref is not None
        and ack.deployment_id is not None
        and ack.deployment_id != authenticated_deployment_ref
    ):
        record = _record(db, ack, AckDisposition.DEPLOYMENT_MISMATCH)
        _audit_ack(db, ack, record, AckDisposition.DEPLOYMENT_MISMATCH, actor_admin_id)
        return AckOutcome(record.id, AckDisposition.DEPLOYMENT_MISMATCH.value, False)

    bound_to = _issued_deployment_id(issuance)
    if bound_to is not None and authenticated_deployment_ref != bound_to:
        record = _record(db, ack, AckDisposition.DEPLOYMENT_MISMATCH)
        _audit_ack(db, ack, record, AckDisposition.DEPLOYMENT_MISMATCH, actor_admin_id)
        return AckOutcome(record.id, AckDisposition.DEPLOYMENT_MISMATCH.value, False)

    delivery = (
        db.execute(
            select(LicenceDelivery).where(LicenceDelivery.issuance_id == issuance.id)
        )
        .scalars()
        .first()
    )

    # 5. The receiver itself reported failure — real information, no activation.
    if ack.status != AckStatus.APPLIED.value:
        record = _record(
            db,
            ack,
            AckDisposition.REJECTED_BY_RECEIVER,
            delivery_id=delivery.id if delivery else None,
        )
        _audit_ack(db, ack, record, AckDisposition.REJECTED_BY_RECEIVER, actor_admin_id)
        return AckOutcome(
            record.id,
            AckDisposition.REJECTED_BY_RECEIVER.value,
            False,
            delivery.id if delivery else None,
        )

    # 6. A late ack for an older version must NEVER regress a newer active one.
    highest_active = _highest_active_version(db, licence.id)
    if ack.licence_version < highest_active:
        record = _record(
            db,
            ack,
            AckDisposition.STALE,
            delivery_id=delivery.id if delivery else None,
        )
        _audit_ack(db, ack, record, AckDisposition.STALE, actor_admin_id)
        return AckOutcome(
            record.id,
            AckDisposition.STALE.value,
            False,
            delivery.id if delivery else None,
        )

    if delivery is None:
        # Applied something we issued but never staged for delivery — worth
        # keeping and flagging rather than silently activating nothing.
        record = _record(db, ack, AckDisposition.UNKNOWN_LICENCE)
        _audit_ack(db, ack, record, AckDisposition.UNKNOWN_LICENCE, actor_admin_id)
        return AckOutcome(record.id, AckDisposition.UNKNOWN_LICENCE.value, False)

    state = _state_of(db, delivery.id)
    if state.state == DeliveryState.ACTIVE.value:
        record = _record(db, ack, AckDisposition.DUPLICATE, delivery_id=delivery.id)
        _audit_ack(db, ack, record, AckDisposition.DUPLICATE, actor_admin_id)
        return AckOutcome(record.id, AckDisposition.DUPLICATE.value, False, delivery.id)

    record = _record(db, ack, AckDisposition.ACCEPTED, delivery_id=delivery.id)
    state.state = DeliveryState.ACTIVE.value
    state.activating_ack_id = record.id
    db.flush()
    _audit_ack(db, ack, record, AckDisposition.ACCEPTED, actor_admin_id)
    enqueue_platform_event(
        db,
        event_type=_EVENT_ACTIVATED,
        payload={
            "delivery_id": str(delivery.id),
            "issuance_id": str(issuance.id),
            "licence_id": str(licence.id),
            "licence_version": issuance.version,
            "digest": issuance.digest,
            "ack_id": str(record.id),
        },
    )
    return AckOutcome(record.id, AckDisposition.ACCEPTED.value, True, delivery.id)


# ── Reads ───────────────────────────────────────────────────────────────────


def delivery_status(db: Session, delivery_id: UUID) -> DeliveryView:
    delivery = db.get(LicenceDelivery, delivery_id)
    if delivery is None:
        raise NotFoundError(f"licence delivery {delivery_id} not found")
    return _view(db, delivery)


def list_acknowledgements(db: Session, licence_id: str) -> list[Mapping[str, object]]:
    rows = db.execute(
        select(LicenceAckRecord)
        .where(LicenceAckRecord.licence_id == licence_id)
        .order_by(LicenceAckRecord.created_at)
    ).scalars()
    return [
        {
            "id": str(r.id),
            "licence_version": r.licence_version,
            "digest": r.digest,
            "status": r.status,
            "reason": r.reason,
            "deployment_id": r.deployment_id,
            "disposition": r.disposition,
        }
        for r in rows
    ]


__all__ = [
    "StageDeliveryCommand",
    "AcknowledgementInput",
    "DeliveryView",
    "AckOutcome",
    "stage_delivery",
    "ingest_acknowledgement",
    "delivery_status",
    "list_acknowledgements",
]
