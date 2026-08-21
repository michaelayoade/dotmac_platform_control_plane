"""`EntitlementProjectionService` — delivery staging + acknowledgement truth.

The second WS8 vendor owner (`docs/design/licence-service.md`). It owns
**delivery evidence and projection state, and nothing else**: it never signs,
never builds documents (that is `dotmac-licensing`), and never writes a product
data plane's WS2 grants (ruling C4).

Its one hard rule: **`active` means the data plane committed a local projection
of this exact version and digest — not that a call succeeded.** Everything here
follows from that:

- Staging a delivery records an immutable fact and emits `licence.delivered`
  atomically with it; delivery is at-least-once, so re-staging is a no-op.
- Only an `applied` acknowledgement from a PROVEN deployment identity, matching
  the licence id, version and digest (and, for a bound document, that exact
  deployment), advances `delivered → active`. An acknowledgement with no proven
  identity is recorded as evidence and activates nothing — bound or unbound —
  because `active` claims the data plane committed, and an unauthenticated
  caller cannot establish that for any licence. A platform admin is not a
  deployment: admin-submitted acks are evidence, permanently, by design and
  not pending some later feature.
- Authenticated, issuer-valid reports are forwarded to `dotmac-licensing` in
  the same transaction; Vendor does not maintain a parallel licence status.
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

from dotmac_kernel import (
    BadRequestError,
    NotFoundError,
    write_platform_audit_event,
)
from dotmac_kernel.messaging import enqueue_platform_event
from sqlalchemy import select
from sqlalchemy.orm import Session

from vendor_cp.deployment.adapter import DeploymentTargetFacts
from vendor_cp.licensing import adapter as licensing
from vendor_cp.licensing.delivery_models import (
    AckDisposition,
    AckStatus,
    DeliveryState,
    LicenceAckRecord,
    LicenceDelivery,
    LicenceDeliveryState,
    LicenceDeliveryTarget,
    TargetStatus,
)

_EVENT_DELIVERED = "licence.delivered"


@dataclass(frozen=True, slots=True)
class StageDeliveryCommand:
    """Stage an issued version for delivery to a REGISTERED target.

    `target_ref` is resolved against the licence-delivery-target projection
    and AUTHORISED (active status, matching customer, and the exact bound
    deployment for a bound document) — registration alone is not permission,
    and a caller can never name an arbitrary destination.
    """

    issuance_id: UUID
    target_ref: str
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


# ── Delivery targets (a projection, reconciled — never registered) ─────────


def reconcile_delivery_target(
    db: Session,
    facts: DeploymentTargetFacts,
    *,
    actor_admin_id: UUID | None = None,
) -> LicenceDeliveryTarget:
    """Project a deployment target the FLEET OWNER knows about, audited.

    This replaced the registration command at the ADR-0011 cutover, and the
    difference is the whole point: that command took `target_ref`,
    `customer_ref`, `connection_ref` and `status` from its caller, which made
    this table a second authority over deployment-target identity. The
    retired name is in ADR-0011 and in the ratchet, not here.
    `DeploymentTargetFacts` can only be built by `vendor_cp.deployment.adapter`
    from a record `mod_deploy` returned, so every value written here has a
    provenance.

    Idempotent on `target_ref`. The old customer-repointing refusal is gone
    along with the reason for it: the customer is no longer a caller's claim to
    get wrong, it is whatever the fleet owner says it is, so a change here is a
    correction to be projected rather than an attack to be blocked. What has NOT
    changed is that this is only a projection — `_authorised_target` still
    performs every eligibility check separately, because registration was never
    authorisation and reconciliation is not either.

    `connection_ref` is deliberately cleared. It is transport metadata the
    module does not own, and ADR-0010 removes the column with the rest of the
    delivery estate.
    """
    row = db.execute(
        select(LicenceDeliveryTarget).where(
            LicenceDeliveryTarget.target_ref == facts.target_ref
        )
    ).scalar_one_or_none()
    if row is None:
        row = LicenceDeliveryTarget(
            target_ref=facts.target_ref,
            customer_ref=facts.customer_ref,
            connection_ref=None,
            status=facts.status.value,
        )
        db.add(row)
    else:
        row.customer_ref = facts.customer_ref
        row.connection_ref = None
        row.status = facts.status.value
    db.flush()

    write_platform_audit_event(
        db,
        actor_admin_id=actor_admin_id,
        action="vendor.licence.delivery_target_reconciled",
        entity_type="licence_delivery_target",
        entity_id=str(row.id),
        details={
            "target_ref": row.target_ref,
            "customer_ref": row.customer_ref,
            "status": row.status,
            "deployment_target_id": str(facts.target_id),
        },
    )
    return row


def list_delivery_targets(db: Session) -> list[LicenceDeliveryTarget]:
    """All projected delivery targets. Lives here rather than in the router so
    the route stays a thin adapter — a direct query in a handler is how a
    second, unowned read path starts."""
    return list(
        db.execute(
            select(LicenceDeliveryTarget).order_by(LicenceDeliveryTarget.target_ref)
        ).scalars()
    )


def map_legacy_delivery(
    db: Session,
    *,
    delivery_id: UUID,
    target_ref: str,
    actor_admin_id: UUID | None = None,
) -> DeliveryView:
    """Attach a destination to a delivery that predates the registry.

    Migration `v010` parks those rows; this is how an operator makes one
    replayable again, and `resume_delivery` refuses until it has been done.
    The same authorisation rules as staging apply — mapping must not become a
    back door around the checks staging performs.
    """
    delivery = db.get(LicenceDelivery, delivery_id)
    if delivery is None:
        raise NotFoundError(f"licence delivery {delivery_id} not found")
    if delivery.target_id is not None:
        raise BadRequestError(
            f"delivery {delivery_id} already has a destination — a delivery "
            "fact is immutable and may not be re-pointed"
        )
    issuance = licensing.issuance_for_delivery(db, delivery.issuance_id)
    if issuance is None:
        raise RuntimeError(f"delivery {delivery_id} references a missing issuance")
    target = _authorised_target(db, target_ref=target_ref, issuance=issuance)

    delivery.target_ref = target.target_ref
    delivery.target_id = target.id
    db.flush()
    write_platform_audit_event(
        db,
        actor_admin_id=actor_admin_id,
        action="vendor.licence.delivery_mapped",
        entity_type="licence_delivery",
        entity_id=str(delivery.id),
        details={"target_ref": target.target_ref},
    )
    return _view(db, delivery)


def _authorised_target(
    db: Session, *, target_ref: str, issuance: licensing.DeliveryIssuanceView
) -> LicenceDeliveryTarget:
    """Resolve a target AND authorise it for this issuance. Registration is not
    authorisation; each check below is a distinct failure mode, so each is made
    and named separately rather than folded into one predicate."""
    target = db.execute(
        select(LicenceDeliveryTarget).where(
            LicenceDeliveryTarget.target_ref == target_ref
        )
    ).scalar_one_or_none()
    if target is None:
        raise NotFoundError(
            f"delivery target {target_ref!r} is not registered — a licence may "
            "only be delivered to a registered destination"
        )
    if target.status != TargetStatus.ACTIVE.value:
        raise BadRequestError(
            f"delivery target {target.target_ref!r} is {target.status!r}, not "
            "active — a suspended or retired destination must not receive "
            "licences"
        )
    if target.customer_ref != issuance.subject_ref:
        raise BadRequestError(
            "refusing cross-customer delivery: the licence lineage belongs to "
            f"{issuance.subject_ref!r} but target {target.target_ref!r} belongs "
            f"to {target.customer_ref!r}"
        )
    bound_to = _issued_deployment_id(issuance)
    if bound_to is not None and bound_to != target.target_ref:
        raise BadRequestError(
            f"licence is bound to deployment {bound_to!r} and may not be staged "
            f"to {target.target_ref!r} — a bound document is unusable there and "
            "delivering it still discloses the entitlement set"
        )
    return target


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
    issuance = licensing.issuance_for_delivery(db, command.issuance_id)
    if issuance is None:
        raise NotFoundError(f"licence issuance {command.issuance_id} not found")

    target = _authorised_target(db, target_ref=command.target_ref, issuance=issuance)

    existing = db.execute(
        select(LicenceDelivery).where(
            LicenceDelivery.issuance_id == command.issuance_id,
            LicenceDelivery.target_ref == command.target_ref,
        )
    ).scalar_one_or_none()
    if existing is not None:
        return _view(db, existing)

    delivery = LicenceDelivery(
        issuance_id=issuance.id,
        target_ref=command.target_ref,
        target_id=target.id,
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
            "target_ref": command.target_ref,
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
            "target_ref": command.target_ref,
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
    authenticated_deployment_ref: str | None = None,
) -> LicenceAckRecord:
    row = LicenceAckRecord(
        delivery_id=delivery_id,
        licence_id=ack.licence_id,
        licence_version=ack.licence_version,
        digest=ack.digest,
        status=ack.status,
        reason=ack.reason,
        # The CLAIM and the PROOF are stored separately, so an audit can never
        # mistake one for the other.
        deployment_id=ack.deployment_id,
        authenticated_deployment_ref=authenticated_deployment_ref,
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
            # Claim and proof are reported SEPARATELY — an audit trail that
            # showed only the claim would look identical whether or not the
            # caller proved anything.
            "claimed_deployment_id": ack.deployment_id,
            "authenticated_deployment_ref": record.authenticated_deployment_ref,
            "disposition": disposition.value,
        },
    )


def _highest_active_version(db: Session, licence_id: UUID) -> int:
    """The newest version of this lineage already acknowledged as applied."""
    issuance_ids = db.execute(
        select(LicenceDelivery.issuance_id)
        .join(
            LicenceDeliveryState,
            LicenceDeliveryState.delivery_id == LicenceDelivery.id,
        )
        .where(
            LicenceDeliveryState.state == DeliveryState.ACTIVE.value,
        )
    ).scalars()
    versions = (
        issuance.version
        for issuance_id in issuance_ids
        if (issuance := licensing.issuance_for_delivery(db, issuance_id)) is not None
        and issuance.licence_id == licence_id
    )
    return max(versions, default=0)


def _issued_deployment_id(
    issuance: licensing.DeliveryIssuanceView,
) -> str | None:
    """The binding recorded by the issuer, not a caller's claim."""
    return issuance.deployment_ref


def _acknowledge_issuer(
    db: Session,
    *,
    ack: AcknowledgementInput,
    record: LicenceAckRecord,
    issuance: licensing.DeliveryIssuanceView,
    authenticated_deployment_ref: str,
    actor_admin_id: UUID | None,
) -> None:
    """Record a verified installation report with the licence authority."""
    if ack.status not in {AckStatus.APPLIED.value, AckStatus.REJECTED.value}:
        return
    licensing.acknowledge_installation(
        db,
        issuance=issuance,
        outcome=ack.status,
        reason=ack.reason,
        reported_at=record.created_at,
        authenticated_deployment_ref=authenticated_deployment_ref,
        actor_admin_id=actor_admin_id,
    )


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
    mismatch.

    **Without a proven identity nothing activates — bound or unbound.** A
    platform admin may SUBMIT an acknowledgement, and it is recorded as
    `unverified_identity` evidence, but it advances no delivery to `active`.
    `active` asserts that the data plane committed this exact version, and no
    third party can attest to that on the data plane's behalf; for a bound
    licence there is additionally nothing to check the binding against, so
    accepting the body's word would make binding decorative.

    This is not a limitation awaiting deployment authentication. Authenticated
    ingestion (`docs/design/deployment-credentials.md`) adds a second adapter
    that CAN supply a proven identity; it never grants admin submissions the
    power to activate.

    Every inbound ack is written to the append-only log first — including the
    ones we refuse — so the decision is always auditable.
    """
    # 1. Does it name a lineage we own?
    try:
        licence_uuid = UUID(ack.licence_id)
    except (ValueError, AttributeError):
        licence_uuid = None
    issuance = (
        licensing.find_issuance(
            db,
            licence_id=licence_uuid,
            version=ack.licence_version,
        )
        if licence_uuid is not None
        else None
    )
    if issuance is None:
        record = _record(
            db,
            ack,
            AckDisposition.UNKNOWN_LICENCE,
            authenticated_deployment_ref=authenticated_deployment_ref,
        )
        _audit_ack(db, ack, record, AckDisposition.UNKNOWN_LICENCE, actor_admin_id)
        return AckOutcome(record.id, AckDisposition.UNKNOWN_LICENCE.value, False)

    # 2. …with the digest WE issued? A mismatch means the deployment applied a
    #    document we did not produce (or produced a claim about one).
    if ack.digest != issuance.digest:
        record = _record(
            db,
            ack,
            AckDisposition.UNKNOWN_DIGEST,
            authenticated_deployment_ref=authenticated_deployment_ref,
        )
        _audit_ack(db, ack, record, AckDisposition.UNKNOWN_DIGEST, actor_admin_id)
        return AckOutcome(record.id, AckDisposition.UNKNOWN_DIGEST.value, False)

    # 4. …from the deployment it was bound to (when it was bound at all)?
    # 4. No PROVEN identity ⇒ evidence only, never activation. `active` means
    #    the data plane committed, and an unauthenticated caller cannot
    #    establish that for ANY licence, bound or unbound. Checked BEFORE the
    #    binding rules because an ABSENT identity is not a contradiction —
    #    calling it a mismatch would misdescribe what happened.
    if authenticated_deployment_ref is None:
        record = _record(
            db,
            ack,
            AckDisposition.UNVERIFIED_IDENTITY,
            authenticated_deployment_ref=None,
        )
        _audit_ack(db, ack, record, AckDisposition.UNVERIFIED_IDENTITY, actor_admin_id)
        return AckOutcome(record.id, AckDisposition.UNVERIFIED_IDENTITY.value, False)

    # A claimed identity that contradicts the proven one is itself a mismatch.
    if (
        authenticated_deployment_ref is not None
        and ack.deployment_id is not None
        and ack.deployment_id != authenticated_deployment_ref
    ):
        record = _record(
            db,
            ack,
            AckDisposition.DEPLOYMENT_MISMATCH,
            authenticated_deployment_ref=authenticated_deployment_ref,
        )
        _audit_ack(db, ack, record, AckDisposition.DEPLOYMENT_MISMATCH, actor_admin_id)
        return AckOutcome(record.id, AckDisposition.DEPLOYMENT_MISMATCH.value, False)

    bound_to = _issued_deployment_id(issuance)
    if bound_to is not None and authenticated_deployment_ref != bound_to:
        record = _record(
            db,
            ack,
            AckDisposition.DEPLOYMENT_MISMATCH,
            authenticated_deployment_ref=authenticated_deployment_ref,
        )
        _audit_ack(db, ack, record, AckDisposition.DEPLOYMENT_MISMATCH, actor_admin_id)
        return AckOutcome(record.id, AckDisposition.DEPLOYMENT_MISMATCH.value, False)

    # The delivery to THIS deployment, not merely the first one for this
    # issuance — the same version may be staged to several targets, and
    # activating an arbitrary one would mark the wrong deployment licensed.
    delivery_query = select(LicenceDelivery).where(
        LicenceDelivery.issuance_id == issuance.id
    )
    if authenticated_deployment_ref is not None:
        delivery_query = delivery_query.where(
            LicenceDelivery.target_ref == authenticated_deployment_ref
        )
    delivery = db.execute(delivery_query).scalars().first()

    # 6. The receiver itself reported failure — real information, no activation.
    if ack.status != AckStatus.APPLIED.value:
        record = _record(
            db,
            ack,
            AckDisposition.REJECTED_BY_RECEIVER,
            delivery_id=delivery.id if delivery else None,
            authenticated_deployment_ref=authenticated_deployment_ref,
        )
        _acknowledge_issuer(
            db,
            ack=ack,
            record=record,
            issuance=issuance,
            authenticated_deployment_ref=authenticated_deployment_ref,
            actor_admin_id=actor_admin_id,
        )
        _audit_ack(db, ack, record, AckDisposition.REJECTED_BY_RECEIVER, actor_admin_id)
        return AckOutcome(
            record.id,
            AckDisposition.REJECTED_BY_RECEIVER.value,
            False,
            delivery.id if delivery else None,
        )

    # 7. A late ack for an older version must NEVER regress a newer active one.
    highest_active = _highest_active_version(db, issuance.licence_id)
    if ack.licence_version < highest_active:
        record = _record(
            db,
            ack,
            AckDisposition.STALE,
            delivery_id=delivery.id if delivery else None,
            authenticated_deployment_ref=authenticated_deployment_ref,
        )
        _acknowledge_issuer(
            db,
            ack=ack,
            record=record,
            issuance=issuance,
            authenticated_deployment_ref=authenticated_deployment_ref,
            actor_admin_id=actor_admin_id,
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
        record = _record(
            db,
            ack,
            AckDisposition.UNKNOWN_LICENCE,
            authenticated_deployment_ref=authenticated_deployment_ref,
        )
        _acknowledge_issuer(
            db,
            ack=ack,
            record=record,
            issuance=issuance,
            authenticated_deployment_ref=authenticated_deployment_ref,
            actor_admin_id=actor_admin_id,
        )
        _audit_ack(db, ack, record, AckDisposition.UNKNOWN_LICENCE, actor_admin_id)
        return AckOutcome(record.id, AckDisposition.UNKNOWN_LICENCE.value, False)

    state = _state_of(db, delivery.id)
    if state.state == DeliveryState.ACTIVE.value:
        record = _record(
            db,
            ack,
            AckDisposition.DUPLICATE,
            delivery_id=delivery.id,
            authenticated_deployment_ref=authenticated_deployment_ref,
        )
        _acknowledge_issuer(
            db,
            ack=ack,
            record=record,
            issuance=issuance,
            authenticated_deployment_ref=authenticated_deployment_ref,
            actor_admin_id=actor_admin_id,
        )
        _audit_ack(db, ack, record, AckDisposition.DUPLICATE, actor_admin_id)
        return AckOutcome(record.id, AckDisposition.DUPLICATE.value, False, delivery.id)

    record = _record(
        db,
        ack,
        AckDisposition.ACCEPTED,
        delivery_id=delivery.id,
        authenticated_deployment_ref=authenticated_deployment_ref,
    )
    _acknowledge_issuer(
        db,
        ack=ack,
        record=record,
        issuance=issuance,
        authenticated_deployment_ref=authenticated_deployment_ref,
        actor_admin_id=actor_admin_id,
    )
    state.state = DeliveryState.ACTIVE.value
    state.activating_ack_id = record.id
    db.flush()
    _audit_ack(db, ack, record, AckDisposition.ACCEPTED, actor_admin_id)
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
            "claimed_deployment_id": r.deployment_id,
            "authenticated_deployment_ref": r.authenticated_deployment_ref,
            "disposition": r.disposition,
        }
        for r in rows
    ]


__all__ = [
    "reconcile_delivery_target",
    "list_delivery_targets",
    "map_legacy_delivery",
    "StageDeliveryCommand",
    "AcknowledgementInput",
    "DeliveryView",
    "AckOutcome",
    "stage_delivery",
    "ingest_acknowledgement",
    "delivery_status",
    "list_acknowledgements",
]
