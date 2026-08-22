"""The three ADR-0010 § 3 ports, as services. Routes are thin adapters over these.

Gate 2a: checked in and authenticated, driving nothing. No `dotmac-integration`
pin, no connector, no mirror mode, no activation. The frozen logging and
offline-bundle paths in `transport.py` are untouched and remain the only thing
that moves bytes today.

## The correlation rule, which is the whole safety property

An intent records four facts at hand-off: `delivery_intent_id`,
`deployment_target_ref`, `licence_version`, `artifact_digest`. An acknowledgement
must present all four and they must all match. **Every mismatch fails closed.**

That is not defensive coding. An acknowledgement is a claim that a specific
signed document was applied at a specific destination; if any of those four
disagree with what Vendor recorded, the claim is about a different delivery than
the one it names, and accepting it would let a real acknowledgement for artifact
A close the obligation for artifact B. The failure is a routing fault to
investigate, never a completion to record.

`authenticated_deployment_ref` is separate from `deployment_target_ref` on
purpose, and the pair is checked. The first is what the TRANSPORT proved about
who is talking; the second is what Vendor decided the destination was. Provider
or plugin input may corroborate destination identity; it may never select or
override it (ADR-0010's 2026-08-22 amendment). Folding them into one field would
delete the distinction that makes corroboration checkable.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from dotmac_kernel import BadRequestError, ConflictError, NotFoundError
from dotmac_kernel.audit import write_platform_audit_event
from sqlalchemy import select
from sqlalchemy.orm import Session

from vendor_cp.deployment import adapter as deployment_adapter
from vendor_cp.licensing import adapter as licensing
from vendor_cp.licensing.intent_models import IntentStatus, LicenceDeliveryIntent

# Action literals are written INLINE at each `write_platform_audit_event` call,
# not through constants. `tests/architecture/test_platform_audit_actions.py`
# sweeps the vocabulary by walking the AST for `action=` keyword LITERALS, so a
# constant is invisible to it and the declaration would read as an orphan. The
# repo's other services do the same; matching them keeps the sweep honest.


@dataclass(frozen=True, slots=True)
class DeliveryIntentView:
    """The hand-off, WITHOUT the signed envelope (ADR-0010 § 3.1)."""

    delivery_intent_id: UUID
    issuance_id: UUID
    deployment_target_ref: str
    licence_version: int
    artifact_digest: str
    status: str
    integrator_receipt_ref: str | None = None
    acknowledged_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class ExactArtifact:
    """The immutable envelope, for dispatch only."""

    delivery_intent_id: UUID
    artifact_digest: str
    envelope: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class AcknowledgeIntentCommand:
    """Every correlation field, plus the two identities and the outcome."""

    delivery_intent_id: UUID
    deployment_target_ref: str
    licence_version: int
    artifact_digest: str
    integrator_receipt_ref: str
    authenticated_deployment_ref: str
    outcome: str
    reason: str | None = None
    reported_at: datetime | None = None
    actor_admin_id: UUID | None = None


def _view(row: LicenceDeliveryIntent) -> DeliveryIntentView:
    return DeliveryIntentView(
        delivery_intent_id=row.id,
        issuance_id=row.issuance_id,
        deployment_target_ref=row.deployment_target_ref,
        licence_version=row.licence_version,
        artifact_digest=row.artifact_digest,
        status=row.status,
        integrator_receipt_ref=row.integrator_receipt_ref,
        acknowledged_at=row.acknowledged_at,
    )


def _intent(db: Session, delivery_intent_id: UUID) -> LicenceDeliveryIntent:
    row = db.get(LicenceDeliveryIntent, delivery_intent_id)
    if row is None:
        raise NotFoundError(f"delivery intent {delivery_intent_id} is not recorded")
    return row


def open_delivery_intent(
    db: Session,
    *,
    issuance_id: UUID,
    deployment_target_id: UUID,
    actor_admin_id: UUID | None = None,
) -> DeliveryIntentView:
    """Record that one exact artifact is owed to one Deployment Control target.

    The caller names an ISSUANCE and a DEPLOYMENT TARGET ID — never a digest, a
    version or a target ref. All four correlation values are derived here from
    their owners: the artifact facts from `dotmac-licensing`, the destination
    reference from `mod_deploy` through the deployment adapter. A caller that
    could supply the digest could correlate an acknowledgement to an artifact
    that was never issued.

    Idempotent on (artifact, destination): a repeated hand-off returns the
    existing intent rather than minting a second correlation id for one
    obligation.
    """
    issuance = licensing.issuance_for_delivery(db, issuance_id)
    if issuance is None:
        raise NotFoundError(f"licence issuance {issuance_id} does not exist")

    target = deployment_adapter.resolve_target(db, deployment_target_id)

    # The lineage's customer must own the licence being sent there. The same
    # cross-customer refusal `_authorised_target` makes for the frozen path,
    # made again here rather than assumed: this port does not go through it.
    if issuance.subject_ref != target.customer_ref:
        raise BadRequestError(
            "refusing cross-customer delivery intent: the licence lineage "
            f"belongs to {issuance.subject_ref!r} but deployment target "
            f"{target.target_ref!r} belongs to {target.customer_ref!r}"
        )

    # A licence bound to a named deployment may only be owed to that deployment.
    if issuance.deployment_ref is not None and (
        issuance.deployment_ref != target.target_ref
    ):
        raise BadRequestError(
            f"licence is bound to deployment {issuance.deployment_ref!r} and "
            f"may not be delivered to {target.target_ref!r} — a bound document "
            "is unusable there and handing it over still discloses the "
            "entitlement set"
        )

    existing = db.execute(
        select(LicenceDeliveryIntent).where(
            LicenceDeliveryIntent.issuance_id == issuance.id,
            LicenceDeliveryIntent.deployment_target_ref == target.target_ref,
        )
    ).scalar_one_or_none()
    if existing is not None:
        return _view(existing)

    row = LicenceDeliveryIntent(
        issuance_id=issuance.id,
        licence_id=issuance.licence_id,
        licence_version=issuance.version,
        artifact_digest=issuance.digest,
        deployment_target_ref=target.target_ref,
        status=IntentStatus.OPEN.value,
    )
    db.add(row)
    db.flush()

    write_platform_audit_event(
        db,
        actor_admin_id=actor_admin_id,
        action="vendor.licence.delivery_intent_opened",
        entity_type="licence_delivery_intent",
        entity_id=str(row.id),
        details={
            "issuance_id": str(row.issuance_id),
            "deployment_target_ref": row.deployment_target_ref,
            "licence_version": row.licence_version,
            "artifact_digest": row.artifact_digest,
        },
    )
    return _view(row)


def read_exact_artifact(
    db: Session,
    *,
    delivery_intent_id: UUID,
    actor_admin_id: UUID | None = None,
) -> ExactArtifact:
    """Return the immutable envelope this intent names, for dispatch only.

    The digest is re-checked against the intent. If the module's artifact no
    longer hashes to what was recorded at hand-off, something has rewritten a
    document that is supposed to be immutable, and the right answer is to refuse
    rather than to dispatch whatever is there now.
    """
    row = _intent(db, delivery_intent_id)
    issuance = licensing.issuance_for_delivery(db, row.issuance_id)
    if issuance is None:
        raise NotFoundError(
            f"delivery intent {row.id} names issuance {row.issuance_id}, which "
            "the licensing owner no longer has"
        )
    if issuance.digest != row.artifact_digest:
        raise ConflictError(
            f"artifact digest for issuance {row.issuance_id} is "
            f"{issuance.digest!r} but this intent was correlated on "
            f"{row.artifact_digest!r} — refusing to dispatch a document that "
            "changed after the hand-off"
        )

    write_platform_audit_event(
        db,
        actor_admin_id=actor_admin_id,
        action="vendor.licence.source_artifact_read",
        entity_type="licence_delivery_intent",
        entity_id=str(row.id),
        details={
            "issuance_id": str(row.issuance_id),
            "artifact_digest": row.artifact_digest,
        },
    )
    return ExactArtifact(
        delivery_intent_id=row.id,
        artifact_digest=row.artifact_digest,
        envelope=issuance.envelope,
    )


def acknowledge_delivery_intent(
    db: Session, command: AcknowledgeIntentCommand
) -> DeliveryIntentView:
    """Complete an already-correlated intent. Idempotent on the receipt.

    Order matters here. Correlation is checked BEFORE the lifecycle owner is
    told anything, so a mismatched acknowledgement produces no licensing
    consequence at all — not an accepted-then-corrected one.
    """
    row = _intent(db, command.delivery_intent_id)

    mismatches = [
        f"{name}: intent has {recorded!r}, acknowledgement claims {claimed!r}"
        for name, recorded, claimed in (
            (
                "deployment_target_ref",
                row.deployment_target_ref,
                command.deployment_target_ref,
            ),
            ("licence_version", row.licence_version, command.licence_version),
            ("artifact_digest", row.artifact_digest, command.artifact_digest),
        )
        if recorded != claimed
    ]
    if mismatches:
        raise BadRequestError(
            "refusing an acknowledgement that does not correlate to the intent "
            f"it names ({'; '.join(mismatches)}). An acknowledgement completes "
            "one exact delivery; a mismatch is a routing fault to investigate, "
            "not a completion to record."
        )

    # Corroboration, never selection: the transport-proven identity must agree
    # with the destination Vendor chose. It cannot redirect the completion.
    if command.authenticated_deployment_ref != row.deployment_target_ref:
        raise BadRequestError(
            "the transport authenticated "
            f"{command.authenticated_deployment_ref!r}, but this intent is owed "
            f"to {row.deployment_target_ref!r} — provider input may corroborate "
            "a destination and may never select one"
        )

    if row.status == IntentStatus.ACKNOWLEDGED.value:
        if row.integrator_receipt_ref == command.integrator_receipt_ref:
            return _view(row)
        raise ConflictError(
            f"delivery intent {row.id} was already completed by receipt "
            f"{row.integrator_receipt_ref!r}; receipt "
            f"{command.integrator_receipt_ref!r} would be a second completion "
            "of one obligation"
        )

    issuance = licensing.issuance_for_delivery(db, row.issuance_id)
    if issuance is None:
        raise NotFoundError(
            f"delivery intent {row.id} names issuance {row.issuance_id}, which "
            "the licensing owner no longer has"
        )

    # The lifecycle decision is the module's, not Vendor's. Vendor records the
    # correlation; `dotmac-licensing` decides what the report means.
    licensing.acknowledge_installation(
        db,
        issuance=issuance,
        outcome=command.outcome,
        reason=command.reason,
        reported_at=command.reported_at,
        authenticated_deployment_ref=command.authenticated_deployment_ref,
        actor_admin_id=command.actor_admin_id,
    )

    row.status = IntentStatus.ACKNOWLEDGED.value
    row.integrator_receipt_ref = command.integrator_receipt_ref
    row.acknowledged_at = command.reported_at or datetime.now(UTC)
    row.applied_outcome = command.outcome
    db.flush()

    write_platform_audit_event(
        db,
        actor_admin_id=command.actor_admin_id,
        action="vendor.licence.delivery_intent_acknowledged",
        entity_type="licence_delivery_intent",
        entity_id=str(row.id),
        details={
            "integrator_receipt_ref": command.integrator_receipt_ref,
            "authenticated_deployment_ref": command.authenticated_deployment_ref,
            "outcome": command.outcome,
            "artifact_digest": row.artifact_digest,
        },
    )
    return _view(row)


def get_delivery_intent(db: Session, delivery_intent_id: UUID) -> DeliveryIntentView:
    return _view(_intent(db, delivery_intent_id))


__all__ = [
    "AcknowledgeIntentCommand",
    "DeliveryIntentView",
    "ExactArtifact",
    "acknowledge_delivery_intent",
    "get_delivery_intent",
    "open_delivery_intent",
    "read_exact_artifact",
]
