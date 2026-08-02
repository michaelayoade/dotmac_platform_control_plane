"""Delivery + acknowledgement state — PLATFORM catalog tables (migration v007).

The shape is deliberate: **immutable facts, append-only records, and one
derived projection the service alone owns.**

- `LicenceDelivery` — an immutable FACT: "issued version X was staged for
  delivery to target T". Never updated after insert; re-staging the same
  `(issuance_id, target_ref)` is a no-op, not an edit.
- `LicenceAckRecord` — an APPEND-ONLY log of every acknowledgement the vendor
  received, including the ones it refuses to act on. A quarantined ack (unknown
  digest, wrong deployment, stale version) is *evidence*, and deleting or
  overwriting it would destroy the tamper trail it exists to preserve. Its
  `disposition` records what the service decided.
- `LicenceDeliveryState` — the DERIVED projection (`delivered` → `active`),
  exactly one row per delivery. Only `EntitlementProjectionService` writes it;
  it is rebuildable from the facts + the ack log, which is why it is kept apart
  from the immutable fact rather than mutated onto it.

Platform catalog (no `tenant_id`, no RLS; GRANTed to `platform_api`/`app_admin`,
REVOKEd from `app_user`). Import-safe: touches only `Base.metadata` (D1).
"""

from __future__ import annotations

from enum import Enum
from uuid import UUID

from dotmac_kernel import Base, TimestampMixin, uuid_pk
from sqlalchemy import ForeignKey, Integer, String, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column


class DeliveryState(str, Enum):
    """`delivered` — staged and handed to a transport (at-least-once, so it may
    be re-sent). `active` — the data plane acknowledged a COMMITTED local
    projection of this exact version+digest. `parked` — replay STOPPED, either
    because a transport reported a terminal failure or attempts were exhausted;
    it alerts immediately and never retries until an operator resumes it. There
    is no "probably applied"."""

    DELIVERED = "delivered"
    ACTIVE = "active"
    PARKED = "parked"


class AckStatus(str, Enum):
    """The receiver's own verdict, mirroring the kernel's
    `LicenceAcknowledgement.status`."""

    APPLIED = "applied"
    REJECTED = "rejected"


class AckDisposition(str, Enum):
    """What the VENDOR decided to do with a received acknowledgement — distinct
    from what the receiver claimed.

    `accepted` — matched an issuance we made and advanced the projection.
    `duplicate` — matched, but that version was already active: no-op.
    `rejected_by_receiver` — the receiver reported a verification/projection
    failure; the reason is its stable kernel error code.
    `stale` — a late ack for a version older than the one already active; it
    must never regress the projection.
    `unverified_identity` — the caller proved no deployment identity, so the
    acknowledgement is recorded as EVIDENCE ONLY and activates nothing. Until
    deployment authentication exists this is what every admin-submitted ack
    becomes: "active" must mean the data plane committed, and an unauthenticated
    caller cannot establish that for any licence, bound or not.
    `unknown_licence` / `unknown_digest` / `deployment_mismatch` —
    QUARANTINED. An ack we cannot tie to something we actually issued (for this
    deployment) is the mis-issue/tamper tripwire: recorded, flagged, and never
    allowed to activate anything.
    """

    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    UNVERIFIED_IDENTITY = "unverified_identity"
    REJECTED_BY_RECEIVER = "rejected_by_receiver"
    STALE = "stale"
    UNKNOWN_LICENCE = "unknown_licence"
    UNKNOWN_DIGEST = "unknown_digest"
    DEPLOYMENT_MISMATCH = "deployment_mismatch"

    @property
    def is_quarantined(self) -> bool:
        return self in {
            AckDisposition.UNKNOWN_LICENCE,
            AckDisposition.UNKNOWN_DIGEST,
            AckDisposition.DEPLOYMENT_MISMATCH,
        }


class LicenceDelivery(Base, TimestampMixin):
    """Immutable fact: one issued version staged for one target."""

    __tablename__ = "licence_deliveries"
    __table_args__ = (
        UniqueConstraint(
            "issuance_id", "target_ref", name="uq_licence_delivery_issuance_target"
        ),
    )

    id: Mapped[UUID] = uuid_pk()
    issuance_id: Mapped[UUID] = mapped_column(
        Uuid(), ForeignKey("licence_issuances.id"), nullable=False
    )
    # The REGISTERED deployment's ref, resolved at staging — not a caller-
    # supplied destination. Kept denormalised for display/uniqueness alongside
    # the FK below.
    target_ref: Mapped[str] = mapped_column(String(200), nullable=False)
    # The resolved destination. Nullable ONLY so pre-existing rows could be
    # adopted; a CHECK constraint (NOT VALID) rejects new/updated rows without
    # one, and legacy nulls are parked by the migration.
    target_id: Mapped[UUID | None] = mapped_column(
        Uuid(), ForeignKey("licence_delivery_targets.id"), nullable=True
    )


class LicenceDeliveryState(Base, TimestampMixin):
    """The derived projection for one delivery — service-owned, rebuildable."""

    __tablename__ = "licence_delivery_states"
    __table_args__ = (
        UniqueConstraint("delivery_id", name="uq_licence_delivery_state_delivery"),
    )

    id: Mapped[UUID] = uuid_pk()
    delivery_id: Mapped[UUID] = mapped_column(
        Uuid(),
        ForeignKey("licence_deliveries.id", ondelete="CASCADE"),
        nullable=False,
    )
    state: Mapped[str] = mapped_column(
        String(20), nullable=False, default=DeliveryState.DELIVERED.value
    )
    # The ack that activated this delivery (provenance for the transition).
    activating_ack_id: Mapped[UUID | None] = mapped_column(Uuid(), nullable=True)
    # Bumped by `resume_delivery`. The retry budget is counted WITHIN a
    # generation, so resuming resets the budget while the immutable attempt
    # history is preserved.
    replay_generation: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )


class AttemptOutcome(str, Enum):
    """What one transport attempt did. `sent` means the transport accepted the
    packet — NOT that the deployment applied it; only an acknowledgement can
    say that. `terminal` will never succeed for this document and stops replay
    at once."""

    SENT = "sent"
    FAILED = "failed"
    TERMINAL = "terminal"


class TargetStatus(str, Enum):
    """Only `active` targets may receive a delivery."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    RETIRED = "retired"


class LicenceDeliveryTarget(Base, TimestampMixin):
    """A licensing-owned projection of where a licence may be delivered.

    Deliberately NOT named `deployments`: `docs/design/domain-foundation.md`
    assigns the authoritative Deployment entity to `FleetDesiredStateService`,
    and ARCHITECTURE.md still records deployment intent as design-only. Having
    licensing quietly create that table would have made it the de-facto owner
    of an entity another service is specified to own — a source-of-truth
    violation dressed as a convenience. This is a narrow delivery-target
    projection owned by `EntitlementProjectionService`; when the fleet slice
    lands, this is rebuilt from it rather than competing with it.

    Registration alone is NOT authorisation — staging additionally requires an
    `active` status, a customer matching the licence lineage, and (for a bound
    document) the exact bound deployment.

    `connection_ref` is an opaque handle a transport interprets (a configured
    endpoint name, a bundle drop, …) — never a URL supplied with a request.
    """

    __tablename__ = "licence_delivery_targets"
    __table_args__ = (
        UniqueConstraint("target_ref", name="uq_licence_delivery_targets_ref"),
    )

    id: Mapped[UUID] = uuid_pk()
    target_ref: Mapped[str] = mapped_column(String(200), nullable=False)
    customer_ref: Mapped[str] = mapped_column(String(200), nullable=False)
    connection_ref: Mapped[str | None] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=TargetStatus.ACTIVE.value
    )


class LicenceDeliveryAttempt(Base, TimestampMixin):
    """Append-only record of each transport attempt.

    Kept because "no acknowledgement" is ambiguous without it: never sent, and
    sent ten times but never acknowledged, are different faults needing
    different responses, and an alert that cannot tell them apart sends the
    operator to the wrong place.
    """

    __tablename__ = "licence_delivery_attempts"
    __table_args__ = (
        UniqueConstraint(
            "delivery_id",
            "replay_generation",
            "attempt_no",
            name="uq_licence_delivery_attempt_no",
        ),
    )

    id: Mapped[UUID] = uuid_pk()
    delivery_id: Mapped[UUID] = mapped_column(
        Uuid(),
        ForeignKey("licence_deliveries.id", ondelete="CASCADE"),
        nullable=False,
    )
    replay_generation: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    attempt_no: Mapped[int] = mapped_column(Integer, nullable=False)
    transport: Mapped[str] = mapped_column(String(40), nullable=False)
    outcome: Mapped[str] = mapped_column(String(20), nullable=False)
    # A STABLE, CLOSED-VOCABULARY code — never a raw exception, response body,
    # URL, header, or token. Transport failures routinely carry credentials in
    # their messages, and this table is read by dashboards and support staff.
    error_code: Mapped[str | None] = mapped_column(String(60))


class LicenceAckRecord(Base, TimestampMixin):
    """Append-only: every acknowledgement received, accepted or not."""

    __tablename__ = "licence_ack_records"

    id: Mapped[UUID] = uuid_pk()
    # Nullable: a quarantined ack may not correspond to any delivery we made —
    # that is precisely the case worth keeping.
    delivery_id: Mapped[UUID | None] = mapped_column(
        Uuid(), ForeignKey("licence_deliveries.id"), nullable=True
    )
    licence_id: Mapped[str] = mapped_column(String(200), nullable=False)
    licence_version: Mapped[int] = mapped_column(Integer, nullable=False)
    digest: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(120))
    # The body's CLAIM — untrusted, kept for evidence.
    deployment_id: Mapped[str | None] = mapped_column(String(200))
    # The identity the caller actually PROVED, or NULL when it proved none.
    # Stored separately so an audit can never mistake a claim for proof.
    authenticated_deployment_ref: Mapped[str | None] = mapped_column(String(200))
    disposition: Mapped[str] = mapped_column(String(40), nullable=False)


__all__ = [
    "DeliveryState",
    "AttemptOutcome",
    "TargetStatus",
    "LicenceDeliveryTarget",
    "LicenceDeliveryAttempt",
    "AckStatus",
    "AckDisposition",
    "LicenceDelivery",
    "LicenceDeliveryState",
    "LicenceAckRecord",
]
