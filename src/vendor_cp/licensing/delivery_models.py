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
    projection of this exact version+digest. There is no "probably applied"."""

    DELIVERED = "delivered"
    ACTIVE = "active"


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
    `unknown_licence` / `unknown_digest` / `deployment_mismatch` —
    QUARANTINED. An ack we cannot tie to something we actually issued (for this
    deployment) is the mis-issue/tamper tripwire: recorded, flagged, and never
    allowed to activate anything.
    """

    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
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
    # Opaque destination handle (a deployment endpoint, an offline bundle
    # recipient, …). The vendor never interprets it; transports do.
    target_ref: Mapped[str] = mapped_column(String(200), nullable=False)


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
    deployment_id: Mapped[str | None] = mapped_column(String(200))
    disposition: Mapped[str] = mapped_column(String(40), nullable=False)


__all__ = [
    "DeliveryState",
    "AckStatus",
    "AckDisposition",
    "LicenceDelivery",
    "LicenceDeliveryState",
    "LicenceAckRecord",
]
