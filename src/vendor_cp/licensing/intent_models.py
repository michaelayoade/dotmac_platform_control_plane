"""The durable delivery intent — Vendor's half of the ADR-0010 handoff.

One row per (exact artifact, Deployment Control target). It is the thing an
acknowledgement COMPLETES, which is why it is durable rather than derived: an
acknowledgement arriving weeks later, from a transport Vendor does not run, has
to correlate against something Vendor wrote down at hand-off time.

## Deliberately NOT a transport ledger

No attempt count, no retry state, no backoff, no checkpoint, no lease, no
`connection_ref`. Every one of those belongs to `dotmac-integration`
(`dotmac_starter_mt` ADR-0024, hard rule 28), and the five tables that hold
Vendor's versions of them are the
estate ADR-0010 retires. Adding one here would rebuild the thing this cutover
exists to remove, under a newer name.

`status` has exactly two values for the same reason. **"Connector accepted" is
not a state this table may hold** — it is the Integrator's, and it is precisely
the state that must stay distinguishable from "the deployment applied it and
said so with a signature". Vendor knows the intent is open, or that a correlated
authenticated acknowledgement has completed it. What happened in between is the
transport's ledger to keep.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import UUID

from dotmac_kernel.models import Base, TimestampMixin, uuid_pk
from sqlalchemy import DateTime, Integer, String, UniqueConstraint
from sqlalchemy import Uuid as SAUuid
from sqlalchemy.orm import Mapped, mapped_column


class IntentStatus(str, Enum):
    """Two states, and the absent third is the point — see the module docstring."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"


class LicenceDeliveryIntent(Base, TimestampMixin):
    """A durable statement that one exact artifact is owed to one destination.

    The unique constraint is on `(issuance_id, deployment_target_ref)`: the same
    artifact to the same destination is ONE intent, so a repeated hand-off
    returns the existing row rather than minting a second correlation id for a
    delivery that already has one. Two ids for one obligation is how a duplicate
    acknowledgement becomes indistinguishable from a second delivery.
    """

    __tablename__ = "licence_delivery_intents"
    __table_args__ = (
        UniqueConstraint(
            "issuance_id",
            "deployment_target_ref",
            name="uq_licence_delivery_intent_artifact_destination",
        ),
    )

    #: The `delivery_intent_id` the contract carries.
    id: Mapped[UUID] = uuid_pk()

    #: Immutable artifact identity. The envelope itself is NEVER stored here —
    #: `dotmac-licensing` owns it, and a second copy is a second thing to keep
    #: byte-identical.
    issuance_id: Mapped[UUID] = mapped_column(SAUuid(), nullable=False)
    licence_id: Mapped[UUID] = mapped_column(SAUuid(), nullable=False)
    licence_version: Mapped[int] = mapped_column(Integer, nullable=False)
    artifact_digest: Mapped[str] = mapped_column(String(128), nullable=False)

    #: The Deployment Control target reference — the routing authority, resolved
    #: through `vendor_cp.deployment.adapter` at hand-off. A caller never
    #: supplies it as a string.
    deployment_target_ref: Mapped[str] = mapped_column(String(200), nullable=False)

    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=IntentStatus.OPEN.value
    )

    #: The Integrator's durable receipt identity, recorded when the intent is
    #: completed. It is the idempotency key for the acknowledgement: the same
    #: receipt replayed returns the same completion instead of a second one.
    integrator_receipt_ref: Mapped[str | None] = mapped_column(String(200))
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    #: What the DEPLOYMENT said, carried verbatim. Vendor does not decide it;
    #: `dotmac-licensing` owns the lifecycle consequence.
    applied_outcome: Mapped[str | None] = mapped_column(String(20))


__all__ = ["IntentStatus", "LicenceDeliveryIntent"]
