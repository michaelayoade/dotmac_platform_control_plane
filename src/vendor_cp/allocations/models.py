"""Persisted state for staged allocations — PLATFORM catalog tables.

An `Allocation` is the vendor CP's IMMUTABLE projection of *what a customer is
entitled to*, derived from an activated contract's lines. It is NOT a product WS2
grant: the vendor control plane never writes `tenant_entitlement_grants`. The
staged allocation is later delivered as a signed/versioned envelope (WS8/C4,
design-only); the product data plane verifies it, writes its OWN local grant, and
acknowledges the version/digest.

Platform catalog (no `tenant_id`, no RLS; GRANTed to `platform_api`/`app_admin`,
REVOKEd from `app_user`; vendor migration v005). `(contract_id, content_hash)` is
unique — one immutable allocation per activated contract version; re-delivery of
the same activation is a no-op.

Import-safe: touches only `Base.metadata`, never the engine (deny-case D1).
"""

from __future__ import annotations

from enum import Enum
from uuid import UUID

from dotmac_kernel import Base, TimestampMixin, uuid_pk
from sqlalchemy import ForeignKey, Integer, String, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship


class AllocationStatus(str, Enum):
    """`staged` — derived + frozen, awaiting signed delivery (WS8). Delivery/ack
    states belong to the WS8 slice, not here."""

    STAGED = "staged"


class Allocation(Base, TimestampMixin):
    """An immutable projection of an activated contract version's entitlement."""

    __tablename__ = "allocations"
    __table_args__ = (
        UniqueConstraint(
            "contract_id", "content_hash", name="uq_allocations_contract_content"
        ),
    )

    id: Mapped[UUID] = uuid_pk()
    contract_id: Mapped[UUID] = mapped_column(
        Uuid(), ForeignKey("contracts.id"), nullable=False
    )
    customer_ref: Mapped[str] = mapped_column(String(200), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=AllocationStatus.STAGED.value
    )
    # Provenance: the platform outbox event id that produced this allocation.
    source_event_id: Mapped[str] = mapped_column(String(200), nullable=False)

    entries: Mapped[list[AllocationEntry]] = relationship(
        "AllocationEntry",
        back_populates="allocation",
        cascade="all, delete-orphan",
        order_by="AllocationEntry.capability_code",
    )


class AllocationEntry(Base, TimestampMixin):
    """One entitled capability + quantity in a staged allocation."""

    __tablename__ = "allocation_entries"

    id: Mapped[UUID] = uuid_pk()
    allocation_id: Mapped[UUID] = mapped_column(
        Uuid(), ForeignKey("allocations.id", ondelete="CASCADE"), nullable=False
    )
    capability_code: Mapped[str] = mapped_column(String(120), nullable=False)
    quantity: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    allocation: Mapped[Allocation] = relationship(
        "Allocation", back_populates="entries"
    )


__all__ = ["AllocationStatus", "Allocation", "AllocationEntry"]
