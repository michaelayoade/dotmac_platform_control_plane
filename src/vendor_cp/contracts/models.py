"""Persisted state for commercial contracts — PLATFORM catalog tables.

A contract is a platform-level record the vendor owns across all its customers, so
these follow the platform-catalog pattern (no `tenant_id`, no RLS; GRANTed to
`platform_api`/`app_admin`, REVOKEd from `app_user`; vendor migration v004).

- `Contract` — the contract header + its lifecycle `status`. `content_hash` is the
  frozen priced snapshot's digest, set at submit and used to bind approvals to the
  exact version (a later change invalidates prior approvals). `customer_ref` is an
  opaque customer/deployment identifier used as the event correlation key — it is
  NOT a tenant FK (contract events are platform-scoped, tenant-free).
- `ContractLine` — one line pinning an immutable `OfferVersion`. At submit its
  unit price is FROZEN (copied from the pinned offer version) so a later offer
  change cannot mutate a submitted contract.

Import-safe: touches only `Base.metadata`, never the engine (deny-case D1).
"""

from __future__ import annotations

from datetime import date
from enum import Enum
from uuid import UUID

import sqlalchemy as sa
from dotmac_kernel import Base, TimestampMixin, uuid_pk
from sqlalchemy import Date, ForeignKey, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship


class ContractStatus(str, Enum):
    """The commercial-contract lifecycle. Commercial approval (`APPROVED`) and
    operational activation (`ACTIVE`) are DIFFERENT decisions / states."""

    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    TERMINATED = "terminated"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class Contract(Base, TimestampMixin):
    """A commercial contract header + lifecycle state."""

    __tablename__ = "contracts"

    id: Mapped[UUID] = uuid_pk()
    customer_ref: Mapped[str] = mapped_column(String(200), nullable=False)
    legal_entity: Mapped[str] = mapped_column(String(200), nullable=False)
    currency_code: Mapped[str] = mapped_column(String(3), nullable=False)
    term_start: Mapped[date] = mapped_column(Date, nullable=False)
    term_end: Mapped[date] = mapped_column(Date, nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=ContractStatus.DRAFT.value
    )
    # The rule that governs approved -> active (countersignature date / manual
    # confirmation / first-deployment). A stable code, never a plan/mode string.
    activation_rule: Mapped[str] = mapped_column(
        String(60), nullable=False, default="manual_confirmation"
    )
    # Frozen priced-snapshot digest (set at submit); approvals bind to it.
    content_hash: Mapped[str | None] = mapped_column(String(128))
    # The approval policy this contract is approved under (recorded at submit).
    approval_policy_code: Mapped[str | None] = mapped_column(String(120))
    approval_policy_version: Mapped[int | None] = mapped_column(Integer)
    submitter_id: Mapped[UUID | None] = mapped_column(Uuid())
    activated_at: Mapped[object | None] = mapped_column(sa.DateTime(timezone=True))
    # Reserved for amendment/supersession (a later slice); unset here.
    superseded_by_id: Mapped[UUID | None] = mapped_column(Uuid())
    last_reason: Mapped[str | None] = mapped_column(String(500))

    lines: Mapped[list[ContractLine]] = relationship(
        "ContractLine",
        back_populates="contract",
        cascade="all, delete-orphan",
        order_by="ContractLine.created_at",
    )


class ContractLine(Base, TimestampMixin):
    """One contract line pinning an immutable offer version. Its unit price is
    frozen (copied from the pinned offer version) at submit."""

    __tablename__ = "contract_lines"

    id: Mapped[UUID] = uuid_pk()
    contract_id: Mapped[UUID] = mapped_column(
        Uuid(), ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False
    )
    offer_version_id: Mapped[UUID] = mapped_column(
        Uuid(), ForeignKey("offer_versions.id"), nullable=False
    )
    offer_code: Mapped[str] = mapped_column(String(120), nullable=False)
    offer_version: Mapped[int] = mapped_column(Integer, nullable=False)
    capability_code: Mapped[str] = mapped_column(String(120), nullable=False)
    quantity: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    # Frozen unit price snapshot — NULL until submit, then immutable.
    unit_amount: Mapped[str | None] = mapped_column(String(40))
    unit_currency_code: Mapped[str | None] = mapped_column(String(3))

    contract: Mapped[Contract] = relationship("Contract", back_populates="lines")


__all__ = ["ContractStatus", "Contract", "ContractLine"]
