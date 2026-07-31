"""Persisted state for vendor accounts — TENANT-scoped (option C spike).

Contrast with option A's platform-catalog table: here every account carries a
`tenant_id` (NOT NULL, FK to `tenants`), the uniqueness of `external_ref` is
composite `(tenant_id, external_ref)`, and in a real deployment the table is
RLS-enabled + FORCEd with a tenant-isolation policy (kernel tenant-table rule).
This is the shape that FORCES a tenant to exist for a resource that has none —
the reason option A was chosen (`docs/spikes/slice3-accounts-tenant.md`).

Import-safe: touches only `Base.metadata`, never the engine (deny-case D1).
"""

from __future__ import annotations

from uuid import UUID

from dotmac_kernel import Base, TimestampMixin, uuid_pk
from sqlalchemy import ForeignKey, String, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column


class AccountStatus:
    """Vendor-account lifecycle vocabulary."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    CLOSED = "closed"


class VendorAccount(Base, TimestampMixin):
    """A vendor account scoped to a tenant. `external_ref` is unique WITHIN a
    tenant (composite), and every row is RLS-isolated by `tenant_id`."""

    __tablename__ = "vendor_accounts"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "external_ref", name="uq_vendor_accounts_tenant_external_ref"
        ),
    )

    id: Mapped[UUID] = uuid_pk()
    tenant_id: Mapped[UUID] = mapped_column(
        Uuid(),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    external_ref: Mapped[str] = mapped_column(String(200), nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=AccountStatus.ACTIVE
    )


__all__ = ["AccountStatus", "VendorAccount"]
