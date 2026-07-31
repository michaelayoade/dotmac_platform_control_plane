"""Persisted state for vendor accounts — a PLATFORM catalog table.

`VendorAccount` mirrors the kernel's platform-catalog pattern (`PlatformAdmin`,
`platform_audit_events`): NO `tenant_id` and NO RLS, because a vendor account has
no tenant context — it is owned by the control plane itself. In a real
deployment the table is GRANTed to `platform_api`/`app_admin` and REVOKEd from
`app_user` by a migration (a vendor-lineage migration is a follow-up; the
testing kit's `create_all` builds it for unit tests, where SQLite has no RLS).

Import-safe: touches only `Base.metadata`, never the engine (deny-case D1).
"""

from __future__ import annotations

from uuid import UUID

from dotmac_kernel import Base, TimestampMixin, uuid_pk
from sqlalchemy import String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column


class AccountStatus:
    """Vendor-account lifecycle vocabulary (a plain string enum kept typed at the
    service boundary via `AccountStatusValue`)."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    CLOSED = "closed"


class VendorAccount(Base, TimestampMixin):
    """A vendor-owned account (platform-level; no tenant). `external_ref` is the
    caller's stable business identifier and is unique across the control plane."""

    __tablename__ = "vendor_accounts"
    __table_args__ = (
        UniqueConstraint("external_ref", name="uq_vendor_accounts_external_ref"),
    )

    id: Mapped[UUID] = uuid_pk()
    external_ref: Mapped[str] = mapped_column(String(200), nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=AccountStatus.ACTIVE
    )


__all__ = ["AccountStatus", "VendorAccount"]
