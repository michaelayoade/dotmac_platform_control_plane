"""Revocation state — PLATFORM catalog tables (migration v008).

- `LicenceRevocationEntry` — APPEND-ONLY. Revoking is a decision with a
  reason and an actor; it is never edited and never deleted. There is
  deliberately no "unrevoke" row type: see the cumulative rule below.
- `LicenceRevocationList` — an immutable published SNAPSHOT: the signed
  envelope, its digest, and a strictly increasing `list_version`. Deployments
  (connected and air-gapped) import exactly this artifact.

**The cumulative rule (ruled by Michael, 2026-08-02):** revoked licence ids are
permanently cumulative — every published snapshot must be a SUPERSET of the one
before it. Version monotonicity alone does not prevent un-revocation: a higher
version that silently omits an earlier id would restore access while looking
perfectly well-ordered to the receiver. Recovery from a mistaken revocation is
re-issuance under a NEW lineage, never quiet removal from the list.
"""

from __future__ import annotations

from uuid import UUID

import sqlalchemy as sa
from dotmac_kernel import Base, TimestampMixin, uuid_pk
from sqlalchemy import ForeignKey, Integer, String, UniqueConstraint, Uuid
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Mapped, mapped_column

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


class LicenceRevocationEntry(Base, TimestampMixin):
    """One revoked lineage. Append-only; unique per licence so revoking twice
    is idempotent rather than duplicating the fact."""

    __tablename__ = "licence_revocation_entries"
    __table_args__ = (
        UniqueConstraint("licence_id", name="uq_licence_revocation_licence"),
    )

    id: Mapped[UUID] = uuid_pk()
    licence_id: Mapped[UUID] = mapped_column(
        Uuid(), ForeignKey("licences.id"), nullable=False
    )
    reason: Mapped[str] = mapped_column(String(200), nullable=False)
    revoked_by_admin_id: Mapped[UUID | None] = mapped_column(Uuid(), nullable=True)


class LicenceRevocationList(Base, TimestampMixin):
    """An immutable published snapshot of the full revoked set."""

    __tablename__ = "licence_revocation_lists"
    __table_args__ = (
        UniqueConstraint("list_version", name="uq_licence_revocation_list_version"),
    )

    id: Mapped[UUID] = uuid_pk()
    list_version: Mapped[int] = mapped_column(Integer, nullable=False)
    # `sha256:<hex>` of the signed payload bytes.
    digest: Mapped[str] = mapped_column(String(128), nullable=False)
    key_id: Mapped[str] = mapped_column(String(120), nullable=False)
    entry_count: Mapped[int] = mapped_column(Integer, nullable=False)
    # The signed envelope, verbatim — what deployments import.
    envelope: Mapped[dict[str, object]] = mapped_column(_JSON, nullable=False)


__all__ = ["LicenceRevocationEntry", "LicenceRevocationList"]
