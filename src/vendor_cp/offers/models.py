"""Persisted state for offer versions — a PLATFORM catalog table (immutable rows).

Mirrors the vendor-account platform-catalog pattern (no `tenant_id`, no RLS,
GRANTed to `platform_api`/`app_admin`, REVOKEd from `app_user`). The price is
stored as an exact decimal string + ISO-4217 code and reconstructed as `Money`
(never float). `capability_codes` are the declared WS1 codes this offer grants.
Rows are write-once: `(product_code, offer_code, version)` is unique and never
updated. ``product_code`` is nullable only for rows predating vendor migration
v011; services refuse those rows until an operator supplies an evidence-backed
mapping.

Import-safe: touches only `Base.metadata`, never the engine (deny-case D1).
"""

from __future__ import annotations

from uuid import UUID

import sqlalchemy as sa
from dotmac_kernel import Base, TimestampMixin, uuid_pk
from sqlalchemy import Integer, String, UniqueConstraint
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Mapped, mapped_column

# JSONB on Postgres, generic JSON on SQLite (unit tests) — the kernel pattern.
_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


class OfferVersion(Base, TimestampMixin):
    """One immutable, priced version of an offer."""

    __tablename__ = "offer_versions"
    __table_args__ = (
        UniqueConstraint(
            "product_code",
            "offer_code",
            "version",
            name="uq_offer_versions_product_code_ver",
        ),
    )

    id: Mapped[UUID] = uuid_pk()
    product_code: Mapped[str | None] = mapped_column(String(120), nullable=True)
    offer_code: Mapped[str] = mapped_column(String(120), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    # Exact price: decimal string (already quantized to the currency) + ISO-4217.
    amount: Mapped[str] = mapped_column(String(40), nullable=False)
    currency_code: Mapped[str] = mapped_column(String(3), nullable=False)
    # Declared WS1 capability codes this offer grants.
    capability_codes: Mapped[list[str]] = mapped_column(
        _JSON, nullable=False, default=list
    )


__all__ = ["OfferVersion"]
