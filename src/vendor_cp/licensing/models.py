"""Persisted licence state — PLATFORM catalog tables (vendor migration v006).

Three tables, per `docs/design/licence-service.md`:

- `LicenceSigningKey` — the **public** half of the vendor's signing keys, with
  the rotation status distributed deployments verify against. There is
  deliberately **no private-key column**: custody is the signer provider's
  concern (ephemeral in-memory this phase; OpenBao-referenced later), so a
  database dump can never leak signing material — structurally, not by
  convention.
- `Licence` — the lineage: one per `(customer_ref, product)`. Its `id` IS the
  `licence_id` carried in every document of the lineage, and the receiver keys
  its replay/rollback guard on it.
- `LicenceIssuance` — one immutable issued version. The exact signed payload
  bytes, their digest, the signing `key_id`, and the envelope are frozen here;
  any change is a NEW version, never an in-place edit. Unique on
  `(licence_id, version)` (two issuances can never claim one version) and on
  `allocation_id` (one issued version per immutable staged allocation).

Platform catalog (no `tenant_id`, no RLS; GRANTed to `platform_api`/`app_admin`,
REVOKEd from `app_user`). Import-safe: touches only `Base.metadata`, never the
engine (deny-case D1).
"""

from __future__ import annotations

from enum import Enum
from uuid import UUID

import sqlalchemy as sa
from dotmac_kernel import Base, TimestampMixin, uuid_pk
from sqlalchemy import ForeignKey, Integer, String, UniqueConstraint, Uuid
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Mapped, mapped_column, relationship

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


class SigningKeyStatus(str, Enum):
    """Mirrors the kernel verifier's `KeyStatus`: `active` signs new documents
    and verifies; `retired` verifies only (rotation overlap for the installed
    base); `revoked` verifies nothing, even a cryptographically valid
    signature."""

    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


class IssuanceStatus(str, Enum):
    """`issued` — signed and frozen. Delivery/ack states belong to the
    projection slice, not here."""

    ISSUED = "issued"


class LicenceSigningKey(Base, TimestampMixin):
    """A signing key's PUBLIC material + rotation status. No private key."""

    __tablename__ = "licence_signing_keys"

    id: Mapped[UUID] = uuid_pk()
    key_id: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    public_key_b64: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=SigningKeyStatus.ACTIVE.value
    )


class Licence(Base, TimestampMixin):
    """A licence lineage — one per customer+product. `id` is the document's
    `licence_id`; versions of this lineage supersede one another."""

    __tablename__ = "licences"
    __table_args__ = (
        UniqueConstraint(
            "customer_ref", "product", name="uq_licences_customer_product"
        ),
    )

    id: Mapped[UUID] = uuid_pk()
    customer_ref: Mapped[str] = mapped_column(String(200), nullable=False)
    product: Mapped[str] = mapped_column(String(120), nullable=False)

    issuances: Mapped[list[LicenceIssuance]] = relationship(
        "LicenceIssuance",
        back_populates="licence",
        cascade="all, delete-orphan",
        order_by="LicenceIssuance.version",
    )


class LicenceIssuance(Base, TimestampMixin):
    """One immutable signed version of a lineage."""

    __tablename__ = "licence_issuances"
    __table_args__ = (
        UniqueConstraint("licence_id", "version", name="uq_licence_issuance_version"),
        UniqueConstraint("allocation_id", name="uq_licence_issuance_allocation"),
    )

    id: Mapped[UUID] = uuid_pk()
    licence_id: Mapped[UUID] = mapped_column(
        Uuid(), ForeignKey("licences.id", ondelete="CASCADE"), nullable=False
    )
    allocation_id: Mapped[UUID] = mapped_column(
        Uuid(), ForeignKey("allocations.id"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    # `sha256:<hex>` of the exact signed payload bytes — the identity the
    # acknowledgement is matched against.
    digest: Mapped[str] = mapped_column(String(128), nullable=False)
    key_id: Mapped[str] = mapped_column(String(120), nullable=False)
    # The signed envelope, verbatim — what delivery hands to the data plane.
    envelope: Mapped[dict[str, object]] = mapped_column(_JSON, nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=IssuanceStatus.ISSUED.value
    )

    licence: Mapped[Licence] = relationship("Licence", back_populates="issuances")


__all__ = [
    "SigningKeyStatus",
    "IssuanceStatus",
    "LicenceSigningKey",
    "Licence",
    "LicenceIssuance",
]
