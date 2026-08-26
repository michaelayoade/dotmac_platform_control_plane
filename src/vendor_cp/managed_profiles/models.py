"""Immutable platform-catalogue rows for managed-service profile versions."""

from __future__ import annotations

from uuid import UUID

import sqlalchemy as sa
from dotmac_kernel import Base, ConflictError, TimestampMixin, uuid_pk
from sqlalchemy import CheckConstraint, Integer, String, UniqueConstraint, event
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Mapped, Mapper, mapped_column

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


class ManagedServiceProfileVersion(Base, TimestampMixin):
    """One content-addressed, write-once commercial deployment contract.

    This is platform state: it has no tenant column and no RLS.  The migration
    owns database-role grants and the database-level immutability trigger; the
    ORM listeners below fail fast for application-side mistakes as well.
    """

    __tablename__ = "managed_service_profile_versions"
    __table_args__ = (
        UniqueConstraint(
            "commercial_product_code",
            "profile_code",
            "version",
            name="uq_managed_profile_product_code_ver",
        ),
        UniqueConstraint(
            "commercial_product_code",
            "content_hash",
            name="uq_managed_profile_product_hash",
        ),
        CheckConstraint("version > 0", name="ck_managed_profile_version_positive"),
        CheckConstraint(
            "schema_version > 0", name="ck_managed_profile_schema_version_positive"
        ),
    )

    id: Mapped[UUID] = uuid_pk()
    profile_code: Mapped[str] = mapped_column(String(120), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False)
    commercial_product_code: Mapped[str] = mapped_column(String(120), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    document: Mapped[dict[str, object]] = mapped_column(_JSON, nullable=False)


@event.listens_for(ManagedServiceProfileVersion, "before_update")
def _refuse_profile_update(
    _mapper: Mapper[ManagedServiceProfileVersion],
    _connection: sa.Connection,
    target: ManagedServiceProfileVersion,
) -> None:
    raise ConflictError(
        f"managed profile {target.commercial_product_code!r}/"
        f"{target.profile_code!r} v{target.version} is immutable"
    )


@event.listens_for(ManagedServiceProfileVersion, "before_delete")
def _refuse_profile_delete(
    _mapper: Mapper[ManagedServiceProfileVersion],
    _connection: sa.Connection,
    target: ManagedServiceProfileVersion,
) -> None:
    raise ConflictError(
        f"managed profile {target.commercial_product_code!r}/"
        f"{target.profile_code!r} v{target.version} is immutable"
    )


__all__ = ["ManagedServiceProfileVersion"]
