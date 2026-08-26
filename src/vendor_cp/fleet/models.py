"""Platform-owned fleet intent and immutable desired-state snapshots.

These tables deliberately contain no provider installation or connector
binding identifiers.  Vendor CP decides *what* a customer deployment should
be; the independently deployed Integrator later selects an implementation for
the exact capability and endpoint versions recorded here.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

import sqlalchemy as sa
from dotmac_kernel import Base, ConflictError, TimestampMixin, uuid_pk
from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    String,
    UniqueConstraint,
    event,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Mapped, Mapper, mapped_column

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


class DeploymentTarget(Base, TimestampMixin):
    """An account-owned destination/failure-domain label.

    A target describes business ownership and topology only.  It is not a
    cloud account, host credential, provider object or remote database.
    """

    __tablename__ = "deployment_targets"
    __table_args__ = (
        UniqueConstraint(
            "account_id", "target_ref", name="uq_deployment_targets_account_ref"
        ),
        # A commercial customer reference belongs to exactly one account-owned
        # target across the control plane.  NULL remains available for internal
        # laboratories that have no commercial contract identity.
        UniqueConstraint("customer_ref", name="uq_deployment_targets_customer_ref"),
        # Supports the composite ownership FK on Deployment.  An FK to id alone
        # would prove the target exists but not that it belongs to account_id.
        UniqueConstraint("account_id", "id", name="uq_deployment_targets_account_id"),
    )

    id: Mapped[UUID] = uuid_pk()
    account_id: Mapped[UUID] = mapped_column(
        sa.Uuid(), ForeignKey("vendor_accounts.id", ondelete="RESTRICT"), nullable=False
    )
    target_ref: Mapped[str] = mapped_column(String(200), nullable=False)
    customer_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    region_code: Mapped[str] = mapped_column(String(80), nullable=False)


class Deployment(Base, TimestampMixin):
    """The authoritative account-scoped deployment aggregate."""

    __tablename__ = "deployments"
    __table_args__ = (
        ForeignKeyConstraint(
            ["account_id", "target_id"],
            ["deployment_targets.account_id", "deployment_targets.id"],
            name="fk_deployments_target_account_owner",
            ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "account_id", "deployment_ref", name="uq_deployments_account_ref"
        ),
        UniqueConstraint(
            "target_id",
            "commercial_product_code",
            name="uq_deployments_target_product",
        ),
        CheckConstraint(
            "((contract_id IS NOT NULL AND internal_source_code IS NULL) OR "
            "(contract_id IS NULL AND internal_source_code IS NOT NULL))",
            name="ck_deployments_exactly_one_source",
        ),
    )

    id: Mapped[UUID] = uuid_pk()
    account_id: Mapped[UUID] = mapped_column(sa.Uuid(), nullable=False)
    target_id: Mapped[UUID] = mapped_column(sa.Uuid(), nullable=False)
    deployment_ref: Mapped[str] = mapped_column(String(200), nullable=False)
    commercial_product_code: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default="intent_recorded"
    )
    contract_id: Mapped[UUID | None] = mapped_column(
        sa.Uuid(), ForeignKey("contracts.id", ondelete="RESTRICT"), nullable=True
    )
    internal_source_code: Mapped[str | None] = mapped_column(String(160), nullable=True)
    current_desired_state_revision: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1
    )


class DeploymentDesiredStateVersion(Base, TimestampMixin):
    """One immutable, content-addressed desired-state version.

    The profile digest binds the schema and catalogue input; the configuration
    digest binds the selected values; `desired_state_hash` binds those plus the
    deployment identity, selected components/capabilities/endpoints/checks and
    update authority.  No mutable provider selection can be smuggled into this
    source record.
    """

    __tablename__ = "deployment_desired_state_versions"
    __table_args__ = (
        UniqueConstraint(
            "deployment_id",
            "revision",
            name="uq_deployment_desired_state_revision",
        ),
        UniqueConstraint(
            "deployment_id",
            "desired_state_hash",
            name="uq_deployment_desired_state_hash",
        ),
        CheckConstraint(
            "revision > 0", name="ck_deployment_desired_state_revision_positive"
        ),
        CheckConstraint(
            "configuration_schema_version > 0",
            name="ck_deployment_configuration_schema_version_positive",
        ),
    )

    id: Mapped[UUID] = uuid_pk()
    deployment_id: Mapped[UUID] = mapped_column(
        sa.Uuid(), ForeignKey("deployments.id", ondelete="RESTRICT"), nullable=False
    )
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    predecessor_id: Mapped[UUID | None] = mapped_column(
        sa.Uuid(),
        ForeignKey("deployment_desired_state_versions.id", ondelete="RESTRICT"),
        nullable=True,
    )
    profile_version_id: Mapped[UUID] = mapped_column(
        sa.Uuid(),
        ForeignKey("managed_service_profile_versions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    profile_code: Mapped[str] = mapped_column(String(120), nullable=False)
    profile_version: Mapped[int] = mapped_column(Integer, nullable=False)
    profile_content_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    commercial_product_code: Mapped[str] = mapped_column(String(120), nullable=False)
    update_authority: Mapped[str] = mapped_column(String(30), nullable=False)
    selected_components: Mapped[list[str]] = mapped_column(_JSON, nullable=False)
    selected_capabilities: Mapped[list[dict[str, Any]]] = mapped_column(
        _JSON, nullable=False
    )
    selected_endpoints: Mapped[list[dict[str, Any]]] = mapped_column(
        _JSON, nullable=False
    )
    selected_verification_checks: Mapped[list[dict[str, Any]]] = mapped_column(
        _JSON, nullable=False
    )
    configuration_snapshot: Mapped[dict[str, Any]] = mapped_column(
        _JSON, nullable=False
    )
    configuration_snapshot_ref: Mapped[str] = mapped_column(String(200), nullable=False)
    configuration_schema_version: Mapped[int] = mapped_column(Integer, nullable=False)
    configuration_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    desired_state_hash: Mapped[str] = mapped_column(String(71), nullable=False)


@event.listens_for(DeploymentDesiredStateVersion, "before_update")
def _refuse_desired_state_update(
    _mapper: Mapper[DeploymentDesiredStateVersion],
    _connection: sa.Connection,
    target: DeploymentDesiredStateVersion,
) -> None:
    raise ConflictError(
        f"deployment desired state {target.deployment_id} "
        f"revision {target.revision} is immutable"
    )


@event.listens_for(DeploymentDesiredStateVersion, "before_delete")
def _refuse_desired_state_delete(
    _mapper: Mapper[DeploymentDesiredStateVersion],
    _connection: sa.Connection,
    target: DeploymentDesiredStateVersion,
) -> None:
    raise ConflictError(
        f"deployment desired state {target.deployment_id} "
        f"revision {target.revision} is immutable"
    )


__all__ = [
    "Deployment",
    "DeploymentDesiredStateVersion",
    "DeploymentTarget",
]
