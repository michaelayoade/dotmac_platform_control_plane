"""Immutable platform records for artifact bundles, plans and approvals."""

from __future__ import annotations

from datetime import datetime
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


class DeploymentBundleManifestVersion(Base, TimestampMixin):
    """One write-once composition of exact component release evidence."""

    __tablename__ = "deployment_bundle_manifest_versions"
    __table_args__ = (
        UniqueConstraint(
            "profile_version_id",
            "bundle_code",
            "version",
            name="uq_deployment_bundle_profile_code_ver",
        ),
        UniqueConstraint(
            "profile_version_id",
            "content_hash",
            name="uq_deployment_bundle_profile_hash",
        ),
        CheckConstraint("version > 0", name="ck_deployment_bundle_version_positive"),
    )

    id: Mapped[UUID] = uuid_pk()
    profile_version_id: Mapped[UUID] = mapped_column(
        sa.Uuid(),
        ForeignKey("managed_service_profile_versions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    bundle_code: Mapped[str] = mapped_column(String(120), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    profile_content_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(_JSON, nullable=False)


class DeploymentPlan(Base, TimestampMixin):
    """One immutable deterministic DAG over exact desired and execution inputs."""

    __tablename__ = "deployment_plans"
    __table_args__ = (
        UniqueConstraint(
            "deployment_id", "revision", name="uq_deployment_plan_revision"
        ),
        CheckConstraint("revision > 0", name="ck_deployment_plan_revision_positive"),
    )

    id: Mapped[UUID] = uuid_pk()
    deployment_id: Mapped[UUID] = mapped_column(
        sa.Uuid(), ForeignKey("deployments.id", ondelete="RESTRICT"), nullable=False
    )
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    predecessor_plan_id: Mapped[UUID | None] = mapped_column(
        sa.Uuid(), ForeignKey("deployment_plans.id", ondelete="RESTRICT"), nullable=True
    )
    desired_state_version_id: Mapped[UUID] = mapped_column(
        sa.Uuid(),
        ForeignKey("deployment_desired_state_versions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    bundle_manifest_version_id: Mapped[UUID] = mapped_column(
        sa.Uuid(),
        ForeignKey("deployment_bundle_manifest_versions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    allocation_id: Mapped[UUID | None] = mapped_column(sa.Uuid(), nullable=True)
    plan_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(_JSON, nullable=False)


class DeploymentPlanApprovalRequest(Base, TimestampMixin):
    """Immutable binding from one current plan to the approvals authority."""

    __tablename__ = "deployment_plan_approval_requests"
    __table_args__ = (
        UniqueConstraint("plan_id", name="uq_deployment_plan_approval_request_plan"),
        UniqueConstraint(
            "approval_request_id",
            name="uq_deployment_plan_approval_request_authority",
        ),
    )

    id: Mapped[UUID] = uuid_pk()
    plan_id: Mapped[UUID] = mapped_column(
        sa.Uuid(),
        ForeignKey("deployment_plans.id", ondelete="RESTRICT"),
        nullable=False,
    )
    approval_request_id: Mapped[UUID] = mapped_column(sa.Uuid(), nullable=False)
    policy_code: Mapped[str] = mapped_column(String(120), nullable=False)
    policy_version: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False
    )
    request_binding_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(_JSON, nullable=False)


class DeploymentPlanApprovalGrant(Base, TimestampMixin):
    """Vendor's immutable evidence that the authority approved an exact plan."""

    __tablename__ = "deployment_plan_approval_grants"
    __table_args__ = (
        UniqueConstraint("plan_id", name="uq_deployment_plan_approval_grant_plan"),
        UniqueConstraint(
            "approval_request_binding_id",
            name="uq_deployment_plan_approval_grant_request",
        ),
    )

    id: Mapped[UUID] = uuid_pk()
    plan_id: Mapped[UUID] = mapped_column(
        sa.Uuid(),
        ForeignKey("deployment_plans.id", ondelete="RESTRICT"),
        nullable=False,
    )
    approval_request_binding_id: Mapped[UUID] = mapped_column(
        sa.Uuid(),
        ForeignKey("deployment_plan_approval_requests.id", ondelete="RESTRICT"),
        nullable=False,
    )
    approval_request_id: Mapped[UUID] = mapped_column(sa.Uuid(), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False
    )
    grant_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(_JSON, nullable=False)


class IntegratorCommandDispatch(Base, TimestampMixin):
    """Immutable Vendor-signed command identity used to authenticate receipts."""

    __tablename__ = "integrator_command_dispatches"
    __table_args__ = (
        ForeignKeyConstraint(
            ["deployment_id", "capability_instance_ref"],
            [
                "deployment_capability_instances.deployment_id",
                "deployment_capability_instances.capability_instance_ref",
            ],
            name="fk_integrator_dispatch_capability_instance",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("command_id", name="uq_integrator_command_dispatch_id"),
        UniqueConstraint(
            "envelope_digest", name="uq_integrator_command_dispatch_envelope"
        ),
        UniqueConstraint(
            "id",
            "plan_id",
            "deployment_id",
            "capability_instance_ref",
            "capability_binding_id",
            name="uq_integrator_dispatch_scope",
        ),
    )

    id: Mapped[UUID] = uuid_pk()
    plan_id: Mapped[UUID] = mapped_column(
        sa.Uuid(),
        ForeignKey("deployment_plans.id", ondelete="RESTRICT"),
        nullable=False,
    )
    deployment_id: Mapped[UUID] = mapped_column(
        sa.Uuid(), ForeignKey("deployments.id", ondelete="RESTRICT"), nullable=False
    )
    capability_instance_ref: Mapped[str] = mapped_column(String(200), nullable=False)
    capability_binding_id: Mapped[UUID] = mapped_column(sa.Uuid(), nullable=False)
    operation: Mapped[str] = mapped_column(String(20), nullable=False)
    command_id: Mapped[str] = mapped_column(String(240), nullable=False)
    request_body_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    envelope_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(_JSON, nullable=False)


class IntegratorExecutionReceipt(Base, TimestampMixin):
    """One verified immutable Integrator transport receipt and module projection."""

    __tablename__ = "integrator_execution_receipts"
    __table_args__ = (
        ForeignKeyConstraint(
            [
                "dispatch_id",
                "plan_id",
                "deployment_id",
                "capability_instance_ref",
                "capability_binding_id",
            ],
            [
                "integrator_command_dispatches.id",
                "integrator_command_dispatches.plan_id",
                "integrator_command_dispatches.deployment_id",
                "integrator_command_dispatches.capability_instance_ref",
                "integrator_command_dispatches.capability_binding_id",
            ],
            name="fk_integrator_receipt_dispatch_scope",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("receipt_digest", name="uq_integrator_receipt_digest"),
    )

    id: Mapped[UUID] = uuid_pk()
    dispatch_id: Mapped[UUID] = mapped_column(
        sa.Uuid(),
        nullable=False,
    )
    plan_id: Mapped[UUID] = mapped_column(
        sa.Uuid(),
        ForeignKey("deployment_plans.id", ondelete="RESTRICT"),
        nullable=False,
    )
    deployment_id: Mapped[UUID] = mapped_column(
        sa.Uuid(), ForeignKey("deployments.id", ondelete="RESTRICT"), nullable=False
    )
    capability_instance_ref: Mapped[str] = mapped_column(String(200), nullable=False)
    capability_binding_id: Mapped[UUID] = mapped_column(sa.Uuid(), nullable=False)
    operation: Mapped[str] = mapped_column(String(20), nullable=False)
    command_id: Mapped[str] = mapped_column(String(240), nullable=False)
    request_body_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    receipt_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    outcome: Mapped[str] = mapped_column(String(40), nullable=False)
    operation_id: Mapped[UUID | None] = mapped_column(sa.Uuid(), nullable=True)
    latest_module_receipt_sequence: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    latest_module_receipt_hash: Mapped[str | None] = mapped_column(
        String(71), nullable=True
    )
    module_plan_receipt_hash: Mapped[str | None] = mapped_column(
        String(71), nullable=True
    )
    occurred_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False
    )
    document: Mapped[dict[str, Any]] = mapped_column(_JSON, nullable=False)


_IMMUTABLE_MODELS = (
    DeploymentBundleManifestVersion,
    DeploymentPlan,
    DeploymentPlanApprovalRequest,
    DeploymentPlanApprovalGrant,
    IntegratorCommandDispatch,
    IntegratorExecutionReceipt,
)


def _refuse_update(
    _mapper: Mapper[object], _connection: sa.Connection, target: object
) -> None:
    raise ConflictError(f"{type(target).__name__} is immutable")


def _refuse_delete(
    _mapper: Mapper[object], _connection: sa.Connection, target: object
) -> None:
    raise ConflictError(f"{type(target).__name__} is immutable")


for _model in _IMMUTABLE_MODELS:
    event.listen(_model, "before_update", _refuse_update)
    event.listen(_model, "before_delete", _refuse_delete)


__all__ = [
    "DeploymentBundleManifestVersion",
    "DeploymentPlan",
    "DeploymentPlanApprovalGrant",
    "DeploymentPlanApprovalRequest",
    "IntegratorCommandDispatch",
    "IntegratorExecutionReceipt",
]
