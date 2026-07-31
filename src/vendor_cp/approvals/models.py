"""Persisted state for approval policies + approvals — PLATFORM catalog tables.

Both follow the vendor platform-catalog pattern (no `tenant_id`, no RLS; GRANTed
to `platform_api`/`app_admin`, REVOKEd from `app_user`; vendor migration v003).

- `ApprovalPolicy` — an IMMUTABLE policy version: how many DISTINCT approvers a
  decision needs (`quorum`) and whether the submitter may self-approve.
  `(policy_code, version)` is unique and never updated.
- `ApprovalRecord` — one approver's approval of a specific `(subject,
  content_hash)` under a policy version. The unique constraint makes approvals
  distinct-by-construction (an approver approves a given content at most once).

Import-safe: touches only `Base.metadata`, never the engine (deny-case D1).
"""

from __future__ import annotations

from uuid import UUID

from dotmac_kernel import Base, TimestampMixin, uuid_pk
from sqlalchemy import Boolean, Integer, String, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column


class ApprovalPolicy(Base, TimestampMixin):
    """An immutable approval-policy version."""

    __tablename__ = "approval_policies"
    __table_args__ = (
        UniqueConstraint(
            "policy_code", "version", name="uq_approval_policies_code_ver"
        ),
    )

    id: Mapped[UUID] = uuid_pk()
    policy_code: Mapped[str] = mapped_column(String(120), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    quorum: Mapped[int] = mapped_column(Integer, nullable=False)
    allow_self_approval: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )


class ApprovalRecord(Base, TimestampMixin):
    """One approver's approval of a `(subject, content_hash)` under a policy
    version. Distinct-by-construction via the unique constraint."""

    __tablename__ = "approval_records"
    __table_args__ = (
        UniqueConstraint(
            "policy_code",
            "policy_version",
            "subject_type",
            "subject_id",
            "content_hash",
            "approver_id",
            name="uq_approval_records_unique",
        ),
    )

    id: Mapped[UUID] = uuid_pk()
    policy_code: Mapped[str] = mapped_column(String(120), nullable=False)
    policy_version: Mapped[int] = mapped_column(Integer, nullable=False)
    subject_type: Mapped[str] = mapped_column(String(120), nullable=False)
    subject_id: Mapped[str] = mapped_column(String(200), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    approver_id: Mapped[UUID] = mapped_column(Uuid(), nullable=False)


__all__ = ["ApprovalPolicy", "ApprovalRecord"]
