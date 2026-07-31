"""Vendor lineage — create `approval_policies` + `approval_records`.

Extends the vendor lineage (child of `v002_offer_versions`). Both are PLATFORM
catalog tables (no `tenant_id`, no RLS): GRANTed to `platform_api`/`app_admin`,
REVOKEd from `app_user`.

Revision ID: v003_approval_policies
Revises: v002_offer_versions
Create Date: 2026-07-31
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "v003_approval_policies"
down_revision = "v002_offer_versions"
branch_labels = None
depends_on = None

_POLICIES = "approval_policies"
_RECORDS = "approval_records"


def _grants(table: str) -> None:
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO platform_api;")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO app_admin;")
    op.execute(f"REVOKE ALL ON {table} FROM app_user;")


def _ts_cols() -> list[sa.Column]:
    return [
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    ]


def upgrade() -> None:
    op.create_table(
        _POLICIES,
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column("policy_code", sa.String(length=120), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("quorum", sa.Integer(), nullable=False),
        sa.Column(
            "allow_self_approval",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        *_ts_cols(),
        sa.UniqueConstraint(
            "policy_code", "version", name="uq_approval_policies_code_ver"
        ),
    )
    _grants(_POLICIES)

    op.create_table(
        _RECORDS,
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column("policy_code", sa.String(length=120), nullable=False),
        sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column("subject_type", sa.String(length=120), nullable=False),
        sa.Column("subject_id", sa.String(length=200), nullable=False),
        sa.Column("content_hash", sa.String(length=128), nullable=False),
        sa.Column("approver_id", postgresql.UUID(as_uuid=True), nullable=False),
        *_ts_cols(),
        sa.UniqueConstraint(
            "policy_code",
            "policy_version",
            "subject_type",
            "subject_id",
            "content_hash",
            "approver_id",
            name="uq_approval_records_unique",
        ),
    )
    _grants(_RECORDS)


def downgrade() -> None:
    op.drop_table(_RECORDS)
    op.drop_table(_POLICIES)
