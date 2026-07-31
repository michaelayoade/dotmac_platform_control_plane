"""Vendor lineage — create `contracts` + `contract_lines` platform catalog tables.

Extends the vendor lineage (child of `v003_approval_policies`). Both are PLATFORM
catalog tables (no `tenant_id`, no RLS): GRANTed to `platform_api`/`app_admin`,
REVOKEd from `app_user`. `contract_lines.offer_version_id` FKs the immutable
`offer_versions` (v002); the frozen unit price is copied onto the line at submit.

Revision ID: v004_contracts
Revises: v003_approval_policies
Create Date: 2026-07-31
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "v004_contracts"
down_revision = "v003_approval_policies"
branch_labels = None
depends_on = None

_CONTRACTS = "contracts"
_LINES = "contract_lines"


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
        _CONTRACTS,
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column("customer_ref", sa.String(length=200), nullable=False),
        sa.Column("legal_entity", sa.String(length=200), nullable=False),
        sa.Column("currency_code", sa.String(length=3), nullable=False),
        sa.Column("term_start", sa.Date(), nullable=False),
        sa.Column("term_end", sa.Date(), nullable=False),
        sa.Column(
            "status",
            sa.String(length=20),
            nullable=False,
            server_default=sa.text("'draft'"),
        ),
        sa.Column(
            "activation_rule",
            sa.String(length=60),
            nullable=False,
            server_default=sa.text("'manual_confirmation'"),
        ),
        sa.Column("content_hash", sa.String(length=128), nullable=True),
        sa.Column("approval_policy_code", sa.String(length=120), nullable=True),
        sa.Column("approval_policy_version", sa.Integer(), nullable=True),
        sa.Column("submitter_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("superseded_by_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("last_reason", sa.String(length=500), nullable=True),
        *_ts_cols(),
    )
    op.create_index("ix_contracts_status", _CONTRACTS, ["status"])
    op.create_index("ix_contracts_customer_ref", _CONTRACTS, ["customer_ref"])
    _grants(_CONTRACTS)

    op.create_table(
        _LINES,
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column(
            "contract_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("contracts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "offer_version_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("offer_versions.id"),
            nullable=False,
        ),
        sa.Column("offer_code", sa.String(length=120), nullable=False),
        sa.Column("offer_version", sa.Integer(), nullable=False),
        sa.Column("capability_code", sa.String(length=120), nullable=False),
        sa.Column(
            "quantity", sa.Integer(), nullable=False, server_default=sa.text("1")
        ),
        sa.Column("unit_amount", sa.String(length=40), nullable=True),
        sa.Column("unit_currency_code", sa.String(length=3), nullable=True),
        *_ts_cols(),
    )
    op.create_index("ix_contract_lines_contract_id", _LINES, ["contract_id"])
    _grants(_LINES)


def downgrade() -> None:
    op.drop_table(_LINES)
    op.drop_table(_CONTRACTS)
