"""Vendor lineage — create `allocations` + `allocation_entries` platform catalog.

Extends the vendor lineage (child of `v004_contracts`). Both are PLATFORM catalog
tables (no `tenant_id`, no RLS): GRANTed to `platform_api`/`app_admin`, REVOKEd from
`app_user`. `allocations.contract_id` FKs `contracts` (v004);
`(contract_id, content_hash)` is unique — one immutable allocation per activated
contract version.

Revision ID: v005_allocations
Revises: v004_contracts
Create Date: 2026-07-31
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "v005_allocations"
down_revision = "v004_contracts"
branch_labels = None
depends_on = None

_ALLOCS = "allocations"
_ENTRIES = "allocation_entries"


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
        _ALLOCS,
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column(
            "contract_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("contracts.id"),
            nullable=False,
        ),
        sa.Column("customer_ref", sa.String(length=200), nullable=False),
        sa.Column("content_hash", sa.String(length=128), nullable=False),
        sa.Column(
            "status",
            sa.String(length=20),
            nullable=False,
            server_default=sa.text("'staged'"),
        ),
        sa.Column("source_event_id", sa.String(length=200), nullable=False),
        *_ts_cols(),
        sa.UniqueConstraint(
            "contract_id", "content_hash", name="uq_allocations_contract_content"
        ),
    )
    op.create_index("ix_allocations_contract_id", _ALLOCS, ["contract_id"])
    _grants(_ALLOCS)

    op.create_table(
        _ENTRIES,
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column(
            "allocation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("allocations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("capability_code", sa.String(length=120), nullable=False),
        sa.Column(
            "quantity", sa.Integer(), nullable=False, server_default=sa.text("1")
        ),
        *_ts_cols(),
    )
    op.create_index("ix_allocation_entries_allocation_id", _ENTRIES, ["allocation_id"])
    _grants(_ENTRIES)


def downgrade() -> None:
    op.drop_table(_ENTRIES)
    op.drop_table(_ALLOCS)
