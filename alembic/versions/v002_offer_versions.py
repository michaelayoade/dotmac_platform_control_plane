"""Vendor lineage — create the `offer_versions` platform catalog table.

Extends the vendor lineage (child of `v001_vendor_accounts`). `offer_versions` is
a PLATFORM catalog table (no `tenant_id`, no RLS): GRANTed to
`platform_api`/`app_admin`, REVOKEd from `app_user`. Rows are immutable —
`(offer_code, version)` is unique and never updated (enforced by the service).

Revision ID: v002_offer_versions
Revises: v001_vendor_accounts
Create Date: 2026-07-31
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "v002_offer_versions"
down_revision = "v001_vendor_accounts"
branch_labels = None
depends_on = None

_TABLE = "offer_versions"


def upgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column("offer_code", sa.String(length=120), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("amount", sa.String(length=40), nullable=False),
        sa.Column("currency_code", sa.String(length=3), nullable=False),
        sa.Column(
            "capability_codes",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
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
        sa.UniqueConstraint("offer_code", "version", name="uq_offer_versions_code_ver"),
    )

    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {_TABLE} TO platform_api;")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {_TABLE} TO app_admin;")
    op.execute(f"REVOKE ALL ON {_TABLE} FROM app_user;")


def downgrade() -> None:
    op.drop_table(_TABLE)
