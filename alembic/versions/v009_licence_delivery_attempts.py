"""Vendor lineage — append-only transport attempts for licence deliveries.

Extends the vendor lineage (child of `v008_licence_revocation`). One PLATFORM
catalog table (no `tenant_id`, no RLS): GRANTed to `platform_api`/`app_admin`,
REVOKEd from `app_user`.

Attempts are recorded because "no acknowledgement" is ambiguous without them:
never sent, and sent ten times but never acknowledged, are different faults
needing different operator responses. `(delivery_id, attempt_no)` is unique, so
a replay pass cannot double-count an attempt.

Revision ID: v009_delivery_attempts
Revises: v008_licence_revocation
Create Date: 2026-08-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "v009_delivery_attempts"
down_revision = "v008_licence_revocation"
branch_labels = None
depends_on = None

_ATTEMPTS = "licence_delivery_attempts"


def upgrade() -> None:
    op.create_table(
        _ATTEMPTS,
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column(
            "delivery_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("licence_deliveries.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("attempt_no", sa.Integer(), nullable=False),
        sa.Column("transport", sa.String(length=40), nullable=False),
        sa.Column("outcome", sa.String(length=20), nullable=False),
        sa.Column("error", sa.String(length=500), nullable=True),
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
        sa.UniqueConstraint(
            "delivery_id", "attempt_no", name="uq_licence_delivery_attempt_no"
        ),
    )
    op.create_index(
        "ix_licence_delivery_attempts_delivery_id", _ATTEMPTS, ["delivery_id"]
    )
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {_ATTEMPTS} TO platform_api;")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {_ATTEMPTS} TO app_admin;")
    op.execute(f"REVOKE ALL ON {_ATTEMPTS} FROM app_user;")


def downgrade() -> None:
    op.drop_table(_ATTEMPTS)
