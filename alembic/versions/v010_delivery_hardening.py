"""Vendor lineage — deployment registry, parked deliveries, safe error codes.

Extends the vendor lineage (child of `v009_delivery_attempts`), applying the
2026-08-02 delivery-pipeline review:

- `deployments` — the authoritative destination registry. A delivery resolves
  through it, so a caller can never name an arbitrary destination; an issued
  licence only goes somewhere the vendor deliberately registered.
- `licence_deliveries.deployment_id` — FK to that registry (nullable only so
  the column can be added; the service requires resolution).
- `licence_delivery_attempts.error_code` REPLACES the free-text `error` column.
  Transport exception text routinely carries URLs, response bodies, headers,
  and bearer tokens, and this table is read by dashboards and support staff, so
  only a stable closed-vocabulary code is persisted. The old column is DROPPED
  rather than migrated: its contents are exactly what must not be retained.

Revision ID: v010_delivery_hardening
Revises: v009_delivery_attempts
Create Date: 2026-08-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "v010_delivery_hardening"
down_revision = "v009_delivery_attempts"
branch_labels = None
depends_on = None

_DEPLOYMENTS = "deployments"


def _grants(table: str) -> None:
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO platform_api;")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO app_admin;")
    op.execute(f"REVOKE ALL ON {table} FROM app_user;")


def upgrade() -> None:
    op.create_table(
        _DEPLOYMENTS,
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column("deployment_ref", sa.String(length=200), nullable=False),
        sa.Column("customer_ref", sa.String(length=200), nullable=False),
        sa.Column("connection_ref", sa.String(length=200), nullable=True),
        sa.Column(
            "status",
            sa.String(length=20),
            nullable=False,
            server_default=sa.text("'active'"),
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
        sa.UniqueConstraint("deployment_ref", name="uq_deployments_ref"),
    )
    _grants(_DEPLOYMENTS)

    op.add_column(
        "licence_deliveries",
        sa.Column("deployment_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_licence_delivery_deployment",
        "licence_deliveries",
        _DEPLOYMENTS,
        ["deployment_id"],
        ["id"],
    )

    # Drop the free-text error column rather than copying it forward: its
    # contents are precisely what must not be retained.
    op.drop_column("licence_delivery_attempts", "error")
    op.add_column(
        "licence_delivery_attempts",
        sa.Column("error_code", sa.String(length=60), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("licence_delivery_attempts", "error_code")
    op.add_column(
        "licence_delivery_attempts",
        sa.Column("error", sa.String(length=500), nullable=True),
    )
    op.drop_constraint(
        "fk_licence_delivery_deployment", "licence_deliveries", type_="foreignkey"
    )
    op.drop_column("licence_deliveries", "deployment_id")
    op.drop_table(_DEPLOYMENTS)
