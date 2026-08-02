"""Vendor lineage — licence delivery, acknowledgement log, projection state.

Extends the vendor lineage (child of `v006_licences`). Three PLATFORM catalog
tables (no `tenant_id`, no RLS): GRANTed to `platform_api`/`app_admin`, REVOKEd
from `app_user`.

`licence_deliveries` is an immutable fact table (unique per
`(issuance_id, target_ref)` — at-least-once delivery re-stages the SAME fact);
`licence_ack_records` is an append-only log including quarantined
acknowledgements (evidence of a mis-issue/tamper attempt must survive);
`licence_delivery_states` is the derived `delivered`/`active` projection the
`EntitlementProjectionService` alone writes, one row per delivery.

Revision ID: v007_licence_delivery
Revises: v006_licences
Create Date: 2026-08-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "v007_licence_delivery"
down_revision = "v006_licences"
branch_labels = None
depends_on = None

_DELIVERIES = "licence_deliveries"
_STATES = "licence_delivery_states"
_ACKS = "licence_ack_records"


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
        _DELIVERIES,
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column(
            "issuance_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("licence_issuances.id"),
            nullable=False,
        ),
        sa.Column("target_ref", sa.String(length=200), nullable=False),
        *_ts_cols(),
        sa.UniqueConstraint(
            "issuance_id", "target_ref", name="uq_licence_delivery_issuance_target"
        ),
    )
    op.create_index("ix_licence_deliveries_issuance_id", _DELIVERIES, ["issuance_id"])
    _grants(_DELIVERIES)

    op.create_table(
        _STATES,
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column(
            "delivery_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("licence_deliveries.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "state",
            sa.String(length=20),
            nullable=False,
            server_default=sa.text("'delivered'"),
        ),
        sa.Column("activating_ack_id", postgresql.UUID(as_uuid=True), nullable=True),
        *_ts_cols(),
        sa.UniqueConstraint("delivery_id", name="uq_licence_delivery_state_delivery"),
    )
    _grants(_STATES)

    op.create_table(
        _ACKS,
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column(
            "delivery_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("licence_deliveries.id"),
            nullable=True,
        ),
        sa.Column("licence_id", sa.String(length=200), nullable=False),
        sa.Column("licence_version", sa.Integer(), nullable=False),
        sa.Column("digest", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("reason", sa.String(length=120), nullable=True),
        sa.Column("deployment_id", sa.String(length=200), nullable=True),
        sa.Column("disposition", sa.String(length=40), nullable=False),
        *_ts_cols(),
    )
    op.create_index("ix_licence_ack_records_licence_id", _ACKS, ["licence_id"])
    _grants(_ACKS)


def downgrade() -> None:
    op.drop_table(_ACKS)
    op.drop_table(_STATES)
    op.drop_table(_DELIVERIES)
