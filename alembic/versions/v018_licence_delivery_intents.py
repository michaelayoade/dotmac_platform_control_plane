"""The durable delivery intent — Vendor's half of the ADR-0010 hand-off.

Gate 2a. One table, platform-plane like every other Vendor table: no
`tenant_id`, no RLS, GRANTed to `platform_api`/`app_admin` and REVOKEd from
`app_user`, which is what the isolation is on this plane.

## Why a new table in an estate ADR-0010 is retiring

The five delivery/evidence tables retire because they are a TRANSPORT ledger
Vendor should not own. This is not one. It holds the correlation an
acknowledgement completes — four facts recorded at hand-off — and it is the
surface that SURVIVES the cutover, alongside the immutable artifact read. Adding
it is the replacement landing, not the estate growing.

Nothing here counts attempts, holds a lease, records a checkpoint or names a
connection. Those are `dotmac-integration`'s (ADR-0024, hard rule 28), and
rebuilding one here under a newer name is the specific mistake this table's
shape is designed to make obvious.

Revision ID: v018_licence_delivery_intents
Revises: v017_deployment_target_authority
Create Date: 2026-08-22
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "v018_licence_delivery_intents"
down_revision = "v017_deployment_target_authority"
branch_labels = None
depends_on = None

_TABLE = "public.licence_delivery_intents"


def upgrade() -> None:
    op.create_table(
        "licence_delivery_intents",
        sa.Column(
            "id",
            sa.Uuid(),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("issuance_id", sa.Uuid(), nullable=False),
        sa.Column("licence_id", sa.Uuid(), nullable=False),
        sa.Column("licence_version", sa.Integer(), nullable=False),
        sa.Column("artifact_digest", sa.String(length=128), nullable=False),
        sa.Column("deployment_target_ref", sa.String(length=200), nullable=False),
        sa.Column(
            "status", sa.String(length=20), nullable=False, server_default="open"
        ),
        sa.Column("integrator_receipt_ref", sa.String(length=200), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("applied_outcome", sa.String(length=20), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        # One artifact to one destination is ONE obligation. Two correlation ids
        # for one delivery is how a duplicate acknowledgement stops being
        # distinguishable from a second delivery.
        sa.UniqueConstraint(
            "issuance_id",
            "deployment_target_ref",
            name="uq_licence_delivery_intent_artifact_destination",
        ),
        # Two states, and the absent third is deliberate: "connector accepted"
        # is the Integrator's, and it must stay distinguishable from "the
        # deployment applied it and said so with a signature".
        sa.CheckConstraint(
            "status IN ('open', 'acknowledged')",
            name="ck_licence_delivery_intent_status",
        ),
        # A completion carries its receipt and its time, or it is not one.
        sa.CheckConstraint(
            "(status = 'open' AND integrator_receipt_ref IS NULL "
            "AND acknowledged_at IS NULL) OR (status = 'acknowledged' "
            "AND integrator_receipt_ref IS NOT NULL "
            "AND acknowledged_at IS NOT NULL)",
            name="ck_licence_delivery_intent_completion_is_complete",
        ),
    )
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {_TABLE} TO platform_api;")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {_TABLE} TO app_admin;")
    op.execute(f"REVOKE ALL ON {_TABLE} FROM app_user;")


def downgrade() -> None:
    op.drop_table("licence_delivery_intents")
