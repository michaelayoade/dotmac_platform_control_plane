"""Verified Integrator command and receipt evidence.

Both tables are append-only platform catalogues. Vendor records commands it
signed and receipts whose held Integrator key verified; no provider credential,
connector client or external write lives in this migration.

Revision ID: v017_integrator_evidence
Revises: v016_deterministic_plans
Create Date: 2026-08-17
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "v017_integrator_evidence"
down_revision = "v016_deterministic_plans"
branch_labels = None
depends_on = None

DISPATCH = "integrator_command_dispatches"
RECEIPT = "integrator_execution_receipts"
TABLES = (DISPATCH, RECEIPT)


def _uuid(
    name: str, *, primary_key: bool = False, nullable: bool = False
) -> sa.Column[object]:
    return sa.Column(
        name,
        postgresql.UUID(as_uuid=True),
        primary_key=primary_key,
        nullable=nullable,
    )


def _timestamps() -> tuple[sa.Column[object], sa.Column[object]]:
    return (
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
    )


def _grants(table: str) -> None:
    op.execute(f"GRANT SELECT, INSERT ON public.{table} TO platform_api;")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON public.{table} TO app_admin;")
    op.execute(f"REVOKE ALL PRIVILEGES ON public.{table} FROM app_user;")


def _immutable(table: str) -> None:
    function = f"refuse_{table}_mutation"
    op.execute(
        f"""
        CREATE FUNCTION public.{function}() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION '{table} rows are immutable' USING ERRCODE = '55000';
        END;
        $$;
        """
    )
    op.execute(
        f"CREATE TRIGGER trg_{table}_immutable BEFORE UPDATE OR DELETE "
        f"ON public.{table} FOR EACH ROW EXECUTE FUNCTION public.{function}();"
    )


def upgrade() -> None:
    op.create_table(
        DISPATCH,
        _uuid("id", primary_key=True),
        _uuid("plan_id"),
        _uuid("deployment_id"),
        sa.Column("capability_instance_ref", sa.String(length=200), nullable=False),
        _uuid("capability_binding_id"),
        sa.Column("operation", sa.String(length=20), nullable=False),
        sa.Column("command_id", sa.String(length=240), nullable=False),
        sa.Column("request_body_digest", sa.String(length=71), nullable=False),
        sa.Column("envelope_digest", sa.String(length=71), nullable=False),
        sa.Column("document", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(
            ["plan_id"], ["deployment_plans.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["deployment_id"], ["deployments.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["deployment_id", "capability_instance_ref"],
            [
                "deployment_capability_instances.deployment_id",
                "deployment_capability_instances.capability_instance_ref",
            ],
            name="fk_integrator_dispatch_capability_instance",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("command_id", name="uq_integrator_command_dispatch_id"),
        sa.UniqueConstraint(
            "envelope_digest", name="uq_integrator_command_dispatch_envelope"
        ),
        sa.UniqueConstraint(
            "id",
            "plan_id",
            "deployment_id",
            "capability_instance_ref",
            "capability_binding_id",
            name="uq_integrator_dispatch_scope",
        ),
        sa.CheckConstraint(
            "operation IN ('plan', 'apply', 'observe', 'cancel')",
            name="ck_integrator_dispatch_operation",
        ),
        sa.CheckConstraint(
            "request_body_digest ~ '^sha256:[0-9a-f]{64}$'",
            name="ck_integrator_dispatch_body_digest",
        ),
        sa.CheckConstraint(
            "envelope_digest ~ '^sha256:[0-9a-f]{64}$'",
            name="ck_integrator_dispatch_envelope_digest",
        ),
        sa.CheckConstraint(
            "capability_instance_ref ~ " "'^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$'",
            name="ck_integrator_dispatch_instance_ref",
        ),
    )
    _grants(DISPATCH)
    _immutable(DISPATCH)

    op.create_table(
        RECEIPT,
        _uuid("id", primary_key=True),
        _uuid("dispatch_id"),
        _uuid("plan_id"),
        _uuid("deployment_id"),
        sa.Column("capability_instance_ref", sa.String(length=200), nullable=False),
        _uuid("capability_binding_id"),
        sa.Column("operation", sa.String(length=20), nullable=False),
        sa.Column("command_id", sa.String(length=240), nullable=False),
        sa.Column("request_body_digest", sa.String(length=71), nullable=False),
        sa.Column("receipt_digest", sa.String(length=71), nullable=False),
        sa.Column("outcome", sa.String(length=40), nullable=False),
        _uuid("operation_id", nullable=True),
        sa.Column("latest_module_receipt_sequence", sa.Integer(), nullable=True),
        sa.Column("latest_module_receipt_hash", sa.String(length=71), nullable=True),
        sa.Column("module_plan_receipt_hash", sa.String(length=71), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("document", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(
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
        sa.ForeignKeyConstraint(
            ["plan_id"], ["deployment_plans.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["deployment_id"], ["deployments.id"], ondelete="RESTRICT"
        ),
        sa.UniqueConstraint("receipt_digest", name="uq_integrator_receipt_digest"),
        sa.CheckConstraint(
            "operation IN ('plan', 'apply', 'observe', 'cancel')",
            name="ck_integrator_receipt_operation",
        ),
        sa.CheckConstraint(
            "request_body_digest ~ '^sha256:[0-9a-f]{64}$'",
            name="ck_integrator_receipt_body_digest",
        ),
        sa.CheckConstraint(
            "receipt_digest ~ '^sha256:[0-9a-f]{64}$'",
            name="ck_integrator_receipt_digest",
        ),
        sa.CheckConstraint(
            "latest_module_receipt_sequence IS NULL OR "
            "latest_module_receipt_sequence > 0",
            name="ck_integrator_receipt_sequence_positive",
        ),
        sa.CheckConstraint(
            "latest_module_receipt_hash IS NULL OR "
            "latest_module_receipt_hash ~ '^sha256:[0-9a-f]{64}$'",
            name="ck_integrator_receipt_module_hash",
        ),
        sa.CheckConstraint(
            "module_plan_receipt_hash IS NULL OR "
            "module_plan_receipt_hash ~ '^sha256:[0-9a-f]{64}$'",
            name="ck_integrator_receipt_plan_hash",
        ),
        sa.CheckConstraint(
            "capability_instance_ref ~ " "'^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$'",
            name="ck_integrator_receipt_instance_ref",
        ),
    )
    _grants(RECEIPT)
    _immutable(RECEIPT)


def downgrade() -> None:
    for table in reversed(TABLES):
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_immutable ON public.{table};")
        op.execute(f"DROP FUNCTION IF EXISTS public.refuse_{table}_mutation();")
        op.drop_table(table)
