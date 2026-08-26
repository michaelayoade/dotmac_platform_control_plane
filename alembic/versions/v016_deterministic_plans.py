"""Immutable bundle, deterministic plan and exact approval bindings.

All four tables are platform catalogues.  They hold no customer secret and no
provider connection; app_user is fully revoked and platform_api can only append
immutable records.  The deployment aggregate alone owns its mutable current
plan pointer.

Revision ID: v016_deterministic_plans
Revises: v015_fleet_desired_state
Create Date: 2026-08-17
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "v016_deterministic_plans"
down_revision = "v015_fleet_desired_state"
branch_labels = None
depends_on = None

BUNDLE = "deployment_bundle_manifest_versions"
PLAN = "deployment_plans"
REQUEST = "deployment_plan_approval_requests"
GRANT = "deployment_plan_approval_grants"
TABLES = (BUNDLE, PLAN, REQUEST, GRANT)


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


def _immutable_table_grants(table: str) -> None:
    op.execute(f"GRANT SELECT, INSERT ON public.{table} TO platform_api;")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON public.{table} TO app_admin;")
    op.execute(f"REVOKE ALL PRIVILEGES ON public.{table} FROM app_user;")


def _immutable_trigger(table: str) -> None:
    function = f"refuse_{table}_mutation"
    trigger = f"trg_{table}_immutable"
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
        f"CREATE TRIGGER {trigger} BEFORE UPDATE OR DELETE ON public.{table} "
        f"FOR EACH ROW EXECUTE FUNCTION public.{function}();"
    )


def upgrade() -> None:
    op.create_table(
        BUNDLE,
        _uuid("id", primary_key=True),
        _uuid("profile_version_id"),
        sa.Column("bundle_code", sa.String(length=120), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("profile_content_hash", sa.String(length=71), nullable=False),
        sa.Column("content_hash", sa.String(length=71), nullable=False),
        sa.Column("document", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(
            ["profile_version_id"],
            ["managed_service_profile_versions.id"],
            name="fk_deployment_bundle_profile",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "profile_version_id",
            "bundle_code",
            "version",
            name="uq_deployment_bundle_profile_code_ver",
        ),
        sa.UniqueConstraint(
            "profile_version_id",
            "content_hash",
            name="uq_deployment_bundle_profile_hash",
        ),
        sa.CheckConstraint("version > 0", name="ck_deployment_bundle_version_positive"),
        sa.CheckConstraint(
            "profile_content_hash ~ '^sha256:[0-9a-f]{64}$'",
            name="ck_deployment_bundle_profile_hash_shape",
        ),
        sa.CheckConstraint(
            "content_hash ~ '^sha256:[0-9a-f]{64}$'",
            name="ck_deployment_bundle_content_hash_shape",
        ),
    )
    _immutable_table_grants(BUNDLE)
    _immutable_trigger(BUNDLE)

    op.create_table(
        PLAN,
        _uuid("id", primary_key=True),
        _uuid("deployment_id"),
        sa.Column("revision", sa.Integer(), nullable=False),
        _uuid("predecessor_plan_id", nullable=True),
        _uuid("desired_state_version_id"),
        _uuid("bundle_manifest_version_id"),
        _uuid("allocation_id", nullable=True),
        sa.Column("plan_hash", sa.String(length=71), nullable=False),
        sa.Column("document", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(
            ["deployment_id"],
            ["deployments.id"],
            name="fk_deployment_plan_deployment",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["predecessor_plan_id"],
            ["deployment_plans.id"],
            name="fk_deployment_plan_predecessor",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["desired_state_version_id"],
            ["deployment_desired_state_versions.id"],
            name="fk_deployment_plan_desired_state",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["bundle_manifest_version_id"],
            ["deployment_bundle_manifest_versions.id"],
            name="fk_deployment_plan_bundle",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "deployment_id", "revision", name="uq_deployment_plan_revision"
        ),
        sa.CheckConstraint("revision > 0", name="ck_deployment_plan_revision_positive"),
        sa.CheckConstraint(
            "plan_hash ~ '^sha256:[0-9a-f]{64}$'",
            name="ck_deployment_plan_hash_shape",
        ),
    )
    _immutable_table_grants(PLAN)
    _immutable_trigger(PLAN)

    op.add_column(
        "deployments",
        sa.Column("current_plan_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "deployments",
        sa.Column(
            "latest_plan_revision",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
    )
    op.create_foreign_key(
        "fk_deployments_current_plan",
        "deployments",
        PLAN,
        ["current_plan_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_check_constraint(
        "ck_deployments_latest_plan_revision_nonnegative",
        "deployments",
        "latest_plan_revision >= 0",
    )

    op.create_table(
        REQUEST,
        _uuid("id", primary_key=True),
        _uuid("plan_id"),
        _uuid("approval_request_id"),
        sa.Column("policy_code", sa.String(length=120), nullable=False),
        sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("request_binding_hash", sa.String(length=71), nullable=False),
        sa.Column("document", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(
            ["plan_id"],
            ["deployment_plans.id"],
            name="fk_deployment_plan_approval_request_plan",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("plan_id", name="uq_deployment_plan_approval_request_plan"),
        sa.UniqueConstraint(
            "approval_request_id",
            name="uq_deployment_plan_approval_request_authority",
        ),
        sa.CheckConstraint(
            "policy_version > 0", name="ck_deployment_plan_approval_policy_version"
        ),
        sa.CheckConstraint(
            "request_binding_hash ~ '^sha256:[0-9a-f]{64}$'",
            name="ck_deployment_plan_approval_request_hash_shape",
        ),
    )
    _immutable_table_grants(REQUEST)
    _immutable_trigger(REQUEST)

    op.create_table(
        GRANT,
        _uuid("id", primary_key=True),
        _uuid("plan_id"),
        _uuid("approval_request_binding_id"),
        _uuid("approval_request_id"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("grant_digest", sa.String(length=71), nullable=False),
        sa.Column("document", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(
            ["plan_id"],
            ["deployment_plans.id"],
            name="fk_deployment_plan_approval_grant_plan",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["approval_request_binding_id"],
            ["deployment_plan_approval_requests.id"],
            name="fk_deployment_plan_approval_grant_request",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("plan_id", name="uq_deployment_plan_approval_grant_plan"),
        sa.UniqueConstraint(
            "approval_request_binding_id",
            name="uq_deployment_plan_approval_grant_request",
        ),
        sa.CheckConstraint(
            "grant_digest ~ '^sha256:[0-9a-f]{64}$'",
            name="ck_deployment_plan_approval_grant_hash_shape",
        ),
    )
    _immutable_table_grants(GRANT)
    _immutable_trigger(GRANT)


def downgrade() -> None:
    for table in reversed(TABLES):
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_immutable ON public.{table};")
        op.execute(f"DROP FUNCTION IF EXISTS public.refuse_{table}_mutation();")
        if table == PLAN:
            op.drop_constraint(
                "fk_deployments_current_plan", "deployments", type_="foreignkey"
            )
            op.drop_constraint(
                "ck_deployments_latest_plan_revision_nonnegative",
                "deployments",
                type_="check",
            )
            op.drop_column("deployments", "latest_plan_revision")
            op.drop_column("deployments", "current_plan_id")
        op.drop_table(table)
