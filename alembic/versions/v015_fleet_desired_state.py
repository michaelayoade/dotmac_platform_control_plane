"""Reusable managed profiles and account-owned fleet desired state.

The five tables are PLATFORM catalogues: no tenant discriminator and no RLS.
`platform_api` operates them, the migration role owns them, and `app_user` is
fully revoked.  Profile and desired-state versions are immutable at the
database boundary, not merely by service convention.

Revision ID: v015_fleet_desired_state
Revises: v014_allocations_authority
Create Date: 2026-08-17
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "v015_fleet_desired_state"
down_revision = "v014_allocations_authority"
branch_labels = None
depends_on = None

PROFILE_TABLE = "managed_service_profile_versions"
TARGET_TABLE = "deployment_targets"
DEPLOYMENT_TABLE = "deployments"
INSTANCE_TABLE = "deployment_capability_instances"
DESIRED_TABLE = "deployment_desired_state_versions"
TABLES = (
    PROFILE_TABLE,
    TARGET_TABLE,
    DEPLOYMENT_TABLE,
    INSTANCE_TABLE,
    DESIRED_TABLE,
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


def _uuid(
    name: str, *, primary_key: bool = False, nullable: bool = False
) -> sa.Column[object]:
    return sa.Column(
        name,
        postgresql.UUID(as_uuid=True),
        primary_key=primary_key,
        nullable=nullable,
    )


def _platform_grants(table: str, *, immutable: bool = False) -> None:
    online = "SELECT, INSERT" if immutable else "SELECT, INSERT, UPDATE, DELETE"
    op.execute(f"GRANT {online} ON public.{table} TO platform_api;")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON public.{table} TO app_admin;")
    op.execute(f"REVOKE ALL PRIVILEGES ON public.{table} FROM app_user;")


def _immutable_trigger(table: str, function: str, trigger: str, message: str) -> None:
    op.execute(
        f"""
        CREATE FUNCTION public.{function}() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION '{message}' USING ERRCODE = '55000';
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
        PROFILE_TABLE,
        _uuid("id", primary_key=True),
        sa.Column("profile_code", sa.String(length=120), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("commercial_product_code", sa.String(length=120), nullable=False),
        sa.Column("content_hash", sa.String(length=71), nullable=False),
        sa.Column("document", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        *_timestamps(),
        sa.UniqueConstraint(
            "commercial_product_code",
            "profile_code",
            "version",
            name="uq_managed_profile_product_code_ver",
        ),
        sa.UniqueConstraint(
            "commercial_product_code",
            "content_hash",
            name="uq_managed_profile_product_hash",
        ),
        sa.CheckConstraint("version > 0", name="ck_managed_profile_version_positive"),
        sa.CheckConstraint(
            "schema_version > 0", name="ck_managed_profile_schema_version_positive"
        ),
        sa.CheckConstraint(
            "content_hash ~ '^sha256:[0-9a-f]{64}$'",
            name="ck_managed_profile_content_hash",
        ),
    )
    _platform_grants(PROFILE_TABLE, immutable=True)
    _immutable_trigger(
        PROFILE_TABLE,
        "refuse_managed_profile_version_mutation",
        "trg_managed_profile_version_immutable",
        "managed service profile versions are immutable",
    )

    op.create_table(
        TARGET_TABLE,
        _uuid("id", primary_key=True),
        _uuid("account_id"),
        sa.Column("target_ref", sa.String(length=200), nullable=False),
        sa.Column("customer_ref", sa.String(length=200), nullable=True),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.Column("region_code", sa.String(length=80), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["vendor_accounts.id"],
            name="fk_deployment_targets_account",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "account_id", "target_ref", name="uq_deployment_targets_account_ref"
        ),
        sa.UniqueConstraint("customer_ref", name="uq_deployment_targets_customer_ref"),
        sa.UniqueConstraint(
            "account_id", "id", name="uq_deployment_targets_account_id"
        ),
    )
    _platform_grants(TARGET_TABLE)

    op.create_table(
        DEPLOYMENT_TABLE,
        _uuid("id", primary_key=True),
        _uuid("account_id"),
        _uuid("target_id"),
        sa.Column("deployment_ref", sa.String(length=200), nullable=False),
        sa.Column("commercial_product_code", sa.String(length=120), nullable=False),
        sa.Column(
            "status",
            sa.String(length=30),
            server_default=sa.text("'intent_recorded'"),
            nullable=False,
        ),
        _uuid("contract_id", nullable=True),
        sa.Column("internal_source_code", sa.String(length=160), nullable=True),
        sa.Column(
            "current_desired_state_revision",
            sa.Integer(),
            server_default=sa.text("1"),
            nullable=False,
        ),
        *_timestamps(),
        sa.ForeignKeyConstraint(
            ["account_id", "target_id"],
            ["deployment_targets.account_id", "deployment_targets.id"],
            name="fk_deployments_target_account_owner",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["contract_id"],
            ["contracts.id"],
            name="fk_deployments_contract",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "account_id", "deployment_ref", name="uq_deployments_account_ref"
        ),
        sa.UniqueConstraint(
            "target_id",
            "commercial_product_code",
            name="uq_deployments_target_product",
        ),
        sa.CheckConstraint(
            "((contract_id IS NOT NULL AND internal_source_code IS NULL) OR "
            "(contract_id IS NULL AND internal_source_code IS NOT NULL))",
            name="ck_deployments_exactly_one_source",
        ),
    )
    _platform_grants(DEPLOYMENT_TABLE)

    op.create_table(
        INSTANCE_TABLE,
        _uuid("id", primary_key=True),
        _uuid("deployment_id"),
        sa.Column("capability_instance_ref", sa.String(length=200), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(
            ["deployment_id"],
            ["deployments.id"],
            name="fk_deployment_capability_instance_deployment",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "deployment_id",
            "capability_instance_ref",
            name="uq_deployment_capability_instance_ref",
        ),
        sa.CheckConstraint(
            "capability_instance_ref ~ " "'^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$'",
            name="ck_deployment_capability_instance_ref_canonical",
        ),
    )
    _platform_grants(INSTANCE_TABLE, immutable=True)
    _immutable_trigger(
        INSTANCE_TABLE,
        "refuse_deployment_capability_instance_mutation",
        "trg_deployment_capability_instance_immutable",
        "deployment capability instances are immutable",
    )

    op.create_table(
        DESIRED_TABLE,
        _uuid("id", primary_key=True),
        _uuid("deployment_id"),
        sa.Column("revision", sa.Integer(), nullable=False),
        _uuid("predecessor_id", nullable=True),
        _uuid("profile_version_id"),
        sa.Column("profile_code", sa.String(length=120), nullable=False),
        sa.Column("profile_version", sa.Integer(), nullable=False),
        sa.Column("profile_content_hash", sa.String(length=71), nullable=False),
        sa.Column("commercial_product_code", sa.String(length=120), nullable=False),
        sa.Column("update_authority", sa.String(length=30), nullable=False),
        sa.Column(
            "selected_components",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "selected_capabilities",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "selected_operations",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "selected_verification_checks",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "configuration_snapshot",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "desired_operation_inputs",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "selected_composition_edges",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("configuration_snapshot_ref", sa.String(length=200), nullable=False),
        sa.Column("configuration_schema_version", sa.Integer(), nullable=False),
        sa.Column("configuration_hash", sa.String(length=71), nullable=False),
        sa.Column("desired_state_hash", sa.String(length=71), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(
            ["deployment_id"],
            ["deployments.id"],
            name="fk_desired_state_deployment",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["predecessor_id"],
            ["deployment_desired_state_versions.id"],
            name="fk_desired_state_predecessor",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["profile_version_id"],
            ["managed_service_profile_versions.id"],
            name="fk_desired_state_profile_version",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "deployment_id",
            "revision",
            name="uq_deployment_desired_state_revision",
        ),
        sa.UniqueConstraint(
            "deployment_id",
            "desired_state_hash",
            name="uq_deployment_desired_state_hash",
        ),
        sa.CheckConstraint(
            "revision > 0", name="ck_deployment_desired_state_revision_positive"
        ),
        sa.CheckConstraint(
            "configuration_schema_version > 0",
            name="ck_deployment_configuration_schema_version_positive",
        ),
        sa.CheckConstraint(
            "profile_content_hash ~ '^sha256:[0-9a-f]{64}$'",
            name="ck_desired_state_profile_hash",
        ),
        sa.CheckConstraint(
            "configuration_hash ~ '^sha256:[0-9a-f]{64}$'",
            name="ck_desired_state_configuration_hash",
        ),
        sa.CheckConstraint(
            "desired_state_hash ~ '^sha256:[0-9a-f]{64}$'",
            name="ck_desired_state_content_hash",
        ),
    )
    _platform_grants(DESIRED_TABLE, immutable=True)
    _immutable_trigger(
        DESIRED_TABLE,
        "refuse_deployment_desired_state_mutation",
        "trg_deployment_desired_state_immutable",
        "deployment desired-state versions are immutable",
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS trg_deployment_desired_state_immutable "
        "ON public.deployment_desired_state_versions;"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS public.refuse_deployment_desired_state_mutation();"
    )
    op.drop_table(DESIRED_TABLE)
    op.execute(
        "DROP TRIGGER IF EXISTS trg_deployment_capability_instance_immutable "
        "ON public.deployment_capability_instances;"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS "
        "public.refuse_deployment_capability_instance_mutation();"
    )
    op.drop_table(INSTANCE_TABLE)
    op.drop_table(DEPLOYMENT_TABLE)
    op.drop_table(TARGET_TABLE)
    op.execute(
        "DROP TRIGGER IF EXISTS trg_managed_profile_version_immutable "
        "ON public.managed_service_profile_versions;"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS public.refuse_managed_profile_version_mutation();"
    )
    op.drop_table(PROFILE_TABLE)
