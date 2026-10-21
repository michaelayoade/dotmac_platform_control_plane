"""Deploy-agent evidence projection and public host identity registry."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "v022_deploy_agent"
down_revision = "v021_issuer_command_receipts"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "deploy_agent_receipts",
        sa.Column("path", sa.Text(), primary_key=True),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("deployment_ref", sa.Text()),
        sa.Column("report_id", sa.Text()),
        sa.Column("nonce", sa.Text(), unique=True),
        sa.Column("fingerprint", sa.Text(), nullable=False),
        sa.Column("envelope", postgresql.JSONB(), nullable=False),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("deployment_ref", "report_id"),
    )
    op.create_table(
        "deploy_host_keys",
        sa.Column("key_id", sa.Text(), primary_key=True),
        sa.Column("deployment_ref", sa.Text(), nullable=False),
        sa.Column("public_key_b64", sa.Text(), nullable=False, unique=True),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("event_path", sa.Text(), nullable=False),
        sa.CheckConstraint("state IN ('pending','active','revoked')"),
    )
    for table in ("deploy_agent_receipts", "deploy_host_keys"):
        op.execute(f"REVOKE ALL ON public.{table} FROM app_user")
        op.execute(f"GRANT SELECT, INSERT ON public.{table} TO platform_api, app_admin")
        op.execute(
            f"REVOKE DELETE, TRUNCATE ON public.{table} FROM platform_api, app_user"
        )
    op.execute(
        "GRANT UPDATE(state,event_path) ON public.deploy_host_keys "
        "TO platform_api, app_admin"
    )
    for operation, level in (("UPDATE OR DELETE", "ROW"), ("TRUNCATE", "STATEMENT")):
        suffix = "row" if level == "ROW" else "truncate"
        op.execute(
            f"CREATE TRIGGER deploy_agent_receipts_{suffix} BEFORE {operation} "
            f"ON public.deploy_agent_receipts FOR EACH {level} EXECUTE FUNCTION "
            "public.forbid_mutation_of_append_only_table()"
        )


def downgrade():
    raise RuntimeError(
        "deploy-agent authoritative evidence is retained; forward repair required"
    )
