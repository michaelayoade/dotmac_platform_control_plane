"""Vendor lineage root — create the `vendor_accounts` platform catalog table.

The vendor control plane's own migration lineage (branch label ``vendor``),
composed with the kernel base lineage in one revision graph. It ``depends_on`` the
current kernel head so the kernel's platform-catalog roles + tables
(``platform_admins``, ``platform_audit_events``, ``platform_inbox_records`` — the
AccountService's audit/idempotency backing) exist before this runs; it is NOT a
child of that head, so the kernel and vendor lineages advance independently (two
heads once the kernel moves past what this pins).

``vendor_accounts`` is a PLATFORM catalog table, matching the kernel pattern
(``platform_admins``): NO ``tenant_id``, NO RLS. GRANTed to ``platform_api`` and
``app_admin``; REVOKEd from the tenant application role ``app_user``.

Revision ID: v001_vendor_accounts
Revises: (vendor lineage root)
Depends on: 0009_platform_audit_inbox (kernel head)
Create Date: 2026-07-31
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "v001_vendor_accounts"
down_revision = None
branch_labels = ("vendor",)
depends_on = "0009_platform_audit_inbox"

_TABLE = "vendor_accounts"


def upgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column("external_ref", sa.String(length=200), nullable=False),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.Column(
            "status",
            sa.String(length=20),
            nullable=False,
            server_default="active",
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
        sa.UniqueConstraint("external_ref", name="uq_vendor_accounts_external_ref"),
    )

    # Platform catalog grants — no RLS (there is no tenant to scope by). The tenant
    # application role must not even SELECT a platform-owned account row.
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {_TABLE} TO platform_api;")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {_TABLE} TO app_admin;")
    op.execute(f"REVOKE ALL ON {_TABLE} FROM app_user;")


def downgrade() -> None:
    op.drop_table(_TABLE)
