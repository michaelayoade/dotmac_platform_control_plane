"""Vendor lineage — revocation entries + published signed list snapshots.

Extends the vendor lineage (child of `v007_licence_delivery`). Two PLATFORM
catalog tables (no `tenant_id`, no RLS): GRANTed to `platform_api`/`app_admin`,
REVOKEd from `app_user`.

`licence_revocation_entries` is append-only (unique per licence, so revoking
twice is idempotent rather than a duplicate fact); `licence_revocation_lists`
holds immutable published snapshots with a strictly increasing `list_version`.
Revoked ids are permanently cumulative — the superset invariant is enforced in
the service, since SQL alone cannot express "every snapshot contains its
predecessor's set".

Revision ID: v008_licence_revocation
Revises: v007_licence_delivery
Create Date: 2026-08-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "v008_licence_revocation"
down_revision = "v007_licence_delivery"
branch_labels = None
depends_on = None

_ENTRIES = "licence_revocation_entries"
_LISTS = "licence_revocation_lists"


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
    # Lineage generations. Revocation is by licence_id and permanent, so the
    # contracted recovery path (re-issuing for the SAME customer+product) needs
    # a new lineage to issue into — without a discriminator the resolver would
    # hand back the revoked one and every recovery document would be dead on
    # arrival. Existing rows are generation 1.
    op.add_column(
        "licences",
        sa.Column(
            "generation", sa.Integer(), nullable=False, server_default=sa.text("1")
        ),
    )
    op.drop_constraint("uq_licences_customer_product", "licences", type_="unique")
    op.create_unique_constraint(
        "uq_licences_customer_product_generation",
        "licences",
        ["customer_ref", "product", "generation"],
    )

    op.create_table(
        _ENTRIES,
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column(
            "licence_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("licences.id"),
            nullable=False,
        ),
        sa.Column("reason", sa.String(length=200), nullable=False),
        sa.Column("revoked_by_admin_id", postgresql.UUID(as_uuid=True), nullable=True),
        *_ts_cols(),
        sa.UniqueConstraint("licence_id", name="uq_licence_revocation_licence"),
    )
    _grants(_ENTRIES)

    op.create_table(
        _LISTS,
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column("list_version", sa.Integer(), nullable=False),
        sa.Column("digest", sa.String(length=128), nullable=False),
        sa.Column("key_id", sa.String(length=120), nullable=False),
        sa.Column("entry_count", sa.Integer(), nullable=False),
        sa.Column("envelope", postgresql.JSONB(), nullable=False),
        *_ts_cols(),
        sa.UniqueConstraint("list_version", name="uq_licence_revocation_list_version"),
    )
    _grants(_LISTS)


def downgrade() -> None:
    op.drop_table(_LISTS)
    op.drop_table(_ENTRIES)
    op.drop_constraint(
        "uq_licences_customer_product_generation", "licences", type_="unique"
    )
    op.create_unique_constraint(
        "uq_licences_customer_product", "licences", ["customer_ref", "product"]
    )
    op.drop_column("licences", "generation")
