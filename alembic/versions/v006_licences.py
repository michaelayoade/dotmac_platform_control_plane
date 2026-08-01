"""Vendor lineage — create the WS8 licence tables (platform catalog).

Extends the vendor lineage (child of `v005_allocations`). Three PLATFORM catalog
tables (no `tenant_id`, no RLS): GRANTed to `platform_api`/`app_admin`, REVOKEd
from `app_user`.

`licence_signing_keys` holds PUBLIC key material only — there is deliberately no
private-key column, so a database dump can never leak signing material.
`licences` is the lineage (unique per customer+product); `licence_issuances`
holds each immutable signed version, unique on `(licence_id, version)` so two
issuances can never claim one version, and unique on `allocation_id` so one
staged allocation yields exactly one issued version.

Revision ID: v006_licences
Revises: v005_allocations
Create Date: 2026-08-01
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "v006_licences"
down_revision = "v005_allocations"
branch_labels = None
depends_on = None

_KEYS = "licence_signing_keys"
_LICENCES = "licences"
_ISSUANCES = "licence_issuances"


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
        _KEYS,
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column("key_id", sa.String(length=120), nullable=False, unique=True),
        sa.Column("public_key_b64", sa.String(length=200), nullable=False),
        sa.Column(
            "status",
            sa.String(length=20),
            nullable=False,
            server_default=sa.text("'active'"),
        ),
        *_ts_cols(),
    )
    _grants(_KEYS)

    op.create_table(
        _LICENCES,
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column("customer_ref", sa.String(length=200), nullable=False),
        sa.Column("product", sa.String(length=120), nullable=False),
        *_ts_cols(),
        sa.UniqueConstraint(
            "customer_ref", "product", name="uq_licences_customer_product"
        ),
    )
    _grants(_LICENCES)

    op.create_table(
        _ISSUANCES,
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column(
            "licence_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("licences.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "allocation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("allocations.id"),
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("digest", sa.String(length=128), nullable=False),
        sa.Column("key_id", sa.String(length=120), nullable=False),
        sa.Column("envelope", postgresql.JSONB(), nullable=False),
        sa.Column(
            "status",
            sa.String(length=20),
            nullable=False,
            server_default=sa.text("'issued'"),
        ),
        *_ts_cols(),
        sa.UniqueConstraint(
            "licence_id", "version", name="uq_licence_issuance_version"
        ),
        sa.UniqueConstraint("allocation_id", name="uq_licence_issuance_allocation"),
    )
    op.create_index("ix_licence_issuances_licence_id", _ISSUANCES, ["licence_id"])
    _grants(_ISSUANCES)


def downgrade() -> None:
    op.drop_table(_ISSUANCES)
    op.drop_table(_LICENCES)
    op.drop_table(_KEYS)
