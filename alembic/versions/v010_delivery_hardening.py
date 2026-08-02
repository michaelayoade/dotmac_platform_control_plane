"""Vendor lineage — delivery-target projection, replay generations, safe codes.

Extends the vendor lineage (child of `v009_delivery_attempts`), applying the
2026-08-02 delivery-pipeline review:

- `licence_delivery_targets` — the licensing-owned projection of where a
  licence may be delivered. Deliberately NOT named `deployments`: the
  authoritative Deployment entity belongs to `FleetDesiredStateService`
  (`docs/design/domain-foundation.md`) and remains design-only, so creating it
  here would have made licensing its de-facto owner.
- `licence_deliveries.target_id` — FK to that projection, guarded by a
  **`NOT VALID` CHECK** so every new or updated row must have a destination
  while pre-existing rows are left for explicit mapping. Those legacy rows are
  **parked** by this migration: they predate the destination boundary and must
  not be replayable until an operator maps them.
- `replay_generation` on delivery state and attempts — the retry budget is
  counted within a generation, so resuming a parked delivery resets the budget
  without mutating the immutable attempt history.
- `error_code` REPLACES the free-text `error` column, which is dropped rather
  than migrated: its contents (URLs, bodies, headers, tokens) are exactly what
  must not be retained.

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

_TARGETS = "licence_delivery_targets"


def _grants(table: str) -> None:
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO platform_api;")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO app_admin;")
    op.execute(f"REVOKE ALL ON {table} FROM app_user;")


def upgrade() -> None:
    op.create_table(
        _TARGETS,
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column("target_ref", sa.String(length=200), nullable=False),
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
        sa.UniqueConstraint("target_ref", name="uq_licence_delivery_targets_ref"),
    )
    _grants(_TARGETS)

    op.add_column(
        "licence_deliveries",
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_licence_delivery_target",
        "licence_deliveries",
        _TARGETS,
        ["target_id"],
        ["id"],
    )

    # PARK every pre-existing delivery. They were staged before destinations
    # were resolved through a registry, so replaying them would deliver to an
    # unvalidated target. Parked is visible and resumable — an operator maps
    # the destination, then resumes.
    op.execute(
        """
        UPDATE licence_delivery_states
           SET state = 'parked'
         WHERE state <> 'active'
           AND delivery_id IN (
               SELECT id FROM licence_deliveries WHERE target_id IS NULL
           );
        """
    )

    # Structurally prevent NEW rows without a destination. NOT VALID so the
    # legacy rows above are tolerated (they are parked) while every insert or
    # update from here on is checked.
    op.execute(
        """
        ALTER TABLE licence_deliveries
          ADD CONSTRAINT ck_licence_delivery_has_target
          CHECK (target_id IS NOT NULL) NOT VALID;
        """
    )

    # Replay generations: budget resets on resume, history stays immutable.
    op.add_column(
        "licence_delivery_states",
        sa.Column(
            "replay_generation",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
    )
    op.add_column(
        "licence_delivery_attempts",
        sa.Column(
            "replay_generation",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
    )
    op.drop_constraint(
        "uq_licence_delivery_attempt_no", "licence_delivery_attempts", type_="unique"
    )
    op.create_unique_constraint(
        "uq_licence_delivery_attempt_no",
        "licence_delivery_attempts",
        ["delivery_id", "replay_generation", "attempt_no"],
    )

    # Free-text errors are dropped, not migrated.
    op.drop_column("licence_delivery_attempts", "error")
    op.add_column(
        "licence_delivery_attempts",
        sa.Column("error_code", sa.String(length=60), nullable=True),
    )

    # The PROVEN identity, stored beside (never merged into) the body's claim.
    op.add_column(
        "licence_ack_records",
        sa.Column("authenticated_deployment_ref", sa.String(length=200), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("licence_ack_records", "authenticated_deployment_ref")
    op.drop_column("licence_delivery_attempts", "error_code")
    op.add_column(
        "licence_delivery_attempts",
        sa.Column("error", sa.String(length=500), nullable=True),
    )
    op.drop_constraint(
        "uq_licence_delivery_attempt_no", "licence_delivery_attempts", type_="unique"
    )
    op.create_unique_constraint(
        "uq_licence_delivery_attempt_no",
        "licence_delivery_attempts",
        ["delivery_id", "attempt_no"],
    )
    op.drop_column("licence_delivery_attempts", "replay_generation")
    op.drop_column("licence_delivery_states", "replay_generation")
    op.execute(
        "ALTER TABLE licence_deliveries "
        "DROP CONSTRAINT IF EXISTS ck_licence_delivery_has_target;"
    )
    op.drop_constraint(
        "fk_licence_delivery_target", "licence_deliveries", type_="foreignkey"
    )
    op.drop_column("licence_deliveries", "target_id")
    op.drop_table(_TARGETS)
