"""Append-only evidence of how an `approval.withdrawn` event was settled.

CP owns the SIX terminal dispositions a withdrawal consumer can reach:
`applied`, `already_applied`, `not_carried`, `cancelled_before_execution`,
`superseded_by_revocation`, `security_conflict`. The seventh semantic
outcome, `retryable`, lives in the kernel outbox row and is never written
here (Michael, 2026-09-26/27; Knowledge
`approval-withdrawal-barrier-ruling-2026-09-26` v5).

Two platform-plane tables (no `tenant_id`, no RLS — the same shape `v019`
already uses): `public.approval_withdrawal_outcomes`, the append-only
disposition record, and `public.approval_withdrawal_conflict_resolutions`,
the append-only human resolution of a `security_conflict` row. Both are made
append-only by a BEFORE UPDATE OR DELETE row trigger plus a BEFORE TRUNCATE
statement trigger — a privilege revoke alone cannot stop `app_admin`, the
migration/offline role, from rewriting a row, and this evidence must survive
even that role.

## Idempotency, encoded in the constraints rather than trusted to the caller

`UNIQUE(event_id, payload_digest)` is what makes an identical replay a
lookup instead of a second row. The partial unique index on `event_id WHERE
disposition <> 'security_conflict'` is the other half: at most one
NON-conflict terminal outcome may ever exist for one event, so a changed
payload under the same event id has exactly one place left to land —
its own `security_conflict` row, with its own digest.

## Why `security_conflict` gets a second table instead of a status column

A conflict keeps health RED until a human redrives or dismisses it, and that
resolution is itself evidence, not a state flip on the outcome row (which
would make the outcome table no longer append-only). `outcome_id` is
`UNIQUE`, so a conflict can be resolved exactly once; a second resolution
attempt hits that constraint rather than silently overwriting the first
human's decision.

Revision ID: v020_withdrawal_outcomes
Revises: v019_relay_heartbeat
Create Date: 2026-09-27
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "v020_withdrawal_outcomes"
down_revision = "v019_relay_heartbeat"
branch_labels = None
depends_on = None

_OUTCOMES = "approval_withdrawal_outcomes"
_RESOLUTIONS = "approval_withdrawal_conflict_resolutions"
_DISPOSITIONS = (
    "applied",
    "already_applied",
    "not_carried",
    "cancelled_before_execution",
    "superseded_by_revocation",
    "security_conflict",
)
_RESOLUTIONS_ENUM = ("dismissed", "redriven")

#: One trigger function, reused by both tables, refusing UPDATE, DELETE and
#: TRUNCATE alike and naming the table in the message. A privilege revoke does
#: not reach `app_admin`; this does.
_GUARD_FUNCTION = "public.forbid_mutation_of_append_only_table()"


def _append_only_guard(table: str) -> None:
    op.execute(
        f"""
        CREATE TRIGGER trg_{table}_append_only
            BEFORE UPDATE OR DELETE ON public.{table}
            FOR EACH ROW EXECUTE FUNCTION {_GUARD_FUNCTION};
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER trg_{table}_append_only_truncate
            BEFORE TRUNCATE ON public.{table}
            FOR EACH STATEMENT EXECUTE FUNCTION {_GUARD_FUNCTION};
        """
    )


def upgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.forbid_mutation_of_append_only_table()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION
                '% is append-only: % is refused', TG_TABLE_NAME, TG_OP;
        END;
        $$;
        """
    )

    op.create_table(
        _OUTCOMES,
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column("event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("payload_digest", sa.String(length=71), nullable=False),
        sa.Column("event_type", sa.String(length=80), nullable=False),
        sa.Column("subject_type", sa.String(length=120), nullable=False),
        sa.Column("subject_id", sa.String(length=200), nullable=False),
        sa.Column("approval_request_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("plan_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("agreement_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("withdrawal_ref", sa.String(length=200), nullable=True),
        sa.Column("disposition", sa.String(length=40), nullable=False),
        sa.Column("reason_code", sa.String(length=80), nullable=False),
        sa.Column("evidence", postgresql.JSONB(), nullable=False),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "disposition IN ("
            + ", ".join(f"'{value}'" for value in _DISPOSITIONS)
            + ")",
            name="ck_approval_withdrawal_outcomes_disposition",
        ),
        sa.UniqueConstraint(
            "event_id",
            "payload_digest",
            name="uq_approval_withdrawal_outcomes_event_digest",
        ),
    )
    # At most one NON-conflict terminal outcome per event. A conflicting
    # replay always lands in its own `security_conflict` row instead.
    op.create_index(
        "uq_approval_withdrawal_outcomes_event_id_non_conflict",
        _OUTCOMES,
        ["event_id"],
        unique=True,
        postgresql_where=sa.text("disposition <> 'security_conflict'"),
    )
    op.create_index(
        "ix_approval_withdrawal_outcomes_disposition", _OUTCOMES, ["disposition"]
    )
    _append_only_guard(_OUTCOMES)
    op.execute(f"GRANT SELECT, INSERT ON public.{_OUTCOMES} TO platform_api;")
    op.execute(f"GRANT SELECT, INSERT ON public.{_OUTCOMES} TO app_admin;")
    op.execute(f"REVOKE ALL ON public.{_OUTCOMES} FROM app_user;")
    # No grant to `platform_outbox_dispatcher`, stated rather than merely
    # absent — the same isolation `v019` holds itself to.

    op.create_table(
        _RESOLUTIONS,
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column(
            "outcome_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(f"{_OUTCOMES}.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("resolution", sa.String(length=20), nullable=False),
        sa.Column("actor_ref", sa.String(length=200), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("redrive_ref", sa.String(length=200), nullable=True),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "resolution IN ("
            + ", ".join(f"'{value}'" for value in _RESOLUTIONS_ENUM)
            + ")",
            name="ck_approval_withdrawal_conflict_resolutions_resolution",
        ),
        sa.CheckConstraint(
            "reason <> ''",
            name="ck_approval_withdrawal_conflict_resolutions_reason_not_blank",
        ),
        sa.UniqueConstraint(
            "outcome_id",
            name="uq_approval_withdrawal_conflict_resolutions_outcome",
        ),
    )
    _append_only_guard(_RESOLUTIONS)
    op.execute(f"GRANT SELECT, INSERT ON public.{_RESOLUTIONS} TO platform_api;")
    op.execute(f"GRANT SELECT, INSERT ON public.{_RESOLUTIONS} TO app_admin;")
    op.execute(f"REVOKE ALL ON public.{_RESOLUTIONS} FROM app_user;")


def downgrade() -> None:
    connection = op.get_bind()
    op.execute(
        f"LOCK TABLE public.{_OUTCOMES}, public.{_RESOLUTIONS} "
        "IN ACCESS EXCLUSIVE MODE"
    )
    populated: list[str] = []
    for table in (_RESOLUTIONS, _OUTCOMES):
        count = connection.execute(
            sa.text(f"SELECT count(*) FROM public.{table}")  # noqa: S608
        ).scalar_one()
        if count:
            populated.append(f"{table}={count}")
    if populated:
        raise RuntimeError(
            "v020_withdrawal_outcomes cannot be downgraded while "
            f"evidence rows remain: {', '.join(populated)}. This table is the "
            "durable record of how a withdrawal was settled; dropping it with "
            "rows present would destroy audit evidence rather than reverse a "
            "schema change."
        )

    op.drop_table(_RESOLUTIONS)
    op.drop_table(_OUTCOMES)
    op.execute("DROP FUNCTION IF EXISTS public.forbid_mutation_of_append_only_table();")
