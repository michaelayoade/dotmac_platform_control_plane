"""An append-only, non-authorizing receipt of one issuer command.

`approve_issuer_plan` and `issue_authorization` take the Approvals hold
(`held_transition`) BEFORE calling Control, so a same-command-id retry of a
COMMITTED command, made after a later withdrawal, was refused as "not held:
withdrawn" with nothing saying the command had committed (D18-C).

CP may own this append-only command receipt, written in the SAME transaction
as Control's call, keyed by command ID and request fingerprint, and pointing
to Control's result id. It must NOT become another issuer-standing or
idempotency authority: Control and the kernel keep those decisions, Approvals
keeps withdrawal standing. On a retry after withdrawal, the seam may report
that the original command committed, but must never return its signed
envelope as currently usable authority (Michael's ruling, 2026-09-27,
constrained option D).

`public.issuer_command_receipts` is a platform-plane table (no `tenant_id`,
no RLS), the same shape `v020` uses, made append-only by the same trigger
pattern: a BEFORE UPDATE OR DELETE row trigger plus a BEFORE TRUNCATE
statement trigger, reusing `v020`'s
`public.forbid_mutation_of_append_only_table()` function rather than
redefining it.

`UNIQUE(command_id)` is the idempotency anchor: a concurrent retry of the
same command id collides here and re-reads the winner's row rather than
inserting a second one. `request_fingerprint` and `control_ref` are compared
by the caller, not by a constraint, because a same-id/different-fingerprint
retry must be refused as reuse rather than silently accepted as a second row
for the same command id.

Revision ID: v021_issuer_command_receipts
Revises: v020_withdrawal_outcomes
Create Date: 2026-09-27
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "v021_issuer_command_receipts"
down_revision = "v020_withdrawal_outcomes"
branch_labels = None
depends_on = None

_RECEIPTS = "issuer_command_receipts"
_VERBS = ("approve_plan", "issue_authorization")

#: Reused from `v020`; this migration does not redefine it.
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
    op.create_table(
        _RECEIPTS,
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column("command_id", sa.String(length=200), nullable=False),
        sa.Column("verb", sa.String(length=40), nullable=False),
        sa.Column("request_fingerprint", sa.String(length=71), nullable=False),
        sa.Column("plan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("approval_request_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("control_ref", sa.String(length=200), nullable=False),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "verb IN (" + ", ".join(f"'{value}'" for value in _VERBS) + ")",
            name="ck_issuer_command_receipts_verb",
        ),
        sa.UniqueConstraint("command_id", name="uq_issuer_command_receipts_command_id"),
    )
    _append_only_guard(_RECEIPTS)
    op.execute(f"GRANT SELECT, INSERT ON public.{_RECEIPTS} TO platform_api;")
    op.execute(f"GRANT SELECT, INSERT ON public.{_RECEIPTS} TO app_admin;")
    op.execute(f"REVOKE ALL ON public.{_RECEIPTS} FROM app_user;")
    # No grant to `platform_outbox_dispatcher` — stated rather than merely
    # absent, matching `v020`.


def downgrade() -> None:
    connection = op.get_bind()
    op.execute(f"LOCK TABLE public.{_RECEIPTS} IN ACCESS EXCLUSIVE MODE")
    count = connection.execute(
        sa.text(f"SELECT count(*) FROM public.{_RECEIPTS}")  # noqa: S608
    ).scalar_one()
    if count:
        raise RuntimeError(
            "v021_issuer_command_receipts cannot be downgraded while receipt "
            f"rows remain: {_RECEIPTS}={count}. This table is the durable "
            "record of which issuer commands committed; dropping it with rows "
            "present would destroy that evidence rather than reverse a schema "
            "change."
        )

    op.drop_table(_RECEIPTS)
