"""Vendor lineage — applied-state receipts and canonical reports (V6 slice 2).

Two tables, because one cannot hold both facts. An append-only log keyed
uniquely on `(authenticated_deployment_ref, report_id)` cannot insert the
SECOND arrival — which is precisely the row worth keeping, being either the
replay or the conflicting bytes — and updating the first would break
append-only semantics AND discard the conflicting evidence.

- `applied_state_receipt_attempts` — one row per arrival, written on EVERY
  path including unknown key, malformed envelope and bad signature. Those are
  the tripwires, and a fail-closed system that discarded them would be blind to
  exactly the traffic it is refusing.
- `applied_state_reports` — one canonical row per idempotency key, holding the
  first eligible verified arrival's bytes, digest and ORIGINAL verdict.

The unique constraint on the canonical table is the concurrency arbiter: two
simultaneous first arrivals both observe no row, and the DATABASE decides which
one wins. See `admission.py` for the transaction algorithm that depends on it.

Revision ID: v012_applied_state_receipts
Revises: v011_deployment_credentials
Create Date: 2026-08-04
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "v012_applied_state_receipts"
down_revision = "v011_deployment_credentials"
branch_labels = None
depends_on = None

_REPORTS = "applied_state_reports"
_ATTEMPTS = "applied_state_receipt_attempts"


def _grants(table: str) -> None:
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO platform_api;")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO app_admin;")
    op.execute(f"REVOKE ALL ON {table} FROM app_user;")


def upgrade() -> None:
    op.create_table(
        _REPORTS,
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("authenticated_deployment_ref", sa.String(200), nullable=False),
        sa.Column("report_id", sa.String(200), nullable=False),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("payload_digest", sa.String(128), nullable=False),
        sa.Column("key_id", sa.String(200), nullable=False),
        sa.Column("first_received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("original_verdict", sa.String(40), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        # Scoped to the PROVEN identity, so one deployment's report_id can never
        # collide with another's. Also the concurrency arbiter.
        sa.UniqueConstraint(
            "authenticated_deployment_ref",
            "report_id",
            name="uq_applied_state_reports_identity_report",
        ),
    )
    _grants(_REPORTS)

    op.create_table(
        _ATTEMPTS,
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("raw_body", sa.LargeBinary(), nullable=True),
        sa.Column(
            "raw_body_truncated",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("raw_body_digest", sa.String(128), nullable=True),
        sa.Column("signature_status", sa.String(20), nullable=False),
        sa.Column("eligibility_at_receipt", sa.String(20), nullable=False),
        sa.Column("key_id", sa.String(200), nullable=True),
        sa.Column("authenticated_deployment_ref", sa.String(200), nullable=True),
        sa.Column("report_id", sa.String(200), nullable=True),
        sa.Column("claimed_deployment_ref", sa.String(200), nullable=True),
        sa.Column("signature", sa.LargeBinary(), nullable=True),
        sa.Column("disposition", sa.String(40), nullable=False),
        sa.Column(
            "report_ref",
            sa.Uuid(),
            sa.ForeignKey(f"{_REPORTS}.id"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        # A proven identity is recorded ONLY alongside a valid signature. This
        # is the claim/proof separation made structural: without it, a row could
        # carry an "authenticated" ref that nothing actually authenticated.
        sa.CheckConstraint(
            "(signature_status = 'valid') OR (authenticated_deployment_ref IS NULL)",
            name="ck_receipt_attempt_identity_needs_valid_signature",
        ),
        # Eligibility is only a meaningful question once the signature verified.
        sa.CheckConstraint(
            "(signature_status = 'valid') OR (eligibility_at_receipt = 'n/a')",
            name="ck_receipt_attempt_eligibility_needs_valid_signature",
        ),
    )
    op.create_index(
        "ix_receipt_attempts_identity_report",
        _ATTEMPTS,
        ["authenticated_deployment_ref", "report_id"],
    )
    op.create_index("ix_receipt_attempts_received_at", _ATTEMPTS, ["received_at"])
    _grants(_ATTEMPTS)


def downgrade() -> None:
    op.drop_index("ix_receipt_attempts_received_at", table_name=_ATTEMPTS)
    op.drop_index("ix_receipt_attempts_identity_report", table_name=_ATTEMPTS)
    op.drop_table(_ATTEMPTS)
    op.drop_table(_REPORTS)
