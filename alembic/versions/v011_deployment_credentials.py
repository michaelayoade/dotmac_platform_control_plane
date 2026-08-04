"""Vendor lineage — deployment credentials and possession challenges (V6).

The vendor half of ADR-0007. Creates the registry that turns
`authenticated_deployment_ref=None` into a PROVEN identity, so `active` becomes
reachable. It changes nothing about what activation means.

Two constraints carry the security argument, and both are enforced by the
DATABASE rather than by a service check:

- `key_id` unique across ALL states, including revoked. Revocation is terminal
  (ADR-0007 §6); a partial index excluding revoked rows would permit exactly
  the reinstatement the rule forbids.
- `public_key_fingerprint` unique globally. Signing `key_id` into the envelope
  makes the §4 substitution attack unexploitable; this makes its precondition
  unreachable.

`status` is a REBUILDABLE PROJECTION of the three timestamps, not an
independent authority, and a CHECK constraint ties them together so a direct
SQL edit cannot leave a row reading `active` with `revoked_at` set. The
timestamps are authoritative because admission is decided for a report received
at some PAST instant, which a status column can never answer.

ALL THREE timeline columns are created here even though only `activated_at` is
written by this slice: the eligibility predicate spans slices, and slice 3 must
add transitions rather than retrofit the schema its own rule depends on.

Revision ID: v011_deployment_credentials
Revises: v010_delivery_hardening
Create Date: 2026-08-04
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "v011_deployment_credentials"
down_revision = "v010_delivery_hardening"
branch_labels = None
depends_on = None

_CREDENTIALS = "deployment_credentials"
_CHALLENGES = "deployment_challenges"

# `status` must equal what the timestamps say. Ordered most-terminal first,
# because revocation outranks retirement: a credential that was retired and
# then revoked is revoked.
_STATUS_MATCHES_TIMESTAMPS = """
    (status = 'revoked' AND revoked_at IS NOT NULL)
 OR (status = 'retired' AND retired_at IS NOT NULL AND revoked_at IS NULL)
 OR (status = 'active'  AND activated_at IS NOT NULL
        AND retired_at IS NULL AND revoked_at IS NULL)
 OR (status = 'pending' AND activated_at IS NULL
        AND retired_at IS NULL AND revoked_at IS NULL)
"""


def _grants(table: str) -> None:
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO platform_api;")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO app_admin;")
    # Platform catalog: a product data plane's role has no business reading
    # credential state, let alone writing it.
    op.execute(f"REVOKE ALL ON {table} FROM app_user;")


def upgrade() -> None:
    op.create_table(
        _CREDENTIALS,
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("key_id", sa.String(200), nullable=False),
        sa.Column("deployment_ref", sa.String(200), nullable=False),
        sa.Column("public_key_b64", sa.String(200), nullable=False),
        sa.Column("public_key_fingerprint", sa.String(128), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.String(200), nullable=True),
        sa.Column("registered_by_admin_id", sa.Uuid(), nullable=True),
        sa.Column("enrollment_authority", sa.String(60), nullable=False),
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
        sa.UniqueConstraint("key_id", name="uq_deployment_credentials_key_id"),
        sa.UniqueConstraint(
            "public_key_fingerprint", name="uq_deployment_credentials_fingerprint"
        ),
        sa.CheckConstraint(
            _STATUS_MATCHES_TIMESTAMPS, name="ck_deployment_credentials_status_timeline"
        ),
    )
    op.create_index(
        "ix_deployment_credentials_deployment_ref", _CREDENTIALS, ["deployment_ref"]
    )
    _grants(_CREDENTIALS)

    op.create_table(
        _CHALLENGES,
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("challenge_id", sa.String(200), nullable=False),
        sa.Column(
            "credential_id",
            sa.Uuid(),
            sa.ForeignKey(f"{_CREDENTIALS}.id"),
            nullable=False,
        ),
        sa.Column("key_id", sa.String(200), nullable=False),
        sa.Column("deployment_ref", sa.String(200), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_reason", sa.String(40), nullable=True),
        sa.Column("failed_attempts", sa.Integer(), nullable=False, server_default="0"),
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
        sa.UniqueConstraint(
            "challenge_id", name="uq_deployment_challenges_challenge_id"
        ),
        # A consumed challenge must say WHY — "this proved possession" and "a
        # sibling did" are different facts an operator needs to tell apart.
        sa.CheckConstraint(
            "(consumed_at IS NULL AND consumed_reason IS NULL)"
            " OR (consumed_at IS NOT NULL AND consumed_reason IS NOT NULL)",
            name="ck_deployment_challenges_consumed_pair",
        ),
    )
    op.create_index(
        "ix_deployment_challenges_credential", _CHALLENGES, ["credential_id"]
    )
    _grants(_CHALLENGES)


def downgrade() -> None:
    op.drop_index("ix_deployment_challenges_credential", table_name=_CHALLENGES)
    op.drop_table(_CHALLENGES)
    op.drop_index("ix_deployment_credentials_deployment_ref", table_name=_CREDENTIALS)
    op.drop_table(_CREDENTIALS)
