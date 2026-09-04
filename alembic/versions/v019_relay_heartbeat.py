"""The relay's durable heartbeat — what makes quiescent liveness measurable.

One table, platform-plane like every other Vendor table: no `tenant_id`, no RLS,
GRANTed to `platform_api`/`app_admin` and REVOKEd from `app_user`, which is what
the isolation is on this plane.

## Why this arrives now and not with the relay itself

The relay's health was derived entirely from the outbox in the slice that
composed it, on an asymmetry that genuinely holds: the fault requires work to
exist, so an activated agreement writes a row and a relay that is not running
lets that row age past its window. That leaves exactly one gap — a relay that
dies while the queue is EMPTY — and the shipped `RelayHealth` declared it
unmeasured rather than omitting it.

The deferral had a premise: while no relay ran in production, its absence during
quiescence was already knowable from the compose file, which named no relay
service. The slice this revision belongs to composes that service, so the
premise dies here. A deferral whose premise has evaporated is the exemption
shape `dotmac_starter_mt` ADR-0018 refuses, so it is lifted in the same change
that kills it rather than left describing nothing.

## What this table must NOT become

No attempt counter, no lease, no backoff, no last error. `platform_outbox_events`
holds all of that and the kernel's relay engine owns it; a second copy here
would be a parallel record of the drain's state with no writer contract. Four
columns, and the narrowness is the point.

## The dispatcher gets nothing

`platform_outbox_dispatcher` holds EXECUTE on `claim_platform_outbox_batch` and
`settle_platform_outbox_event` and no table privilege of any kind — that is the
isolation kernel `0012_platform_outbox` establishes, and the heartbeat must not
erode it. The heartbeat is written on the `platform_api` connection the relay
already opens for delivery, so no grant to the dispatcher is made here and
`tests/migration/test_platform_relay_drain.py` drives the refusal.

Revision ID: v019_relay_heartbeat
Revises: v018_licence_delivery_intents
Create Date: 2026-09-04
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "v019_relay_heartbeat"
down_revision = "v018_licence_delivery_intents"
branch_labels = None
depends_on = None

_TABLE = "public.relay_heartbeats"


def upgrade() -> None:
    op.create_table(
        "relay_heartbeats",
        # The worker identity IS the key. A surrogate id would permit two rows
        # for one worker, which is a state with no meaning.
        sa.Column("worker_id", sa.String(length=200), primary_key=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_polled_at", sa.DateTime(timezone=True), nullable=False),
        # NULL is a normal state: a worker that has run since start and never
        # had anything to claim. It must not read as a fault.
        sa.Column("last_claimed_at", sa.DateTime(timezone=True), nullable=True),
        # A claim cannot predate the start of the worker that made it, and a
        # worker cannot have claimed later than it last polled — it claims
        # DURING a poll. Both are cheap and both catch a clock or a writer that
        # has gone wrong in a way a reader would otherwise trust.
        sa.CheckConstraint(
            "last_polled_at >= started_at",
            name="ck_relay_heartbeat_poll_not_before_start",
        ),
        sa.CheckConstraint(
            "last_claimed_at IS NULL OR "
            "(last_claimed_at >= started_at AND last_claimed_at <= last_polled_at)",
            name="ck_relay_heartbeat_claim_within_run",
        ),
    )
    # Health asks for the freshest poll across every worker. Small table, but
    # the index keeps that a lookup rather than a scan that grows with the
    # number of worker identities the deployment has ever used.
    op.create_index(
        "ix_relay_heartbeats_last_polled_at",
        "relay_heartbeats",
        ["last_polled_at"],
    )
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON {_TABLE} TO platform_api;")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {_TABLE} TO app_admin;")
    op.execute(f"REVOKE ALL ON {_TABLE} FROM app_user;")
    # No grant to `platform_outbox_dispatcher`, stated rather than merely
    # absent. It holds EXECUTE on two functions and no table privilege, and the
    # heartbeat is written on the delivery connection precisely so that stays
    # true.


def downgrade() -> None:
    op.drop_index("ix_relay_heartbeats_last_polled_at", table_name="relay_heartbeats")
    op.drop_table("relay_heartbeats")
