"""The relay's durable heartbeat — a PLATFORM catalog table.

One row per worker identity, updated in place each poll. It exists to answer the
one question the queue cannot: **is the relay running right now, when there is
nothing for it to do?**

## Why this table had to exist, and why it deliberately did not before

Slice 1 composed the drain and derived its health entirely from the outbox,
using an asymmetry: the fault requires work to exist, so an activated agreement
writes a row and a relay that is not running lets that row age. That covers the
defect and needs no table. What it cannot see is a relay that dies while the
queue is EMPTY — and slice 1 shipped
`RelayHealth.relay_liveness_during_quiescence_measurable = False` saying exactly
that, rather than omitting the dimension.

The deferral was correct while no relay ran in production: during total
quiescence the relay's absence was already knowable from the compose file, which
named no relay service. **This slice is what stops that being true.** Once a
relay is composed into the deployment, "the compose file says so" stops
answering "is it alive", and the heartbeat is what replaces it.

## Shape, and what is deliberately absent

Four facts and nothing else. No attempt counter, no lease, no backoff state, no
last-error column: all of those belong to `platform_outbox_events` and the
kernel's relay engine owns them. A second copy of the drain's state living here
is the drift this table's narrowness is designed to make obvious.

`last_claimed_at` is separate from `last_polled_at` on purpose. A relay that
polls and never claims is healthy and idle; a relay that has not polled is dead.
Collapsing them would make an idle relay indistinguishable from a stopped one,
which is the whole subject.

Written on the `platform_api` connection, never the dispatcher's. The dispatcher
role holds EXECUTE on two kernel functions and no table privilege of any kind,
and that is the isolation property this table must not erode: `v019` grants it
nothing.

Import-safe: touches only `Base.metadata`, never the engine (deny-case D1).
"""

from __future__ import annotations

from datetime import datetime

from dotmac_kernel import Base
from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column


class RelayHeartbeat(Base):
    """One relay worker's most recent poll.

    Keyed by `worker_id` rather than a surrogate id: there is exactly one live
    row per worker identity and the natural key IS the identity. A surrogate key
    would allow two rows for one worker, which is a state with no meaning.

    No `TimestampMixin`. `created_at`/`updated_at` would duplicate `started_at`
    and `last_polled_at` with weaker meanings — an `updated_at` that moves for
    any write is not a heartbeat, it is a modification time, and a reader cannot
    tell which one it is looking at.
    """

    __tablename__ = "relay_heartbeats"

    worker_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    #: When this worker identity first reported. A restart moves it, so a
    #: flapping worker is visible as a moving `started_at` rather than only as a
    #: gap nobody was watching during.
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    #: Every poll, claimed or not. This is the liveness fact.
    last_polled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    #: Only polls that actually leased something. `None` for a worker that has
    #: run since start and never had work — which is a NORMAL state and must not
    #: read as a fault.
    last_claimed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


__all__ = ["RelayHeartbeat"]
