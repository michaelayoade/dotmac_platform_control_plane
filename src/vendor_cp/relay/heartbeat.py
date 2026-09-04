"""Stamping and reading the relay's liveness fact.

One row per worker identity, written on every poll — claimed or not. That "or
not" is the entire reason this module exists: a relay with an empty queue does
nothing observable, and before the heartbeat an idle relay and a stopped one
produced identical evidence.

## Written on the delivery connection, never the dispatcher's

`platform_outbox_dispatcher` holds EXECUTE on the kernel's two leasing functions
and no table privilege of any kind. That is the isolation kernel
`0012_platform_outbox` establishes and `v019` deliberately does not erode: it
grants the dispatcher nothing. So the stamp goes through the same `platform_api`
session factory the consumer stages on.

## Upsert, because a heartbeat has no history

`ON CONFLICT ... DO UPDATE`. Appending a row per poll would turn a liveness fact
into a time series nobody reads and a table nobody prunes; the interesting
history — when work actually moved — already lives in `platform_outbox_events`.

## Reading is `max`, and that has a stated limit

`freshest_poll` takes the newest `last_polled_at` across every worker, so a
retired worker identity's stale row cannot produce a false alarm. The cost is
the mirror image: with more than one worker configured, a single dead worker is
invisible while its peers keep the maximum fresh. That is honest for
`replicas = 1`, which is what the descriptor declares, and it is the first thing
that must change if the relay is ever scaled — per-worker liveness is a
different query, not a bigger number.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from vendor_cp.relay.models import RelayHeartbeat


@dataclass(frozen=True, slots=True)
class HeartbeatState:
    """What the heartbeat table says, as of a read.

    `observed` is separate from the timestamps for the reason every count in
    `vendor_cp.relay.health` is `int | None`: a table that could not be read and
    a table with no rows are different facts, and only one of them means the
    relay has never reported.
    """

    observed: bool
    freshest_poll: datetime | None
    freshest_claim: datetime | None

    @property
    def ever_reported(self) -> bool:
        """Whether any worker has ever stamped. False on a fresh database."""
        return self.freshest_poll is not None


def stamp(db: Session, *, worker_id: str, now: datetime, claimed: bool) -> None:
    """Record one poll. `claimed` says whether it actually leased anything.

    RECEIVES a session and only executes — the caller owns the transaction, the
    same contract every kernel messaging function follows.

    `last_claimed_at` advances only on a poll that claimed, so an idle relay
    keeps a fresh `last_polled_at` and a `last_claimed_at` that stands still.
    Those two moving independently is what lets a reader tell "alive with
    nothing to do" from "alive and not getting through the queue".
    """
    statement = pg_insert(RelayHeartbeat).values(
        worker_id=worker_id,
        started_at=now,
        last_polled_at=now,
        last_claimed_at=now if claimed else None,
    )
    db.execute(
        statement.on_conflict_do_update(
            index_elements=[RelayHeartbeat.worker_id],
            set_={
                "last_polled_at": statement.excluded.last_polled_at,
                # COALESCE, not the excluded value: a poll that claimed nothing
                # must not erase the last time this worker did claim. Writing
                # the excluded NULL here would make every idle poll look like a
                # worker that has never claimed since it started.
                "last_claimed_at": func.coalesce(
                    statement.excluded.last_claimed_at,
                    RelayHeartbeat.last_claimed_at,
                ),
            },
        )
    )


def read(db: Session) -> HeartbeatState:
    """The freshest poll and claim across every worker identity.

    Returns rather than raises: an unreadable heartbeat is a NORMAL outcome of
    asking — a revoked privilege, a table not yet migrated, an unreachable
    server — and the caller turns it into an explicit unknown rather than into a
    500 in the logs of everything watching.
    """
    try:
        row = db.execute(
            select(
                func.max(RelayHeartbeat.last_polled_at),
                func.max(RelayHeartbeat.last_claimed_at),
            )
        ).one()
    except Exception:  # noqa: BLE001 - every failure mode is the same answer
        return HeartbeatState(observed=False, freshest_poll=None, freshest_claim=None)
    return HeartbeatState(observed=True, freshest_poll=row[0], freshest_claim=row[1])


__all__ = ["HeartbeatState", "read", "stamp"]
