"""Whether the platform outbox is being drained — read-only, decided here.

`vendor_cp.readiness` and the `relay health` CLI command are both adapters over
this module; the decision about what counts as a stalled relay lives in one
place so the probe and the terminal cannot disagree.

## The distinction this exists to make

An idle relay and a dead relay look identical from the queue when the queue is
empty. They are not the same thing, and a health surface that reports one as the
other is the defect. The asymmetry that resolves it without a heartbeat is that
the fault requires work to exist: an activated agreement WRITES an outbox row,
so if the relay is not running, the row ages and this module sees it. Nothing
queued and nothing overdue means nothing is incomplete, and that is genuinely
ready rather than merely quiet.

## What that leaves uncovered, stated rather than implied

A relay that dies during total quiescence is invisible here until the next
activation. `relay_liveness_during_quiescence_measurable` is `False` and says so
at the point a reader meets it, following the `keyring_uptake_lag_measurable`
precedent in `vendor_cp.licensing.delivery_ops`. Closing it needs a durable
heartbeat the relay stamps each cycle, which needs a table, a migration and a
new writer. That is deliberately deferred to the slice that composes the relay
into the deployment, where the migration, the compose service and the dispatcher
credential land as one change under one authorization — not bought separately
this week to detect a state the compose file already answers.

## A count that could not be taken is `None`

Every count here is `int | None`, and the unobserved value is `None` rather than
`0`. A zero that means "could not query" reads exactly like a zero that means
"nothing is wrong", and it reads that way to a dashboard, an alert rule and an
operator at three in the morning. `RELAY_STATE_UNKNOWN` plus `None` counts can
be mistaken for neither.

## The verdict is over the whole table, the counts single out activation

The relay drains one table. If it is not draining, it is not draining, and the
next activation will be silent whatever is queued right now — so a verdict
scoped to activation events alone would report green during exactly the outage
that makes the next activation disappear. The activation-specific counts are
reported beside it, because which chain is affected is the operator's first
question.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Final

from dotmac_kernel.messaging import OutboxStatus, PlatformOutboxEvent
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vendor_cp.contracts.adapter import ACTIVATED_EVENT_TYPE


class RelayVerdict(str, Enum):
    """The closed vocabulary a relay observation may carry.

    Members, never free text. The readiness probe publishes these values
    unauthenticated, so nothing here may carry a host, a role, a driver message
    or a count — the counts live on `RelayHealth`, which only the authenticated
    operator surface renders.
    """

    #: Nothing is overdue, no lease is abandoned, nothing is dead-lettered.
    #: Includes the genuinely idle case: an empty queue means nothing is
    #: incomplete.
    DRAINING = "relay_draining"
    #: Rows became due at least `overdue_after` ago and are still pending. The
    #: relay is not claiming them.
    ACTIVATION_BACKLOG_OVERDUE = "activation_backlog_overdue"
    #: A worker claimed rows and never settled them. It took the lease and died.
    ACTIVATION_LEASE_STALE = "activation_lease_stale"
    #: Delivery failed `max_attempts` times and the rows are retained as dead
    #: letters. This will not fix itself.
    ACTIVATION_DEAD_LETTERED = "activation_dead_lettered"
    #: The outbox could not be read. Not a green zero, and not a guess.
    RELAY_STATE_UNKNOWN = "relay_state_unknown"


#: Severity order, most severe first. The verdict is the first member whose
#: condition holds. Dead letters outrank a stale lease because they are
#: terminal; a stale lease outranks a backlog because a crashed worker explains
#: the backlog and sends the operator somewhere more specific.
VERDICT_PRECEDENCE: Final[tuple[RelayVerdict, ...]] = (
    RelayVerdict.RELAY_STATE_UNKNOWN,
    RelayVerdict.ACTIVATION_DEAD_LETTERED,
    RelayVerdict.ACTIVATION_LEASE_STALE,
    RelayVerdict.ACTIVATION_BACKLOG_OVERDUE,
    RelayVerdict.DRAINING,
)


@dataclass(frozen=True, slots=True)
class RelayHealth:
    """One observation of the platform outbox, as of an injected `now`.

    Each field is one observation; none is a blend of two, and none is a score.
    """

    verdict: RelayVerdict
    #: `None` means the count could not be taken — never `0`. See the module
    #: docstring.
    pending_total: int | None = None
    overdue_total: int | None = None
    oldest_overdue_age_seconds: int | None = None
    stale_lease_total: int | None = None
    dead_total: int | None = None
    #: The same three observations narrowed to `agreement.activated.v1`, which
    #: is the chain whose incompleteness ADR-0006 and the census name.
    activation_pending: int | None = None
    activation_overdue: int | None = None
    activation_dead: int | None = None
    #: FALSE, and not as a placeholder. A relay that dies while nothing is
    #: queued is undetectable from the queue alone; proving it lives during
    #: quiescence needs a durable heartbeat, a table and a migration, and that
    #: is scoped to the slice that composes the relay into the deployment. A
    #: dashboard reading this field knows the difference between "checked and
    #: fine" and "not checked".
    relay_liveness_during_quiescence_measurable: bool = False

    @property
    def observed(self) -> bool:
        """Whether the outbox answered at all."""
        return self.verdict is not RelayVerdict.RELAY_STATE_UNKNOWN


def relay_health(
    db: Session,
    *,
    now: datetime,
    overdue_after: timedelta,
    stale_lease_after: timedelta,
) -> RelayHealth:
    """Observe the platform outbox as of `now`.

    `now` is injected and never read from the wall clock, so a report is
    reproducible and a test can age a row without sleeping.

    Returns rather than raises: an unreachable database is a NORMAL outcome of
    asking, and a probe that propagated the driver's exception would turn it
    into a 500 in the logs of everything watching. The unreadable case comes
    back as `RELAY_STATE_UNKNOWN` with every count `None`.
    """
    overdue_before = now - overdue_after
    stale_before = now - stale_lease_after
    try:
        pending_total = _count(db, status=OutboxStatus.PENDING)
        dead_total = _count(db, status=OutboxStatus.DEAD)
        overdue_total = _count(
            db, status=OutboxStatus.PENDING, due_at_or_before=overdue_before
        )
        stale_lease_total = _count(
            db, status=OutboxStatus.CLAIMED, leased_at_or_before=stale_before
        )
        oldest = db.scalar(
            select(func.min(PlatformOutboxEvent.available_at)).where(
                PlatformOutboxEvent.status == OutboxStatus.PENDING.value,
                PlatformOutboxEvent.available_at <= overdue_before,
            )
        )
        activation_pending = _count(
            db, status=OutboxStatus.PENDING, event_type=ACTIVATED_EVENT_TYPE
        )
        activation_overdue = _count(
            db,
            status=OutboxStatus.PENDING,
            event_type=ACTIVATED_EVENT_TYPE,
            due_at_or_before=overdue_before,
        )
        activation_dead = _count(
            db, status=OutboxStatus.DEAD, event_type=ACTIVATED_EVENT_TYPE
        )
    except Exception:  # noqa: BLE001 - every failure mode is the same answer
        return RelayHealth(verdict=RelayVerdict.RELAY_STATE_UNKNOWN)

    return RelayHealth(
        verdict=_verdict(
            dead_total=dead_total,
            stale_lease_total=stale_lease_total,
            overdue_total=overdue_total,
        ),
        pending_total=pending_total,
        overdue_total=overdue_total,
        oldest_overdue_age_seconds=_age_seconds(oldest, now=now),
        stale_lease_total=stale_lease_total,
        dead_total=dead_total,
        activation_pending=activation_pending,
        activation_overdue=activation_overdue,
        activation_dead=activation_dead,
    )


def _verdict(
    *, dead_total: int, stale_lease_total: int, overdue_total: int
) -> RelayVerdict:
    """First member of `VERDICT_PRECEDENCE` whose condition holds."""
    if dead_total > 0:
        return RelayVerdict.ACTIVATION_DEAD_LETTERED
    if stale_lease_total > 0:
        return RelayVerdict.ACTIVATION_LEASE_STALE
    if overdue_total > 0:
        return RelayVerdict.ACTIVATION_BACKLOG_OVERDUE
    return RelayVerdict.DRAINING


def _count(
    db: Session,
    *,
    status: OutboxStatus,
    event_type: str | None = None,
    due_at_or_before: datetime | None = None,
    leased_at_or_before: datetime | None = None,
) -> int:
    statement = (
        select(func.count())
        .select_from(PlatformOutboxEvent)
        .where(PlatformOutboxEvent.status == status.value)
    )
    if event_type is not None:
        statement = statement.where(PlatformOutboxEvent.event_type == event_type)
    if due_at_or_before is not None:
        statement = statement.where(
            PlatformOutboxEvent.available_at <= due_at_or_before
        )
    if leased_at_or_before is not None:
        statement = statement.where(
            PlatformOutboxEvent.leased_at <= leased_at_or_before
        )
    return int(db.execute(statement).scalar_one())


def _age_seconds(moment: datetime | None, *, now: datetime) -> int | None:
    """Age in whole seconds, tolerating a naive timestamp from SQLite.

    The integration tier reads real `timestamptz` values; the unit tier may hand
    back a naive one. Assuming `now`'s zone for a naive value is right in both:
    the column is written by Postgres in UTC and `now` is passed in UTC.
    """
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=now.tzinfo)
    return int((now - moment).total_seconds())


__all__ = [
    "VERDICT_PRECEDENCE",
    "RelayHealth",
    "RelayVerdict",
    "relay_health",
]
