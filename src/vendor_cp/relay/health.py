"""Whether the platform outbox is being drained — read-only, decided here.

`vendor_cp.readiness` and the `relay health` CLI command are both adapters over
this module; the decision about what counts as a stalled relay lives in one
place so the probe and the terminal cannot disagree.

## Three states, and the third is the one that hides

"Is it running" and "is work moving" are different questions, and a heartbeat
only answers the first. A relay can be alive, polling, claiming batches and
settling NOTHING — every delivery raising, every row going back to pending.
That reads as healthy to any liveness check, which is exactly why it needs a
name of its own.

* **idle but healthy** (`DRAINING`) — heartbeat fresh, nothing overdue. An
  empty queue means nothing is incomplete; this is genuinely ready rather than
  merely quiet.
* **stopped** (`RELAY_NOT_RUNNING`) — no heartbeat at all, or the freshest is
  older than the window. Nothing moves until someone starts it.
* **wedged** (`RELAY_WEDGED`) — heartbeat fresh, work overdue, and NOTHING has
  settled inside the window. Alive and not getting through.
* **behind** (`ACTIVATION_BACKLOG_OVERDUE`) — heartbeat fresh, work overdue,
  but deliveries ARE settling. A long queue, not a stuck one.

The last two are separated by the freshest `sent_at`, and that separation is the
point: collapsing them lets a wedge hide behind "it is catching up", and sends
an operator to look at throughput when in fact every delivery is failing.

## Two independent sources, and neither is inferred from the other

The heartbeat says whether the process lives. The outbox says whether work
moves. A verdict is only ever formed from what was actually READ: if either
source could not be read, the answer is `RELAY_STATE_UNKNOWN` and every count is
`None`. Nothing here concludes "alive" from an empty queue, or "draining" from a
fresh heartbeat.

## The deferral was LIFTED by the slice that killed its premise

The first slice derived everything from the queue, on an asymmetry that holds:
the fault requires work to exist, so an activated agreement writes a row and a
relay that is not running lets it age. That left exactly one gap — a relay dying
while the queue is empty — and it shipped
`relay_liveness_during_quiescence_measurable = False` naming the gap rather than
omitting the dimension.

Its premise was that while no relay ran in production, absence during quiescence
was already knowable from the compose file, which named no relay service.
`v019_relay_heartbeat` and the production relay service kill that premise in the
same change, so the flag is `True` here and the heartbeat is what answers. An
exemption whose premise has evaporated is the shape `dotmac_starter_mt` ADR-0018
refuses; it is lifted in the change that killed it rather than left describing
nothing.

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
from vendor_cp.relay import heartbeat


class RelayVerdict(str, Enum):
    """The closed vocabulary a relay observation may carry.

    Members, never free text. The readiness probe publishes these values
    unauthenticated, so nothing here may carry a host, a role, a driver message
    or a count — the counts live on `RelayHealth`, which only the authenticated
    operator surface renders.
    """

    #: Alive, and nothing is overdue. Includes the genuinely idle case: an empty
    #: queue means nothing is incomplete.
    DRAINING = "relay_draining"
    #: No heartbeat, or the freshest is older than the window. STOPPED.
    RELAY_NOT_RUNNING = "relay_not_running"
    #: Alive, work overdue, and nothing settled inside the window. WEDGED —
    #: claiming and not getting through. The state a liveness check calls
    #: healthy.
    RELAY_WEDGED = "relay_wedged"
    #: Alive, work overdue, and deliveries ARE settling. BEHIND, not stuck.
    ACTIVATION_BACKLOG_OVERDUE = "activation_backlog_overdue"
    #: A worker claimed rows and never settled them. It took the lease and died.
    ACTIVATION_LEASE_STALE = "activation_lease_stale"
    #: Delivery failed `max_attempts` times and the rows are retained as dead
    #: letters. This will not fix itself.
    ACTIVATION_DEAD_LETTERED = "activation_dead_lettered"
    #: A source could not be read. Not a green zero, and not a guess.
    RELAY_STATE_UNKNOWN = "relay_state_unknown"


#: Severity order, most severe first. The verdict is the first member whose
#: condition holds.
#:
#: `RELAY_NOT_RUNNING` outranks the two stall verdicts because it EXPLAINS them:
#: a stopped relay produces an overdue backlog and an abandoned lease as
#: symptoms, and reporting a symptom above its cause sends an operator to the
#: wrong place. `ACTIVATION_DEAD_LETTERED` outranks even that, because it is
#: terminal — starting the relay will not clear a dead letter, and it is the one
#: state that needs a human rather than a restart.
VERDICT_PRECEDENCE: Final[tuple[RelayVerdict, ...]] = (
    RelayVerdict.RELAY_STATE_UNKNOWN,
    RelayVerdict.ACTIVATION_DEAD_LETTERED,
    RelayVerdict.RELAY_NOT_RUNNING,
    RelayVerdict.ACTIVATION_LEASE_STALE,
    RelayVerdict.RELAY_WEDGED,
    RelayVerdict.ACTIVATION_BACKLOG_OVERDUE,
    RelayVerdict.DRAINING,
)


@dataclass(frozen=True, slots=True)
class RelayHealth:
    """One observation of the relay, as of an injected `now`.

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
    #: Age of the freshest heartbeat, and of the freshest settled delivery.
    #: `None` for "never" — which is a different fact from "long ago" and the
    #: two must not be collapsed: a relay that has never reported and one that
    #: reported an hour ago need different first questions.
    heartbeat_age_seconds: int | None = None
    last_settled_age_seconds: int | None = None
    #: Whether any worker identity has ever stamped a heartbeat.
    relay_ever_reported: bool | None = None
    #: Whether THIS deployment can detect a relay dying while nothing is
    #: queued. True since `v019_relay_heartbeat` wherever a relay is composed;
    #: False where none is, because a deployment with no relay cannot measure
    #: one's liveness and saying otherwise would be the placeholder this field
    #: exists to avoid. It was False everywhere for exactly as long as no relay
    #: ran in production, when the compose file answered the question instead.
    relay_liveness_during_quiescence_measurable: bool = True

    @property
    def observed(self) -> bool:
        """Whether both sources answered."""
        return self.verdict is not RelayVerdict.RELAY_STATE_UNKNOWN


def relay_health(
    db: Session,
    *,
    now: datetime,
    overdue_after: timedelta,
    stale_lease_after: timedelta,
    heartbeat_stale_after: timedelta,
    settled_within: timedelta,
    relay_expected: bool = True,
) -> RelayHealth:
    """Observe the relay as of `now`, from the heartbeat and the outbox.

    `relay_expected` states this deployment's COMPOSITION, not whether to check.
    A deployment that runs no relay cannot be asked whether its relay is alive,
    and answering `RELAY_NOT_RUNNING` there would be true and useless — it would
    make a single-container artifact permanently unready for not running a
    service it was never given. With it False the verdict falls back to the
    queue-derived signals, which need no heartbeat and still turn red on an
    ageing backlog, and `relay_liveness_during_quiescence_measurable` reports
    False because that is then the truth.

    `now` is injected and never read from the wall clock, so a report is
    reproducible and a test can age a row without sleeping.

    Returns rather than raises: an unreachable database is a NORMAL outcome of
    asking, and a probe that propagated the driver's exception would turn it
    into a 500 in the logs of everything watching. The unreadable case comes
    back as `RELAY_STATE_UNKNOWN` with every count `None`.
    """
    overdue_before = now - overdue_after
    stale_before = now - stale_lease_after

    beat = heartbeat.read(db)
    if relay_expected and not beat.observed:
        # The heartbeat could not be read. The outbox might still answer, and it
        # is tempting to report what it says — but every verdict below turns on
        # whether the relay is alive, and a verdict formed without that is a
        # guess wearing a member name.
        return RelayHealth(verdict=RelayVerdict.RELAY_STATE_UNKNOWN)

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
        last_settled = db.scalar(select(func.max(PlatformOutboxEvent.sent_at)))
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

    heartbeat_age = _age_seconds(beat.freshest_poll, now=now)
    settled_age = _age_seconds(last_settled, now=now)
    return RelayHealth(
        verdict=_verdict(
            dead_total=dead_total,
            stale_lease_total=stale_lease_total,
            overdue_total=overdue_total,
            heartbeat_age=heartbeat_age,
            settled_age=settled_age,
            heartbeat_stale_after=heartbeat_stale_after,
            settled_within=settled_within,
            relay_expected=relay_expected,
        ),
        pending_total=pending_total,
        overdue_total=overdue_total,
        oldest_overdue_age_seconds=_age_seconds(oldest, now=now),
        stale_lease_total=stale_lease_total,
        dead_total=dead_total,
        activation_pending=activation_pending,
        activation_overdue=activation_overdue,
        activation_dead=activation_dead,
        heartbeat_age_seconds=heartbeat_age,
        last_settled_age_seconds=settled_age,
        relay_ever_reported=beat.ever_reported if beat.observed else None,
        relay_liveness_during_quiescence_measurable=relay_expected,
    )


def _verdict(
    *,
    dead_total: int,
    stale_lease_total: int,
    overdue_total: int,
    heartbeat_age: int | None,
    settled_age: int | None,
    heartbeat_stale_after: timedelta,
    settled_within: timedelta,
    relay_expected: bool,
) -> RelayVerdict:
    """First member of `VERDICT_PRECEDENCE` whose condition holds."""
    if dead_total > 0:
        return RelayVerdict.ACTIVATION_DEAD_LETTERED
    if relay_expected:
        # `None` is "never reported", which is not the same fact as "reported
        # long ago" but has the same verdict: nothing is draining this queue.
        if (
            heartbeat_age is None
            or heartbeat_age > heartbeat_stale_after.total_seconds()
        ):
            return RelayVerdict.RELAY_NOT_RUNNING
    if stale_lease_total > 0:
        return RelayVerdict.ACTIVATION_LEASE_STALE
    if overdue_total > 0:
        if not relay_expected:
            # No relay is composed here, so nothing has proved it is alive and
            # WEDGED — which asserts exactly that — may not be claimed. The
            # backlog is real and still red; only the diagnosis is weaker.
            return RelayVerdict.ACTIVATION_BACKLOG_OVERDUE
        # Alive, with work that should have moved. WEDGED unless something
        # actually settled inside the window — the one signal that separates a
        # relay failing every delivery from a relay merely behind a long queue.
        settled_recently = (
            settled_age is not None and settled_age <= settled_within.total_seconds()
        )
        if settled_recently:
            return RelayVerdict.ACTIVATION_BACKLOG_OVERDUE
        return RelayVerdict.RELAY_WEDGED
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
