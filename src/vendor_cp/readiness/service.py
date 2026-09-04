"""The readiness decision, in one place, owned by a service.

`router.py` is a thin adapter under hard rule 6; the decision — what is checked,
what counts as ready, and what an operator is told — lives here.

## What it checks, and what it deliberately does not

Two questions, asked in order, kept apart because they have different repairs.

1. **Can this process reach the one control-plane database?** `SELECT 1` on the
   session the kernel hands out. The narrowest statement whose answer changes
   what the process can do.
2. **Is the relay alive, and is work moving?** Delegated whole to
   `vendor_cp.relay.health`, which owns that decision so the probe and the
   `relay health` terminal command cannot disagree. It is asked SECOND and only
   when the first answered, so an unreachable database is reported as an
   unreachable database rather than as an unreadable outbox. Three states reach
   this probe as distinct members — stopped, wedged and merely behind — because
   they need three different first actions from whoever is paged.

The second question is here because readiness that reported only database
liveness was the measured gap: an activated agreement enqueues an outbox row
atomically with its transition, and with nothing draining that row the agreement
looks complete while producing no entitlement allocation. A deployment in that
state cannot do what it exists to do, which is precisely what readiness means.

Still not a health SCORE. `ReadinessReport.detail` is one member of a closed
vocabulary; there is no number and no aggregate, because a probe that blended
several subsystems would make "ready" mean something different on different
days. The counts and ages live on `vendor_cp.relay.health.RelayHealth` and are
rendered only by the authenticated operator surface.

It also does not check liveness. `/health` answers that, the kernel owns it, and
a readiness route that also reported liveness would give an orchestrator two
answers to one question.

## Why the report carries no detail beyond a member

`ReadinessReport.detail` is a fixed member of a closed vocabulary, never an
exception string and never a count. An unauthenticated probe that echoed a
driver error would publish the database host, the role name and the failure
mode to anyone who could reach the port; one that published a queue depth would
tell them how much work the control plane is carrying. The operator's diagnosis
comes from `dotmac-platform relay health` and the container's own logs, which
already hold the exception; the probe's job is to say ready or not.

## Cost

Five counting statements against `platform_outbox_events`, each restricted by
`status` and served by the kernel's own
`ix_platform_outbox_events_status_available_at` index, on top of the existing
`SELECT 1`. Still deliberately not a catalogue query: nothing here reads
`pg_class`, and nothing scans a business table.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Final

from sqlalchemy import text
from sqlalchemy.orm import Session

from vendor_cp.relay.health import RelayVerdict, relay_health


class ReadinessDetail(str, Enum):
    """The closed vocabulary a probe response may carry.

    Members, not free text — see the module docstring. A caller may branch on
    these; nothing here ever reaches a log aggregator carrying a hostname.

    Every member below `DATABASE_UNREACHABLE` carries the SAME STRING as the
    `RelayVerdict` it restates. Two vocabularies for one fact would drift, and
    `test_readiness.py` compares the two sets in both directions rather than
    trusting that they were kept aligned.
    """

    READY = "ready"
    DATABASE_UNREACHABLE = "database_unreachable"
    RELAY_NOT_RUNNING = RelayVerdict.RELAY_NOT_RUNNING.value
    RELAY_WEDGED = RelayVerdict.RELAY_WEDGED.value
    ACTIVATION_BACKLOG_OVERDUE = RelayVerdict.ACTIVATION_BACKLOG_OVERDUE.value
    ACTIVATION_LEASE_STALE = RelayVerdict.ACTIVATION_LEASE_STALE.value
    ACTIVATION_DEAD_LETTERED = RelayVerdict.ACTIVATION_DEAD_LETTERED.value
    RELAY_STATE_UNKNOWN = RelayVerdict.RELAY_STATE_UNKNOWN.value


#: TOTAL over `RelayVerdict`. A verdict with no entry here would fall through to
#: some default, and the default a reader would reach for is "ready" — which is
#: how a new failure mode becomes invisible on the day it is introduced.
#: `test_readiness.py` asserts the mapping covers every member.
_FROM_RELAY: Final[dict[RelayVerdict, ReadinessDetail]] = {
    RelayVerdict.DRAINING: ReadinessDetail.READY,
    RelayVerdict.RELAY_NOT_RUNNING: ReadinessDetail.RELAY_NOT_RUNNING,
    RelayVerdict.RELAY_WEDGED: ReadinessDetail.RELAY_WEDGED,
    RelayVerdict.ACTIVATION_BACKLOG_OVERDUE: (
        ReadinessDetail.ACTIVATION_BACKLOG_OVERDUE
    ),
    RelayVerdict.ACTIVATION_LEASE_STALE: ReadinessDetail.ACTIVATION_LEASE_STALE,
    RelayVerdict.ACTIVATION_DEAD_LETTERED: ReadinessDetail.ACTIVATION_DEAD_LETTERED,
    RelayVerdict.RELAY_STATE_UNKNOWN: ReadinessDetail.RELAY_STATE_UNKNOWN,
}


@dataclass(frozen=True, slots=True)
class ReadinessReport:
    """Ready or not, and the one word that says which."""

    ready: bool
    detail: ReadinessDetail


#: The cheapest statement that proves a session can round-trip to the database.
#: Deliberately not a catalogue query: a probe that read `pg_class` on every
#: orchestrator poll would be a load source of its own.
PROBE: Final[str] = "SELECT 1"


def check_readiness(
    db: Session,
    *,
    now: datetime,
    overdue_after: timedelta,
    stale_lease_after: timedelta,
    heartbeat_stale_after: timedelta,
    settled_within: timedelta,
    relay_expected: bool = True,
) -> ReadinessReport:
    """Can this process reach its database, and is its outbox being drained?

    Returns rather than raises. A readiness probe that propagated the driver's
    exception would turn an expected, transient answer into a 500 and an error
    in the logs of everything watching — the unreachable case is a NORMAL
    outcome of asking, which is the whole reason the question is worth asking.

    `now` and both windows are injected rather than read here, so the answer is
    reproducible and the thresholds stay the deployment's configuration rather
    than this module's opinion.
    """
    try:
        db.execute(text(PROBE))
    except Exception:  # noqa: BLE001 - every failure mode is the same answer
        return ReadinessReport(ready=False, detail=ReadinessDetail.DATABASE_UNREACHABLE)

    health = relay_health(
        db,
        now=now,
        overdue_after=overdue_after,
        stale_lease_after=stale_lease_after,
        heartbeat_stale_after=heartbeat_stale_after,
        settled_within=settled_within,
        relay_expected=relay_expected,
    )
    detail = _FROM_RELAY[health.verdict]
    return ReadinessReport(ready=detail is ReadinessDetail.READY, detail=detail)


__all__ = ["PROBE", "ReadinessDetail", "ReadinessReport", "check_readiness"]
