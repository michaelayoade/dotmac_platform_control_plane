"""The readiness decision, in one place, owned by a service.

`router.py` is a thin adapter under hard rule 6; the decision — what is checked,
what counts as ready, and what an operator is told — lives here.

## What it checks, and what it deliberately does not

One dependency, checked one way: the single control-plane database answers
`SELECT 1` on the session the kernel hands out. That is the narrowest question
whose answer changes what the process can do, and it is deliberately not a
health SCORE. A readiness probe that aggregated several subsystems into a
number would make "ready" mean something different on different days.

It also does not check liveness. `/health` answers that, the kernel owns it,
and a readiness route that also reported liveness would give an orchestrator two
answers to one question.

## Why the report carries no detail

`ReadinessReport.detail` is a fixed member of a closed vocabulary, never an
exception string. An unauthenticated probe that echoed a driver error would
publish the database host, the role name and the failure mode to anyone who
could reach the port. The operator's diagnosis comes from the container's own
logs, which already hold the exception; the probe's job is to say ready or not.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Final

from sqlalchemy import text
from sqlalchemy.orm import Session


class ReadinessDetail(str, Enum):
    """The closed vocabulary a probe response may carry.

    Members, not free text — see the module docstring. A caller may branch on
    these; nothing here ever reaches a log aggregator carrying a hostname.
    """

    READY = "ready"
    DATABASE_UNREACHABLE = "database_unreachable"


@dataclass(frozen=True, slots=True)
class ReadinessReport:
    """Ready or not, and the one word that says which."""

    ready: bool
    detail: ReadinessDetail


#: The cheapest statement that proves a session can round-trip to the database.
#: Deliberately not a catalogue query: a probe that read `pg_class` on every
#: orchestrator poll would be a load source of its own.
PROBE: Final[str] = "SELECT 1"


def check_readiness(db: Session) -> ReadinessReport:
    """Can this process reach the one database it owns?

    Returns rather than raises. A readiness probe that propagated the driver's
    exception would turn an expected, transient answer into a 500 and an error
    in the logs of everything watching — the unreachable case is a NORMAL
    outcome of asking, which is the whole reason the question is worth asking.
    """
    try:
        db.execute(text(PROBE))
    except Exception:  # noqa: BLE001 — every failure mode is the same answer
        return ReadinessReport(ready=False, detail=ReadinessDetail.DATABASE_UNREACHABLE)
    return ReadinessReport(ready=True, detail=ReadinessDetail.READY)


__all__ = ["PROBE", "ReadinessDetail", "ReadinessReport", "check_readiness"]
