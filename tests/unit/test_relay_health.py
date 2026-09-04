"""The relay observation: what it says, and what it refuses to say.

SCOPE. This file exercises the DECISION over a set of outbox rows — verdict
precedence, the closed vocabulary, and the refusal to answer with a zero it did
not measure. It runs on the in-memory SQLite kit and therefore proves NOTHING
about the drain: `claim_platform_outbox_batch` and `settle_platform_outbox_event`
are Postgres `SECURITY DEFINER` functions and do not exist here. The drain proof
is `tests/migration/test_platform_relay_drain.py` and must not be cited from
this file's greenness.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from dotmac_kernel.messaging import OutboxStatus, PlatformOutboxEvent
from dotmac_kernel.testing import create_test_engine, isolated_session
from sqlalchemy.orm import Session

from vendor_cp.contracts.adapter import ACTIVATED_EVENT_TYPE
from vendor_cp.relay.health import (
    VERDICT_PRECEDENCE,
    RelayHealth,
    RelayVerdict,
    relay_health,
)

NOW = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)
OVERDUE_AFTER = timedelta(seconds=300)
STALE_AFTER = timedelta(seconds=300)


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as session:
            yield session
    finally:
        engine.dispose()


def _event(
    db: Session,
    *,
    status: OutboxStatus,
    available_at: datetime,
    event_type: str = ACTIVATED_EVENT_TYPE,
    leased_at: datetime | None = None,
) -> PlatformOutboxEvent:
    row = PlatformOutboxEvent(
        event_type=event_type,
        payload={"agreement_id": str(uuid.uuid4())},
        status=status.value,
        attempts=0,
        available_at=available_at,
        leased_at=leased_at,
        leased_by="worker-1" if leased_at else None,
    )
    db.add(row)
    db.flush()
    return row


def _observe(db: Session, *, now: datetime = NOW) -> RelayHealth:
    return relay_health(
        db, now=now, overdue_after=OVERDUE_AFTER, stale_lease_after=STALE_AFTER
    )


# ── the distinction this module exists to make ──────────────────────────────


def test_an_empty_queue_is_draining_not_a_fault(db: Session) -> None:
    """Nothing queued means nothing incomplete. Idle is genuinely ready.

    The paired case below is what makes this a distinction rather than an
    unconditional pass.
    """
    health = _observe(db)
    assert health.verdict is RelayVerdict.DRAINING
    assert health.pending_total == 0
    assert health.activation_pending == 0


def test_an_activation_left_pending_past_the_window_is_a_stalled_relay(
    db: Session,
) -> None:
    """The paired case. An activated agreement WROTE this row; nothing drained
    it; the deployment must stop claiming it can serve."""
    _event(db, status=OutboxStatus.PENDING, available_at=NOW - timedelta(seconds=600))
    health = _observe(db)
    assert health.verdict is RelayVerdict.ACTIVATION_BACKLOG_OVERDUE
    assert health.overdue_total == 1
    assert health.activation_overdue == 1
    assert health.oldest_overdue_age_seconds == 600


def test_a_pending_event_inside_the_window_is_not_yet_a_stall(db: Session) -> None:
    """SENSITIVITY for the window itself. A row that became due a moment ago is
    a relay about to claim it, or a retry backing off — not a fault. A guard
    that fired here would be red permanently and learned to be ignored."""
    _event(db, status=OutboxStatus.PENDING, available_at=NOW - timedelta(seconds=10))
    health = _observe(db)
    assert health.verdict is RelayVerdict.DRAINING
    assert health.pending_total == 1
    assert health.overdue_total == 0


def test_an_event_not_yet_due_is_not_overdue(db: Session) -> None:
    """A backoff pushes `available_at` into the future. That is the retry engine
    working, and counting it as a stall would blame the relay for its own
    correct behaviour."""
    _event(db, status=OutboxStatus.PENDING, available_at=NOW + timedelta(seconds=600))
    assert _observe(db).verdict is RelayVerdict.DRAINING


# ── the other two faults ────────────────────────────────────────────────────


def test_an_abandoned_lease_is_its_own_verdict(db: Session) -> None:
    _event(
        db,
        status=OutboxStatus.CLAIMED,
        available_at=NOW - timedelta(seconds=600),
        leased_at=NOW - timedelta(seconds=600),
    )
    health = _observe(db)
    assert health.verdict is RelayVerdict.ACTIVATION_LEASE_STALE
    assert health.stale_lease_total == 1


def test_a_fresh_lease_is_not_abandoned(db: Session) -> None:
    """SENSITIVITY. A worker that claimed a batch one second ago is delivering
    it."""
    _event(
        db,
        status=OutboxStatus.CLAIMED,
        available_at=NOW - timedelta(seconds=600),
        leased_at=NOW - timedelta(seconds=1),
    )
    assert _observe(db).verdict is RelayVerdict.DRAINING


def test_a_dead_letter_is_reported_and_outranks_everything_below_it(
    db: Session,
) -> None:
    """Terminal, and it will not fix itself, so it is what the operator is told
    even while a backlog and a stale lease also exist."""
    _event(db, status=OutboxStatus.DEAD, available_at=NOW - timedelta(seconds=900))
    _event(db, status=OutboxStatus.PENDING, available_at=NOW - timedelta(seconds=900))
    _event(
        db,
        status=OutboxStatus.CLAIMED,
        available_at=NOW - timedelta(seconds=900),
        leased_at=NOW - timedelta(seconds=900),
    )
    health = _observe(db)
    assert health.verdict is RelayVerdict.ACTIVATION_DEAD_LETTERED
    assert health.dead_total == 1
    assert health.activation_dead == 1
    # The lower-ranked observations are still REPORTED; only the verdict is one
    # value. An operator loses nothing by the ranking.
    assert health.overdue_total == 1
    assert health.stale_lease_total == 1


# ── the verdict is over the whole table, the counts single out activation ────


def test_a_stalled_relay_is_red_even_when_no_activation_is_queued(
    db: Session,
) -> None:
    """A relay drains ONE table. If some other fact is stuck, the next
    activation will be stuck too, and a verdict scoped to activation alone would
    report green during exactly that outage."""
    _event(
        db,
        status=OutboxStatus.PENDING,
        available_at=NOW - timedelta(seconds=900),
        event_type="agreement.suspended.v1",
    )
    health = _observe(db)
    assert health.verdict is RelayVerdict.ACTIVATION_BACKLOG_OVERDUE
    assert health.overdue_total == 1
    # ...and the operator can still see WHICH chain is affected.
    assert health.activation_overdue == 0


# ── a green zero must never mean "could not query" ──────────────────────────


class _UnreadableSession:
    """A session whose outbox cannot be read. The realistic failure — a revoked
    SELECT, a dropped table, an unreachable server — all raise on execute."""

    def execute(self, statement: object) -> object:
        raise RuntimeError("permission denied for table platform_outbox_events")

    def scalar(self, statement: object) -> object:
        raise RuntimeError("permission denied for table platform_outbox_events")


def test_an_unreadable_outbox_is_unknown_with_no_counts_at_all() -> None:
    health = relay_health(
        _UnreadableSession(),  # type: ignore[arg-type]
        now=NOW,
        overdue_after=OVERDUE_AFTER,
        stale_lease_after=STALE_AFTER,
    )
    assert health.verdict is RelayVerdict.RELAY_STATE_UNKNOWN
    assert health.observed is False
    # NONE, not zero. A zero here reads exactly like "nothing is wrong" to a
    # dashboard, an alert rule and an operator at three in the morning.
    assert health.pending_total is None
    assert health.overdue_total is None
    assert health.stale_lease_total is None
    assert health.dead_total is None
    assert health.activation_pending is None
    assert health.activation_overdue is None
    assert health.activation_dead is None
    assert health.oldest_overdue_age_seconds is None


def test_an_observed_empty_queue_reports_zero_and_says_it_observed(
    db: Session,
) -> None:
    """NON-VACUITY for the test above: a module that returned `None` counts
    unconditionally would pass it while measuring nothing."""
    health = _observe(db)
    assert health.observed is True
    assert health.pending_total == 0
    assert health.dead_total == 0


def test_the_unreadable_verdict_carries_no_driver_text() -> None:
    """The readiness probe publishes this value unauthenticated. It may not
    carry a role name, a table name or a failure mode."""
    health = relay_health(
        _UnreadableSession(),  # type: ignore[arg-type]
        now=NOW,
        overdue_after=OVERDUE_AFTER,
        stale_lease_after=STALE_AFTER,
    )
    assert health.verdict.value == "relay_state_unknown"
    assert "permission denied" not in health.verdict.value


# ── the vocabulary and the ranking are closed and complete ──────────────────


def test_the_verdict_vocabulary_is_closed() -> None:
    assert {member.value for member in RelayVerdict} == {
        "relay_draining",
        "activation_backlog_overdue",
        "activation_lease_stale",
        "activation_dead_lettered",
        "relay_state_unknown",
    }


def test_every_verdict_has_a_rank_and_every_rank_is_a_verdict() -> None:
    """A member missing from the precedence tuple is one nobody decided the
    severity of, and it would be ordered by whatever the code happened to check
    first."""
    assert set(VERDICT_PRECEDENCE) == set(RelayVerdict)
    assert len(VERDICT_PRECEDENCE) == len(RelayVerdict)


def test_quiescent_liveness_is_declared_unmeasured_rather_than_assumed(
    db: Session,
) -> None:
    """The honest gap, asserted so it cannot be quietly flipped to True by a
    change that did not actually build a heartbeat.

    A relay that dies while nothing is queued is invisible from the queue alone.
    Detecting it needs a durable heartbeat, a table and a migration, and that is
    scoped to the slice that composes the relay into the deployment. Until then
    this field is how a dashboard tells "checked and fine" from "not checked".
    """
    assert _observe(db).relay_liveness_during_quiescence_measurable is False
