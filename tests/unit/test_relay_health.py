"""The relay observation: what it says, and what it refuses to say.

SCOPE. This file exercises the DECISION over a set of heartbeat and outbox rows
— verdict precedence, the closed vocabulary, and the refusal to answer with a
zero it did not measure. It runs on the in-memory SQLite kit and therefore
proves NOTHING about the drain: `claim_platform_outbox_batch` and
`settle_platform_outbox_event` are Postgres `SECURITY DEFINER` functions and do
not exist here. The drain proof is
`tests/migration/test_platform_relay_drain.py` and must not be cited from this
file's greenness.

The three states this file is really about are the ones an operator acts on
differently: **idle but healthy**, **stopped**, and **wedged** — alive,
claiming, and settling nothing. The last is the one that hides, because every
liveness check in the world calls it healthy.
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
from vendor_cp.relay.models import RelayHeartbeat

NOW = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)
OVERDUE_AFTER = timedelta(seconds=300)
STALE_AFTER = timedelta(seconds=300)
HEARTBEAT_STALE_AFTER = timedelta(seconds=120)
SETTLED_WITHIN = timedelta(seconds=600)

#: Long enough ago to be overdue, short enough to still be inside every other
#: window unless a test says otherwise.
OVERDUE_AT = NOW - timedelta(seconds=600)


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as session:
            yield session
    finally:
        engine.dispose()


def _alive(
    db: Session,
    *,
    polled_at: datetime | None = None,
    claimed_at: datetime | None = None,
    worker_id: str = "worker-1",
) -> None:
    """Stamp a heartbeat. Default: this instant, so the relay reads as running."""
    moment = polled_at if polled_at is not None else NOW
    db.add(
        RelayHeartbeat(
            worker_id=worker_id,
            started_at=moment,
            last_polled_at=moment,
            last_claimed_at=claimed_at,
        )
    )
    db.flush()


def _event(
    db: Session,
    *,
    status: OutboxStatus,
    available_at: datetime,
    event_type: str = ACTIVATED_EVENT_TYPE,
    leased_at: datetime | None = None,
    sent_at: datetime | None = None,
) -> PlatformOutboxEvent:
    row = PlatformOutboxEvent(
        event_type=event_type,
        payload={"agreement_id": str(uuid.uuid4())},
        status=status.value,
        attempts=0,
        available_at=available_at,
        leased_at=leased_at,
        leased_by="worker-1" if leased_at else None,
        sent_at=sent_at,
    )
    db.add(row)
    db.flush()
    return row


def _settled(db: Session, *, at: datetime) -> None:
    """A delivery that actually completed, at `at`. This is what separates a
    relay that is BEHIND from one that is WEDGED."""
    _event(
        db,
        status=OutboxStatus.SENT,
        available_at=at - timedelta(seconds=1),
        sent_at=at,
    )


def _observe(
    db: Session, *, now: datetime = NOW, relay_expected: bool = True
) -> RelayHealth:
    return relay_health(
        db,
        now=now,
        overdue_after=OVERDUE_AFTER,
        stale_lease_after=STALE_AFTER,
        heartbeat_stale_after=HEARTBEAT_STALE_AFTER,
        settled_within=SETTLED_WITHIN,
        relay_expected=relay_expected,
    )


# ── the three states, and the boundaries between them ───────────────────────


def test_alive_with_an_empty_queue_is_idle_but_healthy(db: Session) -> None:
    """Nothing queued means nothing incomplete. Idle is genuinely ready."""
    _alive(db)
    health = _observe(db)
    assert health.verdict is RelayVerdict.DRAINING
    assert health.pending_total == 0
    assert health.heartbeat_age_seconds == 0
    assert health.relay_ever_reported is True


def test_a_relay_that_has_never_reported_is_stopped(db: Session) -> None:
    """A fresh database, before the relay was ever started. Distinct from a
    relay that reported an hour ago, and reported as such — `relay_ever_reported`
    is what tells an operator which of the two questions to ask first."""
    health = _observe(db)
    assert health.verdict is RelayVerdict.RELAY_NOT_RUNNING
    assert health.relay_ever_reported is False
    assert health.heartbeat_age_seconds is None


def test_a_stale_heartbeat_is_stopped_even_with_an_empty_queue(db: Session) -> None:
    """THE GAP THE HEARTBEAT EXISTS TO CLOSE.

    Nothing is queued, so every queue-derived signal says healthy. The relay is
    dead. Before `v019` this state was indistinguishable from an idle one, and
    the module said so by declaring the dimension unmeasurable rather than
    guessing.
    """
    _alive(db, polled_at=NOW - timedelta(seconds=3600))
    health = _observe(db)
    assert health.verdict is RelayVerdict.RELAY_NOT_RUNNING
    assert health.relay_ever_reported is True
    assert health.pending_total == 0


def test_a_heartbeat_inside_the_window_is_still_running(db: Session) -> None:
    """SENSITIVITY for the window. One slow cycle is not an outage; a window
    near the poll cadence would turn every hiccup into a page."""
    _alive(db, polled_at=NOW - timedelta(seconds=60))
    assert _observe(db).verdict is RelayVerdict.DRAINING


def test_alive_with_overdue_work_and_nothing_settling_is_wedged(
    db: Session,
) -> None:
    """THE STATE THAT HIDES.

    The process is up and heartbeating — every liveness probe in the deployment
    reports it healthy — and no work is getting through. It must be red, and it
    must be its own word, because the operator's first action is to read the
    delivery errors rather than to restart anything.
    """
    _alive(db, claimed_at=NOW)
    _event(db, status=OutboxStatus.PENDING, available_at=OVERDUE_AT)
    health = _observe(db)
    assert health.verdict is RelayVerdict.RELAY_WEDGED
    assert health.overdue_total == 1
    assert health.last_settled_age_seconds is None


def test_alive_with_overdue_work_but_settling_is_merely_behind(
    db: Session,
) -> None:
    """The paired case, and the one that makes WEDGED a measurement rather than
    a synonym for a backlog.

    Same heartbeat, same overdue row — but something settled inside the window,
    so the relay IS getting through and the queue is simply long. Collapsing
    this into `wedged` would send an operator to hunt delivery failures that do
    not exist; collapsing it the other way would let a wedge hide behind "it is
    catching up".
    """
    _alive(db, claimed_at=NOW)
    _event(db, status=OutboxStatus.PENDING, available_at=OVERDUE_AT)
    _settled(db, at=NOW - timedelta(seconds=30))
    health = _observe(db)
    assert health.verdict is RelayVerdict.ACTIVATION_BACKLOG_OVERDUE
    assert health.last_settled_age_seconds == 30


def test_a_settlement_older_than_the_window_does_not_rescue_a_wedge(
    db: Session,
) -> None:
    """SENSITIVITY for the settled window itself. A delivery that succeeded
    yesterday is not evidence that work is moving now."""
    _alive(db, claimed_at=NOW)
    _event(db, status=OutboxStatus.PENDING, available_at=OVERDUE_AT)
    _settled(db, at=NOW - timedelta(seconds=86_400))
    assert _observe(db).verdict is RelayVerdict.RELAY_WEDGED


def test_a_stopped_relay_outranks_a_wedge_it_would_also_satisfy(
    db: Session,
) -> None:
    """A stopped relay produces an overdue backlog as a SYMPTOM. Reporting the
    symptom above its cause sends the operator to the wrong place."""
    _alive(db, polled_at=NOW - timedelta(seconds=3600))
    _event(db, status=OutboxStatus.PENDING, available_at=OVERDUE_AT)
    assert _observe(db).verdict is RelayVerdict.RELAY_NOT_RUNNING


# ── the queue-derived states still hold ─────────────────────────────────────


def test_a_pending_event_inside_the_window_is_not_yet_a_stall(db: Session) -> None:
    """A row that became due a moment ago is a relay about to claim it, or a
    retry backing off — not a fault. A guard that fired here would be red
    permanently and learned to be ignored."""
    _alive(db)
    _event(db, status=OutboxStatus.PENDING, available_at=NOW - timedelta(seconds=10))
    health = _observe(db)
    assert health.verdict is RelayVerdict.DRAINING
    assert health.pending_total == 1
    assert health.overdue_total == 0


def test_an_event_not_yet_due_is_not_overdue(db: Session) -> None:
    """A backoff pushes `available_at` into the future. That is the retry engine
    working, and counting it as a stall would blame the relay for its own
    correct behaviour."""
    _alive(db)
    _event(db, status=OutboxStatus.PENDING, available_at=NOW + timedelta(seconds=600))
    assert _observe(db).verdict is RelayVerdict.DRAINING


def test_an_abandoned_lease_is_its_own_verdict(db: Session) -> None:
    _alive(db)
    _event(
        db,
        status=OutboxStatus.CLAIMED,
        available_at=OVERDUE_AT,
        leased_at=OVERDUE_AT,
    )
    health = _observe(db)
    assert health.verdict is RelayVerdict.ACTIVATION_LEASE_STALE
    assert health.stale_lease_total == 1


def test_a_fresh_lease_is_not_abandoned(db: Session) -> None:
    """SENSITIVITY. A worker that claimed a batch one second ago is delivering
    it."""
    _alive(db)
    _event(
        db,
        status=OutboxStatus.CLAIMED,
        available_at=OVERDUE_AT,
        leased_at=NOW - timedelta(seconds=1),
    )
    assert _observe(db).verdict is RelayVerdict.DRAINING


def test_a_dead_letter_outranks_everything_including_a_stopped_relay(
    db: Session,
) -> None:
    """Terminal, and it will not fix itself — starting the relay does not clear
    a dead letter, which is why it sits above even `RELAY_NOT_RUNNING`."""
    _alive(db, polled_at=NOW - timedelta(seconds=3600))
    _event(db, status=OutboxStatus.DEAD, available_at=OVERDUE_AT)
    _event(db, status=OutboxStatus.PENDING, available_at=OVERDUE_AT)
    health = _observe(db)
    assert health.verdict is RelayVerdict.ACTIVATION_DEAD_LETTERED
    assert health.dead_total == 1
    assert health.activation_dead == 1
    # Lower-ranked observations are still REPORTED; only the verdict is one
    # value. An operator loses nothing by the ranking.
    assert health.overdue_total == 1
    assert health.heartbeat_age_seconds == 3600


def test_a_stalled_relay_is_red_even_when_no_activation_is_queued(
    db: Session,
) -> None:
    """A relay drains ONE table. If some other fact is stuck, the next
    activation will be stuck too, and a verdict scoped to activation alone would
    report green during exactly that outage."""
    _alive(db, claimed_at=NOW)
    _event(
        db,
        status=OutboxStatus.PENDING,
        available_at=OVERDUE_AT,
        event_type="agreement.suspended.v1",
    )
    health = _observe(db)
    assert health.verdict is RelayVerdict.RELAY_WEDGED
    assert health.overdue_total == 1
    # ...and the operator can still see WHICH chain is affected.
    assert health.activation_overdue == 0


# ── a green zero must never mean "could not query" ──────────────────────────


class _UnreadableSession:
    """A session whose tables cannot be read. The realistic failure — a revoked
    SELECT, a table not yet migrated, an unreachable server — all raise."""

    def execute(self, statement: object) -> object:
        raise RuntimeError("permission denied for table platform_outbox_events")

    def scalar(self, statement: object) -> object:
        raise RuntimeError("permission denied for table platform_outbox_events")


def _unreadable() -> RelayHealth:
    return relay_health(
        _UnreadableSession(),  # type: ignore[arg-type]
        now=NOW,
        overdue_after=OVERDUE_AFTER,
        stale_lease_after=STALE_AFTER,
        heartbeat_stale_after=HEARTBEAT_STALE_AFTER,
        settled_within=SETTLED_WITHIN,
    )


def test_an_unreadable_source_is_unknown_with_no_counts_at_all() -> None:
    health = _unreadable()
    assert health.verdict is RelayVerdict.RELAY_STATE_UNKNOWN
    assert health.observed is False
    # NONE, not zero. A zero here reads exactly like "nothing is wrong" to a
    # dashboard, an alert rule and an operator at three in the morning.
    for value in (
        health.pending_total,
        health.overdue_total,
        health.stale_lease_total,
        health.dead_total,
        health.activation_pending,
        health.activation_overdue,
        health.activation_dead,
        health.oldest_overdue_age_seconds,
        health.heartbeat_age_seconds,
        health.last_settled_age_seconds,
        health.relay_ever_reported,
    ):
        assert value is None


def test_an_unreadable_heartbeat_is_never_reported_as_a_stopped_relay(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The specific confusion worth refusing.

    "The heartbeat table could not be read" and "the relay is not running" are
    different facts with different repairs — one is a privilege or a migration,
    the other is a process — and an unread query must never be reported as a
    measurement. So the verdict is UNKNOWN, not `RELAY_NOT_RUNNING`, even though
    both would make readiness red.
    """
    from vendor_cp.relay import heartbeat as heartbeat_module

    monkeypatch.setattr(
        heartbeat_module,
        "read",
        lambda _db: heartbeat_module.HeartbeatState(
            observed=False, freshest_poll=None, freshest_claim=None
        ),
    )
    health = _observe(db)
    assert health.verdict is RelayVerdict.RELAY_STATE_UNKNOWN
    assert health.verdict is not RelayVerdict.RELAY_NOT_RUNNING


def test_an_observed_empty_queue_reports_zero_and_says_it_observed(
    db: Session,
) -> None:
    """NON-VACUITY for the tests above: a module that returned `None` counts
    unconditionally would pass them while measuring nothing."""
    _alive(db)
    health = _observe(db)
    assert health.observed is True
    assert health.pending_total == 0
    assert health.dead_total == 0


def test_the_unreadable_verdict_carries_no_driver_text() -> None:
    """The readiness probe publishes this value unauthenticated. It may not
    carry a role name, a table name or a failure mode."""
    assert _unreadable().verdict.value == "relay_state_unknown"


# ── the vocabulary and the ranking are closed and complete ──────────────────


def test_the_verdict_vocabulary_is_closed() -> None:
    assert {member.value for member in RelayVerdict} == {
        "relay_draining",
        "relay_not_running",
        "relay_wedged",
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


def test_quiescent_liveness_is_now_measured_and_the_deferral_is_recorded(
    db: Session,
) -> None:
    """The flag flipped, and this test is the deliberate update it demanded.

    The first slice shipped `relay_liveness_during_quiescence_measurable = False`
    and a test asserting it could not be quietly flipped to True by a change
    that had not actually built a heartbeat. That test was designed to FAIL
    here, loudly, and be updated in the change that earns the flip — which is
    this one.

    So the assertion is not merely inverted. It asserts the flip AND the fact
    that earns it: with a stale heartbeat and an empty queue — total quiescence,
    the exact state that was previously unmeasurable — the module now reports a
    stopped relay rather than a healthy one. A `True` returned by a module that
    could not actually see quiescent death would fail the second half.
    """
    _alive(db, polled_at=NOW - timedelta(seconds=3600))
    health = _observe(db)
    assert health.relay_liveness_during_quiescence_measurable is True
    assert (
        health.pending_total == 0
    ), "the queue must be empty for this to mean anything"
    assert health.verdict is RelayVerdict.RELAY_NOT_RUNNING


# ── the deployment's composition, which is not a switch on the check ────────


def test_a_deployment_with_no_relay_is_not_permanently_unready(db: Session) -> None:
    """The conflation this flag repairs.

    A single-container artifact acceptance run has a reachable, migrated
    database and no relay. Reporting `RELAY_NOT_RUNNING` there is true and
    useless: it makes the artifact permanently unready for not running a service
    it was never given, and it says nothing about the artifact.
    """
    health = _observe(db, relay_expected=False)
    assert health.verdict is RelayVerdict.DRAINING
    assert health.relay_liveness_during_quiescence_measurable is False


def test_a_deployment_with_no_relay_still_refuses_an_ageing_backlog(
    db: Session,
) -> None:
    """NOT a switch on the check, and this is the assertion that proves it.

    With no relay composed there is no heartbeat to read, so liveness is
    unmeasurable — but the queue asymmetry needs no heartbeat, and work that
    should have moved and did not is still red.
    """
    _event(db, status=OutboxStatus.PENDING, available_at=OVERDUE_AT)
    health = _observe(db, relay_expected=False)
    assert health.verdict is RelayVerdict.ACTIVATION_BACKLOG_OVERDUE
    assert health.overdue_total == 1


def test_a_deployment_with_no_relay_never_claims_a_wedge(db: Session) -> None:
    """WEDGED asserts the relay is ALIVE. Nothing here has proved that, so the
    diagnosis is the weaker true one rather than the stronger convenient one."""
    _event(db, status=OutboxStatus.PENDING, available_at=OVERDUE_AT)
    assert _observe(db, relay_expected=False).verdict is not RelayVerdict.RELAY_WEDGED


def test_a_deployment_with_no_relay_still_reports_dead_letters(db: Session) -> None:
    """Terminal, and independent of whether anything is draining."""
    _event(db, status=OutboxStatus.DEAD, available_at=OVERDUE_AT)
    assert (
        _observe(db, relay_expected=False).verdict
        is RelayVerdict.ACTIVATION_DEAD_LETTERED
    )


def test_expecting_a_relay_is_the_default(db: Session) -> None:
    """FAIL-CLOSED. A deployment that forgot to say gets the strict answer, so
    the permissive reading is never the one nobody chose."""
    from vendor_cp.config import load_vendor_settings

    assert load_vendor_settings().relay_expected is True
    # ...and with the default, a database that has never seen a relay is red.
    assert _observe(db).verdict is RelayVerdict.RELAY_NOT_RUNNING
