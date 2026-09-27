"""Withdrawal health, against real PostgreSQL.

`ApprovalWithdrawalOutcome`/`ApprovalWithdrawalConflictResolution` use
PostgreSQL-only column types (`JSONB`, `postgresql.UUID`) and cannot be created
on the in-memory SQLite kit `tests/unit/test_relay_health.py` uses — confirmed
there and in `tests/unit/test_withdrawal_outcomes.py`'s own docstring. This file
is therefore the only place `WITHDRAWAL_CONFLICT_UNRESOLVED` is proven against a
real recorded row rather than a monkeypatched count, and the only place the
`attempts == 1` claim for `WITHDRAWAL_DELIVERY_FAILING` is proven by an actual
failed delivery through the real relay rather than a hand-set column.

Everything below runs against a migrated scratch database, following
`tests/migration/test_platform_relay_drain.py`'s own composition pattern.
"""

# ruff: noqa: S101

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import pytest
from alembic import command
from dotmac_kernel.messaging import OutboxStatus, PlatformOutboxEvent
from dotmac_kernel.session_runtime import DatabaseRuntime
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vendor_cp.migrations import make_alembic_config
from vendor_cp.relay.approval_router import (
    APPROVAL_WITHDRAWN_EVENT_TYPE,
    RetryableWithdrawal,
)
from vendor_cp.relay.health import RelayVerdict, relay_health
from vendor_cp.relay.runner import RelayComposition, drain_once
from vendor_cp.relay.withdrawal_outcomes import (
    ConflictResolutionRefusal,
    WithdrawalDisposition,
    WithdrawalResolution,
    payload_digest,
    record_outcome,
    resolve_conflict,
)

DISPATCHER_ROLE = "platform_outbox_dispatcher"
PLATFORM_ROLE = "platform_api"
WINDOW = timedelta(seconds=300)
HEARTBEAT_WINDOW = timedelta(seconds=120)
SETTLED_WINDOW = timedelta(seconds=600)


@pytest.fixture
def migrated(scratch_db: str, url_for: Callable[..., str]) -> Iterator[tuple[str, str]]:
    """A scratch database at composed heads, plus the platform and dispatcher
    role DSNs — `test_platform_relay_drain.py`'s own fixture, unchanged."""
    command.upgrade(make_alembic_config(scratch_db), "heads")
    engine = create_engine(scratch_db)
    try:
        with engine.connect() as conn:
            database = conn.execute(text("SELECT current_database()")).scalar_one()
            conn.execute(
                text(f'GRANT CONNECT ON DATABASE "{database}" TO {DISPATCHER_ROLE}')
            )
            conn.commit()
    finally:
        engine.dispose()
    yield (
        url_for(scratch_db, database, user=PLATFORM_ROLE),
        url_for(scratch_db, database, user=DISPATCHER_ROLE),
    )


@contextmanager
def _sessions(url: str) -> Iterator[DatabaseRuntime]:
    runtime = DatabaseRuntime.from_urls(database_url=url, platform_database_url=url)
    try:
        yield runtime
    finally:
        runtime.platform_engine.dispose()
        runtime.engine.dispose()


def _observe(db: Session, *, now: datetime | None = None):
    return relay_health(
        db,
        now=now or datetime.now(UTC),
        overdue_after=WINDOW,
        stale_lease_after=WINDOW,
        heartbeat_stale_after=HEARTBEAT_WINDOW,
        settled_within=SETTLED_WINDOW,
    )


class _RetryableWithdrawalConsumer:
    """A transport that fails every delivery the way a handler that cannot
    decide really does: a typed, redacted `RetryableWithdrawal` — never a bare
    exception standing in for it."""

    def deliver(self, event: object, platform_db: Session) -> None:
        raise RetryableWithdrawal("simulated_failure")


def _composition(
    dispatcher_url: str, platform: DatabaseRuntime, *, transport: object
) -> RelayComposition:
    dispatcher = DatabaseRuntime.from_urls(
        database_url=dispatcher_url,
        platform_database_url=dispatcher_url,
        pool_size=1,
        max_overflow=0,
        platform_pool_size=1,
        platform_max_overflow=0,
    )
    return RelayComposition(
        dispatcher_sessions=dispatcher.platform_session_factory,
        delivery_sessions=platform.platform_session_factory,
        transport=transport,
    )


def _enqueue_withdrawal(db: Session) -> None:
    db.add(
        PlatformOutboxEvent(
            event_type=APPROVAL_WITHDRAWN_EVENT_TYPE,
            payload={"event_id": str(uuid.uuid4())},
        )
    )
    db.commit()


def _record_conflict(db: Session, *, event_id: uuid.UUID) -> uuid.UUID:
    digest = payload_digest(APPROVAL_WITHDRAWN_EVENT_TYPE, {"event_id": str(event_id)})
    outcome = record_outcome(
        db,
        event_id=event_id,
        digest=digest,
        event_type=APPROVAL_WITHDRAWN_EVENT_TYPE,
        subject_type="deployment_plan",
        subject_id=str(uuid.uuid4()),
        disposition=WithdrawalDisposition.SECURITY_CONFLICT,
        reason_code="payload_changed",
        evidence={"withdrawal_ref": "wd-1"},
    )
    db.commit()
    return outcome.id


# ── one failed delivery: WITHDRAWAL_DELIVERY_FAILING at attempts == 1 ───────


def test_a_failed_delivery_is_failing_at_attempts_one(
    migrated: tuple[str, str],
) -> None:
    platform_url, dispatcher_url = migrated
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            _enqueue_withdrawal(db)
        composition = _composition(
            dispatcher_url, platform, transport=_RetryableWithdrawalConsumer()
        )
        report = drain_once(worker_id="relay-test", composition=composition)
        assert report.claimed >= 1

        with platform.platform_session() as db:
            row = db.execute(select(PlatformOutboxEvent)).scalar_one()
            assert row.attempts == 1
            assert row.status == OutboxStatus.PENDING.value
            health = _observe(db)
        assert health.verdict is RelayVerdict.WITHDRAWAL_DELIVERY_FAILING
        assert health.withdrawal_failing == 1


def test_an_undelivered_withdrawal_is_not_yet_failing(
    migrated: tuple[str, str],
) -> None:
    """NON-VACUITY: the same enqueued row, before any delivery attempt, must
    not report `WITHDRAWAL_DELIVERY_FAILING`."""
    platform_url, _dispatcher_url = migrated
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            _enqueue_withdrawal(db)
            health = _observe(db)
        assert health.verdict is not RelayVerdict.WITHDRAWAL_DELIVERY_FAILING
        assert health.withdrawal_failing == 0


# ── a dead-lettered withdrawal ───────────────────────────────────────────────


def test_a_dead_lettered_withdrawal_is_its_own_verdict(
    migrated: tuple[str, str],
) -> None:
    platform_url, _dispatcher_url = migrated
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            db.add(
                PlatformOutboxEvent(
                    event_type=APPROVAL_WITHDRAWN_EVENT_TYPE,
                    payload={"event_id": str(uuid.uuid4())},
                    status=OutboxStatus.DEAD.value,
                    attempts=8,
                )
            )
            db.commit()
            health = _observe(db)
        assert health.verdict is RelayVerdict.WITHDRAWAL_DEAD_LETTERED
        assert health.withdrawal_dead == 1


# ── security_conflict: unresolved until resolve_conflict, then clears ──────


def test_a_recorded_conflict_is_red_until_resolved_then_clears(
    migrated: tuple[str, str],
) -> None:
    platform_url, _dispatcher_url = migrated
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            outcome_id = _record_conflict(db, event_id=uuid.uuid4())
            health = _observe(db)
        assert health.verdict is RelayVerdict.WITHDRAWAL_CONFLICT_UNRESOLVED
        assert health.unresolved_withdrawal_conflicts == 1

        with platform.platform_session() as db:
            resolve_conflict(
                db,
                outcome_id=outcome_id,
                resolution=WithdrawalResolution.DISMISSED,
                actor_ref="platform-admin:alice",
                reason="reviewed and safe to dismiss",
            )
            db.commit()

        with platform.platform_session() as db:
            health = _observe(db)
        assert health.verdict is not RelayVerdict.WITHDRAWAL_CONFLICT_UNRESOLVED
        assert health.unresolved_withdrawal_conflicts == 0


def test_a_second_resolve_is_refused(migrated: tuple[str, str]) -> None:
    """Append-only, at the database: `outcome_id` is unique on the resolution
    table, so a second resolve collides on that constraint — `resolve_conflict`
    never catches its own `IntegrityError` any more than `record_outcome` does
    (see that function's docstring). It never silently overwrites the first
    human's decision."""
    platform_url, _dispatcher_url = migrated
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            outcome_id = _record_conflict(db, event_id=uuid.uuid4())
            resolve_conflict(
                db,
                outcome_id=outcome_id,
                resolution=WithdrawalResolution.REDRIVEN,
                actor_ref="platform-admin:alice",
                reason="redriven after a fix",
                redrive_ref="redrive-1",
            )
            db.commit()

        with platform.platform_session() as db:
            with pytest.raises(IntegrityError):
                resolve_conflict(
                    db,
                    outcome_id=outcome_id,
                    resolution=WithdrawalResolution.DISMISSED,
                    actor_ref="platform-admin:bob",
                    reason="a second, later decision",
                )
            db.rollback()


def test_resolving_something_that_is_not_a_conflict_is_refused(
    migrated: tuple[str, str],
) -> None:
    """NON-VACUITY for `ConflictResolutionRefusal`: it is a real, reachable
    branch (a non-`security_conflict` outcome), distinct from the database
    constraint the test above exercises."""
    platform_url, _dispatcher_url = migrated
    with _sessions(platform_url) as platform:
        with platform.platform_session() as db:
            event_id = uuid.uuid4()
            digest = payload_digest(
                APPROVAL_WITHDRAWN_EVENT_TYPE, {"event_id": str(event_id)}
            )
            outcome = record_outcome(
                db,
                event_id=event_id,
                digest=digest,
                event_type=APPROVAL_WITHDRAWN_EVENT_TYPE,
                subject_type="deployment_plan",
                subject_id=str(uuid.uuid4()),
                disposition=WithdrawalDisposition.APPLIED,
                reason_code="withdrawal_settled",
                evidence={"withdrawal_ref": "wd-2"},
            )
            db.commit()

        with platform.platform_session() as db:
            with pytest.raises(ConflictResolutionRefusal):
                resolve_conflict(
                    db,
                    outcome_id=outcome.id,
                    resolution=WithdrawalResolution.DISMISSED,
                    actor_ref="platform-admin:alice",
                    reason="nothing to resolve",
                )
