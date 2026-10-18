"""A real-PostgreSQL conformance proof of `v020`'s append-only evidence store.

Everything below runs against a migrated scratch database, connected as the
real `platform_api`/`app_admin` roles — never asserted from the migration file
alone. `scratch_db`/`url_for` follow `test_approval_barrier_conformance.py`'s
own pattern.
"""

# ruff: noqa: S101

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator

import pytest
from alembic import command
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError, ProgrammingError
from sqlalchemy.orm import Session

from vendor_cp.migrations import make_alembic_config
from vendor_cp.relay.withdrawal_outcomes import (
    ApprovalWithdrawalConflictResolution,
    ConflictAlreadyResolved,
    WithdrawalDisposition,
    WithdrawalResolution,
    outcomes_for_event,
    payload_digest,
    record_outcome,
    recorded_outcome,
    resolve_conflict,
    unresolved_conflicts,
)

PLATFORM_ROLE = "platform_api"
ADMIN_ROLE = "app_admin"


@pytest.fixture
def engine(scratch_db: str, url_for: Callable[..., str]) -> Iterator[Engine]:
    command.upgrade(make_alembic_config(scratch_db), "heads")
    with create_engine(scratch_db).connect() as conn:
        database = conn.execute(text("SELECT current_database()")).scalar_one()
    eng = create_engine(url_for(scratch_db, database, user=PLATFORM_ROLE), future=True)
    yield eng
    eng.dispose()


@pytest.fixture
def admin_engine(scratch_db: str, url_for: Callable[..., str]) -> Iterator[Engine]:
    with create_engine(scratch_db).connect() as conn:
        database = conn.execute(text("SELECT current_database()")).scalar_one()
    eng = create_engine(url_for(scratch_db, database, user=ADMIN_ROLE), future=True)
    yield eng
    eng.dispose()


def _record(
    db: Session, *, event_id: uuid.UUID, digest: str, disposition: WithdrawalDisposition
) -> object:
    return record_outcome(
        db,
        event_id=event_id,
        digest=digest,
        event_type="approval.withdrawn",
        subject_type="deployment_plan",
        subject_id=str(uuid.uuid4()),
        disposition=disposition,
        reason_code="withdrawal_settled",
        evidence={"withdrawal_ref": "wd-1"},
    )


# ── record, then an identical replay is a lookup ─────────────────────────────


def test_an_identical_replay_returns_the_recorded_terminal_result(
    engine: Engine,
) -> None:
    event_id = uuid.uuid4()
    digest = payload_digest("approval.withdrawn", {"event_id": str(event_id)})
    with Session(engine) as db:
        first = _record(
            db,
            event_id=event_id,
            digest=digest,
            disposition=WithdrawalDisposition.APPLIED,
        )
        db.commit()

    with Session(engine) as db:
        replay = recorded_outcome(db, event_id=event_id, digest=digest)
    assert replay is not None
    assert replay.id == first.id
    assert replay.disposition is WithdrawalDisposition.APPLIED


# ── a changed payload under the same event_id is its own security_conflict ──


def test_a_changed_payload_under_the_same_event_records_a_security_conflict_row(
    engine: Engine,
) -> None:
    event_id = uuid.uuid4()
    digest_a = payload_digest("approval.withdrawn", {"v": 1})
    digest_b = payload_digest("approval.withdrawn", {"v": 2})
    with Session(engine) as db:
        _record(
            db,
            event_id=event_id,
            digest=digest_a,
            disposition=WithdrawalDisposition.APPLIED,
        )
        db.commit()
    with Session(engine) as db:
        _record(
            db,
            event_id=event_id,
            digest=digest_b,
            disposition=WithdrawalDisposition.SECURITY_CONFLICT,
        )
        db.commit()

    with Session(engine) as db:
        rows = outcomes_for_event(db, event_id)
    assert len(rows) == 2
    dispositions = {row.disposition for row in rows}
    assert dispositions == {
        WithdrawalDisposition.APPLIED,
        WithdrawalDisposition.SECURITY_CONFLICT,
    }


def test_a_second_non_conflict_row_for_the_same_event_is_refused(
    engine: Engine,
) -> None:
    """The partial unique index: at most one NON-conflict row per event."""
    event_id = uuid.uuid4()
    digest_a = payload_digest("approval.withdrawn", {"v": 1})
    digest_b = payload_digest("approval.withdrawn", {"v": 2})
    with Session(engine) as db:
        _record(
            db,
            event_id=event_id,
            digest=digest_a,
            disposition=WithdrawalDisposition.APPLIED,
        )
        db.commit()

    with Session(engine) as db:
        with pytest.raises(IntegrityError):
            _record(
                db,
                event_id=event_id,
                digest=digest_b,
                disposition=WithdrawalDisposition.ALREADY_APPLIED,
            )
        db.rollback()


# ── UPDATE, DELETE and TRUNCATE are refused for every role ───────────────────


def test_app_admin_cannot_update_delete_or_truncate_the_outcomes_table(
    engine: Engine, admin_engine: Engine
) -> None:
    event_id = uuid.uuid4()
    digest = payload_digest("approval.withdrawn", {"v": 1})
    with Session(engine) as db:
        outcome = _record(
            db,
            event_id=event_id,
            digest=digest,
            disposition=WithdrawalDisposition.APPLIED,
        )
        db.commit()

    with admin_engine.connect() as conn:
        with pytest.raises(ProgrammingError, match="append-only"):
            conn.execute(
                text(
                    "UPDATE approval_withdrawal_outcomes SET reason_code = 'x' "
                    "WHERE id = :id"
                ),
                {"id": outcome.id},
            )
        conn.rollback()
        with pytest.raises(ProgrammingError, match="append-only"):
            conn.execute(
                text("DELETE FROM approval_withdrawal_outcomes WHERE id = :id"),
                {"id": outcome.id},
            )
        conn.rollback()
        with pytest.raises(ProgrammingError, match="append-only"):
            conn.execute(
                text(
                    "TRUNCATE approval_withdrawal_outcomes, "
                    "approval_withdrawal_conflict_resolutions"
                )
            )
        conn.rollback()


def test_platform_api_gets_permission_denied_on_update_or_delete(
    engine: Engine,
) -> None:
    event_id = uuid.uuid4()
    digest = payload_digest("approval.withdrawn", {"v": 1})
    with Session(engine) as db:
        outcome = _record(
            db,
            event_id=event_id,
            digest=digest,
            disposition=WithdrawalDisposition.APPLIED,
        )
        db.commit()

    with engine.connect() as conn:
        with pytest.raises(ProgrammingError, match="permission denied"):
            conn.execute(
                text(
                    "UPDATE approval_withdrawal_outcomes SET reason_code = 'x' "
                    "WHERE id = :id"
                ),
                {"id": outcome.id},
            )
        conn.rollback()
        with pytest.raises(ProgrammingError, match="permission denied"):
            conn.execute(
                text("DELETE FROM approval_withdrawal_outcomes WHERE id = :id"),
                {"id": outcome.id},
            )
        conn.rollback()


# ── conflict resolution ───────────────────────────────────────────────────────


def test_a_resolution_clears_unresolved_conflicts(engine: Engine) -> None:
    event_id = uuid.uuid4()
    digest = payload_digest("approval.withdrawn", {"v": 1})
    with Session(engine) as db:
        outcome = _record(
            db,
            event_id=event_id,
            digest=digest,
            disposition=WithdrawalDisposition.SECURITY_CONFLICT,
        )
        db.commit()

    with Session(engine) as db:
        assert unresolved_conflicts(db) == 1

    with Session(engine) as db:
        resolve_conflict(
            db,
            outcome_id=outcome.id,
            resolution=WithdrawalResolution.DISMISSED,
            actor_ref="ops:alice",
            reason="reviewed and cleared",
        )
        db.commit()

    with Session(engine) as db:
        assert unresolved_conflicts(db) == 0


def test_a_second_resolution_for_the_same_outcome_is_refused(engine: Engine) -> None:
    event_id = uuid.uuid4()
    digest = payload_digest("approval.withdrawn", {"v": 1})
    with Session(engine) as db:
        outcome = _record(
            db,
            event_id=event_id,
            digest=digest,
            disposition=WithdrawalDisposition.SECURITY_CONFLICT,
        )
        db.commit()

    with Session(engine) as db:
        resolve_conflict(
            db,
            outcome_id=outcome.id,
            resolution=WithdrawalResolution.DISMISSED,
            actor_ref="ops:alice",
            reason="first resolution",
        )
        db.commit()

    with Session(engine) as db:
        with pytest.raises(ConflictAlreadyResolved):
            resolve_conflict(
                db,
                outcome_id=outcome.id,
                resolution=WithdrawalResolution.REDRIVEN,
                actor_ref="ops:bob",
                reason="second resolution attempt",
            )
        db.rollback()

    # The backstop for a CONCURRENT second resolve, which the explicit check
    # cannot see: the unique constraint on `outcome_id` still bites.
    with Session(engine) as db:
        db.add(
            ApprovalWithdrawalConflictResolution(
                outcome_id=outcome.id,
                resolution=WithdrawalResolution.REDRIVEN.value,
                actor_ref="ops:carol",
                reason="raced past the check",
            )
        )
        with pytest.raises(IntegrityError):
            db.flush()
        db.rollback()


def test_event_limit_bounds_changed_payload_conflicts_without_hiding_null_coordinates(
    engine: Engine,
) -> None:
    event_id, request_id, plan_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    with Session(engine) as db:
        record_outcome(
            db,
            event_id=event_id,
            digest=payload_digest("approval.withdrawn", {"revision": 0}),
            event_type="approval.withdrawn",
            subject_type="deployment_plan",
            subject_id=str(plan_id),
            approval_request_id=request_id,
            plan_id=plan_id,
            withdrawal_ref=str(event_id),
            disposition=WithdrawalDisposition.APPLIED,
            reason_code="withdrawal_settled",
            evidence={"authorizations_revoked": ["synthetic-auth"]},
        )
        for revision in range(1, 6):
            record_outcome(
                db,
                event_id=event_id,
                digest=payload_digest("approval.withdrawn", {"revision": revision}),
                event_type="approval.withdrawn",
                subject_type="deployment_plan",
                subject_id=str(plan_id),
                disposition=WithdrawalDisposition.SECURITY_CONFLICT,
                reason_code="changed_payload",
                evidence={},
            )
        db.commit()
    with Session(engine) as db:
        legacy = outcomes_for_event(db, event_id)
        explicit_legacy = outcomes_for_event(db, event_id, limit=None)
        limited = outcomes_for_event(db, event_id, limit=3)
    assert len(legacy) == len(explicit_legacy) == 6
    assert {row.id for row in legacy} == {row.id for row in explicit_legacy}
    assert len(limited) == 3
    assert {row.id for row in limited} <= {row.id for row in legacy}
    assert all(row.event_id == event_id for row in limited)
    conflicts = [
        row
        for row in limited
        if row.disposition is WithdrawalDisposition.SECURITY_CONFLICT
    ]
    assert len(conflicts) >= 2
    assert all(
        row.approval_request_id is None and row.withdrawal_ref is None
        for row in conflicts
    )
