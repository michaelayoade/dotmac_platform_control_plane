"""`payload_digest`, and the refusals `record_outcome`/`resolve_conflict` make
without ever reaching a database.

The live half — real Postgres, the append-only triggers, the partial unique
index and the privilege grants — is
`tests/migration/test_withdrawal_outcomes_store.py`. What is provable without
a database is provable here, following
`tests/unit/test_data_governance_decisions.py`'s own split.

`ApprovalWithdrawalOutcome`/`ApprovalWithdrawalConflictResolution` use
PostgreSQL-only column types (`JSONB`, `postgresql.UUID`), so an in-memory
SQLite session cannot create these tables at all — confirmed by hand before
writing this file. `resolve_conflict`'s refusals are exercised instead against
a minimal duck-typed session double that never touches SQLAlchemy metadata,
which is enough to drive every branch that runs before a real INSERT.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import uuid4

import pytest

from vendor_cp.relay.withdrawal_outcomes import (
    ConflictResolutionRefusal,
    WithdrawalDisposition,
    WithdrawalResolution,
    payload_digest,
    resolve_conflict,
)

# ── payload_digest ───────────────────────────────────────────────────────────


def test_the_digest_is_stable_and_key_order_insensitive() -> None:
    a = payload_digest("approval.withdrawn", {"a": 1, "b": {"x": 2, "y": 3}})
    b = payload_digest("approval.withdrawn", {"b": {"y": 3, "x": 2}, "a": 1})
    assert a == b
    assert a.startswith("sha256:")
    assert len(a) == len("sha256:") + 64


def test_the_digest_is_sensitive_to_a_changed_value() -> None:
    a = payload_digest("approval.withdrawn", {"a": 1})
    b = payload_digest("approval.withdrawn", {"a": 2})
    assert a != b


def test_the_digest_is_sensitive_to_the_event_type() -> None:
    """Non-vacuity for folding `event_type` into the digest: identical payload
    bytes under two different event types must not collide."""
    a = payload_digest("approval.withdrawn", {"a": 1})
    b = payload_digest("approval.superseded", {"a": 1})
    assert a != b


def test_the_digest_normalizes_uuids_and_datetimes_to_plain_strings() -> None:
    from datetime import UTC, datetime

    identifier = uuid4()
    stamp = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)
    digest = payload_digest(
        "approval.withdrawn", {"subject_id": identifier, "at": stamp}
    )
    same = payload_digest(
        "approval.withdrawn", {"subject_id": str(identifier), "at": stamp.isoformat()}
    )
    assert digest == same


# ── resolve_conflict, driven against a duck-typed session double ────────────


@dataclass
class _FakeOutcome:
    id: Any
    disposition: str


class _FakeSession:
    """The narrowest double `resolve_conflict` needs: `get`, `add`, `flush`."""

    def __init__(self, outcome: _FakeOutcome | None) -> None:
        self._outcome = outcome
        self.added: list[object] = []
        self.flushed = False

    def get(self, _model: object, outcome_id: object) -> _FakeOutcome | None:
        if self._outcome is not None and self._outcome.id == outcome_id:
            return self._outcome
        return None

    def add(self, row: object) -> None:
        self.added.append(row)

    def flush(self) -> None:
        self.flushed = True


def test_resolve_conflict_refuses_a_non_conflict_outcome() -> None:
    outcome_id = uuid4()
    session = _FakeSession(_FakeOutcome(id=outcome_id, disposition="applied"))
    with pytest.raises(ConflictResolutionRefusal, match="not security_conflict"):
        resolve_conflict(
            session,  # type: ignore[arg-type]
            outcome_id=outcome_id,
            resolution=WithdrawalResolution.DISMISSED,
            actor_ref="ops:alice",
            reason="reviewed",
        )
    assert session.added == []
    assert not session.flushed


def test_resolve_conflict_refuses_an_outcome_that_does_not_exist() -> None:
    session = _FakeSession(None)
    with pytest.raises(ConflictResolutionRefusal, match="no withdrawal outcome"):
        resolve_conflict(
            session,  # type: ignore[arg-type]
            outcome_id=uuid4(),
            resolution=WithdrawalResolution.DISMISSED,
            actor_ref="ops:alice",
            reason="reviewed",
        )
    assert session.added == []


def test_resolve_conflict_refuses_a_blank_reason() -> None:
    outcome_id = uuid4()
    session = _FakeSession(_FakeOutcome(id=outcome_id, disposition="security_conflict"))
    with pytest.raises(ConflictResolutionRefusal, match="must state a reason"):
        resolve_conflict(
            session,  # type: ignore[arg-type]
            outcome_id=outcome_id,
            resolution=WithdrawalResolution.DISMISSED,
            actor_ref="ops:alice",
            reason="   ",
        )
    assert session.added == []


def test_resolve_conflict_accepts_a_real_conflict_and_writes_one_row() -> None:
    """NON-VACUITY for the three refusals above: the happy path really adds and
    flushes exactly one row, so the refusals are shown to bite something."""
    outcome_id = uuid4()
    session = _FakeSession(_FakeOutcome(id=outcome_id, disposition="security_conflict"))
    resolve_conflict(
        session,  # type: ignore[arg-type]
        outcome_id=outcome_id,
        resolution=WithdrawalResolution.REDRIVEN,
        actor_ref="ops:alice",
        reason="reviewed and redriven",
        redrive_ref="redrive-1",
    )
    assert len(session.added) == 1
    assert session.flushed


# ── the enum is the gate for disposition and resolution values ──────────────


def test_a_disposition_outside_the_six_is_refused_by_construction() -> None:
    """`record_outcome` takes a `WithdrawalDisposition`, not a raw string, and
    the enum itself is where an invalid value is refused — before any session
    or table is ever touched."""
    with pytest.raises(ValueError, match="retryable"):
        WithdrawalDisposition("retryable")
    with pytest.raises(ValueError):
        WithdrawalDisposition("not_a_real_disposition")


def test_every_named_disposition_is_one_of_the_six_ruled_values() -> None:
    assert {member.value for member in WithdrawalDisposition} == {
        "applied",
        "already_applied",
        "not_carried",
        "cancelled_before_execution",
        "superseded_by_revocation",
        "security_conflict",
    }


def test_a_resolution_outside_the_two_is_refused_by_construction() -> None:
    with pytest.raises(ValueError):
        WithdrawalResolution("approved")
