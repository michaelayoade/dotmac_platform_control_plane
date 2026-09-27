"""The router: refusal, replay, conflict, and the exhaustive CA mapping.

`ApprovalWithdrawalOutcome`/`ApprovalWithdrawalConflictResolution` use
PostgreSQL-only column types, so `outcomes_for_event`/`record_outcome`
cannot run against an in-memory SQLite session (confirmed by
`tests/unit/test_withdrawal_outcomes.py`, which took the same fork). This
file fakes the outcome store in-process — a plain dict keyed by event id —
which is enough to drive every branch `ApprovalEventRouter.deliver` decides
between BEFORE it ever reaches a real database. The live half is
`tests/migration/test_withdrawal_outcomes_store.py`'s and S4-B2's own
migration-tier proof.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from uuid import UUID, uuid4

import pytest
from dotmac_kernel.messaging import ClaimedPlatformEvent
from sqlalchemy.exc import OperationalError

from vendor_cp.contracts import adapter as contracts_adapter
from vendor_cp.deployment import protected_rehearsal_issuer as issuer
from vendor_cp.relay import approval_router
from vendor_cp.relay.approval_router import (
    ApprovalEventRouter,
    ApprovalWithdrawalResult,
    RetryableWithdrawal,
    UnroutableApprovalEvent,
)
from vendor_cp.relay.withdrawal_outcomes import WithdrawalDisposition, payload_digest

AGREEMENT_ID = UUID("70000000-0000-0000-0000-000000000007")
REQUEST_ID = UUID("20000000-0000-0000-0000-000000000002")
WITHDRAWAL_ID = UUID("30000000-0000-0000-0000-000000000003")
EVENT_ID = WITHDRAWAL_ID


def _event(
    event_type: str = "approval.withdrawn",
    payload: Mapping[str, object] | None = None,
    *,
    event_id: UUID = EVENT_ID,
) -> ClaimedPlatformEvent:
    return ClaimedPlatformEvent(
        id=event_id,
        event_type=event_type,
        payload=dict(payload or {}),
        attempts=0,
        correlation_id=None,
    )


@dataclass
class _FakeRow:
    payload_digest: str


@dataclass
class _FakeStore:
    """A minimal stand-in for the append-only outcome table."""

    rows: dict[UUID, list[_FakeRow]] = field(default_factory=dict)
    recorded: list[dict[str, object]] = field(default_factory=list)

    def outcomes_for_event(self, db: object, event_id: UUID) -> tuple[_FakeRow, ...]:
        return tuple(self.rows.get(event_id, ()))

    def record_outcome(self, db: object, **kwargs: object) -> None:
        self.recorded.append(kwargs)
        self.rows.setdefault(kwargs["event_id"], []).append(
            _FakeRow(payload_digest=kwargs["digest"])
        )


@pytest.fixture
def store(monkeypatch: pytest.MonkeyPatch) -> _FakeStore:
    fake = _FakeStore()
    monkeypatch.setattr(approval_router, "outcomes_for_event", fake.outcomes_for_event)
    monkeypatch.setattr(approval_router, "record_outcome", fake.record_outcome)
    return fake


# ── refusal: event type ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "event_type",
    [
        "approval.approved",
        "approval.requested",
        "approval.cancelled",
        "approval.rejected",
        "approval.bogus",
        "contract.activated",
    ],
)
def test_every_non_withdrawn_event_type_is_unroutable(
    store: _FakeStore, event_type: str
) -> None:
    with pytest.raises(UnroutableApprovalEvent) as caught:
        ApprovalEventRouter().deliver(_event(event_type, {}), object())
    assert caught.value.code == "event_type"
    assert store.recorded == []


# ── refusal: subject type ───────────────────────────────────────────────────


def test_an_unrecognised_subject_type_is_unroutable(store: _FakeStore) -> None:
    with pytest.raises(UnroutableApprovalEvent) as caught:
        ApprovalEventRouter().deliver(
            _event(payload={"subject_type": "something.else"}), object()
        )
    assert caught.value.code == "subject_type"
    assert store.recorded == []


def test_the_repr_carries_only_the_bounded_code_not_the_event() -> None:
    exc = UnroutableApprovalEvent("subject_type")
    assert repr(exc) == "UnroutableApprovalEvent(subject_type)"
    assert str(exc) == "UnroutableApprovalEvent(subject_type)"


# ── replay and conflict ──────────────────────────────────────────────────────


def test_an_identical_replay_returns_without_calling_any_handler(
    store: _FakeStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = {"subject_type": issuer.SUBJECT_TYPE, "subject_id": "x"}
    digest = payload_digest("approval.withdrawn", payload)
    store.rows[EVENT_ID] = [_FakeRow(payload_digest=digest)]

    called = []
    monkeypatch.setattr(
        issuer,
        "classify_approval_withdrawal",
        lambda db, event: called.append(1),
    )
    ApprovalEventRouter().deliver(_event(payload=payload), object())
    assert called == []
    assert store.recorded == []


def test_a_changed_payload_under_the_same_event_id_records_conflict_and_calls_nothing(
    store: _FakeStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = {"subject_type": issuer.SUBJECT_TYPE, "subject_id": "x"}
    store.rows[EVENT_ID] = [_FakeRow(payload_digest="sha256:" + "0" * 64)]

    called = []
    monkeypatch.setattr(
        issuer,
        "classify_approval_withdrawal",
        lambda db, event: called.append(1),
    )
    ApprovalEventRouter().deliver(_event(payload=payload), object())
    assert called == []
    assert len(store.recorded) == 1
    recorded = store.recorded[0]
    assert recorded["disposition"] == WithdrawalDisposition.SECURITY_CONFLICT
    assert recorded["reason_code"] == "payload_changed_under_event_id"
    assert "prior_digests" in recorded["evidence"]


# ── the router calls the right handler and records its result ──────────────


def test_the_router_calls_the_issuer_handler_for_the_issuer_subject(
    store: _FakeStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = ApprovalWithdrawalResult(
        disposition=WithdrawalDisposition.APPLIED,
        reason_code="applied",
        coordinates={"plan_id": uuid4()},
        evidence={},
    )
    monkeypatch.setattr(
        issuer, "classify_approval_withdrawal", lambda db, event: result
    )
    payload = {"subject_type": issuer.SUBJECT_TYPE, "subject_id": "x"}
    ApprovalEventRouter().deliver(_event(payload=payload), object())
    assert len(store.recorded) == 1
    assert store.recorded[0]["disposition"] == WithdrawalDisposition.APPLIED
    assert store.recorded[0]["plan_id"] == result.coordinates["plan_id"]


def test_the_router_calls_the_agreement_handler_for_the_agreement_subject(
    store: _FakeStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vendor_cp.contracts_authority import APPROVAL_SUBJECT_TYPE

    result = ApprovalWithdrawalResult(
        disposition=WithdrawalDisposition.NOT_CARRIED,
        reason_code="decision_not_carried",
        coordinates={"agreement_id": AGREEMENT_ID},
        evidence={},
    )
    monkeypatch.setattr(
        contracts_adapter,
        "record_agreement_approval_withdrawal",
        lambda db, *, event_id, payload: result,
    )
    payload = {"subject_type": APPROVAL_SUBJECT_TYPE, "subject_id": str(AGREEMENT_ID)}
    ApprovalEventRouter().deliver(_event(payload=payload), object())
    assert len(store.recorded) == 1
    assert store.recorded[0]["disposition"] == WithdrawalDisposition.NOT_CARRIED
    assert store.recorded[0]["agreement_id"] == AGREEMENT_ID


def test_a_retryable_handler_writes_no_row_and_propagates(
    store: _FakeStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    def raise_retryable(db: object, event: object) -> ApprovalWithdrawalResult:
        raise RetryableWithdrawal("database_unavailable")

    monkeypatch.setattr(issuer, "classify_approval_withdrawal", raise_retryable)
    payload = {"subject_type": issuer.SUBJECT_TYPE, "subject_id": "x"}
    with pytest.raises(RetryableWithdrawal) as caught:
        ApprovalEventRouter().deliver(_event(payload=payload), object())
    assert caught.value.code == "database_unavailable"
    assert store.recorded == []


def test_a_database_error_anywhere_on_the_path_is_a_redacted_retryable(
    store: _FakeStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The router's OWN reads and writes are covered too, not just the
    handlers': an OperationalError from the outcome lookup becomes the typed,
    redacted retryable, so no SQL or parameter reaches the kernel row."""

    def failing_lookup(db: object, event_id: object) -> object:
        raise OperationalError("SELECT secret-param", {"p": "secret"}, Exception())

    monkeypatch.setattr(approval_router, "outcomes_for_event", failing_lookup)
    payload = {"subject_type": issuer.SUBJECT_TYPE, "subject_id": "x"}
    with pytest.raises(RetryableWithdrawal) as caught:
        ApprovalEventRouter().deliver(_event(payload=payload), object())
    assert caught.value.code == "database_unavailable"
    assert "secret" not in repr(caught.value)
    assert store.recorded == []


def test_retryable_repr_carries_only_the_bounded_code() -> None:
    exc = RetryableWithdrawal("database_unavailable")
    assert repr(exc) == "RetryableWithdrawal(database_unavailable)"
    assert str(exc) == "RetryableWithdrawal(database_unavailable)"
    # Sensitivity: a code carrying a payload value would show up in the repr
    # the kernel stores — this is exactly what must never happen.
    assert "secret" not in repr(RetryableWithdrawal("database_unavailable"))


# ── the exhaustive CA outcome mapping ───────────────────────────────────────


def _ca_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "subject_type": "commercial_agreement",
        "subject_id": str(AGREEMENT_ID),
        "request_id": str(REQUEST_ID),
        "withdrawal_id": str(WITHDRAWAL_ID),
        "policy_code": "commercial-approval",
        "policy_version": 1,
        "content_digest": "sha256:" + "a" * 64,
        "reason": "no longer needed",
        "effective_at": "2026-09-26T00:00:00+00:00",
    }
    payload.update(overrides)
    return payload


@pytest.mark.parametrize(
    ("outcome_name", "expected_disposition", "expected_reason"),
    [
        ("RECORDED", WithdrawalDisposition.APPLIED, "recorded"),
        ("ALREADY_RECORDED", WithdrawalDisposition.ALREADY_APPLIED, "already_recorded"),
        (
            "DECISION_NOT_CARRIED",
            WithdrawalDisposition.NOT_CARRIED,
            "decision_not_carried",
        ),
        ("CONTENT_NOT_BOUND", WithdrawalDisposition.NOT_CARRIED, "content_not_bound"),
        (
            "EVIDENCE_CONFLICT",
            WithdrawalDisposition.SECURITY_CONFLICT,
            "evidence_conflict",
        ),
    ],
)
def test_every_ca_outcome_maps_to_its_cp_disposition(
    monkeypatch: pytest.MonkeyPatch,
    outcome_name: str,
    expected_disposition: WithdrawalDisposition,
    expected_reason: str,
) -> None:
    from dotmac_commercial_agreements import ApprovalWithdrawalOutcome as CAOutcome
    from dotmac_commercial_agreements import ApprovalWithdrawalResult as CAResult

    ca_result = CAResult(
        outcome=getattr(CAOutcome, outcome_name),
        agreement_id=AGREEMENT_ID,
        status="proposed",
        approval_carried=True,
        withdrawal_id=WITHDRAWAL_ID,
    )
    monkeypatch.setattr(
        contracts_adapter,
        "module_record_approval_withdrawal",
        lambda db, command: ca_result,
    )
    result = contracts_adapter.record_agreement_approval_withdrawal(
        object(), event_id=EVENT_ID, payload=_ca_payload()
    )
    assert result.disposition == expected_disposition
    assert result.reason_code == expected_reason
    assert result.coordinates["agreement_id"] == AGREEMENT_ID
    assert result.coordinates["approval_request_id"] == REQUEST_ID
    assert result.coordinates["withdrawal_ref"] == str(WITHDRAWAL_ID)


def test_a_withdrawal_id_that_does_not_match_the_event_id_is_a_security_conflict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The payload's withdrawal_id must be the event's own id (F5) — a mismatch
    (replayed or forged evidence bound to a different event) is refused before
    CA is ever called, mirroring the issuer path's own `withdrawal_id_mismatch`
    check."""
    called = []
    monkeypatch.setattr(
        contracts_adapter,
        "module_record_approval_withdrawal",
        lambda db, command: called.append(1),
    )
    other_event_id = uuid4()
    payload = _ca_payload()  # withdrawal_id == WITHDRAWAL_ID == EVENT_ID
    result = contracts_adapter.record_agreement_approval_withdrawal(
        object(), event_id=other_event_id, payload=payload
    )
    assert result.disposition == WithdrawalDisposition.SECURITY_CONFLICT
    assert result.reason_code == "withdrawal_id_mismatch"
    assert result.coordinates["agreement_id"] == AGREEMENT_ID
    assert result.evidence == {
        "withdrawal_id": str(WITHDRAWAL_ID),
        "event_id": str(other_event_id),
    }
    assert called == []


@pytest.mark.parametrize(
    ("field", "broken_value"),
    [
        ("subject_id", "not-a-valid-value"),
        ("request_id", "not-a-valid-value"),
        ("withdrawal_id", "not-a-valid-value"),
        ("policy_version", "not-a-valid-value"),
        ("effective_at", "not-a-valid-value"),
        ("reason", ""),
        ("reason", "   "),
    ],
)
def test_a_malformed_ca_payload_is_a_security_conflict_before_any_call(
    monkeypatch: pytest.MonkeyPatch, field: str, broken_value: str
) -> None:
    called = []
    monkeypatch.setattr(
        contracts_adapter,
        "module_record_approval_withdrawal",
        lambda db, command: called.append(1),
    )
    payload = _ca_payload(**{field: broken_value})
    result = contracts_adapter.record_agreement_approval_withdrawal(
        object(), event_id=EVENT_ID, payload=payload
    )
    assert result.disposition == WithdrawalDisposition.SECURITY_CONFLICT
    assert result.reason_code == "malformed_withdrawal_payload"
    assert called == []


def test_a_refusal_building_the_ca_command_is_malformed_not_dead_lettered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CA's command validates its own fields. A refusal there is recorded as a
    malformed payload, and CA is never called — rather than escaping and
    dead-lettering the delivery."""
    called = []

    def refuse(**kwargs: object) -> object:
        raise ValueError("withdrawn_at must be timezone-aware")

    monkeypatch.setattr(contracts_adapter, "RecordApprovalWithdrawalCommand", refuse)
    monkeypatch.setattr(
        contracts_adapter,
        "module_record_approval_withdrawal",
        lambda db, command: called.append(1),
    )
    result = contracts_adapter.record_agreement_approval_withdrawal(
        object(), event_id=EVENT_ID, payload=_ca_payload()
    )
    assert result.disposition == WithdrawalDisposition.SECURITY_CONFLICT
    assert result.reason_code == "malformed_withdrawal_payload"
    assert result.coordinates["agreement_id"] == AGREEMENT_ID
    assert called == []


def test_an_agreement_error_from_ca_is_a_security_conflict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dotmac_commercial_agreements import TransitionRefusedError

    def raise_not_found(db: object, command: object) -> None:
        raise TransitionRefusedError(f"agreement {AGREEMENT_ID} not found")

    monkeypatch.setattr(
        contracts_adapter, "module_record_approval_withdrawal", raise_not_found
    )
    result = contracts_adapter.record_agreement_approval_withdrawal(
        object(), event_id=EVENT_ID, payload=_ca_payload()
    )
    assert result.disposition == WithdrawalDisposition.SECURITY_CONFLICT
    assert result.reason_code == "agreement_not_found"


def test_a_database_error_from_ca_is_retryable_not_a_recorded_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sqlalchemy.exc import OperationalError

    def raise_operational(db: object, command: object) -> None:
        raise OperationalError("record", {}, Exception("lock timeout"))

    monkeypatch.setattr(
        contracts_adapter, "module_record_approval_withdrawal", raise_operational
    )
    with pytest.raises(RetryableWithdrawal):
        contracts_adapter.record_agreement_approval_withdrawal(
            object(), event_id=EVENT_ID, payload=_ca_payload()
        )
