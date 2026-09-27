"""Route `approval.*` platform events, refusing what CP does not own.

## Why this file exists rather than a second silent consumer

`ApprovalWithdrawalConsumer` used to return quietly on any `approval.withdrawn`
event whose `subject_type` it did not recognise (Michael, 2026-09-26/27;
Knowledge `approval-withdrawal-barrier-ruling-2026-09-26` v5, rulings 1-3). A
withdrawal CP does not know how to apply is not the same fact as a withdrawal
CP applied — settling it as delivered would let an authorization keep standing
after the decision behind it was withdrawn, silently. This router refuses
instead: every non-`approval.withdrawn` event type and every unrecognised
`subject_type` under `approval.withdrawn` raises `UnroutableApprovalEvent`,
which the kernel worker backs off and eventually dead-letters — visibly.

## The atomic unit (ruling 4)

`deliver` never commits; it runs inside the kernel's delivery transaction. For
a recognised subject it computes the payload digest, checks
`outcomes_for_event` for a prior row, and either replays (ruling 7, identical
digest), records `security_conflict` for a changed payload under the same
event id (ruling 7), or calls the handler and records its terminal
disposition — domain consequence, outcome row and (via the kernel's own
settlement) the event-id record all land in the ONE transaction the caller
commits.

## `retryable` never writes a CP row (ruling 5)

A handler that cannot decide raises `RetryableWithdrawal`, a typed, redacted
exception: `__repr__`/`__str__` return only a short code, because the kernel
stores `repr(exc)` and that string must never carry a payload value or a DSN.
No `record_outcome` call happens on this path — `retryable` is not one of the
six terminal dispositions `withdrawal_outcomes` owns.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Final, Protocol, TypedDict
from uuid import UUID

from dotmac_kernel.messaging import ClaimedPlatformEvent
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from vendor_cp.relay.withdrawal_outcomes import (
    WithdrawalDisposition,
    outcomes_for_event,
    payload_digest,
    record_outcome,
)

APPROVAL_WITHDRAWN_EVENT_TYPE = "approval.withdrawn"


class UnroutableApprovalEvent(Exception):
    """An `approval.*` event this router does not know how to settle.

    Raised for any event type other than `approval.withdrawn`, and for any
    `approval.withdrawn` payload whose `subject_type` names neither the
    issuer plan subject nor the commercial-agreement subject. Never settled
    as success — it propagates so the kernel worker backs it off and,
    eventually, dead-letters it visibly.
    """

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.code})"

    __str__ = __repr__


class RetryableWithdrawal(Exception):
    """A handler could not decide this withdrawal right now.

    `repr(exc)` is what the kernel stores against the outbox row, so this
    carries only a short bounded code — never a payload value, a DSN, or any
    other detail that could leak through that stored representation.
    """

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.code})"

    __str__ = __repr__


@dataclass(frozen=True, slots=True)
class ApprovalWithdrawalResult:
    """What a subject handler decided: a terminal disposition to record.

    `coordinates` supplies only the `record_outcome` keyword arguments the
    handler actually knows (a subset of `approval_request_id`, `plan_id`,
    `agreement_id`, `withdrawal_ref`) — never a positional shape a handler
    would have to pad with `None`s for the other subject's columns.
    """

    disposition: WithdrawalDisposition
    reason_code: str
    coordinates: Mapping[str, object]
    evidence: Mapping[str, object]


class WithdrawalHandler(Protocol):
    def __call__(
        self, db: Session, event: ClaimedPlatformEvent
    ) -> ApprovalWithdrawalResult: ...


class ApprovalEventRouter:
    """Dispatch one claimed `approval.*` event to its owning subject handler.

    The issuer subject and the commercial-agreement subject are resolved by
    import here (rather than at module load) so this router stays a thin
    dispatcher over two independently evolving handlers.
    """

    def deliver(self, event: ClaimedPlatformEvent, db: Session) -> None:
        """Route, record and never leak: an `OperationalError` from ANY read or
        write on this path (the outcome lookup, the handler, `record_outcome`)
        becomes the typed, redacted `RetryableWithdrawal`, so the kernel row's
        stored error never carries SQL or parameter values."""
        try:
            self._deliver(event, db)
        except OperationalError as exc:
            raise RetryableWithdrawal("database_unavailable") from exc

    def _deliver(self, event: ClaimedPlatformEvent, db: Session) -> None:
        if event.event_type != APPROVAL_WITHDRAWN_EVENT_TYPE:
            raise UnroutableApprovalEvent("event_type")

        from vendor_cp.contracts.adapter import record_agreement_approval_withdrawal
        from vendor_cp.contracts_authority import APPROVAL_SUBJECT_TYPE
        from vendor_cp.deployment.protected_rehearsal_issuer import (
            SUBJECT_TYPE as ISSUER_SUBJECT_TYPE,
        )
        from vendor_cp.deployment.protected_rehearsal_issuer import (
            classify_approval_withdrawal,
        )

        payload = event.payload
        subject_type = payload.get("subject_type")
        handler: WithdrawalHandler
        if subject_type == ISSUER_SUBJECT_TYPE:
            handler = classify_approval_withdrawal
        elif subject_type == APPROVAL_SUBJECT_TYPE:
            handler = _agreement_handler_adapter(record_agreement_approval_withdrawal)
        else:
            raise UnroutableApprovalEvent("subject_type")

        digest = payload_digest(event.event_type, payload)
        prior = outcomes_for_event(db, event.id)
        subject_id = str(payload.get("subject_id", ""))

        if any(row.payload_digest == digest for row in prior):
            return

        if prior:
            record_outcome(
                db,
                event_id=event.id,
                digest=digest,
                event_type=event.event_type,
                subject_type=str(subject_type),
                subject_id=subject_id,
                disposition=WithdrawalDisposition.SECURITY_CONFLICT,
                reason_code="payload_changed_under_event_id",
                evidence={"prior_digests": [row.payload_digest for row in prior]},
            )
            return

        result = handler(db, event)
        record_outcome(
            db,
            event_id=event.id,
            digest=digest,
            event_type=event.event_type,
            subject_type=str(subject_type),
            subject_id=subject_id,
            disposition=result.disposition,
            reason_code=result.reason_code,
            evidence=dict(result.evidence),
            **_coordinates(result.coordinates),
        )


class _Coordinates(TypedDict, total=False):
    approval_request_id: UUID | None
    plan_id: UUID | None
    agreement_id: UUID | None
    withdrawal_ref: str | None


_UUID_COORDINATES: Final = ("approval_request_id", "plan_id", "agreement_id")


def _coordinates(given: Mapping[str, object]) -> _Coordinates:
    """Narrow a handler's coordinates to `record_outcome`'s typed keywords.

    A key outside the four columns, or a value of the wrong type, is a handler
    bug: it raises rather than being dropped, so no coordinate is silently
    lost from the evidence row.
    """
    unknown = set(given) - {*_UUID_COORDINATES, "withdrawal_ref"}
    if unknown:
        raise TypeError(f"unknown withdrawal coordinates: {sorted(unknown)}")
    out: _Coordinates = {}
    if "approval_request_id" in given:
        out["approval_request_id"] = _uuid_coordinate(given, "approval_request_id")
    if "plan_id" in given:
        out["plan_id"] = _uuid_coordinate(given, "plan_id")
    if "agreement_id" in given:
        out["agreement_id"] = _uuid_coordinate(given, "agreement_id")
    if "withdrawal_ref" in given:
        ref = given["withdrawal_ref"]
        if ref is not None and not isinstance(ref, str):
            raise TypeError("withdrawal coordinate withdrawal_ref must be a str")
        out["withdrawal_ref"] = ref
    return out


def _uuid_coordinate(given: Mapping[str, object], key: str) -> UUID | None:
    value = given[key]
    if value is not None and not isinstance(value, UUID):
        raise TypeError(f"withdrawal coordinate {key} must be a UUID")
    return value


def _agreement_handler_adapter(
    fn: Callable[..., ApprovalWithdrawalResult],
) -> WithdrawalHandler:
    """Adapt `record_agreement_approval_withdrawal`'s keyword-only shape."""

    def handler(db: Session, event: ClaimedPlatformEvent) -> ApprovalWithdrawalResult:
        return fn(db, event_id=event.id, payload=event.payload)

    return handler


__all__ = [
    "APPROVAL_WITHDRAWN_EVENT_TYPE",
    "ApprovalEventRouter",
    "ApprovalWithdrawalResult",
    "RetryableWithdrawal",
    "UnroutableApprovalEvent",
    "WithdrawalHandler",
]
