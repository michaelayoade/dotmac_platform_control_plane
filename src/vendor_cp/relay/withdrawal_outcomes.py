"""Append-only evidence of how an `approval.withdrawn` event was settled.

CP owns SIX terminal dispositions — `WithdrawalDisposition` below — and never
writes the seventh, `retryable`, which lives in the kernel outbox row
(Michael, 2026-09-26/27; Knowledge `approval-withdrawal-barrier-ruling-2026-09-26`
v5). This module is the record and the idempotent record/lookup service; it
wires no consumer. S4-B2's router and handlers call `record_outcome` and
`recorded_outcome` from inside the same transaction as the domain consequence
they settle — that atomic unit is enforced there, not here.

## Why the digest, not the raw payload, is what replay compares

`payload_digest` is a canonical SHA256 over the claimed event payload —
sorted keys, compact separators, ASCII-only, UUIDs and datetimes reduced to
the plain strings the kernel's claimed payload already carries them as (see
`dotmac_kernel.fingerprints.fingerprint_of`, which this mirrors but prefixes
`sha256:` and is kept local rather than imported so a caller here is never
tempted to fingerprint an unrelated command payload with it). Two deliveries
of the same event whose payload has not changed hash identically regardless
of key order; a payload that changed under the same event id hashes
differently, which is exactly the fact `security_conflict` exists to record.

## Why `record_outcome` never catches its own `IntegrityError`

The migration's constraints ARE the idempotency contract: `(event_id,
payload_digest)` is unique, and a second non-conflict row for one event
collides on the partial unique index. Catching the exception here and
translating it into a replay would hide a caller that reused the same
disposition write twice in the SAME transaction — a bug, not a retry. The
kernel messaging contract already gives the transactional retry: an
`IntegrityError` aborts the caller's delivery attempt, which is retried once,
and the retry's first move is `recorded_outcome` — a plain SELECT that finds
the row the aborted attempt could not commit.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from dotmac_kernel import Base, uuid_pk
from sqlalchemy import DateTime, ForeignKey, String, Text, func, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, Session, mapped_column

__all__ = [
    "ApprovalWithdrawalConflictResolution",
    "ApprovalWithdrawalOutcome",
    "ConflictResolutionRefusal",
    "RecordedConflictResolution",
    "RecordedOutcome",
    "WithdrawalDisposition",
    "WithdrawalResolution",
    "payload_digest",
    "recorded_outcome",
    "outcomes_for_event",
    "record_outcome",
    "resolve_conflict",
    "unresolved_conflicts",
]


class WithdrawalDisposition(StrEnum):
    """The SIX terminal dispositions CP is authoritative for.

    `retryable` is deliberately absent: it is not a terminal disposition at
    all, and it lives in the kernel outbox row rather than here.
    """

    APPLIED = "applied"
    ALREADY_APPLIED = "already_applied"
    NOT_CARRIED = "not_carried"
    CANCELLED_BEFORE_EXECUTION = "cancelled_before_execution"
    SUPERSEDED_BY_REVOCATION = "superseded_by_revocation"
    SECURITY_CONFLICT = "security_conflict"


class WithdrawalResolution(StrEnum):
    """How a human closed a `security_conflict` row."""

    DISMISSED = "dismissed"
    REDRIVEN = "redriven"


class ApprovalWithdrawalOutcome(Base):
    """One terminal disposition of one `approval.withdrawn` event.

    Append-only by database trigger (`v020`); the ORM never issues an UPDATE
    or DELETE against this table and the database refuses one regardless of
    who sends it.
    """

    __tablename__ = "approval_withdrawal_outcomes"

    id: Mapped[UUID] = uuid_pk()
    event_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    payload_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    subject_type: Mapped[str] = mapped_column(String(120), nullable=False)
    subject_id: Mapped[str] = mapped_column(String(200), nullable=False)
    approval_request_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True), nullable=True
    )
    plan_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    agreement_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True), nullable=True
    )
    withdrawal_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    disposition: Mapped[str] = mapped_column(String(40), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(80), nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB(), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ApprovalWithdrawalConflictResolution(Base):
    """The human decision that clears one `security_conflict` outcome.

    `outcome_id` is unique: a conflict is resolved exactly once, and a second
    attempt collides on that constraint rather than overwriting the first.
    """

    __tablename__ = "approval_withdrawal_conflict_resolutions"

    id: Mapped[UUID] = uuid_pk()
    outcome_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("approval_withdrawal_outcomes.id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    resolution: Mapped[str] = mapped_column(String(20), nullable=False)
    actor_ref: Mapped[str] = mapped_column(String(200), nullable=False)
    reason: Mapped[str] = mapped_column(Text(), nullable=False)
    redrive_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


@dataclass(frozen=True, slots=True)
class RecordedOutcome:
    """A durable terminal-disposition row, read back for the caller."""

    id: UUID
    event_id: UUID
    payload_digest: str
    event_type: str
    subject_type: str
    subject_id: str
    approval_request_id: UUID | None
    plan_id: UUID | None
    agreement_id: UUID | None
    withdrawal_ref: str | None
    disposition: WithdrawalDisposition
    reason_code: str
    evidence: Mapping[str, Any]
    recorded_at: datetime

    @classmethod
    def _from_row(cls, row: ApprovalWithdrawalOutcome) -> RecordedOutcome:
        return cls(
            id=row.id,
            event_id=row.event_id,
            payload_digest=row.payload_digest,
            event_type=row.event_type,
            subject_type=row.subject_type,
            subject_id=row.subject_id,
            approval_request_id=row.approval_request_id,
            plan_id=row.plan_id,
            agreement_id=row.agreement_id,
            withdrawal_ref=row.withdrawal_ref,
            disposition=WithdrawalDisposition(row.disposition),
            reason_code=row.reason_code,
            evidence=dict(row.evidence),
            recorded_at=row.recorded_at,
        )


@dataclass(frozen=True, slots=True)
class RecordedConflictResolution:
    """A durable conflict-resolution row, read back for the caller."""

    id: UUID
    outcome_id: UUID
    resolution: WithdrawalResolution
    actor_ref: str
    reason: str
    redrive_ref: str | None
    recorded_at: datetime

    @classmethod
    def _from_row(
        cls, row: ApprovalWithdrawalConflictResolution
    ) -> RecordedConflictResolution:
        return cls(
            id=row.id,
            outcome_id=row.outcome_id,
            resolution=WithdrawalResolution(row.resolution),
            actor_ref=row.actor_ref,
            reason=row.reason,
            redrive_ref=row.redrive_ref,
            recorded_at=row.recorded_at,
        )


class ConflictResolutionRefusal(ValueError):
    """`resolve_conflict` was asked to resolve an outcome it may not touch."""


def _normalize(value: object) -> object:
    """UUIDs and datetimes as the plain strings a claimed JSONB payload
    already carries them as; anything else falls back to `str`."""
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def payload_digest(event_type: str, payload: Mapping[str, Any]) -> str:
    """A stable, key-order-insensitive `sha256:<64 hex>` over one event.

    `event_type` is folded into the digest so the identical bytes claimed
    under two different event types never collide — the digest identifies
    "this event, with this payload", not the payload alone.
    """
    encoded = json.dumps(
        {"event_type": event_type, "payload": payload},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=_normalize,
    ).encode("ascii")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def recorded_outcome(
    db: Session, *, event_id: UUID, digest: str
) -> RecordedOutcome | None:
    """The recorded terminal result for an identical replay, or `None`.

    A plain SELECT — the read half of idempotency. Called first by a caller
    retrying after an `IntegrityError`, and safe to call speculatively before
    ever attempting `record_outcome`.
    """
    row = db.scalar(
        select(ApprovalWithdrawalOutcome).where(
            ApprovalWithdrawalOutcome.event_id == event_id,
            ApprovalWithdrawalOutcome.payload_digest == digest,
        )
    )
    return None if row is None else RecordedOutcome._from_row(row)


def outcomes_for_event(db: Session, event_id: UUID) -> tuple[RecordedOutcome, ...]:
    """Every outcome row for one event, oldest first.

    More than one row means a `security_conflict`: the non-conflict partial
    unique index guarantees at most one non-conflict row, so a second row for
    the same event can only be a conflict.
    """
    rows = db.scalars(
        select(ApprovalWithdrawalOutcome)
        .where(ApprovalWithdrawalOutcome.event_id == event_id)
        .order_by(ApprovalWithdrawalOutcome.recorded_at)
    )
    return tuple(RecordedOutcome._from_row(row) for row in rows)


def record_outcome(
    db: Session,
    *,
    event_id: UUID,
    digest: str,
    event_type: str,
    subject_type: str,
    subject_id: str,
    disposition: WithdrawalDisposition,
    reason_code: str,
    evidence: Mapping[str, Any],
    approval_request_id: UUID | None = None,
    plan_id: UUID | None = None,
    agreement_id: UUID | None = None,
    withdrawal_ref: str | None = None,
) -> RecordedOutcome:
    """Insert one terminal-disposition row and flush. Never commits.

    RECEIVES a session inside the caller's transaction — the caller's single
    commit is what makes the domain consequence, this row, and the event-id
    record atomic together (S4-B2 enforces that unit).

    An `IntegrityError` on the unique constraints propagates uncaught: the
    caller's delivery attempt aborts and is retried once, and the retry's
    first move is `recorded_outcome`.
    """
    row = ApprovalWithdrawalOutcome(
        event_id=event_id,
        payload_digest=digest,
        event_type=event_type,
        subject_type=subject_type,
        subject_id=subject_id,
        approval_request_id=approval_request_id,
        plan_id=plan_id,
        agreement_id=agreement_id,
        withdrawal_ref=withdrawal_ref,
        disposition=disposition.value,
        reason_code=reason_code,
        evidence=dict(evidence),
    )
    db.add(row)
    db.flush()
    return RecordedOutcome._from_row(row)


def unresolved_conflicts(db: Session) -> int:
    """How many `security_conflict` outcomes have no resolution row yet.

    Health stays RED while this is nonzero — the ruling's own words.
    """
    resolved = select(ApprovalWithdrawalConflictResolution.outcome_id)
    count = db.scalar(
        select(func.count())
        .select_from(ApprovalWithdrawalOutcome)
        .where(
            ApprovalWithdrawalOutcome.disposition
            == WithdrawalDisposition.SECURITY_CONFLICT.value,
            ApprovalWithdrawalOutcome.id.not_in(resolved),
        )
    )
    return int(count or 0)


def resolve_conflict(
    db: Session,
    *,
    outcome_id: UUID,
    resolution: WithdrawalResolution,
    actor_ref: str,
    reason: str,
    redrive_ref: str | None = None,
) -> RecordedConflictResolution:
    """Record the human decision that clears one `security_conflict` outcome.

    Refuses an outcome that is not a `security_conflict` — there is nothing
    to resolve on a row that already reached a clean terminal disposition.
    Append-only, like the outcome table it points at: a second resolution for
    the same `outcome_id` collides on that column's unique constraint rather
    than silently overwriting the first human's decision.
    """
    outcome = db.get(ApprovalWithdrawalOutcome, outcome_id)
    if outcome is None:
        raise ConflictResolutionRefusal(
            f"no withdrawal outcome {outcome_id} exists to resolve"
        )
    if outcome.disposition != WithdrawalDisposition.SECURITY_CONFLICT.value:
        raise ConflictResolutionRefusal(
            f"withdrawal outcome {outcome_id} is {outcome.disposition!r}, not "
            "security_conflict — there is nothing to resolve"
        )
    if not reason.strip():
        raise ConflictResolutionRefusal("a conflict resolution must state a reason")

    row = ApprovalWithdrawalConflictResolution(
        outcome_id=outcome_id,
        resolution=resolution.value,
        actor_ref=actor_ref,
        reason=reason,
        redrive_ref=redrive_ref,
    )
    db.add(row)
    db.flush()
    return RecordedConflictResolution._from_row(row)
