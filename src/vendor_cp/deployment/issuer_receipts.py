"""An append-only, non-authorizing receipt of one issuer command (D18-C).

`approve_issuer_plan` and `issue_authorization` in `protected_rehearsal_issuer.py`
take the Approvals hold (`held_transition`) BEFORE calling Control. A
same-command-id retry of a COMMITTED command, made after a later withdrawal,
is refused by the hold as "not held: withdrawn" with nothing saying the
command had already committed.

This module is the receipt: written in the SAME transaction as Control's
call, keyed by command id and request fingerprint, pointing to Control's
result id (`control_ref`). It is deliberately NOT another issuer-standing or
idempotency authority — Control and the kernel keep those decisions, and
Approvals keeps withdrawal standing. The seam in `protected_rehearsal_issuer.py`
is the only caller that may translate a receipt lookup into
`IssuerCommandCommittedButWithdrawn`; this module never bypasses the
Approvals hold and never returns Control's signed envelope.

## Why the fingerprint, not just the command id, decides reuse

`UNIQUE(command_id)` in `v021_issuer_command_receipts` is the idempotency
anchor for a genuine retry — same command id, same request. A caller that
reuses a command id for a DIFFERENT request (a bug, or an attempted replay
attack) must be refused as `IssuerCommandReused`, not silently treated as the
same command; the fingerprint is what tells the two apart.

## Why `record_receipt` does not catch its own `IntegrityError` as success

A concurrent retry that inserts first will cause the loser's `INTEGRITY`
violation on `command_id`. That loser re-reads the winner's row: if it
matches (same verb, fingerprint, control_ref) the loser's own call is exactly
a replay and returns the winner's row; if it disagrees, something is wrong
enough that failing closed (`IssuerReceiptMismatch`) is the only safe
response.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from dotmac_kernel import Base, ConflictError, uuid_pk
from dotmac_kernel.transactions import conflict_savepoint
from sqlalchemy import DateTime, String, Uuid, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column

__all__ = [
    "IssuerCommandCommittedButWithdrawn",
    "IssuerCommandReceipt",
    "IssuerCommandReused",
    "IssuerReceiptMismatch",
    "RecordedIssuerReceipt",
    "find_receipt",
    "record_receipt",
    "request_fingerprint",
]

#: The only two verbs a receipt may carry, matching the migration's CHECK
#: constraint.
APPROVE_PLAN = "approve_plan"
ISSUE_AUTHORIZATION = "issue_authorization"


class IssuerCommandReceipt(Base):
    """One append-only record that an issuer command committed.

    Append-only by database trigger (`v021`); the ORM never issues an UPDATE
    or DELETE against this table and the database refuses one regardless of
    who sends it. Generic `Uuid()`/`String` types, matching
    `relay/withdrawal_outcomes.py`, so this model is SQLite-compilable for
    unit tests as well as PostgreSQL.
    """

    __tablename__ = "issuer_command_receipts"

    id: Mapped[UUID] = uuid_pk()
    command_id: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    verb: Mapped[str] = mapped_column(String(40), nullable=False)
    request_fingerprint: Mapped[str] = mapped_column(String(71), nullable=False)
    plan_id: Mapped[UUID] = mapped_column(Uuid(), nullable=False)
    approval_request_id: Mapped[UUID] = mapped_column(Uuid(), nullable=False)
    control_ref: Mapped[str] = mapped_column(String(200), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


@dataclass(frozen=True, slots=True)
class RecordedIssuerReceipt:
    """A committed receipt as a plain value, never a live ORM row: it stays
    readable after the session that loaded it closes, and cannot be mutated
    into a second story about the command."""

    id: UUID
    command_id: str
    verb: str
    request_fingerprint: str
    plan_id: UUID
    approval_request_id: UUID
    control_ref: str
    recorded_at: datetime

    @classmethod
    def _from_row(cls, row: IssuerCommandReceipt) -> RecordedIssuerReceipt:
        return cls(
            id=row.id,
            command_id=row.command_id,
            verb=row.verb,
            request_fingerprint=row.request_fingerprint,
            plan_id=row.plan_id,
            approval_request_id=row.approval_request_id,
            control_ref=row.control_ref,
            recorded_at=row.recorded_at,
        )


class IssuerCommandReused(ConflictError):
    """The same command id was submitted with a different verb or payload.

    A genuine retry of a committed command must carry the identical request;
    a changed request under the same command id is refused rather than
    silently treated as the same command.
    """


class IssuerReceiptMismatch(ConflictError):
    """The receipt disagrees with what Control returned or replayed.

    Raised to fail CLOSED — this is not a state a non-authorizing receipt is
    allowed to paper over.
    """


class IssuerCommandCommittedButWithdrawn(ConflictError):
    """An issuer command committed, but its approval has since been withdrawn.

    Carries ONLY `command_id`, `verb`, and `control_ref` — never Control's
    signed envelope or any other result field — so this exception can report
    that the command committed without ever handing back currently usable
    authority.
    """

    def __init__(self, command_id: str, verb: str, control_ref: str) -> None:
        self.command_id = command_id
        self.verb = verb
        self.control_ref = control_ref
        super().__init__(
            f"issuer command {command_id!r} ({verb}) already committed as "
            f"{control_ref!r}; its approval has since been withdrawn, so this "
            "result is not currently usable authority"
        )


def _normalize(value: object) -> object:
    """UUIDs and datetimes as plain strings; anything else raises `TypeError`.

    A silent `str()` fallback would make the fingerprint depend on whatever
    `repr`/`str` an unanticipated type happens to produce -- not guaranteed
    stable across processes or versions, which would make the fingerprint
    non-deterministic for exactly the requests it exists to protect. Mirrors
    `relay/withdrawal_outcomes.py`'s `_normalize`, kept local rather than
    imported so a caller here is never tempted to fingerprint an unrelated
    payload with it.
    """
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(
        f"cannot fingerprint a value of type {type(value).__name__}; "
        "request_fingerprint only accepts JSON-native types, UUID, and "
        "datetime"
    )


def request_fingerprint(verb: str, request: Mapping[str, Any]) -> str:
    """A stable, key-order-insensitive `sha256:<64 hex>` over one command.

    `verb` is folded into the digest so the identical request fields claimed
    under `approve_plan` and `issue_authorization` never collide.
    """
    encoded = json.dumps(
        {"verb": verb, "request": request},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=_normalize,
    ).encode("ascii")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def find_receipt(db: Session, command_id: str) -> RecordedIssuerReceipt | None:
    """The receipt for this command id, or `None`. Read-only."""
    row = db.scalar(
        select(IssuerCommandReceipt).where(
            IssuerCommandReceipt.command_id == command_id
        )
    )
    return None if row is None else RecordedIssuerReceipt._from_row(row)


def record_receipt(
    db: Session,
    *,
    command_id: str,
    verb: str,
    fingerprint: str,
    plan_id: UUID,
    approval_request_id: UUID,
    control_ref: str,
) -> RecordedIssuerReceipt:
    """Insert one receipt row and flush, inside the caller's transaction.

    RECEIVES a session inside the caller's transaction — the caller's single
    commit is what makes the domain consequence (Control's call) and this
    receipt atomic together. Never commits.

    On `IntegrityError` (a concurrent retry that recorded first), re-reads the
    winning row: an identical (verb, fingerprint, control_ref) is treated as
    this call's own replay and returned; any disagreement raises
    `IssuerReceiptMismatch` rather than silently accepting a second story for
    the same command id.
    """
    row = IssuerCommandReceipt(
        command_id=command_id,
        verb=verb,
        request_fingerprint=fingerprint,
        plan_id=plan_id,
        approval_request_id=approval_request_id,
        control_ref=control_ref,
    )
    try:
        with conflict_savepoint(db):
            db.add(row)
            db.flush()
    except IntegrityError as exc:
        existing = find_receipt(db, command_id)
        if existing is None:
            raise
        if (
            existing.verb != verb
            or existing.request_fingerprint != fingerprint
            or existing.control_ref != control_ref
        ):
            raise IssuerReceiptMismatch(
                f"issuer command {command_id!r} recorded a different receipt "
                "concurrently"
            ) from exc
        return existing
    db.refresh(row)
    return RecordedIssuerReceipt._from_row(row)
