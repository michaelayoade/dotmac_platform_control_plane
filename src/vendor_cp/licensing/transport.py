"""Delivery transports + at-least-once replay.

A transport MOVES an already-decided document; it makes no licensing decision
and never touches projection state. `EntitlementProjectionService` owns whether
a delivery is `delivered` or `active`, and only a matching acknowledgement
advances it — a transport reporting "sent" proves nothing about whether the
deployment applied anything.

**At-least-once, deliberately.** Re-delivering an already-applied version is
safe by construction: the receiver's verifier treats the same version+digest as
an idempotent reapply, and the vendor's ack handling treats a repeat as
`duplicate`. So the replay driver re-dispatches anything not yet `active`
rather than trying to be clever about what "probably" arrived. Exactly-once is
neither promised nor needed.

Two reference transports this phase, both side-effect-free in-process (no
network, keeping the D3 posture — a real HTTP/webhook transport is a separate,
credentialed slice):

- `LoggingTransport` — records what would be sent; the default.
- `OfflineBundleTransport` — renders an ENVELOPE bundle (deliberately not
  "self-contained": see the class docstring for the receiver prerequisites it
  does NOT satisfy) for an air-gapped site. Returns bytes; it does NOT write
  files, so nothing here needs filesystem permissions or cleanup.

Every attempt is recorded append-only (`LicenceDeliveryAttempt`) — that record
is what the ageing-delivery alert reads, and what separates "never attempted"
from "attempted, never sent" from "sent repeatedly, never acknowledged". Those
are three different faults pointing at three different systems, and an alert
that blurs them sends the operator to the wrong one.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, runtime_checkable
from uuid import UUID

from dotmac_kernel import (
    BadRequestError,
    NotFoundError,
    write_platform_audit_event,
)
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vendor_cp.config import vendor_settings
from vendor_cp.licensing.delivery_models import (
    AttemptOutcome,
    DeliveryState,
    LicenceDelivery,
    LicenceDeliveryAttempt,
    LicenceDeliveryState,
)
from vendor_cp.licensing.models import LicenceIssuance

LOGGING_MODE = "logging"
OFFLINE_MODE = "offline_bundle"


class TransportModeNotPermittedError(RuntimeError):
    """An unknown `VENDOR_LICENCE_DELIVERY_MODE`. Fail closed rather than
    silently not delivering."""


class TransportErrorCode(str, Enum):
    """The CLOSED vocabulary of persistable failure codes.

    A shape check is not enough, and that was the bug: `bearer
    SUPERSECRETTOKEN` normalises to a perfectly well-formed
    `bearer_supersecrettoken` and would have been stored verbatim. Only members
    of this enum are ever written, so a secret cannot become a code merely by
    looking like one. Extending the vocabulary is a deliberate code change,
    reviewed like any other.
    """

    UNSPECIFIED = "unspecified"
    TRANSPORT_FAILED = "transport_failed"
    TRANSPORT_TERMINAL = "transport_terminal"
    ENDPOINT_UNREACHABLE = "endpoint_unreachable"
    ENDPOINT_TIMEOUT = "endpoint_timeout"
    AUTHENTICATION_FAILED = "authentication_failed"
    REJECTED_BY_TARGET = "rejected_by_target"
    TARGET_NOT_CONFIGURED = "target_not_configured"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    RETRY_EXHAUSTED = "retry_exhausted"


def _closed_code(code: TransportErrorCode | str) -> str:
    """Map to the closed vocabulary, or `unspecified`. Anything not already an
    approved member is DISCARDED — never normalised into storage."""
    if isinstance(code, TransportErrorCode):
        return code.value
    try:
        return TransportErrorCode(code).value
    except ValueError:
        return TransportErrorCode.UNSPECIFIED.value


class TransportError(RuntimeError):
    """A delivery attempt failed.

    `code` is a `TransportErrorCode` member and is the ONLY thing persisted or
    audited. Transport exception text routinely carries URLs, response bodies,
    headers, and bearer tokens; this table is read by dashboards and support
    staff, so the message never reaches storage. `retryable` CONTROLS replay —
    it is not an observation.
    """

    retryable = True
    default_code = TransportErrorCode.TRANSPORT_FAILED

    def __init__(
        self, message: str = "", *, code: TransportErrorCode | str | None = None
    ) -> None:
        super().__init__(message)
        self.code = _closed_code(code if code is not None else self.default_code)


class TerminalTransportError(TransportError):
    """Will never succeed for this document. Parks the delivery immediately —
    no further attempts, alert now."""

    retryable = False
    default_code = TransportErrorCode.TRANSPORT_TERMINAL


@dataclass(frozen=True, slots=True)
class DeliveryPacket:
    """What a transport is handed: the frozen envelope plus the identifiers an
    operator needs to trace it. No decisions, no mutable state."""

    delivery_id: UUID
    licence_id: UUID
    licence_version: int
    digest: str
    target_ref: str
    envelope: Mapping[str, object]


@runtime_checkable
class LicenceDeliveryTransport(Protocol):
    """Move one packet to its target, or raise a `TransportError`."""

    @property
    def name(self) -> str: ...

    def send(self, packet: DeliveryPacket) -> None: ...


class LoggingTransport:
    """Records packets in memory instead of sending them. The reference
    transport for this phase and the one tests drive."""

    name = LOGGING_MODE

    def __init__(self, *, fail_with: TransportError | None = None) -> None:
        self.sent: list[DeliveryPacket] = []
        self._fail_with = fail_with

    def send(self, packet: DeliveryPacket) -> None:
        if self._fail_with is not None:
            raise self._fail_with
        self.sent.append(packet)


class OfflineBundleTransport:
    """Renders an ENVELOPE BUNDLE for an air-gapped site.

    Deliberately NOT called self-contained. It carries the signed licence
    envelope and, when supplied, the current signed revocation list — both
    authenticated artifacts a receiver can verify on its own. It does NOT carry
    the verification keyring, because an unsigned keyring travelling beside the
    document it authenticates is worthless: an attacker who can alter the
    bundle would simply swap both.

    **Receiver prerequisites, which this bundle does not satisfy:**
    1. the verification keyring must already be provisioned out-of-band (that
       is what makes any of this trustworthy);
    2. the receiver applies the revocation list itself — carrying it here does
       not prove import;
    3. there is no import receipt, so nothing in this flow tells the vendor the
       bundle was applied. That needs the import-acknowledgement channel noted
       in `ops.py`.

    Returned as bytes for the caller to route (removable media, ticket
    attachment); writing files is an operator concern, not this module's.
    """

    name = OFFLINE_MODE

    def __init__(self, *, revocation_envelope: Mapping[str, object] | None = None):
        self.bundles: list[bytes] = []
        self._revocation_envelope = revocation_envelope

    def send(self, packet: DeliveryPacket) -> None:
        self.bundles.append(
            self.render(packet, revocation_envelope=self._revocation_envelope)
        )

    @staticmethod
    def render(
        packet: DeliveryPacket,
        *,
        revocation_envelope: Mapping[str, object] | None = None,
    ) -> bytes:
        bundle: dict[str, object] = {
            "bundle": "dotmac-licence-envelope-bundle/1",
            "licence_id": str(packet.licence_id),
            "licence_version": packet.licence_version,
            "digest": packet.digest,
            "target_ref": packet.target_ref,
            "envelope": dict(packet.envelope),
            # Stated in the artifact so an operator opening it sees what it
            # does NOT include, rather than assuming it is everything.
            "requires": [
                "verification-keyring-provisioned-out-of-band",
                "receiver-applies-revocation-list",
                "no-import-receipt",
            ],
        }
        if revocation_envelope is not None:
            bundle["revocation_list"] = dict(revocation_envelope)
        return json.dumps(bundle, indent=2, sort_keys=True).encode()


def build_delivery_transport() -> LicenceDeliveryTransport:
    """The transport for this deployment, per `VENDOR_LICENCE_DELIVERY_MODE`."""
    mode = vendor_settings.licence_delivery_mode
    if mode == LOGGING_MODE:
        return LoggingTransport()
    if mode == OFFLINE_MODE:
        return OfflineBundleTransport()
    raise TransportModeNotPermittedError(
        f"VENDOR_LICENCE_DELIVERY_MODE={mode!r} is not a delivery mode — "
        f"expected {LOGGING_MODE!r} or {OFFLINE_MODE!r}. Networked transports "
        "are a separate, credentialed slice."
    )


# ── Replay ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class DispatchReport:
    """What one replay pass did. Retryable failures, terminal failures, and
    exhaustion are separated because they demand different operator
    responses — and the latter two PARK the delivery."""

    attempted: int
    sent: int
    failed: int
    parked_terminal: int
    parked_exhausted: int


def _packet(db: Session, delivery: LicenceDelivery) -> DeliveryPacket:
    issuance = db.get(LicenceIssuance, delivery.issuance_id)
    if issuance is None:  # unreachable: FK-enforced
        raise RuntimeError(f"delivery {delivery.id} references a missing issuance")
    return DeliveryPacket(
        delivery_id=delivery.id,
        licence_id=issuance.licence_id,
        licence_version=issuance.version,
        digest=issuance.digest,
        target_ref=delivery.target_ref,
        envelope=dict(issuance.envelope),
    )


def _current_generation(db: Session, delivery_id: UUID) -> int:
    state = db.execute(
        select(LicenceDeliveryState).where(
            LicenceDeliveryState.delivery_id == delivery_id
        )
    ).scalar_one()
    return state.replay_generation


def _attempt_count(db: Session, delivery_id: UUID, *, generation: int) -> int:
    """Attempts in the CURRENT replay generation only.

    Attempts are immutable and kept forever, so the historical record survives
    a resume — but the retry BUDGET must reset, otherwise resuming an exhausted
    delivery re-parks it on the next pass without a single new attempt.
    """
    return int(
        db.execute(
            select(func.count())
            .select_from(LicenceDeliveryAttempt)
            .where(
                LicenceDeliveryAttempt.delivery_id == delivery_id,
                LicenceDeliveryAttempt.replay_generation == generation,
            )
        ).scalar_one()
    )


def pending_deliveries(
    db: Session, *, limit: int = 100, claim: bool = False
) -> Sequence[LicenceDelivery]:
    """Deliveries eligible for replay: staged, not acknowledged, not parked.

    With `claim=True` the rows are locked FOR UPDATE SKIP LOCKED, so concurrent
    replay workers take DISJOINT work-lists. Without it, two workers would read
    the same delivery, compute the same `max(attempt_no) + 1`, and race — one
    losing on the unique constraint after already sending. Skip-locked is used
    only on backends that support it (SQLite in unit tests does not; tenancy
    and concurrency are proven on Postgres).
    """
    statement = (
        select(LicenceDelivery)
        .join(
            LicenceDeliveryState,
            LicenceDeliveryState.delivery_id == LicenceDelivery.id,
        )
        .where(
            LicenceDeliveryState.state.notin_(
                [DeliveryState.ACTIVE.value, DeliveryState.PARKED.value]
            ),
            # Defence in depth: a delivery with no resolved destination is
            # never replayable, whatever its state says.
            LicenceDelivery.target_id.isnot(None),
        )
        .order_by(LicenceDelivery.created_at)
        .limit(limit)
    )
    if claim and db.bind is not None and db.bind.dialect.name == "postgresql":
        statement = statement.with_for_update(skip_locked=True, of=LicenceDelivery)
    return list(db.execute(statement).scalars())


def _park(
    db: Session,
    delivery: LicenceDelivery,
    *,
    reason_code: str,
    actor_admin_id: UUID | None,
) -> None:
    """Stop replaying this delivery and make it loud. Parked is not deleted —
    an operator resumes it after fixing the cause."""
    state = db.execute(
        select(LicenceDeliveryState).where(
            LicenceDeliveryState.delivery_id == delivery.id
        )
    ).scalar_one()
    state.state = DeliveryState.PARKED.value
    db.flush()
    write_platform_audit_event(
        db,
        actor_admin_id=actor_admin_id,
        action="vendor.licence.delivery_parked",
        entity_type="licence_delivery",
        entity_id=str(delivery.id),
        details={"reason_code": reason_code, "target_ref": delivery.target_ref},
    )


def resume_delivery(
    db: Session, delivery_id: UUID, *, actor_admin_id: UUID | None = None
) -> None:
    """Un-park a delivery after the cause is fixed; replay picks it up again."""
    delivery = db.get(LicenceDelivery, delivery_id)
    if delivery is None:
        raise NotFoundError(f"licence delivery {delivery_id} not found")
    # Mapping is a PRECONDITION, not an afterthought: resuming an unmapped
    # delivery would move it out of `parked` and straight out of replay
    # eligibility (the claim query excludes null targets), so it would silently
    # disappear instead of being fixed.
    if delivery.target_id is None:
        raise BadRequestError(
            f"delivery {delivery_id} has no resolved destination — map it with "
            "`map_legacy_delivery` before resuming, or it will vanish from "
            "replay instead of being retried"
        )
    state = db.execute(
        select(LicenceDeliveryState).where(
            LicenceDeliveryState.delivery_id == delivery_id
        )
    ).scalar_one_or_none()
    if state is None:
        raise NotFoundError(f"licence delivery {delivery_id} not found")
    if state.state != DeliveryState.PARKED.value:
        return
    state.state = DeliveryState.DELIVERED.value
    # A new generation resets the retry budget WITHOUT touching the immutable
    # attempt history — resuming with the old budget would re-park immediately.
    state.replay_generation += 1
    db.flush()
    write_platform_audit_event(
        db,
        actor_admin_id=actor_admin_id,
        action="vendor.licence.delivery_resumed",
        entity_type="licence_delivery",
        entity_id=str(delivery_id),
        details={"replay_generation": state.replay_generation},
    )


def dispatch_pending(
    db: Session,
    *,
    transport: LicenceDeliveryTransport | None = None,
    limit: int = 100,
    max_attempts: int = 10,
    actor_admin_id: UUID | None = None,
) -> DispatchReport:
    """Re-send every delivery that has not been acknowledged as applied.

    At-least-once: a delivery already received is simply re-sent, which the
    receiver and the ack path both treat as idempotent. A delivery is abandoned
    after `max_attempts` — it stays visible and re-dispatchable once an operator
    fixes the cause; nothing is deleted.
    """
    transport = transport or build_delivery_transport()
    attempted = sent = failed = parked_terminal = parked_exhausted = 0

    for delivery in pending_deliveries(db, limit=limit, claim=True):
        generation = _current_generation(db, delivery.id)
        prior = _attempt_count(db, delivery.id, generation=generation)
        if prior >= max_attempts:
            parked_exhausted += 1
            _park(
                db,
                delivery,
                reason_code=TransportErrorCode.RETRY_EXHAUSTED.value,
                actor_admin_id=actor_admin_id,
            )
            continue

        attempted += 1
        attempt_no = prior + 1
        try:
            transport.send(_packet(db, delivery))
        except TransportError as exc:
            failed += 1
            terminal = not exc.retryable
            db.add(
                LicenceDeliveryAttempt(
                    delivery_id=delivery.id,
                    replay_generation=generation,
                    attempt_no=attempt_no,
                    transport=transport.name,
                    outcome=(
                        AttemptOutcome.TERMINAL.value
                        if terminal
                        else AttemptOutcome.FAILED.value
                    ),
                    # ONLY the stable code — never the exception text.
                    error_code=exc.code,
                )
            )
            db.flush()
            write_platform_audit_event(
                db,
                actor_admin_id=actor_admin_id,
                action="vendor.licence.delivery_attempt_failed",
                entity_type="licence_delivery",
                entity_id=str(delivery.id),
                details={
                    "attempt_no": attempt_no,
                    "transport": transport.name,
                    "retryable": exc.retryable,
                    "error_code": exc.code,
                },
            )
            if terminal:
                parked_terminal += 1
                _park(
                    db,
                    delivery,
                    reason_code=exc.code,
                    actor_admin_id=actor_admin_id,
                )
            continue

        sent += 1
        db.add(
            LicenceDeliveryAttempt(
                delivery_id=delivery.id,
                replay_generation=generation,
                attempt_no=attempt_no,
                transport=transport.name,
                outcome=AttemptOutcome.SENT.value,
            )
        )
        db.flush()

    return DispatchReport(
        attempted=attempted,
        sent=sent,
        failed=failed,
        parked_terminal=parked_terminal,
        parked_exhausted=parked_exhausted,
    )


__all__ = [
    "LOGGING_MODE",
    "OFFLINE_MODE",
    "TransportModeNotPermittedError",
    "TransportErrorCode",
    "TransportError",
    "TerminalTransportError",
    "DeliveryPacket",
    "LicenceDeliveryTransport",
    "LoggingTransport",
    "OfflineBundleTransport",
    "build_delivery_transport",
    "DispatchReport",
    "pending_deliveries",
    "dispatch_pending",
    "resume_delivery",
]
