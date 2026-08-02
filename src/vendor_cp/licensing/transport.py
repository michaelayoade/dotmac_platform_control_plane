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
- `OfflineBundleTransport` — renders the signed envelope as a self-contained
  bundle an operator carries to an air-gapped site. Returns bytes; it does NOT
  write files, so nothing here needs filesystem permissions or cleanup.

Every attempt is recorded append-only (`LicenceDeliveryAttempt`) — that record
is what the ageing-delivery alert reads, and what tells an operator whether
silence means "never sent" or "sent repeatedly, never acknowledged". Those are
completely different faults and must not look alike.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable
from uuid import UUID

from dotmac_kernel import write_platform_audit_event
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


class TransportError(RuntimeError):
    """A delivery attempt failed. `retryable` distinguishes a transient fault
    from one that will never succeed for this document — the replay driver
    keeps retrying the former and stops wasting attempts on the latter."""

    retryable = True


class TerminalTransportError(TransportError):
    retryable = False


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
    """Renders a self-contained bundle for an air-gapped site.

    The bundle is the signed envelope plus its identifiers — everything the
    receiver needs, and nothing it must trust us about, since the signature is
    what makes it acceptable. Returned as bytes for the caller to route
    (removable media, ticket attachment); writing files is an operator concern,
    not this module's.
    """

    name = OFFLINE_MODE

    def __init__(self) -> None:
        self.bundles: list[bytes] = []

    def send(self, packet: DeliveryPacket) -> None:
        self.bundles.append(self.render(packet))

    @staticmethod
    def render(packet: DeliveryPacket) -> bytes:
        return json.dumps(
            {
                "bundle": "dotmac-licence-bundle/1",
                "licence_id": str(packet.licence_id),
                "licence_version": packet.licence_version,
                "digest": packet.digest,
                "target_ref": packet.target_ref,
                "envelope": dict(packet.envelope),
            },
            indent=2,
            sort_keys=True,
        ).encode()


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
    """What one replay pass did. `failed` and `abandoned` are separated because
    they demand different operator responses."""

    attempted: int
    sent: int
    failed: int
    abandoned: int


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


def _attempt_count(db: Session, delivery_id: UUID) -> int:
    return int(
        db.execute(
            select(func.count())
            .select_from(LicenceDeliveryAttempt)
            .where(LicenceDeliveryAttempt.delivery_id == delivery_id)
        ).scalar_one()
    )


def pending_deliveries(db: Session, *, limit: int = 100) -> Sequence[LicenceDelivery]:
    """Deliveries not yet acknowledged as applied — the replay work-list."""
    rows = db.execute(
        select(LicenceDelivery)
        .join(
            LicenceDeliveryState,
            LicenceDeliveryState.delivery_id == LicenceDelivery.id,
        )
        .where(LicenceDeliveryState.state != DeliveryState.ACTIVE.value)
        .order_by(LicenceDelivery.created_at)
        .limit(limit)
    ).scalars()
    return list(rows)


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
    attempted = sent = failed = abandoned = 0

    for delivery in pending_deliveries(db, limit=limit):
        prior = _attempt_count(db, delivery.id)
        if prior >= max_attempts:
            abandoned += 1
            continue

        attempted += 1
        attempt_no = prior + 1
        try:
            transport.send(_packet(db, delivery))
        except TransportError as exc:
            failed += 1
            db.add(
                LicenceDeliveryAttempt(
                    delivery_id=delivery.id,
                    attempt_no=attempt_no,
                    transport=transport.name,
                    outcome=AttemptOutcome.FAILED.value,
                    error=f"{type(exc).__name__}: {exc}"[:500],
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
                    "error": str(exc)[:200],
                },
            )
            continue

        sent += 1
        db.add(
            LicenceDeliveryAttempt(
                delivery_id=delivery.id,
                attempt_no=attempt_no,
                transport=transport.name,
                outcome=AttemptOutcome.SENT.value,
            )
        )
        db.flush()

    return DispatchReport(
        attempted=attempted, sent=sent, failed=failed, abandoned=abandoned
    )


__all__ = [
    "LOGGING_MODE",
    "OFFLINE_MODE",
    "TransportModeNotPermittedError",
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
]
