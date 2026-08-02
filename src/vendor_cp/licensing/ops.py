"""Operational signals for the licence pipeline — what to alert on.

These are read-only queries over facts the pipeline already records. They exist
because the WS8 failure modes are quiet: nothing crashes when a deployment
stops acknowledging, or when acks start arriving for digests we never issued.

Seven observations are kept SEPARATE, because each points at a different
system and collapsing them sends operators to the wrong place:

1. **Never attempted** — ZERO attempts exist. Nothing has tried to send it:
   the replay worker is not running, or the delivery is not eligible.
   (Attempts that were made and FAILED are a different fault and live in
   `attempted_never_sent`; folding them in here would blame the scheduler for
   a transport outage.)
2. **Attempted but never sent** — attempts exist, none of them a REAL handoff.
   Our transport or configuration. A `simulated` attempt lands here, never in
   "sent": an in-process transport that discarded the bytes has delivered
   nothing, whatever the endpoint reported.
3. **Sent, unacknowledged** — we delivered; the receiver is not applying or not
   reporting. Connectivity or receiver fault.
4. **Retry exhausted / terminal** — parked, replay STOPPED. Needs a human now;
   it will not fix itself.
5. **Receiver rejections, grouped by stable reason** — the deployment told us
   why. A spike in one reason is systematic, not bad luck.
6. **Unknown digest / unknown licence / deployment mismatch — CRITICAL.** The
   mis-issue and tamper tripwire; alert at ANY non-zero count, never on a
   threshold, and keep the three sub-counts visible.
7. **Keyring uptake lag during overlap** — NOT MEASURABLE (below).
8. **Revocation-list application lag** — NOT MEASURABLE (below).

Acknowledgement counts are computed over a **window** (default 24h), not
lifetime: a single historical quarantine event must not leave the dashboard
permanently red, because an alert that can never clear is one people learn to
ignore. Lifetime totals remain queryable from the append-only log.

**Why 6 and 7 are absent rather than approximated.** Both need the receiver to
report the keyring and revocation-list versions it has actually applied. The
vendor cannot infer either: "we sent it" and "we published it" describe only
our own behaviour, and a metric built from them would look like uptake while
measuring nothing about the fleet — worse than reporting nothing, because it
would read as green during exactly the outage it exists to catch. The flags
below say "not measurable" so a dashboard shows that honestly. Closing both
needs the same thing: a receiver-reported version channel (an import
acknowledgement, mirroring the licence ack) — a cross-plane contract change,
not a query.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vendor_cp.licensing.delivery_models import (
    AckDisposition,
    AttemptOutcome,
    DeliveryState,
    LicenceAckRecord,
    LicenceDelivery,
    LicenceDeliveryAttempt,
    LicenceDeliveryState,
)
from vendor_cp.licensing.revocation_models import LicenceRevocationList

DEFAULT_ACK_SLA = timedelta(hours=24)
# Acknowledgement counts are windowed so one historical event cannot pin the
# dashboard red forever — an alert that never clears is one people ignore.
DEFAULT_ACK_WINDOW = timedelta(hours=24)


@dataclass(frozen=True, slots=True)
class LicencePipelineHealth:
    """A snapshot an alerting rule can evaluate directly. Each field is one
    observation; none is a blend of two."""

    # 1–3: ageing, by what actually happened
    never_attempted: int = 0
    attempted_never_sent: int = 0
    sent_unacknowledged: int = 0
    oldest_unacknowledged_age_seconds: int | None = None
    # 3: replay stopped
    parked_total: int = 0
    # 4: receiver said no
    rejected_by_reason: dict[str, int] = field(default_factory=dict)
    # 5: CRITICAL — alert at any non-zero
    unknown_digest_acks: int = 0
    unknown_licence_acks: int = 0
    deployment_mismatch_acks: int = 0
    # Acks recorded as evidence because the caller proved no deployment
    # identity. Not a fault in itself — but a rising count means deployments
    # are reporting through a path that can never activate anything, which
    # looks like silence from the licence pipeline's side.
    unverified_identity_acks: int = 0
    # context
    latest_revocation_list_version: int | None = None
    # 6–7: not measurable without receiver-reported versions
    keyring_uptake_lag_measurable: bool = False
    revocation_application_lag_measurable: bool = False

    @property
    def critical_acks(self) -> int:
        """Any non-zero value here is a page, not a ticket."""
        return (
            self.unknown_digest_acks
            + self.unknown_licence_acks
            + self.deployment_mismatch_acks
        )

    @property
    def unacknowledged_total(self) -> int:
        return (
            self.never_attempted + self.attempted_never_sent + self.sent_unacknowledged
        )


def revocation_application_lag_supported() -> bool:
    """False until deployments report the revocation-list version they have
    APPLIED. "We published it" is not uptake."""
    return False


def keyring_uptake_lag_supported() -> bool:
    """False until deployments report the keyring version they hold. During a
    rotation overlap this is the number that decides whether it is safe to
    retire the old key — and guessing it is how a fleet gets stranded."""
    return False


def pipeline_health(
    db: Session,
    *,
    now: datetime,
    ack_sla: timedelta = DEFAULT_ACK_SLA,
    ack_window: timedelta = DEFAULT_ACK_WINDOW,
) -> LicencePipelineHealth:
    """Compute the alertable signals as of `now` (injected, never read from the
    wall clock, so a report is reproducible).

    `ack_window` bounds the acknowledgement counts so a single old event cannot
    pin the dashboard red forever.
    """
    cutoff = now - ack_sla
    ack_cutoff = now - ack_window

    parked_total = int(
        db.execute(
            select(func.count())
            .select_from(LicenceDeliveryState)
            .where(LicenceDeliveryState.state == DeliveryState.PARKED.value)
        ).scalar_one()
    )
    stale = db.execute(
        select(LicenceDelivery.id, LicenceDelivery.created_at)
        .join(
            LicenceDeliveryState,
            LicenceDeliveryState.delivery_id == LicenceDelivery.id,
        )
        .where(
            LicenceDeliveryState.state.notin_(
                [DeliveryState.ACTIVE.value, DeliveryState.PARKED.value]
            ),
            LicenceDelivery.created_at <= cutoff,
        )
    ).all()
    never_attempted = attempted_never_sent = sent_unacknowledged = 0
    oldest_age: int | None = None
    for delivery_id, created_at in stale:
        total_attempts = int(
            db.execute(
                select(func.count())
                .select_from(LicenceDeliveryAttempt)
                .where(LicenceDeliveryAttempt.delivery_id == delivery_id)
            ).scalar_one()
        )
        sent_attempts = int(
            db.execute(
                select(func.count())
                .select_from(LicenceDeliveryAttempt)
                .where(
                    LicenceDeliveryAttempt.delivery_id == delivery_id,
                    # ONLY real handoffs count. A `simulated` attempt means an
                    # in-process transport accepted and discarded the bytes;
                    # counting it as sent would report delivery that never
                    # happened and point the operator away from the fault.
                    LicenceDeliveryAttempt.outcome.in_(
                        [
                            AttemptOutcome.SENT.value,
                            AttemptOutcome.EXPORTED.value,
                        ]
                    ),
                )
            ).scalar_one()
        )
        if total_attempts == 0:
            never_attempted += 1
        elif sent_attempts == 0:
            attempted_never_sent += 1
        else:
            sent_unacknowledged += 1
        if created_at is not None:
            reference = created_at
            if reference.tzinfo is None:
                reference = reference.replace(tzinfo=now.tzinfo)
            age = int((now - reference).total_seconds())
            oldest_age = age if oldest_age is None else max(oldest_age, age)

    rejected_rows = db.execute(
        select(LicenceAckRecord.reason, func.count())
        .where(
            LicenceAckRecord.disposition == AckDisposition.REJECTED_BY_RECEIVER.value,
            LicenceAckRecord.created_at >= ack_cutoff,
        )
        .group_by(LicenceAckRecord.reason)
    ).all()
    rejected_by_reason: dict[str, int] = {
        (reason or "unspecified"): int(count) for reason, count in rejected_rows
    }

    unknown_digest = int(
        db.execute(
            select(func.count())
            .select_from(LicenceAckRecord)
            .where(
                LicenceAckRecord.disposition == AckDisposition.UNKNOWN_DIGEST.value,
                LicenceAckRecord.created_at >= ack_cutoff,
            )
        ).scalar_one()
    )

    def _count(disposition: AckDisposition) -> int:
        return int(
            db.execute(
                select(func.count())
                .select_from(LicenceAckRecord)
                .where(
                    LicenceAckRecord.disposition == disposition.value,
                    LicenceAckRecord.created_at >= ack_cutoff,
                )
            ).scalar_one()
        )

    latest_list = db.execute(
        select(func.max(LicenceRevocationList.list_version))
    ).scalar()

    return LicencePipelineHealth(
        never_attempted=never_attempted,
        attempted_never_sent=attempted_never_sent,
        sent_unacknowledged=sent_unacknowledged,
        oldest_unacknowledged_age_seconds=oldest_age,
        parked_total=parked_total,
        rejected_by_reason=rejected_by_reason,
        unknown_digest_acks=unknown_digest,
        unknown_licence_acks=_count(AckDisposition.UNKNOWN_LICENCE),
        deployment_mismatch_acks=_count(AckDisposition.DEPLOYMENT_MISMATCH),
        unverified_identity_acks=_count(AckDisposition.UNVERIFIED_IDENTITY),
        latest_revocation_list_version=(
            int(latest_list) if latest_list is not None else None
        ),
        keyring_uptake_lag_measurable=keyring_uptake_lag_supported(),
        revocation_application_lag_measurable=(revocation_application_lag_supported()),
    )


__all__ = [
    "DEFAULT_ACK_SLA",
    "DEFAULT_ACK_WINDOW",
    "LicencePipelineHealth",
    "revocation_application_lag_supported",
    "keyring_uptake_lag_supported",
    "pipeline_health",
]
