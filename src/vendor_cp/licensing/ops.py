"""Operational signals for the licence pipeline — what to alert on.

These are read-only queries over facts the pipeline already records. They exist
because the WS8 failure modes are quiet: nothing crashes when a deployment
stops acknowledging, or when acks start arriving for digests we never issued.

Four signals were requested. Three are computable from vendor-side facts and
are implemented here:

- **Ageing unacknowledged deliveries** — staged, dispatched, never acknowledged
  as applied. Split by whether we ever managed to send, because "never sent"
  (transport/config fault) and "sent repeatedly, never acknowledged" (receiver
  or connectivity fault) point at completely different causes.
- **Rejected acknowledgements by reason** — the receiver told us why it refused;
  a spike in one reason is a systematic fault, not bad luck.
- **Unknown-digest acknowledgements** — the mis-issue/tamper tripwire. This one
  should be alerted on at ANY non-zero count, not on a threshold.

The fourth, **revocation-import lag**, is NOT implemented, and deliberately not
faked: the vendor has no way to know which list version a deployment has
imported, because there is no import-acknowledgement channel — the product
imports lists locally and tells no one. Reporting "time since we published"
would look like a lag metric while measuring only our own behaviour, which is
worse than reporting nothing. `revocation_import_lag_supported()` returns False
so a dashboard can say "not measurable" instead of showing a misleading zero.
Closing this needs an import-ack path (product reports its applied list
version) — a cross-plane contract change, not a query.
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


@dataclass(frozen=True, slots=True)
class LicencePipelineHealth:
    """A snapshot an alerting rule can evaluate directly."""

    unacknowledged_total: int
    unacknowledged_never_sent: int
    unacknowledged_sent: int
    oldest_unacknowledged_age_seconds: int | None
    rejected_by_reason: dict[str, int] = field(default_factory=dict)
    unknown_digest_acks: int = 0
    quarantined_acks: int = 0
    latest_revocation_list_version: int | None = None
    revocation_import_lag_measurable: bool = False


def revocation_import_lag_supported() -> bool:
    """False until deployments acknowledge revocation-list imports. See the
    module docstring — a proxy metric here would mislead."""
    return False


def pipeline_health(
    db: Session, *, now: datetime, ack_sla: timedelta = DEFAULT_ACK_SLA
) -> LicencePipelineHealth:
    """Compute the alertable signals as of `now` (injected, never read from the
    wall clock, so a report is reproducible)."""
    cutoff = now - ack_sla

    stale = db.execute(
        select(LicenceDelivery.id, LicenceDelivery.created_at)
        .join(
            LicenceDeliveryState,
            LicenceDeliveryState.delivery_id == LicenceDelivery.id,
        )
        .where(
            LicenceDeliveryState.state != DeliveryState.ACTIVE.value,
            LicenceDelivery.created_at <= cutoff,
        )
    ).all()
    never_sent = 0
    oldest_age: int | None = None
    for delivery_id, created_at in stale:
        sent_attempts = int(
            db.execute(
                select(func.count())
                .select_from(LicenceDeliveryAttempt)
                .where(
                    LicenceDeliveryAttempt.delivery_id == delivery_id,
                    LicenceDeliveryAttempt.outcome == AttemptOutcome.SENT.value,
                )
            ).scalar_one()
        )
        if sent_attempts == 0:
            never_sent += 1
        if created_at is not None:
            reference = created_at
            if reference.tzinfo is None:
                reference = reference.replace(tzinfo=now.tzinfo)
            age = int((now - reference).total_seconds())
            oldest_age = age if oldest_age is None else max(oldest_age, age)

    rejected_rows = db.execute(
        select(LicenceAckRecord.reason, func.count())
        .where(
            LicenceAckRecord.disposition == AckDisposition.REJECTED_BY_RECEIVER.value
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
            .where(LicenceAckRecord.disposition == AckDisposition.UNKNOWN_DIGEST.value)
        ).scalar_one()
    )
    quarantined = int(
        db.execute(
            select(func.count())
            .select_from(LicenceAckRecord)
            .where(
                LicenceAckRecord.disposition.in_(
                    [
                        AckDisposition.UNKNOWN_DIGEST.value,
                        AckDisposition.UNKNOWN_LICENCE.value,
                        AckDisposition.DEPLOYMENT_MISMATCH.value,
                    ]
                )
            )
        ).scalar_one()
    )
    latest_list = db.execute(
        select(func.max(LicenceRevocationList.list_version))
    ).scalar()

    return LicencePipelineHealth(
        unacknowledged_total=len(stale),
        unacknowledged_never_sent=never_sent,
        unacknowledged_sent=len(stale) - never_sent,
        oldest_unacknowledged_age_seconds=oldest_age,
        rejected_by_reason=rejected_by_reason,
        unknown_digest_acks=unknown_digest,
        quarantined_acks=quarantined,
        latest_revocation_list_version=(
            int(latest_list) if latest_list is not None else None
        ),
        revocation_import_lag_measurable=revocation_import_lag_supported(),
    )


__all__ = [
    "DEFAULT_ACK_SLA",
    "LicencePipelineHealth",
    "revocation_import_lag_supported",
    "pipeline_health",
]
