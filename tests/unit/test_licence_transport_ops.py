"""Delivery transports, at-least-once replay, and the alerting surface.

The properties that matter operationally:

- replay re-sends anything not acknowledged as `active`, because a transport
  reporting success proves nothing about whether a deployment applied it;
- attempts are recorded, so an alert can distinguish "never sent" from "sent
  repeatedly, never acknowledged" — different faults, different responses;
- the mis-issue tripwire (unknown-digest acks) is surfaced as its own count.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from datetime import UTC, date, datetime, timedelta

import pytest
from dotmac_kernel import CapabilityCatalogue, FeatureManifest
from dotmac_kernel.testing import create_test_engine, isolated_session
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vendor_cp import config as vendor_config
from vendor_cp.allocations import service as allocations
from vendor_cp.approvals import service as approvals
from vendor_cp.contracts import service as contracts
from vendor_cp.licensing import ops, projection
from vendor_cp.licensing import service as licensing
from vendor_cp.licensing import transport as transport_module
from vendor_cp.licensing.delivery_models import (
    AttemptOutcome,
    DeliveryState,
    LicenceDeliveryAttempt,
)
from vendor_cp.licensing.signer import EphemeralLicenceSigner
from vendor_cp.licensing.transport import (
    DeliveryPacket,
    LoggingTransport,
    OfflineBundleTransport,
    TerminalTransportError,
    TransportError,
    TransportModeNotPermittedError,
    build_delivery_transport,
    dispatch_pending,
    pending_deliveries,
)
from vendor_cp.offers.models import OfferVersion

NOW = datetime(2026, 8, 2, 12, 0, 0, tzinfo=UTC)
TARGET = "deployment-endpoint-1"


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as s:
            yield s
    finally:
        engine.dispose()


@pytest.fixture
def signer() -> EphemeralLicenceSigner:
    return EphemeralLicenceSigner(key_id="vendor-key-1")


def _catalogue(*codes: str) -> CapabilityCatalogue:
    return CapabilityCatalogue.from_manifests(
        [FeatureManifest(name="t", capabilities=tuple(codes))]
    )


def _staged(db: Session, *, suffix: str, customer_ref: str) -> uuid.UUID:
    offer_code = f"off-{suffix}"
    db.add(
        OfferVersion(
            offer_code=offer_code,
            version=1,
            amount="10.00",
            currency_code="USD",
            capability_codes=["cap.a"],
        )
    )
    db.flush()
    draft = contracts.create_draft(
        db,
        contracts.CreateDraftCommand(
            command_id=f"d-{uuid.uuid4()}",
            customer_ref=customer_ref,
            legal_entity="Dotmac Ltd",
            currency_code="USD",
            term_start=date(2026, 1, 1),
            term_end=date(2026, 12, 31),
            lines=(contracts.LineInput(offer_code, 1, "cap.a", quantity=1),),
        ),
    )
    submitted = contracts.submit(
        db,
        contracts.SubmitCommand(
            command_id=f"s-{uuid.uuid4()}",
            contract_id=draft.id,
            approval_policy_code=f"p-{suffix}",
            approval_policy_version=1,
            submitter_id=uuid.uuid4(),
        ),
        catalogue=_catalogue("cap.a"),
    )
    approvals.publish_policy_version(
        db,
        approvals.PublishPolicyCommand(
            command_id=f"pol-{uuid.uuid4()}",
            policy_code=f"p-{suffix}",
            version=1,
            quorum=1,
        ),
    )
    approvals.record_approval(
        db,
        approvals.RecordApprovalCommand(
            command_id=f"a-{uuid.uuid4()}",
            policy_code=f"p-{suffix}",
            policy_version=1,
            subject_type="contract",
            subject_id=str(draft.id),
            content_hash=submitted.content_hash or "",
            approver_id=uuid.uuid4(),
        ),
    )
    contracts.approve(
        db,
        contracts.TransitionCommand(
            command_id=f"ap-{uuid.uuid4()}", contract_id=draft.id
        ),
    )
    contracts.activate(
        db,
        contracts.TransitionCommand(
            command_id=f"act-{uuid.uuid4()}",
            contract_id=draft.id,
            activation_evidence="countersigned",
        ),
    )
    return allocations.stage_allocation(
        db,
        allocations.StageAllocationCommand(
            source_event_id=f"evt-{uuid.uuid4()}",
            contract_id=draft.id,
            content_hash=submitted.content_hash or "",
            customer_ref=customer_ref,
        ),
    ).id


def _issue_and_stage(db, signer, *, suffix="a", customer_ref="cust-a"):
    issued = licensing.issue_licence(
        db,
        licensing.IssueLicenceCommand(
            allocation_id=_staged(db, suffix=suffix, customer_ref=customer_ref),
            product="dotmac-sub",
        ),
        signer=signer,
        now=NOW,
    )
    delivery = projection.stage_delivery(
        db,
        projection.StageDeliveryCommand(issuance_id=issued.id, target_ref=TARGET),
    )
    return issued, delivery


def _ack(db, issued, *, status="applied", reason=None, digest=None):
    return projection.ingest_acknowledgement(
        db,
        projection.AcknowledgementInput(
            licence_id=str(issued.licence_id),
            licence_version=issued.version,
            digest=digest or issued.digest,
            status=status,
            reason=reason,
        ),
    )


# ── Transports ──────────────────────────────────────────────────────────────


def test_logging_transport_receives_the_frozen_envelope(db, signer) -> None:
    issued, delivery = _issue_and_stage(db, signer)
    transport = LoggingTransport()
    dispatch_pending(db, transport=transport)

    assert len(transport.sent) == 1
    packet = transport.sent[0]
    assert packet.delivery_id == delivery.id
    assert packet.digest == issued.digest
    assert packet.envelope == issued.envelope


def test_offline_bundle_is_self_contained_and_deterministic(db, signer) -> None:
    issued, delivery = _issue_and_stage(db, signer)
    packet = DeliveryPacket(
        delivery_id=delivery.id,
        licence_id=issued.licence_id,
        licence_version=issued.version,
        digest=issued.digest,
        target_ref=TARGET,
        envelope=issued.envelope,
    )
    bundle = OfflineBundleTransport.render(packet)
    decoded = json.loads(bundle)

    # Everything the air-gapped receiver needs, and the signature is what makes
    # it acceptable — so a bundle needs no trusted channel.
    assert decoded["bundle"] == "dotmac-licence-bundle/1"
    assert decoded["digest"] == issued.digest
    assert decoded["envelope"] == issued.envelope
    assert OfflineBundleTransport.render(packet) == bundle  # deterministic


def test_unknown_delivery_mode_fails_closed(monkeypatch) -> None:
    monkeypatch.setattr(
        transport_module,
        "vendor_settings",
        vendor_config.VendorSettings(
            provider_mode="fake", licence_delivery_mode="carrier-pigeon"
        ),
    )
    with pytest.raises(TransportModeNotPermittedError, match="carrier-pigeon"):
        build_delivery_transport()


def test_delivery_mode_selects_the_transport(monkeypatch) -> None:
    monkeypatch.setattr(
        transport_module,
        "vendor_settings",
        vendor_config.VendorSettings(
            provider_mode="fake", licence_delivery_mode="offline_bundle"
        ),
    )
    assert isinstance(build_delivery_transport(), OfflineBundleTransport)


# ── At-least-once replay ────────────────────────────────────────────────────


def test_unacknowledged_deliveries_are_resent(db, signer) -> None:
    """Re-delivery is expected, not exceptional: the receiver dedupes by
    version+digest and the ack path treats a repeat as `duplicate`."""
    _issue_and_stage(db, signer)
    transport = LoggingTransport()

    first = dispatch_pending(db, transport=transport)
    second = dispatch_pending(db, transport=transport)

    assert (first.sent, second.sent) == (1, 1)
    assert len(transport.sent) == 2
    assert (
        db.execute(
            select(func.count()).select_from(LicenceDeliveryAttempt)
        ).scalar_one()
        == 2
    )


def test_an_acknowledged_delivery_is_not_resent(db, signer) -> None:
    issued, delivery = _issue_and_stage(db, signer)
    dispatch_pending(db, transport=LoggingTransport())
    _ack(db, issued)
    assert (
        projection.delivery_status(db, delivery.id).state == DeliveryState.ACTIVE.value
    )

    transport = LoggingTransport()
    report = dispatch_pending(db, transport=transport)
    assert report.attempted == 0
    assert transport.sent == []


def test_failed_attempts_are_recorded_with_their_error(db, signer) -> None:
    _issue_and_stage(db, signer)
    transport = LoggingTransport(fail_with=TransportError("endpoint unreachable"))

    report = dispatch_pending(db, transport=transport)

    assert (report.attempted, report.sent, report.failed) == (1, 0, 1)
    attempt = db.execute(select(LicenceDeliveryAttempt)).scalar_one()
    assert attempt.outcome == AttemptOutcome.FAILED.value
    assert "endpoint unreachable" in (attempt.error or "")


def test_delivery_is_abandoned_after_max_attempts_but_retained(db, signer) -> None:
    """Abandoned is not deleted: the delivery stays visible and re-dispatchable
    once an operator fixes the cause."""
    _, delivery = _issue_and_stage(db, signer)
    failing = LoggingTransport(fail_with=TransportError("down"))
    for _ in range(3):
        dispatch_pending(db, transport=failing, max_attempts=3)

    report = dispatch_pending(db, transport=failing, max_attempts=3)
    assert (report.attempted, report.abandoned) == (0, 1)
    assert delivery.id in {d.id for d in pending_deliveries(db)}

    # Raising the ceiling resumes delivery — nothing was lost.
    resumed = dispatch_pending(db, transport=LoggingTransport(), max_attempts=5)
    assert resumed.sent == 1


def test_terminal_errors_are_still_recorded_as_attempts(db, signer) -> None:
    _issue_and_stage(db, signer)
    transport = LoggingTransport(fail_with=TerminalTransportError("rejected"))
    report = dispatch_pending(db, transport=transport)
    assert report.failed == 1
    assert db.execute(select(LicenceDeliveryAttempt)).scalar_one().error is not None


# ── Alerting surface ────────────────────────────────────────────────────────


def test_ageing_unacknowledged_split_by_whether_we_ever_sent(db, signer) -> None:
    """The distinction that decides where an operator looks: our transport, or
    the deployment."""
    _issue_and_stage(db, signer, suffix="a", customer_ref="cust-a")
    _issue_and_stage(db, signer, suffix="b", customer_ref="cust-b")
    # Send only one of them.
    sent_once = LoggingTransport()
    dispatch_pending(db, transport=sent_once, limit=1)

    later = NOW + timedelta(days=2)
    health = ops.pipeline_health(db, now=later, ack_sla=timedelta(hours=24))

    assert health.unacknowledged_total == 2
    assert health.unacknowledged_sent == 1
    assert health.unacknowledged_never_sent == 1
    assert health.oldest_unacknowledged_age_seconds is not None


def test_recent_deliveries_are_not_flagged(db, signer) -> None:
    _issue_and_stage(db, signer)
    health = ops.pipeline_health(
        db, now=NOW + timedelta(minutes=5), ack_sla=timedelta(hours=24)
    )
    assert health.unacknowledged_total == 0


def test_rejected_acks_are_grouped_by_reason(db, signer) -> None:
    issued_a, _ = _issue_and_stage(db, signer, suffix="a", customer_ref="cust-a")
    issued_b, _ = _issue_and_stage(db, signer, suffix="b", customer_ref="cust-b")
    _ack(db, issued_a, status="rejected", reason="UndeclaredCapabilityError")
    _ack(db, issued_b, status="rejected", reason="UndeclaredCapabilityError")
    _ack(db, issued_b, status="rejected", reason="LicenceExpiredError")

    health = ops.pipeline_health(db, now=NOW)
    assert health.rejected_by_reason == {
        "UndeclaredCapabilityError": 2,
        "LicenceExpiredError": 1,
    }


def test_unknown_digest_acks_are_surfaced_as_the_tripwire(db, signer) -> None:
    issued, _ = _issue_and_stage(db, signer)
    _ack(db, issued, digest="sha256:never-issued-this")

    health = ops.pipeline_health(db, now=NOW)
    assert health.unknown_digest_acks == 1
    assert health.quarantined_acks == 1


def test_revocation_import_lag_is_reported_as_unmeasurable(db, signer) -> None:
    """Honest by design: the vendor cannot know which list a deployment
    imported, so this must read "not measurable" rather than a misleading
    zero. Closing it needs an import-acknowledgement channel."""
    assert ops.revocation_import_lag_supported() is False
    health = ops.pipeline_health(db, now=NOW)
    assert health.revocation_import_lag_measurable is False
    assert health.latest_revocation_list_version is None


def test_latest_published_revocation_list_is_reported(db, signer) -> None:
    from vendor_cp.licensing import revocation

    revocation.publish_revocation_list(db, signer=signer, now=NOW)
    health = ops.pipeline_health(db, now=NOW)
    assert health.latest_revocation_list_version == 1
