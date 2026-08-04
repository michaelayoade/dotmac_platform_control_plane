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
    LicenceDelivery,
    LicenceDeliveryAttempt,
    LicenceDeliveryTarget,
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


def _target_for(customer_ref: str) -> str:
    return f"{TARGET}-{customer_ref}"


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
    # Each customer gets its OWN registered target — sharing one across
    # customers is exactly what the cross-customer guard forbids.
    target_ref = _target_for(customer_ref)
    if (
        db.execute(
            select(LicenceDeliveryTarget).where(
                LicenceDeliveryTarget.target_ref == target_ref
            )
        ).scalar_one_or_none()
        is None
    ):
        db.add(LicenceDeliveryTarget(target_ref=target_ref, customer_ref=customer_ref))
        db.flush()
    delivery = projection.stage_delivery(
        db,
        projection.StageDeliveryCommand(issuance_id=issued.id, target_ref=target_ref),
    )
    delivery_row = db.get(LicenceDelivery, delivery.id)
    assert delivery_row is not None
    # Keep every SLA assertion on the injected test clock. TimestampMixin uses
    # the wall clock by default, which made this fixed-date suite expire as
    # soon as real time crossed the test's cutoff.
    delivery_row.created_at = NOW
    db.flush()
    return issued, delivery


def _ack(
    db, issued, *, status="applied", reason=None, digest=None, customer_ref="cust-a"
):
    return projection.ingest_acknowledgement(
        db,
        # A PROVEN deployment identity — the only path that can activate.
        authenticated_deployment_ref=_target_for(customer_ref),
        ack=projection.AcknowledgementInput(
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
    dispatch_pending(db, simulate=True, transport=transport)

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
        target_ref=_target_for("cust-a"),
        envelope=issued.envelope,
    )
    bundle = OfflineBundleTransport.render(packet)
    decoded = json.loads(bundle)

    # Everything the air-gapped receiver needs, and the signature is what makes
    # it acceptable — so a bundle needs no trusted channel.
    assert decoded["bundle"] == "dotmac-licence-envelope-bundle/1"
    assert decoded["digest"] == issued.digest
    assert decoded["envelope"] == issued.envelope
    # The artifact STATES what it does not include, so an operator opening it
    # cannot assume it is everything the receiver needs.
    assert decoded["requires"] == [
        "verification-keyring-provisioned-out-of-band",
        "receiver-applies-revocation-list",
        "no-import-receipt",
    ]
    assert "revocation_list" not in decoded  # none supplied
    assert OfflineBundleTransport.render(packet) == bundle  # deterministic


def test_offline_bundle_carries_the_signed_revocation_list_when_supplied(
    db, signer
) -> None:
    """The revocation list IS authenticated, so it can travel with the bundle —
    unlike the keyring, which would be worthless beside the document it
    authenticates."""
    from vendor_cp.licensing import revocation

    issued, delivery = _issue_and_stage(db, signer)
    published = revocation.publish_revocation_list(db, signer=signer, now=NOW)
    packet = DeliveryPacket(
        delivery_id=delivery.id,
        licence_id=issued.licence_id,
        licence_version=issued.version,
        digest=issued.digest,
        target_ref=_target_for("cust-a"),
        envelope=issued.envelope,
    )
    decoded = json.loads(
        OfflineBundleTransport.render(packet, revocation_envelope=published.envelope)
    )
    assert decoded["revocation_list"] == published.envelope


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

    first = dispatch_pending(db, simulate=True, transport=transport)
    second = dispatch_pending(db, simulate=True, transport=transport)

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
    dispatch_pending(db, simulate=True, transport=LoggingTransport())
    _ack(db, issued)
    assert (
        projection.delivery_status(db, delivery.id).state == DeliveryState.ACTIVE.value
    )

    transport = LoggingTransport()
    report = dispatch_pending(db, simulate=True, transport=transport)
    assert report.attempted == 0
    assert transport.sent == []


def test_failed_attempts_persist_a_safe_code_not_the_exception(db, signer) -> None:
    """Transport messages routinely carry URLs, bodies, and bearer tokens; this
    table is read by dashboards and support staff, so only the stable code is
    stored."""
    secret = "https://tenant.example/api?token=SUPERSECRET"
    _issue_and_stage(db, signer)
    transport = LoggingTransport(
        fail_with=TransportError(secret, code="endpoint_unreachable")
    )

    report = dispatch_pending(db, simulate=True, transport=transport)

    assert (report.attempted, report.sent, report.failed) == (1, 0, 1)
    attempt = db.execute(select(LicenceDeliveryAttempt)).scalar_one()
    assert attempt.outcome == AttemptOutcome.FAILED.value
    assert attempt.error_code == "endpoint_unreachable"
    assert "SUPERSECRET" not in str(attempt.__dict__)


@pytest.mark.parametrize(
    "smuggled",
    [
        # THE canary for the original defect: this is SAFE-LOOKING. A
        # shape-only filter normalises it to `bearer_supersecrettoken` and
        # stores the token verbatim. Only a closed vocabulary rejects it, so
        # this test fails the moment anyone reverts to shape filtering.
        "bearer SUPERSECRETTOKEN",
        "Bearer-AbC123",
        "api_key_9f8e7d6c",
        # URL/obviously-unsafe shapes a naive filter would already catch.
        "https://tenant.example/?token=abc",
        "endpoint unreachable: 401 {'authorization': 'Bearer xyz'}",
    ],
)
def test_codes_outside_the_closed_vocabulary_are_discarded(
    db, signer, smuggled: str
) -> None:
    _issue_and_stage(db, signer)
    transport = LoggingTransport(fail_with=TransportError("boom", code=smuggled))
    dispatch_pending(db, simulate=True, transport=transport)

    attempt = db.execute(select(LicenceDeliveryAttempt)).scalar_one()
    assert attempt.error_code == "unspecified"
    # The secret never reaches storage in ANY column.
    persisted = " ".join(str(v) for v in attempt.__dict__.values())
    assert "SUPERSECRETTOKEN" not in persisted
    assert "9f8e7d6c" not in persisted
    assert "Bearer" not in persisted


def test_a_code_carrying_unsafe_content_is_collapsed(db, signer) -> None:
    _issue_and_stage(db, signer)
    transport = LoggingTransport(
        fail_with=TransportError("boom", code="https://tenant.example/?token=abc")
    )
    dispatch_pending(db, simulate=True, transport=transport)
    assert (
        db.execute(select(LicenceDeliveryAttempt)).scalar_one().error_code
        == "unspecified"
    )


def test_exhausted_retries_park_the_delivery_and_stop_replay(db, signer) -> None:
    """Parked is not deleted, and it is not silently retried either: replay
    STOPS until an operator resumes it."""
    _, delivery = _issue_and_stage(db, signer)
    failing = LoggingTransport(fail_with=TransportError("down", code="down"))
    for _ in range(3):
        dispatch_pending(db, simulate=True, transport=failing, max_attempts=3)

    report = dispatch_pending(db, simulate=True, transport=failing, max_attempts=3)
    assert report.parked_exhausted == 1
    assert (
        projection.delivery_status(db, delivery.id).state == DeliveryState.PARKED.value
    )
    # Parked work is OFF the replay list…
    assert delivery.id not in {d.id for d in pending_deliveries(db)}
    quiet = dispatch_pending(
        db, simulate=True, transport=LoggingTransport(), max_attempts=9
    )
    assert quiet.attempted == 0

    # …until an operator resumes it, and nothing was lost.
    transport_module.resume_delivery(db, delivery.id)
    resumed = dispatch_pending(
        db, simulate=True, transport=LoggingTransport(), max_attempts=9
    )
    assert resumed.sent == 1


def test_terminal_failure_parks_immediately_without_burning_retries(db, signer) -> None:
    """`retryable` CONTROLS replay rather than describing it: a terminal fault
    will never succeed, so retrying is only delay before someone looks."""
    _, delivery = _issue_and_stage(db, signer)
    transport = LoggingTransport(
        fail_with=TerminalTransportError("rejected", code="rejected_by_target")
    )

    report = dispatch_pending(db, simulate=True, transport=transport, max_attempts=10)

    assert (report.failed, report.parked_terminal) == (1, 1)
    assert (
        projection.delivery_status(db, delivery.id).state == DeliveryState.PARKED.value
    )
    attempt = db.execute(select(LicenceDeliveryAttempt)).scalar_one()
    assert attempt.outcome == AttemptOutcome.TERMINAL.value
    assert attempt.error_code == "rejected_by_target"
    # One attempt only — no further retries were spent.
    assert dispatch_pending(db, simulate=True, transport=transport).attempted == 0


# ── Alerting surface ────────────────────────────────────────────────────────


def test_ageing_buckets_separate_never_attempted_simulated_and_real(db, signer) -> None:
    """Three distinct observations, and the middle one is the point of this
    batch: an in-process transport that DISCARDED the bytes must never be
    counted as sent. Reporting it as delivered manufactures evidence and sends
    the operator looking at the receiver instead of at our transport."""
    from vendor_cp.licensing import transport as transport_module

    # 1. never attempted — nothing has tried.
    _issue_and_stage(db, signer, suffix="a", customer_ref="cust-a")
    # 2. attempted, but only ever SIMULATED (in-process, discarded).
    _, simulated = _issue_and_stage(db, signer, suffix="b", customer_ref="cust-b")
    dispatch_pending(db, transport=LoggingTransport(), simulate=True, limit=100)
    # 3. a REAL handoff: the bundle left the process in a response.
    _, exported = _issue_and_stage(db, signer, suffix="c", customer_ref="cust-c")
    transport_module.export_delivery_bundle(db, delivery_id=exported.id)

    later = NOW + timedelta(days=2)
    health = ops.pipeline_health(db, now=later, ack_sla=timedelta(hours=24))

    assert health.unacknowledged_total == 3
    # The simulated one attempted twice (its own pass plus the sweep) and still
    # counts as never SENT.
    assert health.sent_unacknowledged == 1
    assert health.attempted_never_sent == 2
    assert health.never_attempted == 0
    assert simulated.id is not None


def test_recent_deliveries_are_not_flagged(db, signer) -> None:
    _issue_and_stage(db, signer)
    health = ops.pipeline_health(
        db, now=NOW + timedelta(minutes=5), ack_sla=timedelta(hours=24)
    )
    assert health.unacknowledged_total == 0


def test_rejected_acks_are_grouped_by_reason(db, signer) -> None:
    issued_a, _ = _issue_and_stage(db, signer, suffix="a", customer_ref="cust-a")
    issued_b, _ = _issue_and_stage(db, signer, suffix="b", customer_ref="cust-b")
    _ack(
        db,
        issued_a,
        status="rejected",
        reason="UndeclaredCapabilityError",
        customer_ref="cust-a",
    )
    _ack(
        db,
        issued_b,
        status="rejected",
        reason="UndeclaredCapabilityError",
        customer_ref="cust-b",
    )
    _ack(
        db,
        issued_b,
        status="rejected",
        reason="LicenceExpiredError",
        customer_ref="cust-b",
    )

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
    assert health.critical_acks == 1


def test_uptake_signals_are_reported_as_unmeasurable(db, signer) -> None:
    """Honest by design: the vendor cannot know which keyring or revocation
    list a deployment has APPLIED, so both must read "not measurable" rather
    than a misleading zero that would look green during the very outage they
    exist to catch. Both need receiver-reported versions."""
    assert ops.revocation_application_lag_supported() is False
    assert ops.keyring_uptake_lag_supported() is False
    health = ops.pipeline_health(db, now=NOW)
    assert health.revocation_application_lag_measurable is False
    assert health.keyring_uptake_lag_measurable is False
    assert health.latest_revocation_list_version is None


def test_parked_deliveries_are_their_own_alert_bucket(db, signer) -> None:
    """Retry-exhausted/terminal is a different response from "still trying"."""
    _issue_and_stage(db, signer)
    dispatch_pending(
        db,
        simulate=True,
        transport=LoggingTransport(
            fail_with=TerminalTransportError("x", code="rejected_by_target")
        ),
    )
    health = ops.pipeline_health(db, now=NOW + timedelta(days=2))
    assert health.parked_total == 1
    # Parked work is NOT also counted as ageing-unacknowledged: that would
    # double-report one fault in two buckets.
    assert health.unacknowledged_total == 0


def test_latest_published_revocation_list_is_reported(db, signer) -> None:
    from vendor_cp.licensing import revocation

    revocation.publish_revocation_list(db, signer=signer, now=NOW)
    health = ops.pipeline_health(db, now=NOW)
    assert health.latest_revocation_list_version == 1
