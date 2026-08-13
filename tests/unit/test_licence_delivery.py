"""Unit tests for `EntitlementProjectionService` (delivery + acknowledgement).

The contract under test: **`active` means the data plane COMMITTED a local
projection of this exact version and digest** — not that a call returned
successfully. Everything else follows: only a matching `applied` ack activates;
unknown/conflicting acks are recorded but quarantined; duplicates are
idempotent; a late v1 ack can never regress a v2 delivery.

The centrepiece is a cross-plane canary running the full chain —
activate → allocate → issue → stage → receiver apply → ingest ack → active —
plus its negative twin, where the receiver's transaction is rolled back and NO
applied acknowledgement is allowed to reach the vendor.

The "receiver" here is a stand-in built ONLY on the kernel's public licensing +
entitlement API (`verify_licence`, `grant_entitlement`, `AppliedLicence`), the
same contract the real reference receiver consumes: the vendor control plane
may not import a product data plane (deny-case D2). The REAL receiver
(`app/features/licensing`) is proven in `dotmac_starter_mt`; what this proves
is that documents this repo issues drive that contract correctly, and that the
vendor's ack handling is right.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, date, datetime

import pytest
from dotmac_kernel import (
    BadRequestError,
    CapabilityCatalogue,
    FeatureManifest,
    Tenant,
    grant_entitlement,
    is_entitled,
)
from dotmac_kernel.licensing import (
    AppliedLicence,
    LicenceAcknowledgement,
    verify_licence,
)
from dotmac_kernel.messaging import PlatformOutboxEvent
from dotmac_kernel.testing import create_test_engine, isolated_session
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vendor_cp.allocations import service as allocations
from vendor_cp.approvals import service as approvals
from vendor_cp.contracts import service as contracts
from vendor_cp.licensing import projection
from vendor_cp.licensing import service as licensing
from vendor_cp.licensing.delivery_models import (
    AckDisposition,
    DeliveryState,
    LicenceAckRecord,
    LicenceDelivery,
    LicenceDeliveryState,
    LicenceDeliveryTarget,
    TargetStatus,
)
from vendor_cp.licensing.signer import EphemeralLicenceSigner
from vendor_cp.offers.catalog import ProductCapabilityCatalogues
from vendor_cp.offers.models import OfferVersion

NOW = datetime(2026, 8, 2, 12, 0, 0, tzinfo=UTC)
PRODUCT = "dotmac-sub"
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


def _product_catalogues(*codes: str) -> ProductCapabilityCatalogues:
    return ProductCapabilityCatalogues.from_capabilities({PRODUCT: tuple(codes)})


def _staged_allocation(db: Session, *, suffix: str, customer_ref: str) -> uuid.UUID:
    """contract → submit → approve → activate → stage."""
    offer_code = f"off-{suffix}"
    db.add(
        OfferVersion(
            product_code=PRODUCT,
            offer_code=offer_code,
            version=1,
            amount="10.00",
            currency_code="USD",
            capability_codes=["cap.a", "cap.b"],
        )
    )
    db.flush()
    draft = contracts.create_draft(
        db,
        contracts.CreateDraftCommand(
            command_id=f"d-{uuid.uuid4()}",
            product_code=PRODUCT,
            customer_ref=customer_ref,
            legal_entity="Dotmac Ltd",
            currency_code="USD",
            term_start=date(2026, 1, 1),
            term_end=date(2026, 12, 31),
            lines=(
                contracts.LineInput(offer_code, 1, "cap.a", quantity=2),
                contracts.LineInput(offer_code, 1, "cap.b", quantity=1),
            ),
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
        catalogues=_product_catalogues("cap.a", "cap.b"),
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


def _issue(db, signer, *, suffix="a", customer_ref="cust-a", **over):
    alloc = _staged_allocation(db, suffix=suffix, customer_ref=customer_ref)
    return licensing.issue_licence(
        db,
        licensing.IssueLicenceCommand(
            allocation_id=alloc, product=over.pop("product", PRODUCT), **over
        ),
        signer=signer,
        now=NOW,
    )


PROVEN = TARGET  # the deployment identity a receiver would authenticate as


def _register(db, ref=TARGET, customer_ref="cust-a"):
    """Destinations must be registered — a delivery can never name an
    arbitrary target."""
    existing = db.execute(
        select(LicenceDeliveryTarget).where(LicenceDeliveryTarget.target_ref == ref)
    ).scalar_one_or_none()
    if existing is not None:
        return existing
    row = LicenceDeliveryTarget(target_ref=ref, customer_ref=customer_ref)
    db.add(row)
    db.flush()
    return row


def _stage(db, issued, target=TARGET):
    _register(db, target)
    return projection.stage_delivery(
        db,
        projection.StageDeliveryCommand(issuance_id=issued.id, target_ref=target),
    )


def _ingest(db, ack_input, *, proven=PROVEN, authenticated_deployment_ref=None):
    """Ack ingestion with a PROVEN deployment identity — the only path that can
    activate anything."""
    return projection.ingest_acknowledgement(
        db,
        ack_input,
        authenticated_deployment_ref=(
            authenticated_deployment_ref
            if authenticated_deployment_ref is not None
            else proven
        ),
    )


def _ack_from(ack: LicenceAcknowledgement) -> projection.AcknowledgementInput:
    """Adapt the kernel's cross-plane ack value object to the ingestion input —
    the vendor speaks exactly the vocabulary the receiver emits."""
    return projection.AcknowledgementInput(
        licence_id=ack.licence_id,
        licence_version=ack.licence_version,
        digest=ack.digest,
        status=ack.status,
        reason=ack.reason,
        deployment_id=ack.deployment_id,
    )


# ── The receiver stand-in (kernel public API only) ──────────────────────────


def _receive(
    db: Session,
    envelope,
    *,
    keyring,
    tenant_id: uuid.UUID,
    catalogue: CapabilityCatalogue,
    applied: AppliedLicence | None = None,
    deployment_id: str | None = None,
    fail_after_grants: bool = False,
) -> LicenceAcknowledgement:
    """Verify → project into local WS2 grants → emit the ack, exactly as the
    reference receiver does. `fail_after_grants` simulates a receiver whose
    transaction dies after writing grants but before commit."""
    verified = verify_licence(
        envelope,
        keyring=keyring,
        now=NOW,
        expected_deployment_id=deployment_id,
        applied=applied,
    )
    for grant in verified.document.capabilities:
        grant_entitlement(
            db,
            tenant_id=tenant_id,
            capability_code=grant.code,
            catalogue=catalogue,
            limits=dict(grant.limits),
            source=f"licence:{verified.document.licence_id}",
        )
    if fail_after_grants:
        raise RuntimeError("receiver crashed before commit")
    return LicenceAcknowledgement(
        licence_id=verified.document.licence_id,
        licence_version=verified.document.licence_version,
        digest=verified.digest,
        status="applied",
        deployment_id=deployment_id,
    )


# ── Delivery staging ────────────────────────────────────────────────────────


def test_staging_records_the_fact_state_and_event_atomically(db, signer) -> None:
    issued = _issue(db, signer)
    view = _stage(db, issued)

    assert view.state == DeliveryState.DELIVERED.value
    assert view.activating_ack_id is None
    events = (
        db.execute(
            select(PlatformOutboxEvent).where(
                PlatformOutboxEvent.event_type == "licence.delivered"
            )
        )
        .scalars()
        .all()
    )
    assert len(events) == 1
    assert events[0].payload["digest"] == issued.digest
    assert events[0].payload["target_ref"] == TARGET


def test_restaging_is_the_same_fact_not_a_second_one(db, signer) -> None:
    issued = _issue(db, signer)
    first = _stage(db, issued)
    second = _stage(db, issued)
    assert first.id == second.id
    assert (
        db.execute(select(func.count()).select_from(LicenceDelivery)).scalar_one() == 1
    )


def test_staging_to_an_unregistered_destination_is_rejected(db, signer) -> None:
    """A caller may not invent a destination: delivery resolves through the
    registry or not at all."""
    from dotmac_kernel import NotFoundError

    issued = _issue(db, signer)
    with pytest.raises(NotFoundError, match="not registered"):
        projection.stage_delivery(
            db,
            projection.StageDeliveryCommand(
                issuance_id=issued.id, target_ref="https://attacker.example/steal"
            ),
        )


def test_staging_an_unknown_issuance_is_rejected(db) -> None:
    from dotmac_kernel import NotFoundError

    _register(db)
    with pytest.raises(NotFoundError):
        projection.stage_delivery(
            db,
            projection.StageDeliveryCommand(
                issuance_id=uuid.uuid4(), target_ref=TARGET
            ),
        )


# ── The cross-plane canary ──────────────────────────────────────────────────


def test_cross_plane_canary_activate_to_active(db, signer) -> None:
    """activate → allocate → issue → stage → receiver apply → ingest ack → active."""
    issued = _issue(db, signer)
    delivery = _stage(db, issued)
    assert delivery.state == DeliveryState.DELIVERED.value

    # --- data plane (kernel contract only) ---
    tenant = Tenant(slug="acme", name="Acme")
    db.add(tenant)
    db.flush()
    receiver_catalogue = _catalogue("cap.a", "cap.b")
    ack = _receive(
        db,
        issued.envelope,
        keyring=licensing.build_keyring(db),
        tenant_id=tenant.id,
        catalogue=receiver_catalogue,
    )
    # The product's local decision is live and explainable.
    assert is_entitled(db, tenant_id=tenant.id, capability_code="cap.a").allowed

    # --- back at the vendor ---
    outcome = _ingest(db, _ack_from(ack))
    assert outcome.disposition == AckDisposition.ACCEPTED.value
    assert outcome.activated is True
    assert (
        projection.delivery_status(db, delivery.id).state == DeliveryState.ACTIVE.value
    )
    activated = (
        db.execute(
            select(PlatformOutboxEvent).where(
                PlatformOutboxEvent.event_type == "licence.activated"
            )
        )
        .scalars()
        .all()
    )
    assert len(activated) == 1
    assert activated[0].payload["digest"] == issued.digest


def test_receiver_commit_failure_produces_no_applied_ack(db, signer) -> None:
    """`applied` means COMMITTED. A receiver that dies before commit emits no
    acknowledgement, so the vendor's delivery must stay `delivered` — never
    activated on the strength of a call that did not stick."""
    issued = _issue(db, signer)
    delivery = _stage(db, issued)
    tenant = Tenant(slug="acme", name="Acme")
    db.add(tenant)
    db.flush()

    with pytest.raises(RuntimeError, match="crashed before commit"):
        _receive(
            db,
            issued.envelope,
            keyring=licensing.build_keyring(db),
            tenant_id=tenant.id,
            catalogue=_catalogue("cap.a", "cap.b"),
            fail_after_grants=True,
        )

    # No ack was produced, so none can be ingested: nothing reaches the vendor.
    assert (
        db.execute(select(func.count()).select_from(LicenceAckRecord)).scalar_one() == 0
    )
    assert (
        projection.delivery_status(db, delivery.id).state
        == DeliveryState.DELIVERED.value
    )


# ── Matching rules ──────────────────────────────────────────────────────────


def test_unknown_licence_is_quarantined(db, signer) -> None:
    issued = _issue(db, signer)
    _stage(db, issued)
    outcome = _ingest(
        db,
        projection.AcknowledgementInput(
            licence_id=str(uuid.uuid4()),
            licence_version=1,
            digest=issued.digest,
            status="applied",
        ),
    )
    assert outcome.disposition == AckDisposition.UNKNOWN_LICENCE.value
    assert outcome.quarantined and not outcome.activated


def test_unknown_digest_is_quarantined_as_the_tamper_tripwire(db, signer) -> None:
    issued = _issue(db, signer)
    delivery = _stage(db, issued)
    outcome = _ingest(
        db,
        projection.AcknowledgementInput(
            licence_id=str(issued.licence_id),
            licence_version=issued.version,
            digest="sha256:not-a-digest-we-issued",
            status="applied",
        ),
    )
    assert outcome.disposition == AckDisposition.UNKNOWN_DIGEST.value
    assert outcome.quarantined and not outcome.activated
    assert (
        projection.delivery_status(db, delivery.id).state
        == DeliveryState.DELIVERED.value
    )
    # …and the evidence is retained.
    record = db.execute(select(LicenceAckRecord)).scalar_one()
    assert record.digest == "sha256:not-a-digest-we-issued"


def test_unknown_version_is_quarantined(db, signer) -> None:
    issued = _issue(db, signer)
    _stage(db, issued)
    outcome = _ingest(
        db,
        projection.AcknowledgementInput(
            licence_id=str(issued.licence_id),
            licence_version=99,
            digest=issued.digest,
            status="applied",
        ),
    )
    assert outcome.disposition == AckDisposition.UNKNOWN_LICENCE.value
    assert not outcome.activated


def test_bound_licence_requires_the_acking_deployment_to_match(db, signer) -> None:
    """A bound licence may only be staged to its bound deployment, and only
    that deployment can acknowledge it."""
    issued = _issue(db, signer, deployment_id="dep-a")
    delivery = _stage(db, issued, target="dep-a")

    wrong = _ingest(
        db,
        projection.AcknowledgementInput(
            licence_id=str(issued.licence_id),
            licence_version=issued.version,
            digest=issued.digest,
            status="applied",
        ),
        authenticated_deployment_ref="dep-b",
    )
    assert wrong.disposition == AckDisposition.DEPLOYMENT_MISMATCH.value
    assert wrong.quarantined
    assert (
        projection.delivery_status(db, delivery.id).state
        == DeliveryState.DELIVERED.value
    )

    right = _ingest(
        db,
        projection.AcknowledgementInput(
            licence_id=str(issued.licence_id),
            licence_version=issued.version,
            digest=issued.digest,
            status="applied",
        ),
        authenticated_deployment_ref="dep-a",
    )
    assert right.activated is True


def test_bound_licence_cannot_be_activated_without_proven_identity(db, signer):
    """Fail-closed: with no authenticated identity there is nothing to check
    the binding against, and taking the body's word would make binding
    decorative."""
    issued = _issue(db, signer, deployment_id="dep-a")
    delivery = _stage(db, issued, target="dep-a")
    outcome = projection.ingest_acknowledgement(
        db,
        projection.AcknowledgementInput(
            licence_id=str(issued.licence_id),
            licence_version=issued.version,
            digest=issued.digest,
            status="applied",
            deployment_id="dep-a",  # a CLAIM, not proof
        ),
        # No authenticated identity at all — the platform-admin path.
    )
    # No proven identity ⇒ evidence only, and it is NOT recorded as a mismatch
    # (nothing contradicted anything) — it simply cannot activate.
    assert outcome.disposition == AckDisposition.UNVERIFIED_IDENTITY.value
    assert not outcome.activated
    assert (
        projection.delivery_status(db, delivery.id).state
        == DeliveryState.DELIVERED.value
    )


def test_claimed_identity_contradicting_the_proven_one_is_a_mismatch(db, signer):
    issued = _issue(db, signer)
    _stage(db, issued)
    outcome = _ingest(
        db,
        projection.AcknowledgementInput(
            licence_id=str(issued.licence_id),
            licence_version=issued.version,
            digest=issued.digest,
            status="applied",
            deployment_id="dep-impostor",
        ),
        authenticated_deployment_ref="dep-real",
    )
    assert outcome.disposition == AckDisposition.DEPLOYMENT_MISMATCH.value


def test_rejected_ack_records_the_reason_without_activating(db, signer) -> None:
    issued = _issue(db, signer)
    delivery = _stage(db, issued)
    outcome = _ingest(
        db,
        projection.AcknowledgementInput(
            licence_id=str(issued.licence_id),
            licence_version=issued.version,
            digest=issued.digest,
            status="rejected",
            reason="UndeclaredCapabilityError",
        ),
    )
    assert outcome.disposition == AckDisposition.REJECTED_BY_RECEIVER.value
    assert not outcome.activated and not outcome.quarantined
    assert (
        projection.delivery_status(db, delivery.id).state
        == DeliveryState.DELIVERED.value
    )
    record = db.execute(select(LicenceAckRecord)).scalar_one()
    assert record.reason == "UndeclaredCapabilityError"


def test_duplicate_acknowledgement_is_idempotent(db, signer) -> None:
    issued = _issue(db, signer)
    delivery = _stage(db, issued)
    ack = projection.AcknowledgementInput(
        licence_id=str(issued.licence_id),
        licence_version=issued.version,
        digest=issued.digest,
        status="applied",
    )
    first = _ingest(db, ack)
    second = _ingest(db, ack)

    assert first.activated is True
    assert second.activated is False
    assert second.disposition == AckDisposition.DUPLICATE.value
    state = projection.delivery_status(db, delivery.id)
    assert state.state == DeliveryState.ACTIVE.value
    # The activating ack is unchanged — the duplicate did not take it over.
    assert state.activating_ack_id == first.ack_id
    # Both are retained: the log is append-only.
    assert (
        db.execute(select(func.count()).select_from(LicenceAckRecord)).scalar_one() == 2
    )


def test_late_v1_ack_cannot_regress_an_active_v2(db, signer) -> None:
    v1 = _issue(db, signer, suffix="a", customer_ref="cust-x")
    _register(db, "target-x", customer_ref="cust-x")
    d1 = _stage(db, v1, target="target-x")
    v2 = _issue(db, signer, suffix="a2", customer_ref="cust-x")
    assert (v1.licence_id, v2.version) == (v2.licence_id, 2)
    d2 = _stage(db, v2, target="target-x")

    # v2 acknowledged and active first…
    _ingest(
        db,
        projection.AcknowledgementInput(
            licence_id=str(v2.licence_id),
            licence_version=2,
            digest=v2.digest,
            status="applied",
        ),
        proven="target-x",
    )
    assert projection.delivery_status(db, d2.id).state == DeliveryState.ACTIVE.value

    # …then a delayed v1 ack arrives. It must not activate the older delivery.
    late = _ingest(
        db,
        projection.AcknowledgementInput(
            licence_id=str(v1.licence_id),
            licence_version=1,
            digest=v1.digest,
            status="applied",
        ),
        proven="target-x",
    )
    assert late.disposition == AckDisposition.STALE.value
    assert late.activated is False
    assert projection.delivery_status(db, d1.id).state == DeliveryState.DELIVERED.value
    assert projection.delivery_status(db, d2.id).state == DeliveryState.ACTIVE.value


def test_acknowledgement_log_lists_every_verdict(db, signer) -> None:
    issued = _issue(db, signer)
    _stage(db, issued)
    good = projection.AcknowledgementInput(
        licence_id=str(issued.licence_id),
        licence_version=issued.version,
        digest=issued.digest,
        status="applied",
    )
    _ingest(db, good)
    _ingest(
        db,
        projection.AcknowledgementInput(
            licence_id=str(issued.licence_id),
            licence_version=issued.version,
            digest="sha256:bogus",
            status="applied",
        ),
    )
    log = projection.list_acknowledgements(db, str(issued.licence_id))
    assert [entry["disposition"] for entry in log] == [
        AckDisposition.ACCEPTED.value,
        AckDisposition.UNKNOWN_DIGEST.value,
    ]


def test_projection_writes_no_product_entitlement_grants(db, signer) -> None:
    """The C4 boundary holds on this side too: tracking an acknowledgement
    never writes a data plane's grants."""
    from dotmac_kernel.entitlements import TenantEntitlementGrant

    issued = _issue(db, signer)
    _stage(db, issued)
    _ingest(
        db,
        projection.AcknowledgementInput(
            licence_id=str(issued.licence_id),
            licence_version=issued.version,
            digest=issued.digest,
            status="applied",
        ),
    )
    assert (
        db.execute(
            select(func.count()).select_from(TenantEntitlementGrant)
        ).scalar_one()
        == 0
    )


# ── The delivery-target projection has ONE writer ───────────────────────────


def test_register_delivery_target_is_the_writer_and_is_idempotent(db) -> None:
    first = projection.register_delivery_target(
        db,
        projection.RegisterTargetCommand(
            target_ref="dep-1", customer_ref="cust-a", connection_ref="edge-1"
        ),
    )
    second = projection.register_delivery_target(
        db,
        projection.RegisterTargetCommand(
            target_ref="dep-1", customer_ref="cust-a", connection_ref="edge-2"
        ),
    )
    assert first.id == second.id
    assert second.connection_ref == "edge-2"


def test_a_target_cannot_be_repointed_to_another_customer(db) -> None:
    """Re-pointing would move a destination between customers, after which the
    cross-customer staging check could no longer catch it — the guard would
    still pass while delivering to the wrong party."""
    projection.register_delivery_target(
        db, projection.RegisterTargetCommand(target_ref="dep-1", customer_ref="cust-a")
    )
    with pytest.raises(BadRequestError, match="between customers"):
        projection.register_delivery_target(
            db,
            projection.RegisterTargetCommand(target_ref="dep-1", customer_ref="cust-b"),
        )


def test_a_suspended_target_cannot_receive_a_licence(db, signer) -> None:
    issued = _issue(db, signer)
    projection.register_delivery_target(
        db,
        projection.RegisterTargetCommand(
            target_ref="dep-suspended",
            customer_ref="cust-a",
            status=TargetStatus.SUSPENDED,
        ),
    )
    with pytest.raises(BadRequestError, match="not\\s+active"):
        projection.stage_delivery(
            db,
            projection.StageDeliveryCommand(
                issuance_id=issued.id, target_ref="dep-suspended"
            ),
        )


def test_mapping_a_legacy_delivery_applies_the_same_authorisation(db, signer) -> None:
    """Mapping must not be a back door around the checks staging performs."""
    issued = _issue(db, signer)
    delivery = _stage(db, issued)
    # Simulate the v009-era shape: a delivery with no resolved destination.
    row = db.get(LicenceDelivery, delivery.id)
    assert row is not None
    row.target_id = None
    db.flush()

    projection.register_delivery_target(
        db,
        projection.RegisterTargetCommand(target_ref="dep-other", customer_ref="cust-z"),
    )
    with pytest.raises(BadRequestError, match="cross-customer"):
        projection.map_legacy_delivery(
            db, delivery_id=delivery.id, target_ref="dep-other"
        )

    mapped = projection.map_legacy_delivery(
        db, delivery_id=delivery.id, target_ref=TARGET
    )
    assert mapped.target_ref == TARGET


def test_resuming_an_unmapped_delivery_is_refused(db, signer) -> None:
    """Resuming without a destination would move the row out of `parked` and
    straight out of replay eligibility — it would vanish rather than retry."""
    from vendor_cp.licensing import transport as transport_module

    issued = _issue(db, signer)
    delivery = _stage(db, issued)
    row = db.get(LicenceDelivery, delivery.id)
    assert row is not None
    row.target_id = None
    db.flush()
    state = db.execute(
        select(LicenceDeliveryState).where(
            LicenceDeliveryState.delivery_id == delivery.id
        )
    ).scalar_one()
    state.state = DeliveryState.PARKED.value
    db.flush()

    with pytest.raises(BadRequestError, match="no resolved destination"):
        transport_module.resume_delivery(db, delivery.id)

    projection.map_legacy_delivery(db, delivery_id=delivery.id, target_ref=TARGET)
    transport_module.resume_delivery(db, delivery.id)
    assert (
        projection.delivery_status(db, delivery.id).state
        == DeliveryState.DELIVERED.value
    )


def test_proven_identity_is_visible_to_operators(db, signer) -> None:
    """The claim and the proof must be separately visible; a log showing only
    the claim looks identical whether or not anything was proven."""
    issued = _issue(db, signer)
    _stage(db, issued)
    _ingest(
        db,
        projection.AcknowledgementInput(
            licence_id=str(issued.licence_id),
            licence_version=issued.version,
            digest=issued.digest,
            status="applied",
            deployment_id="claimed-something-else",
        ),
    )
    entry = projection.list_acknowledgements(db, str(issued.licence_id))[0]
    assert entry["claimed_deployment_id"] == "claimed-something-else"
    assert entry["authenticated_deployment_ref"] == PROVEN


# ── Every operational service has a runtime caller ──────────────────────────


def test_every_operational_service_is_reachable_from_a_route() -> None:
    """Structural guard against the gap this batch fixed.

    `register_delivery_target`, `map_legacy_delivery` and `resume_delivery`
    existed with NO caller outside tests, so a clean deployment could not
    register a target, map a quarantined delivery, or resume it. Code that only
    tests call is not a feature.

    `dispatch_pending` is deliberately ABSENT from this list: generic replay is
    disabled while both reference transports are in-process, because an
    endpoint that reported success while the bytes were discarded would
    manufacture delivery evidence. `export_delivery_bundle` is the enabled
    path, and it is a real handoff.
    """
    import inspect

    from vendor_cp.licensing.router import router

    source = "\n".join(
        inspect.getsource(route.endpoint)
        for route in router.routes
        if getattr(route, "endpoint", None) is not None
    )
    for service_call in (
        "projection.register_delivery_target",
        "projection.list_delivery_targets",
        "projection.map_legacy_delivery",
        "transport.resume_delivery",
        "transport.export_delivery_bundle",
    ):
        assert service_call in source, f"{service_call} has no route caller"
    assert "transport.dispatch_pending" not in source, (
        "generic replay must stay disabled until a transport performs a real "
        "external handoff — otherwise it records deliveries that never left "
        "the process"
    )


def test_dispatch_refuses_a_transport_that_hands_off_nothing(db, signer) -> None:
    """The false-SENT boundary. An in-process transport accepts a packet and
    drops it; recording that as delivery corrupts the unacknowledged signal and
    can park a licence nothing ever carried anywhere."""
    from vendor_cp.licensing import transport as transport_module

    issued = _issue(db, signer)
    _stage(db, issued)
    with pytest.raises(
        transport_module.TransportModeNotPermittedError, match="external handoff"
    ):
        transport_module.dispatch_pending(
            db, transport=transport_module.LoggingTransport()
        )
