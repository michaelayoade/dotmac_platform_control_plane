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

import hashlib
import json
import uuid
from collections.abc import Iterator
from datetime import UTC, date, datetime
from uuid import uuid4

import dotmac_deployment_control as deployment_control
import pytest
from dotmac_kernel import (
    BadRequestError,
    CapabilityCatalogue,
    ConflictError,
    FeatureManifest,
    NotFoundError,
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
from dotmac_licensing import LicenceAcknowledgement as ModuleLicenceAcknowledgement
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vendor_cp.allocations import adapter as allocations
from vendor_cp.approvals import adapter as approvals
from vendor_cp.contracts import adapter as contracts
from vendor_cp.deployment.adapter import DeploymentTargetFacts
from vendor_cp.licensing import adapter as licensing
from vendor_cp.licensing import projection, source_contract, source_ports
from vendor_cp.licensing.delivery_models import (
    AckDisposition,
    DeliveryState,
    LicenceAckRecord,
    LicenceDelivery,
    LicenceDeliveryState,
    LicenceDeliveryTarget,
    TargetStatus,
)
from vendor_cp.licensing.intent_models import IntentStatus
from vendor_cp.licensing.signing_adapter import EphemeralLicenceSigner
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


def _approve(db: Session, proposed: contracts.ContractView) -> None:
    assert proposed.content_hash is not None
    assert proposed.approval_request_id is not None
    approvals.record_decision(
        db,
        approvals.RecordDecisionCommand(
            command_id=f"dec-{uuid.uuid4()}",
            request_id=proposed.approval_request_id,
            approver_id=uuid.uuid4(),
            content_hash=proposed.content_hash,
        ),
    )


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
            reference=f"AGR-{uuid.uuid4()}",
            product_code=PRODUCT,
            counterparty_ref=customer_ref,
            agreement_type="software_subscription",
            term_start=date(2026, 1, 1),
            term_end=date(2026, 12, 31),
            lines=(
                contracts.LineInput(offer_code, 1, "cap.a", quantity=2),
                contracts.LineInput(offer_code, 1, "cap.b", quantity=1),
            ),
        ),
        catalogues=_product_catalogues("cap.a", "cap.b"),
    )
    # The policy must exist BEFORE submit: submit opens the approval
    # request against that exact revision, so publishing after it would
    # be too late.
    approvals.publish_policy_version(
        db,
        approvals.PublishPolicyCommand(
            command_id=f"pol-{uuid.uuid4()}",
            policy_code=f"p-{suffix}",
            version=1,
            quorum=1,
            allow_self_approval=False,
        ),
    )
    proposed = contracts.propose(
        db,
        contracts.ProposeCommand(
            command_id=f"s-{uuid.uuid4()}",
            agreement_id=draft.id,
            approval_policy_code=f"p-{suffix}",
            approval_policy_version=1,
            requested_by=uuid.uuid4(),
        ),
        catalogues=_product_catalogues("cap.a", "cap.b"),
    )
    _approve(db, proposed)
    assert proposed.approval_request_id is not None
    contracts.approve(
        db,
        contracts.ApprovalCommand(
            command_id=f"ap-{uuid.uuid4()}",
            agreement_id=draft.id,
            approval_request_id=proposed.approval_request_id,
        ),
    )
    active = contracts.activate(
        db,
        contracts.ActivateCommand(
            command_id=f"act-{uuid.uuid4()}",
            agreement_id=draft.id,
            approval_request_id=proposed.approval_request_id,
            activation_rule="countersigned",
            activation_reference="signature-1",
            activation_satisfied_at=NOW,
        ),
    )
    return allocations.stage_allocation(
        db,
        allocations.StageAllocationCommand(
            source_event_id=f"evt-{uuid.uuid4()}",
            contract_id=draft.id,
            content_hash=active.content_hash or "",
        ),
        catalogues=_product_catalogues("cap.a", "cap.b"),
    ).id


def _issue(db, signer, *, suffix="a", customer_ref="cust-a", **over):
    alloc = _staged_allocation(db, suffix=suffix, customer_ref=customer_ref)
    return licensing.issue_licence(
        db,
        licensing.IssueLicenceCommand(allocation_id=alloc, **over),
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


def _target(
    db,
    *,
    target_ref: str = "dep-1",
    customer_ref: str = "cust-a",
    status: TargetStatus = TargetStatus.ACTIVE,
):
    """Project a delivery target the way production now does.

    These tests used to call the registration command with caller-chosen values.
    That path is gone (ADR-0011): the only way a target reaches this projection
    is as facts the deployment adapter read out of `mod_deploy`. Constructing
    `DeploymentTargetFacts` here keeps the tests honest about that seam instead
    of reaching around it.
    """
    return projection.reconcile_delivery_target(
        db,
        DeploymentTargetFacts(
            target_id=uuid4(),
            target_ref=target_ref,
            customer_ref=customer_ref,
            status=status,
        ),
    )


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
    acknowledged = (
        db.execute(
            select(PlatformOutboxEvent).where(
                PlatformOutboxEvent.event_type == "licence.acknowledged.v1"
            )
        )
        .scalars()
        .all()
    )
    assert len(acknowledged) == 1
    assert acknowledged[0].payload["digest"] == issued.digest


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
    assert (
        db.execute(
            select(func.count()).select_from(ModuleLicenceAcknowledgement)
        ).scalar_one()
        == 1
    )
    assert (
        db.execute(
            select(func.count())
            .select_from(PlatformOutboxEvent)
            .where(PlatformOutboxEvent.event_type == "licence.acknowledged.v1")
        ).scalar_one()
        == 1
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


def test_reconciling_a_target_is_the_writer_and_is_idempotent(db) -> None:
    first = _target(db)
    second = _target(db)
    assert first.id == second.id
    assert second.status == TargetStatus.ACTIVE.value


def test_a_reconciled_target_follows_the_fleet_owner_across_customers(db) -> None:
    """The old command REFUSED a customer change, because the customer was a
    caller's claim and moving it would defeat the cross-customer staging check.

    After ADR-0011 the customer is whatever `mod_deploy` says it is, so a change
    is a correction to be projected rather than an attack to be blocked — and
    the staging check still runs against the projected value, which is what
    keeps the original guarantee intact.
    """
    first = _target(db, customer_ref="cust-a")
    second = _target(db, customer_ref="cust-b")
    assert first.id == second.id
    assert second.customer_ref == "cust-b"


def test_a_reconciled_target_never_carries_a_connection_ref(db) -> None:
    """Transport metadata the module does not own is not invented here; the
    column goes with the rest of the delivery estate at ADR-0010."""
    assert _target(db).connection_ref is None


def test_a_suspended_target_cannot_receive_a_licence(db, signer) -> None:
    issued = _issue(db, signer)
    _target(
        db,
        target_ref="dep-suspended",
        customer_ref="cust-a",
        status=TargetStatus.SUSPENDED,
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

    _target(db, target_ref="dep-other", customer_ref="cust-z")
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

    The target writer, `map_legacy_delivery` and `resume_delivery` existed with
    NO caller outside tests, so a clean deployment could not make a destination
    available, map a quarantined delivery, or resume it. Code that only tests
    call is not a feature.

    The target writer is now `reconcile_delivery_target`, reached through
    `deployment_adapter.resolve_target` — the ADR-0011 cutover changed which
    service the route calls, not whether a route calls one.

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
        "deployment_adapter.resolve_target",
        "projection.reconcile_delivery_target",
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


# ── ADR-0010 § 3 source ports (gate 2a) ─────────────────────────────────────
#
# These live here rather than in a file of their own because the issuance chain
# above — agreement, approval, activation, allocation, issue — is what makes a
# real artifact to correlate against, and duplicating it would be ~80 lines of
# setup that could drift from the thing it mirrors.
#
# The happy path is the least interesting part. An acknowledgement claims that
# one exact signed document was applied at one exact destination, and almost
# everything worth testing is a way that claim can be wrong.


def _intent(db, issued, *, target_ref: str = TARGET, customer_ref: str = "cust-a"):
    facts_target = deployment_control.register_target(
        db,
        deployment_control.RegisterTargetCommand(
            command_id=f"src-reg-{target_ref}",
            target_ref=target_ref,
            subject_ref=customer_ref,
            product_code="vendor-cp",
            environment="test",
        ),
    )
    deployment_control.set_desired_state(
        db,
        deployment_control.SetDesiredStateCommand(
            command_id=f"src-desire-{target_ref}",
            target_id=facts_target.id,
            desired=deployment_control.DesiredDeployment(release_ref="rel-1"),
        ),
    )
    db.flush()
    return source_ports.open_delivery_intent(
        db, issuance_id=issued.id, deployment_target_id=facts_target.id
    )


def _ack(intent, **overrides) -> source_ports.AcknowledgeIntentCommand:
    fields = {
        "delivery_intent_id": intent.delivery_intent_id,
        "deployment_target_ref": intent.deployment_target_ref,
        "licence_version": intent.licence_version,
        "artifact_digest": intent.artifact_digest,
        "integrator_receipt_ref": "receipt-1",
        "authenticated_deployment_ref": intent.deployment_target_ref,
        "outcome": "active",
        "reported_at": NOW,
    }
    fields.update(overrides)
    return source_ports.AcknowledgeIntentCommand(**fields)


def test_the_contract_declares_exactly_the_three_ports() -> None:
    """ADR-0010 § 3 says three. A fourth is a contract change with a new
    digest, not an implementation detail somebody slipped in."""
    assert [operation.name for operation in source_contract.OPERATIONS] == [
        "open_delivery_intent",
        "read_exact_artifact",
        "acknowledge_delivery_intent",
    ]


def test_the_contract_is_not_a_destination_descriptor() -> None:
    """The reason this contract exists separately.

    `ProductPortDescriptorV1` answers "where does this land?" and is
    destination-owned. Vendor is the SOURCE; the destination is the deployment,
    whose descriptor and binding to the Deployment Control `target_ref` are gate
    2b elsewhere. These names appearing here would mean two answers to the
    routing question.
    """
    body = json.dumps(source_contract.declaration())
    for forbidden in (
        "delivery_path",
        "mirror_path",
        "destination_binding_id",
        "destination_scope",
        "product-port-descriptor",
    ):
        assert forbidden not in body, forbidden
    assert source_contract.CONTRACT_SCHEMA == "dotmac.io/licence-source-contract/v1"


def test_the_contract_digest_is_stable_and_moves_with_the_surface() -> None:
    """A pin that churned on a docstring edit would be re-pinned reflexively
    and stop meaning anything; one that never moved would pin nothing."""
    first = source_contract.contract_digest()
    assert first == source_contract.contract_digest()
    widened = source_contract.declaration()
    widened["operations"].append({"name": "smuggled"})
    canonical = json.dumps(
        widened, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    assert first != f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()}"


def test_opening_an_intent_derives_every_correlation_value(db, signer) -> None:
    """The caller names an issuance and a target id — never the digest, version
    or target ref. A caller that could supply the digest could correlate an
    acknowledgement to an artifact that was never issued."""
    issued = _issue(db, signer)
    intent = _intent(db, issued)
    assert intent.artifact_digest == issued.digest
    assert intent.licence_version == issued.version
    assert intent.deployment_target_ref == TARGET
    assert intent.status == IntentStatus.OPEN.value


def test_opening_the_same_hand_off_twice_is_one_obligation(db, signer) -> None:
    """Two correlation ids for one delivery is how a duplicate acknowledgement
    stops being distinguishable from a second delivery."""
    issued = _issue(db, signer)
    assert (
        _intent(db, issued).delivery_intent_id == _intent(db, issued).delivery_intent_id
    )


def test_an_unknown_deployment_target_cannot_receive_an_intent(db, signer) -> None:
    issued = _issue(db, signer)
    with pytest.raises(NotFoundError, match="mod_deploy"):
        source_ports.open_delivery_intent(
            db, issuance_id=issued.id, deployment_target_id=uuid.uuid4()
        )


def test_a_cross_customer_intent_is_refused(db, signer) -> None:
    """The frozen path makes this check in `_authorised_target`; this port does
    not go through it, so it makes the check again rather than assuming it."""
    issued = _issue(db, signer)
    with pytest.raises(BadRequestError, match="cross-customer"):
        _intent(db, issued, target_ref="dep-other", customer_ref="cust-z")


def test_the_artifact_read_returns_the_envelope_for_the_intent(db, signer) -> None:
    issued = _issue(db, signer)
    intent = _intent(db, issued)
    artifact = source_ports.read_exact_artifact(
        db, delivery_intent_id=intent.delivery_intent_id
    )
    assert artifact.artifact_digest == issued.digest
    assert artifact.envelope


def test_reading_an_unknown_intent_is_refused(db) -> None:
    with pytest.raises(NotFoundError):
        source_ports.read_exact_artifact(db, delivery_intent_id=uuid.uuid4())


def test_a_correlated_acknowledgement_completes_the_intent(db, signer) -> None:
    intent = _intent(db, _issue(db, signer))
    done = source_ports.acknowledge_delivery_intent(db, _ack(intent))
    assert done.status == IntentStatus.ACKNOWLEDGED.value
    assert done.integrator_receipt_ref == "receipt-1"
    assert done.acknowledged_at is not None


def test_the_same_receipt_replays_rather_than_completing_twice(db, signer) -> None:
    intent = _intent(db, _issue(db, signer))
    assert source_ports.acknowledge_delivery_intent(
        db, _ack(intent)
    ) == source_ports.acknowledge_delivery_intent(db, _ack(intent))


def test_a_second_receipt_cannot_complete_the_same_obligation(db, signer) -> None:
    intent = _intent(db, _issue(db, signer))
    source_ports.acknowledge_delivery_intent(db, _ack(intent))
    with pytest.raises(ConflictError, match="second completion"):
        source_ports.acknowledge_delivery_intent(
            db, _ack(intent, integrator_receipt_ref="receipt-2")
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("deployment_target_ref", "dep-somewhere-else"),
        ("licence_version", 99),
        ("artifact_digest", "0" * 64),
    ],
)
def test_every_correlation_mismatch_fails_closed(db, signer, field, value) -> None:
    """One case per correlation field: "all mismatches fail closed" is a claim
    about EACH of them, and a single case would prove it for one."""
    intent = _intent(db, _issue(db, signer))
    overrides = {field: value}
    # A wrong target ref would also fail corroboration; keep the authenticated
    # identity aligned with the CLAIM so this isolates the correlation failure.
    if field == "deployment_target_ref":
        overrides["authenticated_deployment_ref"] = value
    with pytest.raises(BadRequestError, match="does not correlate"):
        source_ports.acknowledge_delivery_intent(db, _ack(intent, **overrides))


def test_provider_identity_may_corroborate_but_never_select(db, signer) -> None:
    """The authenticated identity and the chosen destination are separate
    fields on purpose. Folding them into one would delete the distinction that
    makes corroboration checkable."""
    intent = _intent(db, _issue(db, signer))
    with pytest.raises(BadRequestError, match="may never select"):
        source_ports.acknowledge_delivery_intent(
            db, _ack(intent, authenticated_deployment_ref="dep-impostor")
        )


def test_a_mismatched_acknowledgement_leaves_no_lifecycle_consequence(
    db, signer
) -> None:
    """Correlation is checked BEFORE the lifecycle owner is told anything, so a
    bad acknowledgement produces no licensing consequence — not an
    accepted-then-corrected one."""
    intent = _intent(db, _issue(db, signer))
    with pytest.raises(BadRequestError):
        source_ports.acknowledge_delivery_intent(
            db, _ack(intent, artifact_digest="0" * 64)
        )
    assert (
        source_ports.get_delivery_intent(db, intent.delivery_intent_id).status
        == IntentStatus.OPEN.value
    )
