"""The Commercial Agreements → Entitlement Allocation composition seam."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, date, datetime

import pytest
from dotmac_commercial_agreements import AGREEMENT_ACTIVATED_V1
from dotmac_kernel import NotFoundError
from dotmac_kernel.entitlements import TenantEntitlementGrant
from dotmac_kernel.messaging import ClaimedPlatformEvent, PlatformOutboxEvent
from dotmac_kernel.testing import create_test_engine, isolated_session
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vendor_cp.allocations import adapter
from vendor_cp.allocations.consumer import ContractEventConsumer
from vendor_cp.approvals import adapter as approvals
from vendor_cp.contracts import adapter as agreements
from vendor_cp.offers.catalog import ProductCapabilityCatalogues
from vendor_cp.offers.models import OfferVersion

PRODUCT = "dotmac-sub"


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as session:
            yield session
    finally:
        engine.dispose()


def _catalogue(*codes: str) -> ProductCapabilityCatalogues:
    return ProductCapabilityCatalogues.from_capabilities({PRODUCT: tuple(codes)})


def _proposed_agreement(db: Session) -> agreements.ContractView:
    db.add(
        OfferVersion(
            product_code=PRODUCT,
            offer_code="off",
            version=1,
            amount="10.00",
            currency_code="USD",
            capability_codes=["cap.a", "cap.b"],
        )
    )
    db.flush()
    catalogues = _catalogue("cap.a", "cap.b")
    draft = agreements.create_draft(
        db,
        agreements.CreateDraftCommand(
            command_id=f"draft-{uuid.uuid4()}",
            reference=f"AGR-{uuid.uuid4()}",
            product_code=PRODUCT,
            counterparty_ref="cust-42",
            agreement_type="software_subscription",
            term_start=date(2026, 1, 1),
            term_end=date(2026, 12, 31),
            lines=(
                agreements.LineInput("off", 1, "cap.a", quantity=2),
                agreements.LineInput("off", 1, "cap.b", quantity=1),
            ),
        ),
        catalogues=catalogues,
    )
    approvals.publish_policy_version(
        db,
        approvals.PublishPolicyCommand(
            command_id=f"policy-{uuid.uuid4()}",
            policy_code="commercial",
            version=1,
            quorum=1,
            allow_self_approval=False,
        ),
    )
    return agreements.propose(
        db,
        agreements.ProposeCommand(
            command_id=f"propose-{uuid.uuid4()}",
            agreement_id=draft.id,
            approval_policy_code="commercial",
            approval_policy_version=1,
            requested_by=uuid.uuid4(),
        ),
        catalogues=catalogues,
    )


def _approved_agreement(
    db: Session,
) -> tuple[agreements.ContractView, uuid.UUID]:
    proposed = _proposed_agreement(db)
    assert proposed.approval_request_id is not None
    assert proposed.content_hash is not None
    approvals.record_decision(
        db,
        approvals.RecordDecisionCommand(
            command_id=f"decision-{uuid.uuid4()}",
            request_id=proposed.approval_request_id,
            approver_id=uuid.uuid4(),
            content_hash=proposed.content_hash,
        ),
    )
    return (
        agreements.approve(
            db,
            agreements.ApprovalCommand(
                command_id=f"approve-{uuid.uuid4()}",
                agreement_id=proposed.id,
                approval_request_id=proposed.approval_request_id,
            ),
        ),
        proposed.approval_request_id,
    )


def _activated_agreement(db: Session) -> agreements.ContractView:
    approved, approval_request_id = _approved_agreement(db)
    return agreements.activate(
        db,
        agreements.ActivateCommand(
            command_id=f"activate-{uuid.uuid4()}",
            agreement_id=approved.id,
            approval_request_id=approval_request_id,
            activation_rule="countersigned",
            activation_reference="signature-42",
            activation_satisfied_at=datetime.now(UTC),
        ),
    )


def _activated_event(db: Session) -> ClaimedPlatformEvent:
    row = db.scalar(
        select(PlatformOutboxEvent).where(
            PlatformOutboxEvent.event_type == AGREEMENT_ACTIVATED_V1
        )
    )
    assert row is not None
    return ClaimedPlatformEvent(
        id=row.id,
        event_type=row.event_type,
        payload=dict(row.payload),
        attempts=0,
        correlation_id=row.correlation_id,
    )


def _stage(
    db: Session,
    agreement_id: uuid.UUID,
    content_hash: str,
    *,
    source_event_id: str = "evt-1",
) -> adapter.AllocationView:
    return adapter.stage_allocation(
        db,
        adapter.StageAllocationCommand(
            source_event_id=source_event_id,
            contract_id=agreement_id,
            content_hash=content_hash,
        ),
        catalogues=_catalogue("cap.a", "cap.b"),
    )


def test_stage_projects_the_authoritative_agreement_snapshot(db: Session) -> None:
    active = _activated_agreement(db)
    assert active.content_hash is not None
    view = _stage(db, active.id, active.content_hash)
    assert view.status == str(adapter.STAGED_STATUS)
    assert view.customer_ref == "cust-42"
    assert view.product_code == PRODUCT
    assert view.content_hash == active.content_hash
    assert not view.replayed
    assert {(entry.capability_code, entry.quantity) for entry in view.entries} == {
        ("cap.a", 2),
        ("cap.b", 1),
    }


def test_stage_is_idempotent_on_event_and_activation(db: Session) -> None:
    active = _activated_agreement(db)
    assert active.content_hash is not None
    first = _stage(db, active.id, active.content_hash, source_event_id="evt-dup")
    replay = _stage(db, active.id, active.content_hash, source_event_id="evt-dup")
    redelivery = _stage(db, active.id, active.content_hash, source_event_id="evt-other")
    assert replay.id == first.id and redelivery.id == first.id
    assert replay.replayed and redelivery.replayed
    assert len(adapter.list_for_contract(db, active.id)) == 1


def test_a_stale_activation_fact_is_refused(db: Session) -> None:
    active = _activated_agreement(db)
    with pytest.raises(NotFoundError, match="stale event"):
        _stage(db, active.id, "not-the-current-digest")
    assert adapter.list_for_contract(db, active.id) == []


def test_an_agreement_that_is_not_active_is_refused(db: Session) -> None:
    approved, _request_id = _approved_agreement(db)
    assert approved.content_hash is not None
    with pytest.raises(NotFoundError, match="not active"):
        _stage(db, approved.id, approved.content_hash)


def test_an_unknown_agreement_is_refused(db: Session) -> None:
    with pytest.raises(NotFoundError, match="not found"):
        _stage(db, uuid.uuid4(), "whatever")


def test_stage_writes_no_product_ws2_grant(db: Session) -> None:
    active = _activated_agreement(db)
    assert active.content_hash is not None
    _stage(db, active.id, active.content_hash)
    assert (
        int(db.scalar(select(func.count()).select_from(TenantEntitlementGrant)) or 0)
        == 0
    )


def test_consumer_reacts_only_to_the_versioned_activation_fact(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    active = _activated_agreement(db)
    consumer = ContractEventConsumer()
    monkeypatch.setattr(
        ContractEventConsumer,
        "_catalogues",
        lambda _self, _db: _catalogue("cap.a", "cap.b"),
    )
    consumer.deliver(
        ClaimedPlatformEvent(
            id=uuid.uuid4(),
            event_type="agreement.proposed.v1",
            payload={"agreement_id": str(active.id)},
            attempts=0,
            correlation_id=None,
        ),
        db,
    )
    assert adapter.list_for_contract(db, active.id) == []
    consumer.deliver(_activated_event(db), db)
    assert len(adapter.list_for_contract(db, active.id)) == 1
