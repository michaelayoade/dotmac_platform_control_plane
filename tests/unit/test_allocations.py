"""Unit tests for AllocationService (SQLite).

Proves: an allocation is an immutable projection of an activated contract, staging
is idempotent on the source event id AND unique per `(contract_id, content_hash)`,
it writes NO product WS2 grants, and the `ContractEventConsumer` reacts only to
`contract.activated` — end-to-end from a real ContractService activation event.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import date

import pytest
from dotmac_kernel.entitlements import TenantEntitlementGrant
from dotmac_kernel.messaging import ClaimedPlatformEvent, PlatformOutboxEvent
from dotmac_kernel.testing import create_test_engine, isolated_session
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vendor_cp.allocations import service
from vendor_cp.allocations.consumer import ContractEventConsumer
from vendor_cp.allocations.models import Allocation, AllocationStatus
from vendor_cp.approvals import service as approvals
from vendor_cp.contracts import service as contracts
from vendor_cp.offers.catalog import ProductCapabilityCatalogues
from vendor_cp.offers.models import OfferVersion


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as s:
            yield s
    finally:
        engine.dispose()


def _catalogue(*codes: str) -> ProductCapabilityCatalogues:
    return ProductCapabilityCatalogues.from_capabilities({"dotmac-sub": tuple(codes)})


def _activated_contract(db: Session):
    """Drive a contract all the way to ACTIVE via the real ContractService, so a
    genuine `contract.activated` event lands in the platform outbox."""
    db.add(
        OfferVersion(
            product_code="dotmac-sub",
            offer_code="off",
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
            product_code="dotmac-sub",
            customer_ref="cust-42",
            legal_entity="Dotmac Ltd",
            currency_code="USD",
            term_start=date(2026, 1, 1),
            term_end=date(2026, 12, 31),
            lines=(
                contracts.LineInput("off", 1, "cap.a", quantity=2),
                contracts.LineInput("off", 1, "cap.b", quantity=1),
            ),
        ),
    )
    submitter = uuid.uuid4()
    submitted = contracts.submit(
        db,
        contracts.SubmitCommand(
            command_id=f"s-{uuid.uuid4()}",
            contract_id=draft.id,
            approval_policy_code="p",
            approval_policy_version=1,
            submitter_id=submitter,
        ),
        catalogues=_catalogue("cap.a", "cap.b"),
    )
    approvals.publish_policy_version(
        db,
        approvals.PublishPolicyCommand(
            command_id=f"pol-{uuid.uuid4()}", policy_code="p", version=1, quorum=1
        ),
    )
    approvals.record_approval(
        db,
        approvals.RecordApprovalCommand(
            command_id=f"a-{uuid.uuid4()}",
            policy_code="p",
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
    return draft.id, submitted.content_hash


def _activated_event(db: Session):
    """The `contract.activated` row ContractService emitted, as a claimed event."""
    row = db.execute(
        select(PlatformOutboxEvent).where(
            PlatformOutboxEvent.event_type == "contract.activated"
        )
    ).scalar_one()
    return ClaimedPlatformEvent(
        id=row.id,
        event_type=row.event_type,
        payload=dict(row.payload),
        attempts=0,
        correlation_id=row.correlation_id,
    )


def test_stage_projects_immutable_allocation_from_contract(db: Session) -> None:
    contract_id, chash = _activated_contract(db)
    view = service.stage_allocation(
        db,
        service.StageAllocationCommand(
            source_event_id="evt-1",
            contract_id=contract_id,
            content_hash=chash or "",
            customer_ref="cust-42",
        ),
    )
    assert view.status == AllocationStatus.STAGED.value
    assert view.customer_ref == "cust-42"
    caps = {(e.capability_code, e.quantity) for e in view.entries}
    assert caps == {("cap.a", 2), ("cap.b", 1)}  # projected from the contract lines


def test_stage_is_idempotent_on_event_and_content(db: Session) -> None:
    contract_id, chash = _activated_contract(db)
    cmd = service.StageAllocationCommand(
        source_event_id="evt-dup",
        contract_id=contract_id,
        content_hash=chash or "",
        customer_ref="cust-42",
    )
    service.stage_allocation(db, cmd)
    service.stage_allocation(db, cmd)  # same event id -> no-op
    # A different event id for the SAME activation still stages nothing new
    # (unique on contract_id, content_hash).
    service.stage_allocation(
        db,
        service.StageAllocationCommand(
            source_event_id="evt-other",
            contract_id=contract_id,
            content_hash=chash or "",
            customer_ref="cust-42",
        ),
    )
    assert int(db.scalar(select(func.count()).select_from(Allocation)) or 0) == 1


def test_stage_writes_no_product_ws2_grant(db: Session) -> None:
    contract_id, chash = _activated_contract(db)
    service.stage_allocation(
        db,
        service.StageAllocationCommand(
            source_event_id="evt-1",
            contract_id=contract_id,
            content_hash=chash or "",
            customer_ref="cust-42",
        ),
    )
    assert (
        int(db.scalar(select(func.count()).select_from(TenantEntitlementGrant)) or 0)
        == 0
    )


def test_consumer_reacts_only_to_contract_activated(db: Session) -> None:
    contract_id, _chash = _activated_contract(db)
    consumer = ContractEventConsumer()

    # A non-activation event is ignored — nothing staged.
    consumer.deliver(
        ClaimedPlatformEvent(
            id=uuid.uuid4(),
            event_type="contract.submitted",
            payload={"contract_id": str(contract_id)},
            attempts=0,
            correlation_id=None,
        ),
        db,
    )
    assert int(db.scalar(select(func.count()).select_from(Allocation)) or 0) == 0

    # The real activation event stages the allocation.
    consumer.deliver(_activated_event(db), db)
    assert int(db.scalar(select(func.count()).select_from(Allocation)) or 0) == 1
