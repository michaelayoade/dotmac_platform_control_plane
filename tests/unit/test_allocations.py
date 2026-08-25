"""Unit tests for the Vendor→`dotmac-entitlement-allocation` adapter (SQLite).

`dotmac-entitlement-allocation` is the allocation authority; Vendor reaches it
through `vendor_cp.allocations.adapter` and nothing else. What the MODULE owns —
catalogue legality, non-empty entries, duplicate refusal, the immutable row —
is proven in the module's own suite and is deliberately not re-asserted here.

What is proven here is the SEAM: that an activated contract maps onto the
module's `ContractSnapshot` correctly, that the staleness checks Vendor keeps on
its own side of the boundary bite (a non-ACTIVE contract, a stale
`content_hash`, a contract carrying no `product_code`), that staging is
idempotent on the source event id, that no product WS2 grant is ever written,
and that the `ContractEventConsumer` reacts only to `contract.activated` — end
to end from a real ContractService activation event.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import date

import pytest
from dotmac_kernel import NotFoundError
from dotmac_kernel.entitlements import TenantEntitlementGrant
from dotmac_kernel.messaging import ClaimedPlatformEvent, PlatformOutboxEvent
from dotmac_kernel.testing import create_test_engine, isolated_session
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vendor_cp.allocations import adapter
from vendor_cp.allocations.consumer import ContractEventConsumer
from vendor_cp.approvals import adapter as approvals
from vendor_cp.contracts import service as contracts
from vendor_cp.contracts.models import Contract
from vendor_cp.offers.catalog import ProductCapabilityCatalogues
from vendor_cp.offers.models import OfferVersion

PRODUCT = "dotmac-sub"


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as s:
            yield s
    finally:
        engine.dispose()


def _approve(db: Session, contract_id: uuid.UUID, content_hash: str | None) -> None:
    """Reach quorum on the contract's OWN approval request.

    `submit` opened that request and stored its id on the row, so the id is read
    back off the ORM row — the service returns a view, which does not carry it.
    """
    assert content_hash is not None
    row = db.get(Contract, contract_id)
    assert row is not None and row.approval_request_id is not None
    approvals.record_decision(
        db,
        approvals.RecordDecisionCommand(
            command_id=f"dec-{uuid.uuid4()}",
            request_id=row.approval_request_id,
            approver_id=uuid.uuid4(),
            content_hash=content_hash,
        ),
    )


def _catalogue(*codes: str) -> ProductCapabilityCatalogues:
    """The `CapabilityCatalogueReader` the adapter now requires.

    The same product-qualified adapter production builds from pinned release
    evidence, constructed from literal codes rather than from Release Catalog
    rows — the catalogue's own evidence path has its canaries in
    `test_catalogued_product_manifests.py`.
    """
    return ProductCapabilityCatalogues.from_capabilities({PRODUCT: tuple(codes)})


def _submitted_contract(db: Session) -> tuple[uuid.UUID, str]:
    """A contract driven through the real ContractService as far as APPROVED."""
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
    draft = contracts.create_draft(
        db,
        contracts.CreateDraftCommand(
            command_id=f"d-{uuid.uuid4()}",
            product_code=PRODUCT,
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
    # The policy must exist BEFORE submit: submit opens the approval
    # request against that exact revision, so publishing after it would
    # be too late.
    approvals.publish_policy_version(
        db,
        approvals.PublishPolicyCommand(
            command_id=f"pol-{uuid.uuid4()}",
            policy_code="p",
            version=1,
            quorum=1,
            allow_self_approval=False,
        ),
    )
    submitted = contracts.submit(
        db,
        contracts.SubmitCommand(
            command_id=f"s-{uuid.uuid4()}",
            contract_id=draft.id,
            approval_policy_code="p",
            approval_policy_version=1,
            submitter_id=uuid.uuid4(),
        ),
        catalogues=_catalogue("cap.a", "cap.b"),
    )
    _approve(db, draft.id, submitted.content_hash)
    contracts.approve(
        db,
        contracts.TransitionCommand(
            command_id=f"ap-{uuid.uuid4()}", contract_id=draft.id
        ),
    )
    assert submitted.content_hash is not None
    return draft.id, submitted.content_hash


def _activated_contract(db: Session) -> tuple[uuid.UUID, str]:
    """Drive a contract all the way to ACTIVE via the real ContractService, so a
    genuine `contract.activated` event lands in the platform outbox."""
    contract_id, content_hash = _submitted_contract(db)
    contracts.activate(
        db,
        contracts.TransitionCommand(
            command_id=f"act-{uuid.uuid4()}",
            contract_id=contract_id,
            activation_evidence="countersigned",
        ),
    )
    return contract_id, content_hash


def _activated_event(db: Session) -> ClaimedPlatformEvent:
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


def _stage(
    db: Session,
    contract_id: uuid.UUID,
    content_hash: str,
    *,
    source_event_id: str = "evt-1",
) -> adapter.AllocationView:
    return adapter.stage_allocation(
        db,
        adapter.StageAllocationCommand(
            source_event_id=source_event_id,
            contract_id=contract_id,
            content_hash=content_hash,
            customer_ref="cust-42",
        ),
        catalogues=_catalogue("cap.a", "cap.b"),
    )


def test_stage_projects_the_contract_entitlement_into_the_module(db: Session) -> None:
    contract_id, chash = _activated_contract(db)
    view = _stage(db, contract_id, chash)

    assert view.status == str(adapter.STAGED_STATUS)
    assert view.customer_ref == "cust-42"
    # Product-qualified: the module records the product whose catalogue the
    # entries were validated against, read off the contract rather than invented.
    assert view.product_code == PRODUCT
    assert view.content_hash == chash
    assert not view.replayed
    caps = {(e.capability_code, e.quantity) for e in view.entries}
    assert caps == {("cap.a", 2), ("cap.b", 1)}  # projected from the contract lines


def test_stage_is_idempotent_on_event_and_activation(db: Session) -> None:
    contract_id, chash = _activated_contract(db)
    first = _stage(db, contract_id, chash, source_event_id="evt-dup")
    # The SAME delivery again.
    again = _stage(db, contract_id, chash, source_event_id="evt-dup")
    # A DIFFERENT delivery of the same activation.
    other = _stage(db, contract_id, chash, source_event_id="evt-other")

    assert again.id == first.id and other.id == first.id
    assert again.replayed and other.replayed
    assert len(adapter.list_for_contract(db, contract_id)) == 1


def test_a_stale_content_hash_is_refused(db: Session) -> None:
    """Vendor's own check, and it stays Vendor's: only Vendor can say whether an
    activation event still describes the contract's current version."""
    contract_id, _chash = _activated_contract(db)
    with pytest.raises(NotFoundError, match="stale event"):
        _stage(db, contract_id, "sha256:not-the-current-version")
    assert adapter.list_for_contract(db, contract_id) == []


def test_a_contract_that_is_not_active_is_refused(db: Session) -> None:
    contract_id, chash = _submitted_contract(db)  # approved, never activated
    with pytest.raises(NotFoundError, match="not active"):
        _stage(db, contract_id, chash)
    assert adapter.list_for_contract(db, contract_id) == []


def test_a_contract_with_no_product_code_cannot_be_allocated(db: Session) -> None:
    """A capability code is only meaningful against the product declaring it, so
    an unattributed contract fails closed rather than being allocated to a
    guessed product."""
    contract_id, chash = _activated_contract(db)
    row = db.get(Contract, contract_id)
    assert row is not None
    row.product_code = None
    db.flush()

    with pytest.raises(NotFoundError, match="product_code"):
        _stage(db, contract_id, chash)


def test_an_unknown_contract_is_refused(db: Session) -> None:
    with pytest.raises(NotFoundError, match="not found"):
        _stage(db, uuid.uuid4(), "sha256:whatever")


def test_stage_writes_no_product_ws2_grant(db: Session) -> None:
    """Ruling C4: the vendor control plane allocates; the product data plane is
    the only writer of its own `tenant_entitlement_grants`."""
    contract_id, chash = _activated_contract(db)
    _stage(db, contract_id, chash)
    assert (
        int(db.scalar(select(func.count()).select_from(TenantEntitlementGrant)) or 0)
        == 0
    )


def test_consumer_reacts_only_to_contract_activated(db: Session, monkeypatch) -> None:
    contract_id, _chash = _activated_contract(db)
    consumer = ContractEventConsumer()
    # The consumer resolves its catalogue from configured release pins and held
    # evidence; this suite is about WHICH events it acts on, so the resolution
    # itself is stubbed and proven in `test_catalogued_product_manifests.py`.
    monkeypatch.setattr(
        ContractEventConsumer,
        "_catalogues",
        lambda _self, _db: _catalogue("cap.a", "cap.b"),
    )

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
    assert adapter.list_for_contract(db, contract_id) == []

    # The real activation event stages the allocation.
    consumer.deliver(_activated_event(db), db)
    assert len(adapter.list_for_contract(db, contract_id)) == 1
