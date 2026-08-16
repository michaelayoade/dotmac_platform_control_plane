"""Unit tests for ContractService (SQLite) — the design's acceptance cases.

Proves: submit rejects an undeclared capability (WS1), submit freezes an immutable
priced snapshot with exact Money, approval is separate from activation, activation
is a separate rule-driven command that emits `contract.activated` and writes NO
cross-plane state, and transitions are idempotent + atomic with their platform
outbox event. See docs/design/contract-service.md.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import date

import pytest
from dotmac_approvals import SelfApprovalRefused
from dotmac_entitlement_allocation import UndeclaredCapabilityError
from dotmac_kernel import ConflictError, NotFoundError
from dotmac_kernel.entitlements import TenantEntitlementGrant
from dotmac_kernel.messaging import PlatformOutboxEvent
from dotmac_kernel.testing import create_test_engine, isolated_session
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vendor_cp.approvals import adapter as approvals
from vendor_cp.contracts import service
from vendor_cp.contracts.models import Contract, ContractStatus
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


def _offer(
    db: Session,
    *,
    code: str,
    ver: int,
    caps: list[str],
    amount: str,
    product_code: str = "dotmac-sub",
) -> None:
    db.add(
        OfferVersion(
            product_code=product_code,
            offer_code=code,
            version=ver,
            amount=amount,
            currency_code="USD",
            capability_codes=caps,
        )
    )
    db.flush()


def _draft(
    db: Session,
    *,
    cap: str = "cap.a",
    offer_code: str = "off",
    ver: int = 1,
    product_code: str = "dotmac-sub",
):
    return service.create_draft(
        db,
        service.CreateDraftCommand(
            command_id=f"d-{uuid.uuid4()}",
            product_code=product_code,
            customer_ref="cust-1",
            legal_entity="Dotmac Ltd",
            currency_code="USD",
            term_start=date(2026, 1, 1),
            term_end=date(2026, 12, 31),
            lines=(
                service.LineInput(
                    offer_code=offer_code, offer_version=ver, capability_code=cap
                ),
            ),
        ),
    )


def _policy(db: Session) -> None:
    """Publish `two_person` v1 — a stable command id, so calling this again in the
    same test REPLAYS rather than colliding with the immutable revision."""
    approvals.publish_policy_version(
        db,
        approvals.PublishPolicyCommand(
            command_id="pol-two_person-1",
            policy_code="two_person",
            version=1,
            quorum=2,
            allow_self_approval=False,
        ),
    )


def _submit(db: Session, cid, catalogue, *, submitter=None):
    # The policy must exist BEFORE submit: submit opens the approval request
    # against that exact revision, so publishing afterwards would be too late.
    _policy(db)
    return service.submit(
        db,
        service.SubmitCommand(
            command_id=f"s-{uuid.uuid4()}",
            contract_id=cid,
            approval_policy_code="two_person",
            approval_policy_version=1,
            submitter_id=submitter or uuid.uuid4(),
        ),
        catalogues=catalogue,
    )


def _events(db: Session, event_type: str) -> int:
    return int(
        db.scalar(
            select(func.count())
            .select_from(PlatformOutboxEvent)
            .where(PlatformOutboxEvent.event_type == event_type)
        )
        or 0
    )


def _approve_quorum(db: Session, contract_id, content_hash: str | None) -> None:
    """Reach the published quorum on the contract's OWN approval request.

    The request id lives on the ORM row (`submit` set it); the service returns a
    view, so read it back rather than inventing a subject/content lookup.
    """
    assert content_hash is not None
    row = db.get(Contract, contract_id)
    assert row is not None and row.approval_request_id is not None
    for _ in range(2):
        approvals.record_decision(
            db,
            approvals.RecordDecisionCommand(
                command_id=f"dec-{uuid.uuid4()}",
                request_id=row.approval_request_id,
                approver_id=uuid.uuid4(),  # distinct, non-submitter
                content_hash=content_hash,
            ),
        )


def test_a_submitter_cannot_self_approve_their_own_contract(db: Session) -> None:
    """The domain safety property, end to end.

    The authority-level rule is proven in `test_approvals.py`; this proves it
    still holds through the CONTRACT path, which is where it matters — the
    submitter is recorded as the request's requester, so the module refuses their
    decision rather than silently not counting it.

    The refusal shape changed with the authority: the legacy writer accepted the
    row and excluded it from the count, so a self-approval looked recorded and
    did nothing. Refusing at decision time is the better behaviour and the reason
    to check it here rather than assume it transferred.
    """
    _offer(db, code="off", ver=1, caps=["cap.a"], amount="10.00")
    draft = _draft(db, cap="cap.a")
    submitter = uuid.uuid4()
    submitted = _submit(db, draft.id, _catalogue("cap.a"), submitter=submitter)

    row = db.get(Contract, draft.id)
    assert row is not None and row.approval_request_id is not None

    with pytest.raises(SelfApprovalRefused):
        approvals.record_decision(
            db,
            approvals.RecordDecisionCommand(
                command_id=f"dec-{uuid.uuid4()}",
                request_id=row.approval_request_id,
                approver_id=submitter,
                content_hash=submitted.content_hash or "",
            ),
        )

    # And the contract cannot be approved on the strength of it.
    with pytest.raises(ConflictError):
        service.approve(
            db, service.TransitionCommand(command_id="ap-self", contract_id=draft.id)
        )


def test_submit_rejects_undeclared_capability(db: Session) -> None:
    _offer(db, code="off", ver=1, caps=["cap.a"], amount="10.00")
    draft = _draft(db, cap="cap.a")
    # Catalogue does NOT declare cap.a -> WS1 require fails at submit.
    with pytest.raises(UndeclaredCapabilityError):
        _submit(db, draft.id, _catalogue("cap.other"))


def test_submit_freezes_exact_priced_snapshot(db: Session) -> None:
    _offer(db, code="off", ver=1, caps=["cap.a"], amount="19.99")
    draft = _draft(db, cap="cap.a")
    assert draft.status == ContractStatus.DRAFT.value
    assert draft.lines[0].unit_amount is None  # not priced until submit
    submitted = _submit(db, draft.id, _catalogue("cap.a"))
    assert submitted.status == ContractStatus.PENDING_APPROVAL.value
    assert submitted.product_code == "dotmac-sub"
    # Exact Money, frozen onto the line as a string (never float).
    assert submitted.lines[0].unit_amount == "19.99"
    assert submitted.lines[0].unit_currency_code == "USD"
    assert submitted.content_hash is not None
    assert _events(db, "contract.submitted") == 1


def test_contract_refuses_an_offer_owned_by_another_product(db: Session) -> None:
    _offer(
        db,
        code="off",
        ver=1,
        caps=["cap.a"],
        amount="19.99",
        product_code="dotmac-erp",
    )
    with pytest.raises(NotFoundError, match="offer version.*not found"):
        _draft(db, cap="cap.a")


def test_contract_content_hash_binds_the_product_identity(db: Session) -> None:
    for product in ("dotmac-sub", "dotmac-erp"):
        _offer(
            db,
            code="off",
            ver=1,
            caps=["cap.a"],
            amount="19.99",
            product_code=product,
        )
    catalogues = ProductCapabilityCatalogues.from_capabilities(
        {"dotmac-sub": ("cap.a",), "dotmac-erp": ("cap.a",)}
    )
    sub = _draft(db, product_code="dotmac-sub")
    erp = _draft(db, product_code="dotmac-erp")
    submitted_sub = _submit(db, sub.id, catalogues)
    submitted_erp = _submit(db, erp.id, catalogues)
    assert submitted_sub.content_hash != submitted_erp.content_hash


def test_activation_event_carries_the_hashed_product_identity(db: Session) -> None:
    _offer(db, code="off", ver=1, caps=["cap.a"], amount="10.00")
    draft = _draft(db, cap="cap.a")
    submitter = uuid.uuid4()
    submitted = _submit(db, draft.id, _catalogue("cap.a"), submitter=submitter)
    _approve_quorum(db, draft.id, submitted.content_hash)
    service.approve(
        db, service.TransitionCommand(command_id="ap-product", contract_id=draft.id)
    )
    service.activate(
        db,
        service.TransitionCommand(
            command_id="act-product",
            contract_id=draft.id,
            activation_evidence="countersigned",
        ),
    )
    event = db.scalar(
        select(PlatformOutboxEvent).where(
            PlatformOutboxEvent.event_type == "contract.activated"
        )
    )
    assert event is not None
    assert event.payload["product_code"] == "dotmac-sub"


def test_historical_contract_without_product_fails_closed(db: Session) -> None:
    _offer(db, code="off", ver=1, caps=["cap.a"], amount="10.00")
    draft = _draft(db, cap="cap.a")
    row = db.get(Contract, draft.id)
    assert row is not None
    row.product_code = None
    db.flush()
    with pytest.raises(ConflictError, match="has no product identity"):
        _submit(db, draft.id, _catalogue("cap.a"))
    assert _events(db, "contract.submitted") == 0


def test_approval_is_separate_from_activation(db: Session) -> None:
    _offer(db, code="off", ver=1, caps=["cap.a"], amount="10.00")
    draft = _draft(db, cap="cap.a")
    submitter = uuid.uuid4()
    submitted = _submit(db, draft.id, _catalogue("cap.a"), submitter=submitter)
    _approve_quorum(db, draft.id, submitted.content_hash)
    approved = service.approve(
        db, service.TransitionCommand(command_id="ap-1", contract_id=draft.id)
    )
    # APPROVED is a commercial decision — it is NOT active.
    assert approved.status == ContractStatus.APPROVED.value
    assert _events(db, "contract.approved") == 1
    assert _events(db, "contract.activated") == 0


def test_activation_is_separate_rule_driven_and_writes_no_cross_plane_state(
    db: Session,
) -> None:
    _offer(db, code="off", ver=1, caps=["cap.a"], amount="10.00")
    draft = _draft(db, cap="cap.a")
    submitter = uuid.uuid4()
    submitted = _submit(db, draft.id, _catalogue("cap.a"), submitter=submitter)
    _approve_quorum(db, draft.id, submitted.content_hash)
    service.approve(
        db, service.TransitionCommand(command_id="ap-1", contract_id=draft.id)
    )
    # Activation requires evidence (rule-driven), not a bare request.
    with pytest.raises(ConflictError):
        service.activate(
            db, service.TransitionCommand(command_id="act-x", contract_id=draft.id)
        )
    active = service.activate(
        db,
        service.TransitionCommand(
            command_id="act-1",
            contract_id=draft.id,
            activation_evidence="countersigned 2026-01-05",
        ),
    )
    assert active.status == ContractStatus.ACTIVE.value
    assert _events(db, "contract.activated") == 1
    # ContractService writes NO WS2 grants — that is the data plane's job.
    assert (
        int(db.scalar(select(func.count()).select_from(TenantEntitlementGrant)) or 0)
        == 0
    )


def test_transitions_are_idempotent_and_atomic_with_their_event(db: Session) -> None:
    _offer(db, code="off", ver=1, caps=["cap.a"], amount="10.00")
    draft = _draft(db, cap="cap.a")
    submitter = uuid.uuid4()
    submitted = _submit(db, draft.id, _catalogue("cap.a"), submitter=submitter)
    _approve_quorum(db, draft.id, submitted.content_hash)
    cmd = service.TransitionCommand(command_id="ap-dup", contract_id=draft.id)
    service.approve(db, cmd)
    service.approve(db, cmd)  # same command_id -> idempotent replay
    # Exactly one transition, exactly one event (no double-emit).
    assert _events(db, "contract.approved") == 1


def test_failed_guard_emits_no_event_atomic_rollback(db: Session) -> None:
    _offer(db, code="off", ver=1, caps=["cap.a"], amount="10.00")
    draft = _draft(db, cap="cap.a")
    # Activate straight from draft is an illegal transition -> ConflictError, and
    # because the emit is inside the same handler, NO event is left behind.
    with pytest.raises(ConflictError):
        service.activate(
            db,
            service.TransitionCommand(
                command_id="act-bad",
                contract_id=draft.id,
                activation_evidence="x",
            ),
        )
    assert _events(db, "contract.activated") == 0


def test_reject_clears_snapshot_and_returns_to_draft(db: Session) -> None:
    _offer(db, code="off", ver=1, caps=["cap.a"], amount="10.00")
    draft = _draft(db, cap="cap.a")
    submitted = _submit(db, draft.id, _catalogue("cap.a"))
    assert submitted.content_hash is not None
    rejected = service.reject(
        db,
        service.TransitionCommand(
            command_id="rj-1", contract_id=draft.id, reason="pricing off"
        ),
    )
    assert rejected.status == ContractStatus.DRAFT.value
    assert rejected.content_hash is None  # must be re-submitted
    assert _events(db, "contract.rejected") == 1
