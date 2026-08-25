"""Vendor's typed seams into Commercial Agreements and Approvals."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, date, datetime

import pytest
from dotmac_approvals import SelfApprovalRefused
from dotmac_commercial_agreements import (
    AGREEMENT_ACTIVATED_V1,
    AGREEMENT_APPROVED_V1,
    AGREEMENT_PROPOSED_V1,
    AgreementError,
    AgreementStatus,
    UndeclaredCapabilityError,
)
from dotmac_kernel import ConflictError, NotFoundError
from dotmac_kernel.entitlements import TenantEntitlementGrant
from dotmac_kernel.messaging import PlatformOutboxEvent
from dotmac_kernel.testing import create_test_engine, isolated_session
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vendor_cp.approvals import adapter as approvals
from vendor_cp.contracts import adapter as agreements
from vendor_cp.contracts.terms import (
    TermEndNotRepresentable,
    end_exclusive_from_inclusive,
)
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


def _offer(
    db: Session,
    *,
    product_code: str = PRODUCT,
    code: str = "off",
    amount: str = "19.99",
) -> None:
    db.add(
        OfferVersion(
            product_code=product_code,
            offer_code=code,
            version=1,
            amount=amount,
            currency_code="USD",
            capability_codes=["cap.a"],
        )
    )
    db.flush()


def _draft(
    db: Session,
    *,
    product_code: str = PRODUCT,
    catalogue: ProductCapabilityCatalogues | None = None,
) -> agreements.ContractView:
    return agreements.create_draft(
        db,
        agreements.CreateDraftCommand(
            command_id=f"draft-{uuid.uuid4()}",
            reference=f"AGR-{uuid.uuid4()}",
            product_code=product_code,
            counterparty_ref="counterparty-1",
            agreement_type="software_subscription",
            term_start=date(2026, 1, 1),
            term_end=date(2026, 12, 31),
            lines=(agreements.LineInput("off", 1, "cap.a"),),
        ),
        catalogues=catalogue or _catalogue("cap.a"),
    )


def _policy(db: Session, *, quorum: int = 1) -> None:
    approvals.publish_policy_version(
        db,
        approvals.PublishPolicyCommand(
            command_id=f"policy-{uuid.uuid4()}",
            policy_code="commercial",
            version=1,
            quorum=quorum,
            allow_self_approval=False,
        ),
    )


def _propose(
    db: Session,
    agreement_id: uuid.UUID,
    *,
    requested_by: uuid.UUID | None = None,
) -> agreements.ContractView:
    _policy(db)
    return agreements.propose(
        db,
        agreements.ProposeCommand(
            command_id=f"propose-{uuid.uuid4()}",
            agreement_id=agreement_id,
            approval_policy_code="commercial",
            approval_policy_version=1,
            requested_by=requested_by or uuid.uuid4(),
        ),
        catalogues=_catalogue("cap.a"),
    )


def _decide(db: Session, proposed: agreements.ContractView, actor: uuid.UUID) -> None:
    assert proposed.approval_request_id is not None
    assert proposed.content_hash is not None
    approvals.record_decision(
        db,
        approvals.RecordDecisionCommand(
            command_id=f"decision-{uuid.uuid4()}",
            request_id=proposed.approval_request_id,
            approver_id=actor,
            content_hash=proposed.content_hash,
        ),
    )


def _approve(db: Session, proposed: agreements.ContractView) -> agreements.ContractView:
    assert proposed.approval_request_id is not None
    _decide(db, proposed, uuid.uuid4())
    return agreements.approve(
        db,
        agreements.ApprovalCommand(
            command_id=f"approve-{uuid.uuid4()}",
            agreement_id=proposed.id,
            approval_request_id=proposed.approval_request_id,
        ),
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


def test_draft_resolves_and_freezes_vendor_offer_terms(db: Session) -> None:
    _offer(db)
    draft = _draft(db)
    assert draft.status == AgreementStatus.DRAFT.value
    assert draft.product_code == PRODUCT
    assert draft.lines[0].unit_amount == "19.99"
    assert draft.lines[0].unit_currency_code == "USD"
    assert draft.lines[0].offer_ref is not None
    assert draft.term_start == date(2026, 1, 1)
    assert draft.term_end_exclusive == date(2027, 1, 1)

    proposed = _propose(db, draft.id)
    assert proposed.status == AgreementStatus.PROPOSED.value
    assert proposed.content_hash is not None
    assert proposed.approval_request_id is not None
    assert _events(db, AGREEMENT_PROPOSED_V1) == 1


def test_inclusive_term_end_has_one_end_exclusive_translation() -> None:
    assert end_exclusive_from_inclusive(date(2026, 12, 31)) == date(2027, 1, 1)
    with pytest.raises(TermEndNotRepresentable):
        end_exclusive_from_inclusive(date.max)


def test_draft_rejects_an_undeclared_capability(db: Session) -> None:
    _offer(db)
    with pytest.raises(UndeclaredCapabilityError):
        _draft(db, catalogue=_catalogue("cap.other"))


def test_offer_resolution_is_product_qualified(db: Session) -> None:
    _offer(db, product_code="dotmac-erp")
    with pytest.raises(NotFoundError, match="offer version.*not found"):
        _draft(db)


def test_the_accepted_digest_binds_product_identity(db: Session) -> None:
    _offer(db, product_code=PRODUCT)
    _offer(db, product_code="dotmac-erp")
    catalogues = ProductCapabilityCatalogues.from_capabilities(
        {PRODUCT: ("cap.a",), "dotmac-erp": ("cap.a",)}
    )
    _policy(db)
    sub = _draft(db, product_code=PRODUCT, catalogue=catalogues)
    erp = _draft(db, product_code="dotmac-erp", catalogue=catalogues)
    sub_proposed = agreements.propose(
        db,
        agreements.ProposeCommand(
            command_id=f"propose-{uuid.uuid4()}",
            agreement_id=sub.id,
            approval_policy_code="commercial",
            approval_policy_version=1,
            requested_by=uuid.uuid4(),
        ),
        catalogues=catalogues,
    )
    erp_proposed = agreements.propose(
        db,
        agreements.ProposeCommand(
            command_id=f"propose-{uuid.uuid4()}",
            agreement_id=erp.id,
            approval_policy_code="commercial",
            approval_policy_version=1,
            requested_by=uuid.uuid4(),
        ),
        catalogues=catalogues,
    )
    assert sub_proposed.content_hash != erp_proposed.content_hash


def test_a_requester_cannot_approve_their_own_agreement(db: Session) -> None:
    _offer(db)
    draft = _draft(db)
    requester = uuid.uuid4()
    proposed = _propose(db, draft.id, requested_by=requester)
    with pytest.raises(SelfApprovalRefused):
        _decide(db, proposed, requester)

    assert proposed.approval_request_id is not None
    with pytest.raises(ConflictError, match="not approved"):
        agreements.approve(
            db,
            agreements.ApprovalCommand(
                command_id="approve-self",
                agreement_id=draft.id,
                approval_request_id=proposed.approval_request_id,
            ),
        )


def test_approval_is_separate_from_activation(db: Session) -> None:
    _offer(db)
    approved = _approve(db, _propose(db, _draft(db).id))
    assert approved.status == AgreementStatus.APPROVED.value
    assert _events(db, AGREEMENT_APPROVED_V1) == 1
    assert _events(db, AGREEMENT_ACTIVATED_V1) == 0


def test_activation_requires_both_approval_and_activation_evidence(
    db: Session,
) -> None:
    _offer(db)
    proposed = _propose(db, _draft(db).id)
    approved = _approve(db, proposed)
    assert proposed.approval_request_id is not None

    with pytest.raises(AgreementError, match="named activation rule"):
        agreements.activate(
            db,
            agreements.ActivateCommand(
                command_id="activate-without-rule",
                agreement_id=approved.id,
                approval_request_id=proposed.approval_request_id,
                activation_rule="",
                activation_reference="countersignature-1",
                activation_satisfied_at=datetime.now(UTC),
            ),
        )

    active = agreements.activate(
        db,
        agreements.ActivateCommand(
            command_id="activate-1",
            agreement_id=approved.id,
            approval_request_id=proposed.approval_request_id,
            activation_rule="countersigned",
            activation_reference="countersignature-1",
            activation_satisfied_at=datetime.now(UTC),
        ),
    )
    assert active.status == AgreementStatus.ACTIVE.value
    assert _events(db, AGREEMENT_ACTIVATED_V1) == 1
    assert (
        int(db.scalar(select(func.count()).select_from(TenantEntitlementGrant)) or 0)
        == 0
    )


def test_activation_fact_names_the_authoritative_agreement(db: Session) -> None:
    _offer(db)
    proposed = _propose(db, _draft(db).id)
    approved = _approve(db, proposed)
    assert proposed.approval_request_id is not None
    agreements.activate(
        db,
        agreements.ActivateCommand(
            command_id="activate-fact",
            agreement_id=approved.id,
            approval_request_id=proposed.approval_request_id,
            activation_rule="countersigned",
            activation_reference="countersignature-1",
            activation_satisfied_at=datetime.now(UTC),
        ),
    )
    event = db.scalar(
        select(PlatformOutboxEvent).where(
            PlatformOutboxEvent.event_type == AGREEMENT_ACTIVATED_V1
        )
    )
    assert event is not None
    assert event.payload["agreement_id"] == str(approved.id)
    assert event.payload["content_hash"] == approved.content_hash


def test_an_idempotent_approval_emits_one_fact(db: Session) -> None:
    _offer(db)
    proposed = _propose(db, _draft(db).id)
    _decide(db, proposed, uuid.uuid4())
    assert proposed.approval_request_id is not None
    command = agreements.ApprovalCommand(
        command_id="approve-replay",
        agreement_id=proposed.id,
        approval_request_id=proposed.approval_request_id,
    )
    agreements.approve(db, command)
    agreements.approve(db, command)
    assert _events(db, AGREEMENT_APPROVED_V1) == 1


def test_a_refused_transition_emits_no_fact(db: Session) -> None:
    _offer(db)
    draft = _draft(db)
    with pytest.raises(AgreementError):
        agreements.reject(
            db,
            agreements.TransitionCommand(
                command_id="reject-draft", agreement_id=draft.id
            ),
        )
    assert _events(db, "agreement.rejected.v1") == 0


def test_reject_clears_the_frozen_snapshot(db: Session) -> None:
    _offer(db)
    proposed = _propose(db, _draft(db).id)
    rejected = agreements.reject(
        db,
        agreements.TransitionCommand(
            command_id="reject-1",
            agreement_id=proposed.id,
            reason="pricing changed",
        ),
    )
    assert rejected.status == AgreementStatus.DRAFT.value
    assert rejected.content_hash is None
