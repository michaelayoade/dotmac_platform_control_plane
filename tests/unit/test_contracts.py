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
from dotmac_kernel import CapabilityCatalogue, ConflictError, FeatureManifest
from dotmac_kernel.capabilities import UndeclaredCapabilityError
from dotmac_kernel.entitlements import TenantEntitlementGrant
from dotmac_kernel.messaging import PlatformOutboxEvent
from dotmac_kernel.testing import create_test_engine, isolated_session
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vendor_cp.approvals import service as approvals
from vendor_cp.contracts import service
from vendor_cp.contracts.models import ContractStatus
from vendor_cp.offers.models import OfferVersion


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as s:
            yield s
    finally:
        engine.dispose()


def _catalogue(*codes: str) -> CapabilityCatalogue:
    return CapabilityCatalogue.from_manifests(
        [FeatureManifest(name="t", capabilities=tuple(codes))]
    )


def _offer(db: Session, *, code: str, ver: int, caps: list[str], amount: str) -> None:
    db.add(
        OfferVersion(
            offer_code=code,
            version=ver,
            amount=amount,
            currency_code="USD",
            capability_codes=caps,
        )
    )
    db.flush()


def _draft(db: Session, *, cap: str = "cap.a", offer_code: str = "off", ver: int = 1):
    return service.create_draft(
        db,
        service.CreateDraftCommand(
            command_id=f"d-{uuid.uuid4()}",
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


def _submit(db: Session, cid, catalogue, *, submitter=None):
    return service.submit(
        db,
        service.SubmitCommand(
            command_id=f"s-{uuid.uuid4()}",
            contract_id=cid,
            approval_policy_code="two_person",
            approval_policy_version=1,
            submitter_id=submitter or uuid.uuid4(),
        ),
        catalogue=catalogue,
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


def _approve_quorum(db: Session, contract, content_hash: str, submitter) -> None:
    approvals.publish_policy_version(
        db,
        approvals.PublishPolicyCommand(
            command_id=f"p-{uuid.uuid4()}",
            policy_code="two_person",
            version=1,
            quorum=2,
        ),
    )
    for _ in range(2):
        approvals.record_approval(
            db,
            approvals.RecordApprovalCommand(
                command_id=f"a-{uuid.uuid4()}",
                policy_code="two_person",
                policy_version=1,
                subject_type="contract",
                subject_id=str(contract.id),
                content_hash=content_hash,
                approver_id=uuid.uuid4(),  # distinct, non-submitter
            ),
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
    # Exact Money, frozen onto the line as a string (never float).
    assert submitted.lines[0].unit_amount == "19.99"
    assert submitted.lines[0].unit_currency_code == "USD"
    assert submitted.content_hash is not None
    assert _events(db, "contract.submitted") == 1


def test_approval_is_separate_from_activation(db: Session) -> None:
    _offer(db, code="off", ver=1, caps=["cap.a"], amount="10.00")
    draft = _draft(db, cap="cap.a")
    submitter = uuid.uuid4()
    submitted = _submit(db, draft.id, _catalogue("cap.a"), submitter=submitter)
    _approve_quorum(db, submitted, submitted.content_hash, submitter)
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
    _approve_quorum(db, submitted, submitted.content_hash, submitter)
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
    _approve_quorum(db, submitted, submitted.content_hash, submitter)
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
