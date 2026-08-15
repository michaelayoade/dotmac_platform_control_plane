"""Unit tests for the approvals ADAPTER (SQLite).

`dotmac-approvals` is the authority now; `vendor_cp.approvals.adapter` is the one
seam Vendor speaks to it through. These tests are about the SEAM, not the
module's internals: that a policy revision is immutable, that a request is opened
against exact content, that a quorum of distinct approvers satisfies it, that
self-approval is refused by default, and — the obligation ADR-0004 § 4 put on
whatever replaced the legacy service — that a RETRIED command replays rather than
raising the module's duplicate refusal.

The module's own rules (level sequencing, SoD, MFA) are its own tests' business.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Iterator

import pytest
from dotmac_approvals import (
    ContentChanged,
    PolicyNotFound,
    PolicyVersionExists,
    SelfApprovalRefused,
)
from dotmac_kernel.testing import create_test_engine, isolated_session
from sqlalchemy.orm import Session

from vendor_cp.approvals import adapter as approvals

POLICY = "two_person"
HASH = hashlib.sha256(b"contract-1").hexdigest()
OTHER_HASH = hashlib.sha256(b"contract-1-amended").hexdigest()


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as s:
            yield s
    finally:
        engine.dispose()


def _publish(
    db: Session,
    *,
    quorum: int = 2,
    self_ok: bool = False,
    version: int = 1,
    command_id: str | None = None,
) -> approvals.PolicyView:
    return approvals.publish_policy_version(
        db,
        approvals.PublishPolicyCommand(
            command_id=command_id or f"pol-{POLICY}-{version}",
            policy_code=POLICY,
            version=version,
            quorum=quorum,
            allow_self_approval=self_ok,
        ),
    )


def _open(
    db: Session,
    *,
    requester: uuid.UUID,
    content_hash: str = HASH,
    version: int = 1,
    command_id: str | None = None,
) -> approvals.RequestView:
    return approvals.open_request(
        db,
        approvals.OpenRequestCommand(
            command_id=command_id or f"req-{uuid.uuid4()}",
            policy_code=POLICY,
            policy_version=version,
            subject_type="contract",
            subject_id="c1",
            content_hash=content_hash,
            requested_by=requester,
        ),
    )


def _decide(
    db: Session,
    request_id: uuid.UUID,
    approver: uuid.UUID,
    *,
    content_hash: str = HASH,
    command_id: str | None = None,
) -> approvals.RequestView:
    return approvals.record_decision(
        db,
        approvals.RecordDecisionCommand(
            command_id=command_id or f"dec-{uuid.uuid4()}",
            request_id=request_id,
            approver_id=approver,
            content_hash=content_hash,
        ),
    )


# ── Policy revisions ────────────────────────────────────────────────────────


def test_a_published_revision_is_immutable(db: Session) -> None:
    _publish(db, quorum=2)
    # A DIFFERENT command re-publishing the same code+version is not a retry —
    # it is an attempt to rewrite what open requests were opened against.
    with pytest.raises(PolicyVersionExists):
        _publish(db, quorum=3, command_id="pol-rewrite")


def test_a_retried_publish_replays_rather_than_raising(db: Session) -> None:
    first = _publish(db, quorum=2)
    again = _publish(db, quorum=2)  # same command id -> at-most-once replay
    assert (again.policy_code, again.version) == (first.policy_code, first.version)


# ── Opening a request ───────────────────────────────────────────────────────


def test_a_request_needs_a_published_policy(db: Session) -> None:
    # Fail CLOSED: no policy is never "no approval required".
    with pytest.raises(PolicyNotFound):
        _open(db, requester=uuid.uuid4())


def test_a_new_request_is_pending_not_satisfied(db: Session) -> None:
    _publish(db, quorum=2)
    view = _open(db, requester=uuid.uuid4())
    assert not view.satisfied
    assert (view.satisfied_levels, view.total_levels) == (0, 1)


def test_a_retried_open_replays_the_same_request(db: Session) -> None:
    _publish(db, quorum=2)
    requester = uuid.uuid4()
    first = _open(db, requester=requester, command_id="req-dup")
    again = _open(db, requester=requester, command_id="req-dup")
    assert again.request_id == first.request_id


# ── Reaching quorum ─────────────────────────────────────────────────────────


def test_quorum_of_distinct_approvers(db: Session) -> None:
    _publish(db, quorum=2)
    opened = _open(db, requester=uuid.uuid4())
    after_one = _decide(db, opened.request_id, uuid.uuid4())
    assert not after_one.satisfied  # one approver is not a two-person quorum
    after_two = _decide(db, opened.request_id, uuid.uuid4())
    assert after_two.satisfied
    # Evaluation is the module's answer, read back the same way the contract
    # service reads it.
    assert approvals.evaluate_request(db, request_id=opened.request_id).satisfied


def test_a_retried_decision_replays_rather_than_raising(db: Session) -> None:
    """The module REFUSES a duplicate decision; the adapter makes a retried
    COMMAND replay instead — and the replay does not count toward quorum."""
    _publish(db, quorum=2)
    opened = _open(db, requester=uuid.uuid4())
    approver = uuid.uuid4()
    _decide(db, opened.request_id, approver, command_id="dec-dup")
    replayed = _decide(db, opened.request_id, approver, command_id="dec-dup")
    assert not replayed.satisfied
    assert replayed.satisfied_levels == 0


def test_self_approval_is_refused_by_default(db: Session) -> None:
    _publish(db, quorum=1, self_ok=False)
    submitter = uuid.uuid4()
    opened = _open(db, requester=submitter)
    with pytest.raises(SelfApprovalRefused):
        _decide(db, opened.request_id, submitter)


def test_a_decision_must_present_the_requests_content(db: Session) -> None:
    _publish(db, quorum=1)
    opened = _open(db, requester=uuid.uuid4())
    # A decision carrying a different digest is a decision about other content.
    with pytest.raises(ContentChanged):
        _decide(db, opened.request_id, uuid.uuid4(), content_hash=OTHER_HASH)


def test_a_content_hash_that_cannot_translate_is_refused(db: Session) -> None:
    _publish(db, quorum=1)
    # Vendor stores bare 64-hex; anything else never reaches the module.
    with pytest.raises(ValueError, match="not translatable"):
        _open(db, requester=uuid.uuid4(), content_hash="not-a-digest")
