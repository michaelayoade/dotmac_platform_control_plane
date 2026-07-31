"""Unit tests for ApprovalPolicyService (SQLite).

Proves: immutable policy versions, content-bound + distinct-actor quorum, fail-
closed on a missing policy, no-self-approval exclusion, and idempotent recording.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from dotmac_kernel import ConflictError
from dotmac_kernel.testing import create_test_engine, isolated_session
from sqlalchemy.orm import Session

from vendor_cp.approvals import service


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as s:
            yield s
    finally:
        engine.dispose()


def _policy(db: Session, *, quorum: int = 2, self_ok: bool = False, ver: int = 1):
    return service.publish_policy_version(
        db,
        service.PublishPolicyCommand(
            command_id=f"p-{ver}",
            policy_code="two_person",
            version=ver,
            quorum=quorum,
            allow_self_approval=self_ok,
        ),
    )


def _approve(
    db: Session, approver: uuid.UUID, chash: str = "h1", cid: str | None = None
):
    service.record_approval(
        db,
        service.RecordApprovalCommand(
            command_id=cid or f"a-{approver}-{chash}",
            policy_code="two_person",
            policy_version=1,
            subject_type="contract",
            subject_id="c1",
            content_hash=chash,
            approver_id=approver,
        ),
    )


def _evaluate(db: Session, chash: str = "h1", submitter=None):
    return service.evaluate(
        db,
        policy_code="two_person",
        policy_version=1,
        subject_type="contract",
        subject_id="c1",
        content_hash=chash,
        submitter_id=submitter,
    )


def test_policy_versions_are_immutable(db: Session) -> None:
    _policy(db)
    with pytest.raises(ConflictError):
        service.publish_policy_version(
            db,
            service.PublishPolicyCommand(
                command_id="p-dup", policy_code="two_person", version=1, quorum=3
            ),
        )


def test_quorum_of_distinct_approvers(db: Session) -> None:
    _policy(db, quorum=2)
    a, b = uuid.uuid4(), uuid.uuid4()
    _approve(db, a)
    assert not _evaluate(db).satisfied  # only 1 distinct approver
    _approve(db, a)  # same approver again — no new count (idempotent + distinct)
    assert _evaluate(db).distinct_approvers == 1
    _approve(db, b)
    decision = _evaluate(db)
    assert decision.satisfied and decision.distinct_approvers == 2


def test_content_bound_approvals(db: Session) -> None:
    _policy(db, quorum=1)
    _approve(db, uuid.uuid4(), chash="h1")
    assert _evaluate(db, chash="h1").satisfied
    # A different content hash (content changed) has no approvals.
    assert not _evaluate(db, chash="h2").satisfied


def test_fail_closed_on_missing_policy(db: Session) -> None:
    # No policy published -> not satisfied, explicit reason (never implicit yes).
    decision = _evaluate(db)
    assert not decision.satisfied and decision.reason == "policy_not_found"


def test_self_approval_excluded_when_disallowed(db: Session) -> None:
    _policy(db, quorum=1, self_ok=False)
    submitter = uuid.uuid4()
    _approve(db, submitter)  # the submitter approving their own subject
    assert not _evaluate(db, submitter=submitter).satisfied  # self-approval excluded
    # A distinct approver satisfies it.
    _approve(db, uuid.uuid4())
    assert _evaluate(db, submitter=submitter).satisfied
