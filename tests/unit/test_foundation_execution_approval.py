"""Composition unit doubles; real standing/locks are proved only on hosted PG."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest

from vendor_cp.deployment import foundation_execution_approval as owner


def _plan(**changes):
    values = dict(
        id=uuid4(),
        target_id=uuid4(),
        purpose="foundation_execution",
        operation="deploy",
        execution_plan_digest="sha256:" + "ab" * 32,
        plan_digest="sha256:" + "cd" * 32,
        requires_approval=True,
        approval_policy_code="foundation",
        approval_policy_version=1,
        approval_decision_ref=str(uuid4()),
    )
    values.update(changes)
    return SimpleNamespace(**values)


@pytest.mark.parametrize(
    "change",
    [
        {"id": "not-a-uuid"},
        {"purpose": "rehearsal_issuer_operation"},
        {"operation": "recover"},
        {"operation": None},
        {"execution_plan_digest": "sha256:" + "AB" * 32},
        {"execution_plan_digest": None},
        {"plan_digest": "descriptor"},
        {"requires_approval": False},
        {"approval_policy_code": None},
        {"approval_policy_version": None},
    ],
)
def test_invalid_authority_coordinate_refuses(change):
    with pytest.raises(ValueError):
        owner.foundation_approval_subject(_plan(**change))


def test_subject_binds_each_execution_coordinate_but_content_is_separate():
    plan = _plan()
    subject = owner.foundation_approval_subject(plan)
    assert (
        subject
        == f"v1|{plan.id}|foundation_execution|deploy|{plan.execution_plan_digest}"
    )
    assert len(subject) <= 200
    for field, value in (
        ("id", uuid4()),
        ("operation", "rollback"),
        ("execution_plan_digest", "sha256:" + "ef" * 32),
    ):
        changed = SimpleNamespace(**{**vars(plan), field: value})
        assert owner.foundation_approval_subject(changed) != subject
    assert (
        owner.foundation_approval_subject(
            SimpleNamespace(**{**vars(plan), "plan_digest": "sha256:" + "ff" * 32})
        )
        == subject
    )


def _composition(monkeypatch, *, policy="foundation", version=1):
    plan = _plan()
    events = []
    held = SimpleNamespace(
        request_id=uuid4(),
        policy_code=policy,
        policy_version=version,
        decided_at=datetime(2026, 11, 7, tzinfo=UTC),
        approver_ids=(uuid4(),),
    )

    def hold(db, **kwargs):
        events.append(("hold", db, kwargs))
        assert kwargs["subject_type"] == owner.SUBJECT_TYPE
        assert kwargs["subject_id"] == owner.foundation_approval_subject(plan)
        assert kwargs["content_digest"] == plan.plan_digest
        return kwargs["transition"](held)

    def call(db, command=None, **kwargs):
        events.append(("control", db, command, kwargs))
        if command is not None and hasattr(command, "evidence"):
            plan.approval_decision_ref = str(held.request_id)
        if command is not None and hasattr(command, "rollout_ref"):
            return SimpleNamespace(plan_id=plan.id, rollout_ref=command.rollout_ref)
        return plan

    control = SimpleNamespace(
        get_plan=lambda *_: plan,
        approve_plan=call,
        request_rollout=call,
        dispatch_attempt=call,
        admit_and_consume_host_admission=call,
        get_rollout=lambda *_: SimpleNamespace(plan_id=plan.id),
        ApprovePlanCommand=SimpleNamespace,
        ApprovalEvidence=SimpleNamespace,
        RequestRolloutCommand=SimpleNamespace,
    )
    monkeypatch.setattr(owner, "import_module", lambda _: control)
    monkeypatch.setattr(owner, "held_transition", hold)
    return plan, held, events, control


def test_approval_evidence_comes_only_from_the_held_request(monkeypatch):
    plan, held, events, _ = _composition(monkeypatch)
    db = object()
    owner.approve_foundation_plan(
        db,
        command_id="approve",
        plan_id=plan.id,
        approval_request_id=held.request_id,
    )
    assert [event[0] for event in events] == ["hold", "control"]
    evidence = events[1][2].evidence
    assert evidence.decision_ref == str(held.request_id)
    assert evidence.content_digest == plan.plan_digest
    assert evidence.execution_plan_digest == plan.execution_plan_digest
    assert evidence.decided_at == held.decided_at
    assert evidence.approver_refs == tuple(map(str, held.approver_ids))
    assert events[0][1] is events[1][1] is db


@pytest.mark.parametrize("policy,version", [("different", 1), ("foundation", 2)])
def test_wrong_held_policy_refuses_before_control(monkeypatch, policy, version):
    plan, held, events, _ = _composition(monkeypatch, policy=policy, version=version)
    with pytest.raises(ValueError, match="policy"):
        owner.approve_foundation_plan(
            object(),
            command_id="approve",
            plan_id=plan.id,
            approval_request_id=held.request_id,
        )
    assert [event[0] for event in events] == ["hold"]


@pytest.mark.parametrize("operation", ["rollout", "dispatch", "finalize"])
def test_consumers_derive_request_from_control_plan(monkeypatch, operation):
    plan, _, events, _ = _composition(monkeypatch)
    db = object()
    if operation == "rollout":
        owner.request_foundation_rollout(
            db,
            command_id="rollout",
            plan_id=plan.id,
            rollout_ref="rollout",
            authorization_expires_at=datetime.now(UTC),
            signer=object(),
        )
    elif operation == "dispatch":
        owner.dispatch_foundation_attempt(
            db,
            command_id="dispatch",
            rollout_id=uuid4(),
            verifier=object(),
            dispatch_signer=object(),
        )
    else:
        owner.finalize_foundation_dispatch(
            db,
            context=object(),
            foreign_evidence=object(),
            execution=SimpleNamespace(
                expected_context=SimpleNamespace(plan_id=str(plan.id))
            ),
        )
    assert str(events[0][2]["request_id"]) == plan.approval_decision_ref
    assert [event[0] for event in events] == ["hold", "control"]


@pytest.mark.parametrize("reference", [None, "apr-invented", ""])
def test_invented_approval_reference_cannot_reach_hold(monkeypatch, reference):
    plan, _, events, _ = _composition(monkeypatch)
    plan.approval_decision_ref = reference
    with pytest.raises(ValueError, match="genuine approval"):
        owner.finalize_foundation_dispatch(
            object(),
            context=object(),
            foreign_evidence=object(),
            execution=SimpleNamespace(
                expected_context=SimpleNamespace(plan_id=str(plan.id))
            ),
        )
    assert events == []


def test_unsupported_proposal_is_refused_before_owner_mutation(monkeypatch):
    monkeypatch.setattr(owner, "import_module", lambda _: object())
    request = owner.ProposeFoundationPlan(
        command_id="proposal",
        target_id=uuid4(),
        operation="recover",
        descriptor_digest="sha256:" + "aa" * 32,
        execution_plan_digest="sha256:" + "bb" * 32,
        approval_policy_code="foundation",
        approval_policy_version=1,
    )
    with pytest.raises(ValueError, match="unsupported"):
        owner.propose_foundation_plan(object(), request)
    with pytest.raises(ValueError):
        owner.propose_foundation_plan(
            object(), replace(request, operation="deploy", execution_plan_digest="bad")
        )
