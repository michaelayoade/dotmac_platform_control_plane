"""Fast source contract for the successor composition before wheels exist."""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from types import ModuleType, SimpleNamespace
from uuid import UUID

import pytest
from dotmac_kernel.messaging import ClaimedPlatformEvent

from vendor_cp.deployment import protected_rehearsal_issuer as issuer
from vendor_cp.deployment.rehearsal_issuer_seam import (
    RehearsalIssuerCommand,
    RehearsalIssuerInvocation,
)

PLAN_ID = UUID("10000000-0000-0000-0000-000000000001")
REQUEST_ID = UUID("20000000-0000-0000-0000-000000000002")
WITHDRAWAL_ID = UUID("30000000-0000-0000-0000-000000000003")
EXECUTION = "sha256:" + "a" * 64
PLAN_DIGEST = "sha256:" + "b" * 64


class Command(SimpleNamespace):
    pass


@pytest.fixture
def ports(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    plan = SimpleNamespace(
        id=PLAN_ID,
        target_id=UUID("40000000-0000-0000-0000-000000000004"),
        purpose=issuer.PLAN_PURPOSE,
        operation=issuer.ISSUER_OPERATION,
        execution_plan_digest=EXECUTION,
        plan_digest=PLAN_DIGEST,
        approval_policy_code="issuer-approval",
        approval_policy_version=2,
        approval_decision_ref=str(REQUEST_ID),
    )
    calls: list[tuple[str, object]] = []
    control = ModuleType("dotmac_deployment_control")
    control.ProposePlanCommand = Command  # type: ignore[attr-defined]
    control.ApprovePlanCommand = Command  # type: ignore[attr-defined]
    control.ApprovalEvidence = Command  # type: ignore[attr-defined]
    control.RevokePlanApprovalCommand = Command  # type: ignore[attr-defined]
    control.get_plan = lambda db, plan_id: plan if plan_id == PLAN_ID else None  # type: ignore[attr-defined]
    control.propose_plan = lambda db, cmd: (calls.append(("propose", cmd)), plan)[1]  # type: ignore[attr-defined]
    control.approve_plan = lambda db, cmd: (calls.append(("approve", cmd)), plan)[1]  # type: ignore[attr-defined]
    revoked_commands: set[str] = set()

    def revoke(db: object, command: Command) -> object:
        if command.command_id not in revoked_commands:
            revoked_commands.add(command.command_id)
            calls.append(("revoke", command))
        return plan

    control.revoke_plan_approval = revoke  # type: ignore[attr-defined]
    control.issue_rehearsal_issuer_authorization_for_plan = (  # type: ignore[attr-defined]
        lambda db, request, *, harness_evidence_document: calls.append(
            ("issue", (request, harness_evidence_document))
        )
    )
    approvals = ModuleType("vendor_cp.approvals.adapter")
    approvals.OpenRequestCommand = Command  # type: ignore[attr-defined]
    approvals.open_request = lambda db, cmd: calls.append(("open", cmd))  # type: ignore[attr-defined]
    approvals.approved_request_evidence = (  # type: ignore[attr-defined]
        lambda db, **kwargs: (
            calls.append(("evidence", kwargs)),
            SimpleNamespace(
                policy_code="issuer-approval",
                policy_version=2,
                request_id=REQUEST_ID,
                decided_at=datetime(2026, 9, 25, tzinfo=UTC),
                approver_refs=("approver-1",),
            ),
        )[1]
    )
    authority = ModuleType("vendor_cp.approvals_authority")
    authority.bare_content_hash = lambda digest: digest.removeprefix("sha256:")  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, control.__name__, control)
    monkeypatch.setitem(sys.modules, approvals.__name__, approvals)
    monkeypatch.setitem(sys.modules, authority.__name__, authority)
    return SimpleNamespace(plan=plan, calls=calls)


def test_proposal_and_approval_bind_exact_upstream_terms(
    ports: SimpleNamespace,
) -> None:
    db = object()
    request = issuer.ProposeIssuerPlan(
        "propose-1",
        ports.plan.target_id,
        "sha256:" + "c" * 64,
        EXECUTION,
        "issuer-approval",
        2,
    )
    issuer.propose_issuer_plan(db, request)
    proposed = ports.calls[-1][1]
    assert vars(proposed) == {
        "command_id": "propose-1",
        "target_id": ports.plan.target_id,
        "operation": "deploy",
        "descriptor_digest": request.descriptor_digest,
        "execution_plan_digest": EXECUTION,
        "purpose": "rehearsal_issuer_operation",
        "requires_approval": True,
        "approval_policy_code": "issuer-approval",
        "approval_policy_version": 2,
        "expected_desired_revision": None,
        "actor_ref": None,
    }
    issuer.open_issuer_approval(
        db, command_id="open-1", plan_id=PLAN_ID, requested_by=REQUEST_ID
    )
    opened = ports.calls[-1][1]
    assert opened.subject_type == "rehearsal_issuer_plan.v1"
    assert opened.subject_id == (
        f"v1|{PLAN_ID}|rehearsal_issuer_operation|deploy|{EXECUTION}"
    )
    assert opened.content_hash == "b" * 64
    issuer.approve_issuer_plan(
        db,
        command_id="approve-1",
        plan_id=PLAN_ID,
        approval_request_id=REQUEST_ID,
    )
    approved = ports.calls[-1][1]
    assert vars(approved.evidence) == {
        "policy_code": "issuer-approval",
        "policy_version": 2,
        "decision_ref": str(REQUEST_ID),
        "content_digest": PLAN_DIGEST,
        "decided_at": datetime(2026, 9, 25, tzinfo=UTC),
        "approver_refs": ("approver-1",),
        "decision_status": "granted",
        "operation": "deploy",
        "execution_plan_digest": EXECUTION,
    }
    assert [name for name, _ in ports.calls] == [
        "propose",
        "open",
        "evidence",
        "approve",
    ]


@pytest.mark.parametrize("field", ["purpose", "operation", "execution_plan_digest"])
def test_mutated_approval_subject_is_refused(
    ports: SimpleNamespace, field: str
) -> None:
    setattr(ports.plan, field, "wrong")
    with pytest.raises(ValueError):
        issuer.open_issuer_approval(
            object(), command_id="open", plan_id=PLAN_ID, requested_by=REQUEST_ID
        )
    assert ports.calls == []


def test_issuance_carries_only_existing_seam_fields(ports: SimpleNamespace) -> None:
    evidence = object()
    invocation = RehearsalIssuerInvocation(
        RehearsalIssuerCommand("issue-1", PLAN_ID), evidence
    )
    issuer.issue_authorization(object(), invocation)
    assert ports.calls == [
        ("issue", ({"command_id": "issue-1", "plan_id": PLAN_ID}, evidence))
    ]


def _withdrawal(ports: SimpleNamespace) -> dict[str, object]:
    return {
        "state": "withdrawn",
        "subject_type": issuer.SUBJECT_TYPE,
        "subject_id": issuer._subject(ports.plan),
        "content_digest": PLAN_DIGEST,
        "policy_code": "issuer-approval",
        "policy_version": 2,
        "request_id": str(REQUEST_ID),
        "withdrawal_id": str(WITHDRAWAL_ID),
        "reason": "approval withdrawn",
    }


def _claimed(
    payload: dict[str, object], *, id: UUID = WITHDRAWAL_ID
) -> ClaimedPlatformEvent:
    return ClaimedPlatformEvent(
        id=id,
        event_type="approval.withdrawn",
        payload=payload,
        attempts=0,
        correlation_id=None,
    )


def test_withdrawal_replay_uses_one_stable_control_command(
    ports: SimpleNamespace,
) -> None:
    event = _withdrawal(ports)
    for _ in range(2):
        issuer.ApprovalWithdrawalConsumer().deliver(_claimed(event), object())
    commands = [command for name, command in ports.calls if name == "revoke"]
    assert len(commands) == 1
    assert commands[0].revocation_ref == f"approval.withdrawn:{WITHDRAWAL_ID}"


@pytest.mark.parametrize(
    "field",
    ["subject_id", "content_digest", "request_id", "policy_code", "policy_version"],
)
def test_withdrawal_must_match_frozen_control_plan(
    ports: SimpleNamespace, field: str
) -> None:
    event = _withdrawal(ports)
    event[field] = "wrong"
    with pytest.raises(ValueError):
        issuer.ApprovalWithdrawalConsumer().deliver(_claimed(event), object())
    assert ports.calls == []


def test_withdrawal_id_must_be_the_claimed_outbox_row(
    ports: SimpleNamespace,
) -> None:
    with pytest.raises(ValueError, match="claimed outbox row"):
        issuer.ApprovalWithdrawalConsumer().deliver(
            _claimed(
                _withdrawal(ports), id=UUID("50000000-0000-0000-0000-000000000005")
            ),
            object(),
        )
    assert ports.calls == []


def test_other_platform_events_do_not_load_successor_control(
    ports: SimpleNamespace,
) -> None:
    consumer = issuer.ApprovalWithdrawalConsumer()
    consumer.deliver(
        ClaimedPlatformEvent(WITHDRAWAL_ID, "contract.activated", {}, 0, None),
        object(),
    )
    unrelated = _withdrawal(ports)
    unrelated["subject_type"] = "another.subject.v1"
    consumer.deliver(_claimed(unrelated), object())
    assert ports.calls == []
