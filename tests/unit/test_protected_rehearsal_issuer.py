"""Fast source contract for the successor composition before wheels exist."""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from enum import StrEnum
from types import ModuleType, SimpleNamespace
from uuid import UUID

import pytest
from dotmac_kernel.messaging import ClaimedPlatformEvent

from vendor_cp.deployment import approval_barrier
from vendor_cp.deployment import protected_rehearsal_issuer as issuer
from vendor_cp.deployment.issuer_receipts import (
    APPROVE_PLAN,
    ISSUE_AUTHORIZATION,
    request_fingerprint,
)
from vendor_cp.deployment.rehearsal_issuer_seam import (
    RehearsalIssuerCommand,
    RehearsalIssuerInvocation,
)


class FakeApprovalHoldRefusal(StrEnum):
    """Stand-in for `dotmac_approvals.ApprovalHoldRefusal` -- same seven
    members, so `exc.code is ApprovalHoldRefusal.WITHDRAWN` in
    `protected_rehearsal_issuer.py` can be exercised without the real wheel."""

    MALFORMED_DIGEST = "malformed_digest"
    REQUEST_NOT_FOUND = "request_not_found"
    SUBJECT_MISMATCH = "subject_mismatch"
    DIGEST_MISMATCH = "digest_mismatch"
    WITHDRAWN = "withdrawn"
    NOT_APPROVED = "not_approved"
    NO_APPROVE_DECISION = "no_approve_decision"


PLAN_ID = UUID("10000000-0000-0000-0000-000000000001")
REQUEST_ID = UUID("20000000-0000-0000-0000-000000000002")
WITHDRAWAL_ID = UUID("30000000-0000-0000-0000-000000000003")
EXECUTION = "sha256:" + "a" * 64
PLAN_DIGEST = "sha256:" + "b" * 64


class Command(SimpleNamespace):
    pass


APPROVER_ID = UUID("60000000-0000-0000-0000-000000000006")


class FakeApprovalNotHeld(Exception):
    """Stand-in for `dotmac_approvals.ApprovalNotHeld` (code + message)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


#: A JSON-native harness evidence document, the shape the real harness emits
#: (`rehearsal_issuer_harness/security.py::document()` returns a plain dict);
#: the issuance fingerprint refuses anything it cannot digest canonically.
_EVIDENCE: dict[str, object] = {"schema": "test-harness-evidence", "lease": "L-1"}


class FakeRehearsalIssuerIssuanceRefusalCode(StrEnum):
    """Stand-in for `dotmac_deployment_control.RehearsalIssuerIssuanceRefusalCode`
    -- only the two members `classify_approval_withdrawal` distinguishes."""

    NOT_REVOCABLE = "rehearsal_issuer_issuance_not_revocable"
    NOT_RECORDED = "rehearsal_issuer_issuance_not_recorded"


class FakeRehearsalIssuerIssuanceRefusedError(Exception):
    """Stand-in for `dotmac_deployment_control.RehearsalIssuerIssuanceRefusedError`
    (code + message), the shape `revoke_rehearsal_issuer_authorization` and
    `stage_rehearsal_issuer_consumption` raise. The message format
    (`f"{code}: {detail}"`) matches the real error
    (`rehearsal_issuer_issuance.py:191`) exactly -- an earlier version of this
    fake used a bare `detail`, which hid that `_revoke_issued_authorizations`'
    `str(exc)` embeds the code in the recorded `detail` field against the
    real error too."""

    def __init__(
        self, code: FakeRehearsalIssuerIssuanceRefusalCode, detail: str
    ) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code


@pytest.fixture(autouse=True)
def _no_receipt_store(monkeypatch: pytest.MonkeyPatch) -> None:
    """These seam tests pass a bare stand-in session; the receipt store (its
    own unit and real-PG tests cover it) is replaced with an empty one here."""
    from vendor_cp.deployment import issuer_receipts

    monkeypatch.setattr(issuer_receipts, "find_receipt", lambda db, command_id: None)
    monkeypatch.setattr(issuer_receipts, "record_receipt", lambda db, **kwargs: None)
    monkeypatch.setattr(
        issuer_receipts, "issued_authorization_refs", lambda db, plan_id: ()
    )


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
        status="approved",
        approval_decision_status="granted",
        approval_revocation_ref=None,
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

    class FakeTransitionRefusedError(Exception):
        pass

    class FakeExpectedStateError(Exception):
        def __init__(self, subject_ref: str, **kwargs: object) -> None:
            super().__init__(subject_ref)
            self.actual_status = kwargs["actual_status"]

    control.TransitionRefusedError = FakeTransitionRefusedError  # type: ignore[attr-defined]
    control.ExpectedStateError = FakeExpectedStateError  # type: ignore[attr-defined]

    def issue(
        db: object, request: dict[str, object], *, harness_evidence_document: object
    ) -> object:
        calls.append(("issue", (request, harness_evidence_document)))
        # Control's issuance result carries its authorization id on
        # `statement`; the seam records that id (never the envelope).
        return SimpleNamespace(statement=SimpleNamespace(authorization_id="auth-1"))

    control.issue_rehearsal_issuer_authorization_for_plan = issue  # type: ignore[attr-defined]
    control.RehearsalIssuerIssuanceRefusalCode = (  # type: ignore[attr-defined]
        FakeRehearsalIssuerIssuanceRefusalCode
    )
    control.RehearsalIssuerIssuanceRefusedError = (  # type: ignore[attr-defined]
        FakeRehearsalIssuerIssuanceRefusedError
    )

    #: `{authorization_id: (code, detail)}` -- set by a test to make ONE
    #: authorization's revocation refuse; every other id succeeds.
    revoke_refusals: dict[str, tuple[FakeRehearsalIssuerIssuanceRefusalCode, str]] = {}

    def revoke_authorization(
        db: object,
        *,
        authorization_id: str,
        revocation_ref: str,
        actor_ref: str | None = None,
    ) -> None:
        calls.append(
            (
                "revoke_authorization",
                SimpleNamespace(
                    authorization_id=authorization_id,
                    revocation_ref=revocation_ref,
                    actor_ref=actor_ref,
                ),
            )
        )
        if authorization_id in revoke_refusals:
            code, detail = revoke_refusals[authorization_id]
            raise FakeRehearsalIssuerIssuanceRefusedError(code, detail)

    control.revoke_rehearsal_issuer_authorization = revoke_authorization  # type: ignore[attr-defined]

    def stage_consumption(
        db: object, *, authorization_document: object, harness_evidence_document: object
    ) -> object:
        calls.append(("consume", (authorization_document, harness_evidence_document)))
        return SimpleNamespace(
            authorization_id="auth-1",
            single_use_reference="ref-1",
            lease_id="lease-1",
        )

    control.stage_rehearsal_issuer_consumption = stage_consumption  # type: ignore[attr-defined]

    def fake_parse_authorization(value: object) -> SimpleNamespace:
        """Stand-in for `RehearsalIssuerAuthorizationV1.parse`: reads
        `value["statement"]`, defaulting a missing `immutable_reference` to
        `None` (an absent field is a mismatch, not an attribute error)."""
        raw_statement = value.get("statement") if isinstance(value, dict) else None
        statement = dict(raw_statement) if isinstance(raw_statement, dict) else {}
        statement.setdefault("immutable_reference", None)
        return SimpleNamespace(statement=SimpleNamespace(**statement))

    control.RehearsalIssuerAuthorizationV1 = SimpleNamespace(  # type: ignore[attr-defined]
        parse=fake_parse_authorization
    )
    approvals = ModuleType("vendor_cp.approvals.adapter")
    approvals.ApprovalHoldRefusal = FakeApprovalHoldRefusal  # type: ignore[attr-defined]
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

    hold_refusal: dict[str, str] = {}

    def hold_platform_approval(
        db: object,
        *,
        request_id: UUID,
        subject_type: str,
        subject_id: str,
        content_digest: str,
    ) -> SimpleNamespace:
        calls.append(
            (
                "hold",
                {
                    "request_id": request_id,
                    "subject_type": subject_type,
                    "subject_id": subject_id,
                    "content_digest": content_digest,
                },
            )
        )
        if hold_refusal:
            raise FakeApprovalNotHeld(hold_refusal["code"], hold_refusal["message"])
        return SimpleNamespace(
            request_id=request_id,
            subject_type=subject_type,
            subject_id=subject_id,
            content_digest=content_digest,
            policy_code="issuer-approval",
            policy_version=2,
            decided_at=datetime(2026, 9, 25, tzinfo=UTC),
            approver_ids=(APPROVER_ID,),
        )

    dotmac_approvals = ModuleType("dotmac_approvals")
    dotmac_approvals.ApprovalNotHeld = FakeApprovalNotHeld  # type: ignore[attr-defined]
    approvals.hold_approval = hold_platform_approval  # type: ignore[attr-defined]
    approvals.ApprovalNotHeld = FakeApprovalNotHeld  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, control.__name__, control)
    monkeypatch.setitem(sys.modules, approvals.__name__, approvals)
    monkeypatch.setitem(sys.modules, authority.__name__, authority)
    monkeypatch.setitem(sys.modules, dotmac_approvals.__name__, dotmac_approvals)
    # These fakes are not SQLAlchemy sessions; the AUTOCOMMIT refusal is
    # proved on its own below and against real PostgreSQL.
    monkeypatch.setattr(approval_barrier, "_require_transactional", lambda _db: None)
    monkeypatch.setattr(
        approval_barrier, "_require_the_hold_is_still_open", lambda _db: None
    )
    return SimpleNamespace(
        plan=plan,
        calls=calls,
        control=control,
        hold_refusal=hold_refusal,
        revoke_refusals=revoke_refusals,
    )


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
    held, approved = ports.calls[-2], ports.calls[-1]
    assert held == (
        "hold",
        {
            "request_id": REQUEST_ID,
            "subject_type": issuer.SUBJECT_TYPE,
            "subject_id": issuer._subject(ports.plan),
            "content_digest": PLAN_DIGEST,
        },
    )
    assert vars(approved[1].evidence) == {
        "policy_code": "issuer-approval",
        "policy_version": 2,
        "decision_ref": str(REQUEST_ID),
        "content_digest": PLAN_DIGEST,
        "decided_at": datetime(2026, 9, 25, tzinfo=UTC),
        "approver_refs": (str(APPROVER_ID),),
        "decision_status": "granted",
        "operation": "deploy",
        "execution_plan_digest": EXECUTION,
    }
    assert [name for name, _ in ports.calls] == [
        "propose",
        "open",
        "hold",
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
    evidence = dict(_EVIDENCE)
    invocation = RehearsalIssuerInvocation(
        RehearsalIssuerCommand("issue-1", PLAN_ID), evidence
    )
    issuer.issue_authorization(object(), invocation)
    assert ports.calls == [
        (
            "hold",
            {
                "request_id": REQUEST_ID,
                "subject_type": issuer.SUBJECT_TYPE,
                "subject_id": issuer._subject(ports.plan),
                "content_digest": PLAN_DIGEST,
            },
        ),
        ("issue", ({"command_id": "issue-1", "plan_id": PLAN_ID}, evidence)),
    ]


def test_issuance_derives_request_id_only_from_the_frozen_plan(
    ports: SimpleNamespace,
) -> None:
    """`RehearsalIssuerCommand`/`Invocation` carry no request id at all — the
    hold's `request_id` can only come from `plan.approval_decision_ref`."""
    other_request_id = UUID("80000000-0000-0000-0000-000000000008")
    ports.plan.approval_decision_ref = str(other_request_id)
    invocation = RehearsalIssuerInvocation(
        RehearsalIssuerCommand("issue-1", PLAN_ID), dict(_EVIDENCE)
    )
    issuer.issue_authorization(object(), invocation)
    held = ports.calls[0]
    assert held[0] == "hold"
    assert held[1]["request_id"] == other_request_id


def test_issuance_refuses_without_a_recorded_approval_decision(
    ports: SimpleNamespace,
) -> None:
    ports.plan.approval_decision_ref = None
    invocation = RehearsalIssuerInvocation(
        RehearsalIssuerCommand("issue-1", PLAN_ID), dict(_EVIDENCE)
    )
    with pytest.raises(ValueError, match="no recorded approval decision"):
        issuer.issue_authorization(object(), invocation)
    assert ports.calls == []


def test_issuance_refuses_a_malformed_approval_decision_ref(
    ports: SimpleNamespace,
) -> None:
    ports.plan.approval_decision_ref = "not-a-uuid"
    invocation = RehearsalIssuerInvocation(
        RehearsalIssuerCommand("issue-1", PLAN_ID), dict(_EVIDENCE)
    )
    with pytest.raises(ValueError, match="is not a UUID"):
        issuer.issue_authorization(object(), invocation)
    assert ports.calls == []


def test_issuance_reread_mismatch_after_a_concurrent_change_raises(
    ports: SimpleNamespace,
) -> None:
    """Simulate a projection landing between issuance and the re-read: the
    window `held_transition`'s re-read check is meant to close."""

    def issue_and_mutate(
        db: object, request: dict[str, object], *, harness_evidence_document: object
    ) -> object:
        ports.plan.approval_decision_ref = str(
            UUID("90000000-0000-0000-0000-000000000009")
        )
        return SimpleNamespace(statement=SimpleNamespace(authorization_id="auth-1"))

    ports.control.issue_rehearsal_issuer_authorization_for_plan = issue_and_mutate
    invocation = RehearsalIssuerInvocation(
        RehearsalIssuerCommand("issue-1", PLAN_ID), dict(_EVIDENCE)
    )
    with pytest.raises(ValueError, match="approval standing changed"):
        issuer.issue_authorization(object(), invocation)


def test_approval_not_held_refusal_means_control_never_sees_approve(
    ports: SimpleNamespace,
) -> None:
    ports.hold_refusal["code"] = "withdrawn"
    ports.hold_refusal["message"] = "withdrawn"
    with pytest.raises(FakeApprovalNotHeld):
        issuer.approve_issuer_plan(
            object(),
            command_id="approve-1",
            plan_id=PLAN_ID,
            approval_request_id=REQUEST_ID,
        )
    assert [name for name, _ in ports.calls] == ["hold"]


def test_approval_not_held_refusal_means_control_never_sees_issuance(
    ports: SimpleNamespace,
) -> None:
    ports.hold_refusal["code"] = "withdrawn"
    ports.hold_refusal["message"] = "withdrawn"
    invocation = RehearsalIssuerInvocation(
        RehearsalIssuerCommand("issue-1", PLAN_ID), dict(_EVIDENCE)
    )
    with pytest.raises(FakeApprovalNotHeld):
        issuer.issue_authorization(object(), invocation)
    assert [name for name, _ in ports.calls] == ["hold"]


# ── fix 4: only a WITHDRAWN hold refusal is translated ───────────────────────


def test_a_non_withdrawn_hold_refusal_propagates_even_with_a_receipt_present_on_approve(
    ports: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SENSITIVITY (near-miss) for fix 4: a receipt exists (a genuine retry of
    an already-committed command), but the hold's refusal is NOT_APPROVED, not
    WITHDRAWN. It must propagate unchanged rather than being reported as
    `IssuerCommandCommittedButWithdrawn` -- overriding the autouse
    `_no_receipt_store` fixture with a store that returns a matching receipt.
    """
    from vendor_cp.deployment import issuer_receipts

    fingerprint = request_fingerprint(
        APPROVE_PLAN,
        {
            "command_id": "approve-1",
            "plan_id": PLAN_ID,
            "approval_request_id": REQUEST_ID,
            "expected_plan_version": None,
            "actor_ref": None,
        },
    )
    receipt = SimpleNamespace(
        verb=APPROVE_PLAN,
        request_fingerprint=fingerprint,
        plan_id=PLAN_ID,
        approval_request_id=REQUEST_ID,
        control_ref=str(PLAN_ID),
    )
    monkeypatch.setattr(issuer_receipts, "find_receipt", lambda db, command_id: receipt)
    ports.hold_refusal["code"] = FakeApprovalHoldRefusal.NOT_APPROVED
    ports.hold_refusal["message"] = "not approved"

    with pytest.raises(FakeApprovalNotHeld) as excinfo:
        issuer.approve_issuer_plan(
            object(),
            command_id="approve-1",
            plan_id=PLAN_ID,
            approval_request_id=REQUEST_ID,
        )
    assert not isinstance(
        excinfo.value, issuer_receipts.IssuerCommandCommittedButWithdrawn
    )


def test_a_non_withdrawn_hold_refusal_propagates_with_a_receipt_present_on_issuance(
    ports: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same sensitivity as above, at the issuance call site."""
    from vendor_cp.deployment import issuer_receipts

    evidence = b"placeholder"
    fingerprint = request_fingerprint(
        ISSUE_AUTHORIZATION,
        {
            "command_id": "issue-1",
            "plan_id": PLAN_ID,
            "harness_evidence_digest": issuer._evidence_digest(b"placeholder"),
        },
    )
    receipt = SimpleNamespace(
        verb=ISSUE_AUTHORIZATION,
        request_fingerprint=fingerprint,
        plan_id=PLAN_ID,
        approval_request_id=REQUEST_ID,
        control_ref="auth-0",
    )
    monkeypatch.setattr(issuer_receipts, "find_receipt", lambda db, command_id: receipt)
    ports.hold_refusal["code"] = FakeApprovalHoldRefusal.NOT_APPROVED
    ports.hold_refusal["message"] = "not approved"
    invocation = RehearsalIssuerInvocation(
        RehearsalIssuerCommand("issue-1", PLAN_ID), evidence
    )

    with pytest.raises(FakeApprovalNotHeld):
        issuer.issue_authorization(object(), invocation)


# ── D18-C: the in-hold fingerprint branch, deterministically ────────────────


def test_approve_in_hold_fingerprint_mismatch_raises_issuer_command_reused(
    ports: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`find_receipt` answers `None` on its FIRST call (the pre-hold check,
    which must therefore let this request through) and a receipt with a
    DIFFERENT fingerprint on its SECOND call, made from inside
    `transition()` after Control's `approve_plan` has already run. That
    second call is the branch this test pins: `approve_issuer_plan` must
    raise `IssuerCommandReused` from inside the hold, not treat the
    disagreeing receipt as its own."""
    from vendor_cp.deployment import issuer_receipts

    command_id = "approve-1"
    different_fingerprint = request_fingerprint(
        APPROVE_PLAN,
        {
            "command_id": command_id,
            "plan_id": PLAN_ID,
            "approval_request_id": REQUEST_ID,
            "expected_plan_version": None,
            "actor_ref": "someone-else",
        },
    )
    receipt = SimpleNamespace(
        verb=APPROVE_PLAN,
        request_fingerprint=different_fingerprint,
        plan_id=PLAN_ID,
        approval_request_id=REQUEST_ID,
        control_ref=str(PLAN_ID),
    )
    calls = {"n": 0}

    def fake_find_receipt(db: object, command_id: str) -> object | None:
        calls["n"] += 1
        return None if calls["n"] == 1 else receipt

    monkeypatch.setattr(issuer_receipts, "find_receipt", fake_find_receipt)

    with pytest.raises(issuer_receipts.IssuerCommandReused):
        issuer.approve_issuer_plan(
            object(),
            command_id=command_id,
            plan_id=PLAN_ID,
            approval_request_id=REQUEST_ID,
        )
    assert calls["n"] == 2, "the in-hold branch must re-check find_receipt"
    assert [name for name, _ in ports.calls] == ["hold", "approve"]


def test_issuance_in_hold_fingerprint_mismatch_raises_issuer_command_reused(
    ports: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The issuance equivalent of the test above, using the file's own dict
    harness evidence document (`_EVIDENCE`)."""
    from vendor_cp.deployment import issuer_receipts

    command_id = "issue-1"
    evidence = dict(_EVIDENCE)
    different_evidence = {**_EVIDENCE, "lease": "L-2"}
    different_fingerprint = request_fingerprint(
        ISSUE_AUTHORIZATION,
        {
            "command_id": command_id,
            "plan_id": PLAN_ID,
            "harness_evidence_digest": issuer._evidence_digest(different_evidence),
        },
    )
    receipt = SimpleNamespace(
        verb=ISSUE_AUTHORIZATION,
        request_fingerprint=different_fingerprint,
        plan_id=PLAN_ID,
        approval_request_id=REQUEST_ID,
        control_ref="auth-0",
    )
    calls = {"n": 0}

    def fake_find_receipt(db: object, command_id: str) -> object | None:
        calls["n"] += 1
        return None if calls["n"] == 1 else receipt

    monkeypatch.setattr(issuer_receipts, "find_receipt", fake_find_receipt)
    invocation = RehearsalIssuerInvocation(
        RehearsalIssuerCommand(command_id, PLAN_ID), evidence
    )

    with pytest.raises(issuer_receipts.IssuerCommandReused):
        issuer.issue_authorization(object(), invocation)
    assert calls["n"] == 2, "the in-hold branch must re-check find_receipt"
    assert [name for name, _ in ports.calls] == ["hold", "issue"]


# ── fix 3: the issuance fingerprint covers the harness evidence ─────────────


def test_evidence_digest_changes_when_the_document_changes() -> None:
    a = issuer._evidence_digest({"lease_id": "lease-1"})
    b = issuer._evidence_digest({"lease_id": "lease-2"})
    assert a != b
    assert a.startswith("sha256:")


def test_evidence_digest_is_key_order_insensitive_for_a_mapping() -> None:
    a = issuer._evidence_digest({"a": 1, "b": 2})
    b = issuer._evidence_digest({"b": 2, "a": 1})
    assert a == b


def test_evidence_digest_raises_on_an_unrecognised_type() -> None:
    with pytest.raises(TypeError):
        issuer._evidence_digest(object())
    with pytest.raises(TypeError):
        issuer._evidence_digest(12345)


# ── D18-D: consume_authorization, the seam under the barrier ────────────────


def test_consume_authorization_goes_through_held_transition(
    ports: SimpleNamespace,
) -> None:
    document = {
        "statement": {
            "authorization_id": "auth-1",
            "immutable_reference": str(PLAN_ID),
        }
    }
    evidence = {"lease": "L-2"}
    result = issuer.consume_authorization(
        object(),
        plan_id=PLAN_ID,
        authorization_document=document,
        harness_evidence_document=evidence,
    )
    assert ports.calls == [
        (
            "hold",
            {
                "request_id": REQUEST_ID,
                "subject_type": issuer.SUBJECT_TYPE,
                "subject_id": issuer._subject(ports.plan),
                "content_digest": PLAN_DIGEST,
            },
        ),
        ("consume", (document, evidence)),
    ]
    assert result.authorization_id == "auth-1"


def test_consume_authorization_derives_request_id_only_from_the_frozen_plan(
    ports: SimpleNamespace,
) -> None:
    """The documents carry no request id at all -- the hold's `request_id`
    can only come from `plan.approval_decision_ref`, exactly like issuance."""
    other_request_id = UUID("80000000-0000-0000-0000-000000000008")
    ports.plan.approval_decision_ref = str(other_request_id)
    issuer.consume_authorization(
        object(),
        plan_id=PLAN_ID,
        authorization_document={"statement": {"immutable_reference": str(PLAN_ID)}},
        harness_evidence_document={},
    )
    held = ports.calls[0]
    assert held[0] == "hold"
    assert held[1]["request_id"] == other_request_id


def test_consume_authorization_refused_by_a_withdrawn_hold_never_reaches_control(
    ports: SimpleNamespace,
) -> None:
    ports.hold_refusal["code"] = "withdrawn"
    ports.hold_refusal["message"] = "withdrawn"
    with pytest.raises(FakeApprovalNotHeld):
        issuer.consume_authorization(
            object(),
            plan_id=PLAN_ID,
            authorization_document={"statement": {"immutable_reference": str(PLAN_ID)}},
            harness_evidence_document={},
        )
    assert [name for name, _ in ports.calls] == ["hold"]


# ── fix 1: consumption binds to the DOCUMENT's own plan, not the caller's ──


def test_consume_authorization_refuses_a_document_naming_a_different_plan(
    ports: SimpleNamespace,
) -> None:
    """The failure this fix closes: P2's authorization document is presented
    under `plan_id=P1` (P1's hold, standing or not, must never apply to P2's
    authority). Neither `held_transition` (no "hold" call) nor Control's
    consumption call may be reached."""
    other_plan_id = UUID("70000000-0000-0000-0000-000000000007")
    document = {"statement": {"immutable_reference": str(other_plan_id)}}

    with pytest.raises(issuer.AuthorizationPlanMismatch) as excinfo:
        issuer.consume_authorization(
            object(),
            plan_id=PLAN_ID,
            authorization_document=document,
            harness_evidence_document={},
        )
    assert excinfo.value.plan_id == PLAN_ID
    assert excinfo.value.document_plan_ref == str(other_plan_id)
    assert ports.calls == []


def test_consume_authorization_accepts_a_document_naming_the_same_plan(
    ports: SimpleNamespace,
) -> None:
    """SENSITIVITY (near-miss): the identical shape, with the document's
    `immutable_reference` matching `plan_id`, must proceed normally."""
    document = {"statement": {"immutable_reference": str(PLAN_ID)}}
    issuer.consume_authorization(
        object(),
        plan_id=PLAN_ID,
        authorization_document=document,
        harness_evidence_document={},
    )
    assert [name for name, _ in ports.calls] == ["hold", "consume"]


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


def test_withdrawal_applies_and_revokes_with_a_stable_command_id(
    ports: SimpleNamespace,
) -> None:
    event = _withdrawal(ports)
    result = issuer.classify_approval_withdrawal(object(), _claimed(event))
    assert result.disposition == issuer.WithdrawalDisposition.APPLIED
    assert result.reason_code == "applied"
    commands = [command for name, command in ports.calls if name == "revoke"]
    assert len(commands) == 1
    assert commands[0].revocation_ref == f"approval.withdrawn:{WITHDRAWAL_ID}"


# ── D18-D: withdrawal invalidates issued, unconsumed authorizations ────────


def test_withdrawal_revokes_every_issued_authorization_for_the_plan(
    ports: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vendor_cp.deployment import issuer_receipts

    monkeypatch.setattr(
        issuer_receipts,
        "issued_authorization_refs",
        lambda db, plan_id: ("auth-1", "auth-2"),
    )
    result = issuer.classify_approval_withdrawal(object(), _claimed(_withdrawal(ports)))
    assert result.disposition == issuer.WithdrawalDisposition.APPLIED
    assert result.evidence == {
        "authorizations_revoked": ["auth-1", "auth-2"],
        "authorizations_not_revocable": [],
    }
    revocations = [
        command for name, command in ports.calls if name == "revoke_authorization"
    ]
    assert [c.authorization_id for c in revocations] == ["auth-1", "auth-2"]
    for command in revocations:
        assert command.revocation_ref == f"approval.withdrawn:{WITHDRAWAL_ID}"
        assert command.actor_ref is None


def test_a_not_revocable_authorization_is_recorded_and_history_preserved(
    ports: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SENSITIVITY: `auth-1` is already spent/revoked (`NOT_REVOCABLE`) --
    it must be reported as `not_revocable`, never raised, and `auth-2` (a
    genuinely revocable near-miss) must still be revoked in the same pass."""
    from vendor_cp.deployment import issuer_receipts

    monkeypatch.setattr(
        issuer_receipts,
        "issued_authorization_refs",
        lambda db, plan_id: ("auth-1", "auth-2"),
    )
    ports.revoke_refusals["auth-1"] = (
        FakeRehearsalIssuerIssuanceRefusalCode.NOT_REVOCABLE,
        "authorization auth-1 is spent, not issued",
    )
    result = issuer.classify_approval_withdrawal(object(), _claimed(_withdrawal(ports)))
    assert result.disposition == issuer.WithdrawalDisposition.APPLIED
    assert result.evidence == {
        "authorizations_revoked": ["auth-2"],
        "authorizations_not_revocable": ["auth-1"],
    }


def test_an_unexpected_authorization_refusal_is_a_security_conflict(
    ports: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vendor_cp.deployment import issuer_receipts

    monkeypatch.setattr(
        issuer_receipts, "issued_authorization_refs", lambda db, plan_id: ("auth-1",)
    )
    ports.revoke_refusals["auth-1"] = (
        FakeRehearsalIssuerIssuanceRefusalCode.NOT_RECORDED,
        "no ledger row for auth-1",
    )
    result = issuer.classify_approval_withdrawal(object(), _claimed(_withdrawal(ports)))
    assert result.disposition == issuer.WithdrawalDisposition.SECURITY_CONFLICT
    assert result.reason_code == "authorization_revocation_refused"
    assert result.evidence == {
        "authorizations_revoked": [],
        "authorizations_not_revocable": [],
        "authorization_conflicts": [
            {
                "authorization_id": "auth-1",
                "code": str(FakeRehearsalIssuerIssuanceRefusalCode.NOT_RECORDED),
                "detail": (
                    f"{FakeRehearsalIssuerIssuanceRefusalCode.NOT_RECORDED}: "
                    "no ledger row for auth-1"
                ),
            }
        ],
    }


def test_a_conflict_does_not_stop_the_revoke_loop_for_later_refs(
    ports: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fix 2: the FIRST unexpected refusal (auth-2) must not stop the loop --
    auth-1 and auth-3 are still revoked, and the security_conflict evidence
    names all three lists so repair sees exactly which ref remains."""
    from vendor_cp.deployment import issuer_receipts

    monkeypatch.setattr(
        issuer_receipts,
        "issued_authorization_refs",
        lambda db, plan_id: ("auth-1", "auth-2", "auth-3"),
    )
    ports.revoke_refusals["auth-2"] = (
        FakeRehearsalIssuerIssuanceRefusalCode.NOT_RECORDED,
        "no ledger row for auth-2",
    )
    result = issuer.classify_approval_withdrawal(object(), _claimed(_withdrawal(ports)))
    assert result.disposition == issuer.WithdrawalDisposition.SECURITY_CONFLICT
    assert result.reason_code == "authorization_revocation_refused"
    assert result.evidence["authorizations_revoked"] == ["auth-1", "auth-3"]
    assert result.evidence["authorizations_not_revocable"] == []
    assert result.evidence["authorization_conflicts"] == [
        {
            "authorization_id": "auth-2",
            "code": str(FakeRehearsalIssuerIssuanceRefusalCode.NOT_RECORDED),
            "detail": (
                f"{FakeRehearsalIssuerIssuanceRefusalCode.NOT_RECORDED}: "
                "no ledger row for auth-2"
            ),
        }
    ]
    revocations = [
        command for name, command in ports.calls if name == "revoke_authorization"
    ]
    assert [c.authorization_id for c in revocations] == ["auth-1", "auth-2", "auth-3"]


def test_a_replayed_already_applied_withdrawal_still_converges_authorizations(
    ports: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The `already_applied` pre-read path (this event's own ref already won)
    must still attempt authorization revocation, so a replay converges."""
    from vendor_cp.deployment import issuer_receipts

    monkeypatch.setattr(
        issuer_receipts, "issued_authorization_refs", lambda db, plan_id: ("auth-1",)
    )
    ports.plan.approval_decision_status = "revoked"
    ports.plan.approval_revocation_ref = f"approval.withdrawn:{WITHDRAWAL_ID}"
    result = issuer.classify_approval_withdrawal(object(), _claimed(_withdrawal(ports)))
    assert result.disposition == issuer.WithdrawalDisposition.ALREADY_APPLIED
    assert result.evidence["authorizations_revoked"] == ["auth-1"]
    assert result.evidence["authorizations_not_revocable"] == []
    revocations = [
        command for name, command in ports.calls if name == "revoke_authorization"
    ]
    assert len(revocations) == 1


def test_superseded_by_revocation_does_attempt_authorization_revocation(
    ports: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fix 3: a DIFFERENT withdrawal ref already revoked the plan's approval
    -- this event is not the one that converged the PLAN, but the plan's
    approval no longer stands either way, so it must still attempt to
    converge any authorization CP issued under it."""
    from vendor_cp.deployment import issuer_receipts

    monkeypatch.setattr(
        issuer_receipts, "issued_authorization_refs", lambda db, plan_id: ("auth-1",)
    )
    ports.plan.approval_decision_status = "revoked"
    ports.plan.approval_revocation_ref = "approval.withdrawn:other-event"
    result = issuer.classify_approval_withdrawal(object(), _claimed(_withdrawal(ports)))
    assert result.disposition == issuer.WithdrawalDisposition.SUPERSEDED_BY_REVOCATION
    assert result.evidence["authorizations_revoked"] == ["auth-1"]
    revocations = [
        command for name, command in ports.calls if name == "revoke_authorization"
    ]
    assert [c.authorization_id for c in revocations] == ["auth-1"]


def test_a_redrive_through_superseded_by_revocation_repairs_an_earlier_conflict(
    ports: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fix 3 repairs a fix-2 conflict: the first classification of this event
    leaves auth-1 stuck ISSUED (`NOT_RECORDED`, a `security_conflict`). A
    later redrive of the SAME event, after a DIFFERENT withdrawal has since
    revoked the plan's approval (`superseded_by_revocation`) and the ledger
    condition that caused the earlier refusal has cleared, must still attempt
    -- and this time succeed at -- revoking auth-1."""
    from vendor_cp.deployment import issuer_receipts

    monkeypatch.setattr(
        issuer_receipts, "issued_authorization_refs", lambda db, plan_id: ("auth-1",)
    )
    ports.revoke_refusals["auth-1"] = (
        FakeRehearsalIssuerIssuanceRefusalCode.NOT_RECORDED,
        "no ledger row for auth-1",
    )
    first = issuer.classify_approval_withdrawal(object(), _claimed(_withdrawal(ports)))
    assert first.disposition == issuer.WithdrawalDisposition.SECURITY_CONFLICT

    del ports.revoke_refusals["auth-1"]
    ports.plan.approval_decision_status = "revoked"
    ports.plan.approval_revocation_ref = "approval.withdrawn:other-event"

    redriven = issuer.classify_approval_withdrawal(
        object(), _claimed(_withdrawal(ports))
    )
    assert redriven.disposition == issuer.WithdrawalDisposition.SUPERSEDED_BY_REVOCATION
    assert redriven.evidence["authorizations_revoked"] == ["auth-1"]
    revocations = [
        command for name, command in ports.calls if name == "revoke_authorization"
    ]
    assert [c.authorization_id for c in revocations] == ["auth-1", "auth-1"]


def test_withdrawal_replay_reuses_one_stable_control_command_id(
    ports: SimpleNamespace,
) -> None:
    """The fake's own dedup on `command_id` proves the id is stable across
    two independent classifications of the identical event."""
    event = _withdrawal(ports)
    for _ in range(2):
        issuer.classify_approval_withdrawal(object(), _claimed(event))
    commands = [command for name, command in ports.calls if name == "revoke"]
    assert len(commands) == 1


@pytest.mark.parametrize(
    "field",
    ["subject_id", "content_digest", "request_id", "policy_code", "policy_version"],
)
def test_withdrawal_must_match_frozen_control_plan(
    ports: SimpleNamespace, field: str
) -> None:
    event = _withdrawal(ports)
    event[field] = "wrong"
    result = issuer.classify_approval_withdrawal(object(), _claimed(event))
    assert result.disposition == issuer.WithdrawalDisposition.SECURITY_CONFLICT
    assert ports.calls == []


def test_withdrawal_id_must_be_the_claimed_outbox_row(
    ports: SimpleNamespace,
) -> None:
    result = issuer.classify_approval_withdrawal(
        object(),
        _claimed(_withdrawal(ports), id=UUID("50000000-0000-0000-0000-000000000005")),
    )
    assert result.disposition == issuer.WithdrawalDisposition.SECURITY_CONFLICT
    assert result.reason_code == "withdrawal_id_mismatch"
    assert ports.calls == []


def test_an_unrecognised_subject_type_is_a_security_conflict_without_loading_control(
    ports: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected_import(name: str) -> None:
        raise AssertionError(f"unrecognised subject loaded {name}")

    monkeypatch.setattr(issuer, "import_module", unexpected_import)
    unrelated = _withdrawal(ports)
    unrelated["subject_type"] = "another.subject.v1"
    result = issuer.classify_approval_withdrawal(object(), _claimed(unrelated))
    assert result.disposition == issuer.WithdrawalDisposition.SECURITY_CONFLICT
    assert result.reason_code == "subject_type_mismatch"
    assert ports.calls == []


def test_d2_a_superseded_plan_maps_to_not_carried_plan_superseded(
    ports: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fix 3: `plan_superseded` is one of the reason codes that also revokes
    CP's own issued authorizations for the plan."""
    from vendor_cp.deployment import issuer_receipts

    monkeypatch.setattr(
        issuer_receipts, "issued_authorization_refs", lambda db, plan_id: ("auth-1",)
    )

    def refuse(db: object, command: object) -> object:
        raise ports.control.ExpectedStateError(
            "plan",
            expected_status="approved",
            actual_status="superseded",
            expected_version=None,
            actual_version=1,
        )

    ports.control.revoke_plan_approval = refuse
    result = issuer.classify_approval_withdrawal(object(), _claimed(_withdrawal(ports)))
    assert result.disposition == issuer.WithdrawalDisposition.NOT_CARRIED
    assert result.reason_code == "plan_superseded"
    assert result.evidence["authorizations_revoked"] == ["auth-1"]
    revocations = [
        command for name, command in ports.calls if name == "revoke_authorization"
    ]
    assert [c.authorization_id for c in revocations] == ["auth-1"]


def test_d4_a_cancelled_plan_is_a_terminal_cancelled_before_execution(
    ports: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fix 3: `cancelled_before_execution` also revokes CP's own issued
    authorizations for the plan."""
    from vendor_cp.deployment import issuer_receipts

    monkeypatch.setattr(
        issuer_receipts, "issued_authorization_refs", lambda db, plan_id: ("auth-1",)
    )

    def refuse(db: object, command: object) -> object:
        raise ports.control.ExpectedStateError(
            "plan",
            expected_status="approved",
            actual_status="cancelled",
            expected_version=None,
            actual_version=1,
        )

    ports.control.revoke_plan_approval = refuse
    result = issuer.classify_approval_withdrawal(object(), _claimed(_withdrawal(ports)))
    assert result.disposition == issuer.WithdrawalDisposition.CANCELLED_BEFORE_EXECUTION
    assert result.reason_code == "cancelled_before_execution"
    assert result.evidence["authorizations_revoked"] == ["auth-1"]
    revocations = [
        command for name, command in ports.calls if name == "revoke_authorization"
    ]
    assert [c.authorization_id for c in revocations] == ["auth-1"]


def test_a_proposed_plan_was_never_approved_and_is_not_carried(
    ports: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SENSITIVITY (near-miss): `never_approved` is deliberately ABSENT from
    the set of reason codes that revoke authorizations -- a plan that was
    never approved could never have had an authorization issued under it, so
    no revocation attempt is made."""
    from vendor_cp.deployment import issuer_receipts

    monkeypatch.setattr(
        issuer_receipts, "issued_authorization_refs", lambda db, plan_id: ("auth-1",)
    )

    def refuse(db: object, command: object) -> object:
        raise ports.control.ExpectedStateError(
            "plan",
            expected_status="approved",
            actual_status="proposed",
            expected_version=None,
            actual_version=1,
        )

    ports.control.revoke_plan_approval = refuse
    result = issuer.classify_approval_withdrawal(object(), _claimed(_withdrawal(ports)))
    assert result.disposition == issuer.WithdrawalDisposition.NOT_CARRIED
    assert result.reason_code == "never_approved"
    assert "authorizations_revoked" not in result.evidence
    assert [name for name, _ in ports.calls if name == "revoke_authorization"] == []


def test_an_unexpected_plan_status_is_a_security_conflict(
    ports: SimpleNamespace,
) -> None:
    def refuse(db: object, command: object) -> object:
        raise ports.control.ExpectedStateError(
            "plan",
            expected_status="approved",
            actual_status="draft",
            expected_version=None,
            actual_version=1,
        )

    ports.control.revoke_plan_approval = refuse
    result = issuer.classify_approval_withdrawal(object(), _claimed(_withdrawal(ports)))
    assert result.disposition == issuer.WithdrawalDisposition.SECURITY_CONFLICT
    assert result.reason_code == "unexpected_plan_state"


def test_already_revoked_under_this_event_replays_as_already_applied(
    ports: SimpleNamespace,
) -> None:
    ports.plan.approval_decision_status = "revoked"
    ports.plan.approval_revocation_ref = f"approval.withdrawn:{WITHDRAWAL_ID}"
    result = issuer.classify_approval_withdrawal(object(), _claimed(_withdrawal(ports)))
    assert result.disposition == issuer.WithdrawalDisposition.ALREADY_APPLIED
    assert ports.calls == []


def test_revoked_under_a_different_reference_is_superseded_by_revocation(
    ports: SimpleNamespace,
) -> None:
    ports.plan.approval_decision_status = "revoked"
    ports.plan.approval_revocation_ref = "approval.withdrawn:other-event"
    result = issuer.classify_approval_withdrawal(object(), _claimed(_withdrawal(ports)))
    assert result.disposition == issuer.WithdrawalDisposition.SUPERSEDED_BY_REVOCATION
    assert ports.calls == []


def test_a_decision_that_no_longer_matches_the_approved_plan_is_not_carried(
    ports: SimpleNamespace,
) -> None:
    """The plan moved on (re-approved under a new decision) while this
    withdrawal still names the old one: the withdrawal simply no longer
    applies, which is `not_carried`, not a security conflict."""
    ports.plan.approval_decision_ref = str(UUID("90000000-0000-0000-0000-000000000009"))
    result = issuer.classify_approval_withdrawal(object(), _claimed(_withdrawal(ports)))
    assert result.disposition == issuer.WithdrawalDisposition.NOT_CARRIED
    assert result.reason_code == "decision_not_carried"
    assert ports.calls == []


def test_a_database_lock_during_revocation_is_retryable_not_a_recorded_row(
    ports: SimpleNamespace,
) -> None:
    from sqlalchemy.exc import OperationalError

    def refuse(db: object, command: object) -> object:
        raise OperationalError("revoke", {}, Exception("lock timeout"))

    ports.control.revoke_plan_approval = refuse
    with pytest.raises(issuer.RetryableWithdrawal):
        issuer.classify_approval_withdrawal(object(), _claimed(_withdrawal(ports)))


def test_retryable_repr_carries_only_a_bounded_code() -> None:
    exc = issuer.RetryableWithdrawal("database_unavailable")
    assert repr(exc) == "RetryableWithdrawal(database_unavailable)"
    assert str(exc) == "RetryableWithdrawal(database_unavailable)"


def test_the_barrier_refuses_an_autocommit_session_before_holding() -> None:
    """On AUTOCOMMIT a FOR SHARE lock ends with its own statement, so the
    barrier would hold nothing; it must refuse before the hold or transition."""
    calls: list[str] = []

    class _Connection:
        # SQLAlchemy Connection -> pool proxy -> DBAPI connection, whose
        # `autocommit` flag is what the barrier reads.
        connection = SimpleNamespace(dbapi_connection=SimpleNamespace(autocommit=True))

    class _AutocommitSession:
        def connection(self) -> _Connection:
            return _Connection()

    with pytest.raises(approval_barrier.ApprovalBarrierUnavailable):
        approval_barrier.held_transition(
            _AutocommitSession(),  # type: ignore[arg-type]
            request_id=REQUEST_ID,
            subject_type="x",
            subject_id="y",
            content_digest="sha256:" + "a" * 64,
            transition=lambda _held: calls.append("transition"),
        )
    assert calls == []


def test_the_autocommit_check_is_not_fooled_by_sqlites_legacy_sentinel() -> None:
    """SENSITIVITY (near-miss). `sqlite3.Connection.autocommit` defaults to
    `sqlite3.LEGACY_TRANSACTION_CONTROL` (`-1`) on Python 3.12+ -- truthy, but
    meaning "PEP 249 legacy, transactional", not autocommit. `-1` and `False`
    must both pass; only `True` (identity, not truthiness) may refuse."""

    class _Connection:
        def __init__(self, autocommit: object) -> None:
            self.connection = SimpleNamespace(
                dbapi_connection=SimpleNamespace(autocommit=autocommit)
            )

    class _Session:
        def __init__(self, autocommit: object) -> None:
            self._connection = _Connection(autocommit)

        def connection(self) -> _Connection:
            return self._connection

    for non_autocommit in (-1, False):
        approval_barrier._require_transactional(_Session(non_autocommit))  # type: ignore[arg-type]

    with pytest.raises(approval_barrier.ApprovalBarrierUnavailable):
        approval_barrier._require_transactional(_Session(True))  # type: ignore[arg-type]
