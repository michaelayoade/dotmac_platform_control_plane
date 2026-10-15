"""Synthetic closed codec and real framed-pipe mechanism; no live E acceptance."""

import socket
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from vendor_cp.deployment.gate0_collection import (
    FramedCaseCollector,
    IssuerOutcome,
    OutcomeKind,
    digest,
    request_identity,
    run_installed_collection,
)
from vendor_cp.deployment.gate0_framing import FramedChannel, ServiceRefused, canonical


def refused(request, ordinal=1):
    from vendor_cp.approvals.adapter import ApprovalHoldRefusal

    return IssuerOutcome(
        ordinal,
        "consume",
        request_identity(request),
        digest(b"synthetic-window"),
        None,
        None,
        OutcomeKind.OWNER_REFUSED,
        "approvals",
        ApprovalHoldRefusal.WITHDRAWN.value,
        canonical({}),
    ).document()


def test_request_identity_strips_credentials():
    request = {"operation": "consume", "workload_token": "synthetic-token"}
    changed = dict(request, workload_token="other-synthetic-token")
    assert request_identity(request) == request_identity(changed)
    assert b"synthetic-token" not in canonical(refused(request))


@pytest.mark.parametrize(
    "change", ["pass", "extra", "ordinal", "namespace", "code", "result", "boolean"]
)
def test_closed_owner_outcome_rejects_input_claims(change):
    document = refused({"operation": "consume"})
    if change == "pass":
        document["kind"] = "PASS"
    elif change == "extra":
        document["cleanup"] = True
    elif change == "ordinal":
        document["ordinal"] = True
    elif change == "namespace":
        document["owner_namespace"] = "caller"
    elif change == "code":
        document["owner_code"] = "anything-refused"
    elif change == "result":
        document["result"] = {"accepted": True}
    else:
        document["readiness_accepted"] = True
    with pytest.raises(ServiceRefused):
        IssuerOutcome.parse(document)


@pytest.mark.parametrize("swap", [False, True])
def test_real_framed_channel_terminal_refusal_or_mismatched_identity(swap):
    left, right = socket.socketpair()
    try:
        deadline = time.monotonic() + 5
        collector = FramedCaseCollector(
            FramedChannel(left.fileno(), left.fileno(), deadline=deadline)
        )
        server = FramedChannel(right.fileno(), right.fileno(), deadline=deadline)
        request = {"operation": "consume", "workload_token": "synthetic"}

        def owner():
            actual = server.receive()
            response = refused(actual)
            if swap:
                response["request_digest"] = digest(b"different-request")
            server.send(response)

        with ThreadPoolExecutor(max_workers=1) as pool:
            job = pool.submit(owner)
            if swap:
                with pytest.raises(ServiceRefused):
                    collector._exchange(request)
            else:
                assert collector._exchange(request).kind is OutcomeKind.OWNER_REFUSED
            job.result(timeout=5)
        with pytest.raises(ServiceRefused):
            collector._exchange(request)
    finally:
        left.close()
        right.close()


def test_installed_collection_cannot_admit_or_emit_private_bytes(capsys):
    assert run_installed_collection() == 3
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "GATE0_COLLECTION_UNAVAILABLE\n"


@pytest.mark.parametrize(
    "change",
    [
        "none",
        "wrong-request",
        "wrong-plan",
        "direct-revoke",
        "conflict",
        "missing-revocation",
        "cleanup",
    ],
)
def test_withdrawal_requires_exact_committed_owner_effect_and_confirmed_cleanup(
    monkeypatch, change
):
    from types import SimpleNamespace
    from uuid import UUID

    from vendor_cp.deployment.gate0_collection import FixedEvidenceCollector
    from vendor_cp.relay import withdrawal_outcomes as owner

    collector = object.__new__(FixedEvidenceCollector)
    collector._b_expected = SimpleNamespace(
        approval_request_id=UUID(int=1),
        operation=SimpleNamespace(plan_id=str(UUID(int=2))),
        window_freshness=SimpleNamespace(require_open=lambda: None),
    )
    collector._b_issue = SimpleNamespace(
        result_bytes=canonical({"authorization_id": "synthetic-auth"})
    )
    collector._b_revocation = None
    collector._b_consume = b"synthetic-captured-proof"
    collector._withdrawal_reads = 0
    collector._approvals = {
        "b": canonical(
            {
                "subject_type": "synthetic-subject-type",
                "subject_id": "synthetic-subject",
            }
        )
    }
    row = SimpleNamespace(
        event_id=UUID(int=3),
        payload_digest=digest(b"synthetic-payload"),
        event_type="approval.withdrawn",
        approval_request_id=UUID(int=1),
        withdrawal_ref="synthetic-withdrawal",
        plan_id=UUID(int=2),
        subject_type="synthetic-subject-type",
        subject_id="synthetic-subject",
        disposition=owner.WithdrawalDisposition.APPLIED,
        evidence={"authorizations_revoked": ["synthetic-auth"]},
    )
    if change == "wrong-request":
        row.approval_request_id = UUID(int=99)
    if change == "wrong-plan":
        row.plan_id = UUID(int=99)
    if change == "conflict":
        row.disposition = owner.WithdrawalDisposition.SECURITY_CONFLICT
    if change == "missing-revocation":
        row.evidence = {"authorizations_revoked": []}

    def rows(db, *, request_id, withdrawal_ref):
        assert request_id == UUID(int=1) and withdrawal_ref == "synthetic-withdrawal"
        return () if change == "direct-revoke" else (row,)

    monkeypatch.setattr(owner, "outcomes_for_request", rows)
    events = []

    def close():
        events.append("close")
        if change == "cleanup":
            raise RuntimeError("sensitive-cleanup")

    db = SimpleNamespace(rollback=lambda: events.append("rollback"), close=close)
    if change in ("none", "direct-revoke"):
        found = collector.observe_b_withdrawal(
            sessions=lambda: db, withdrawal_ref="synthetic-withdrawal"
        )
        assert found is (change == "none")
        assert (collector._b_revocation is not None) is found
    else:
        with pytest.raises(ServiceRefused):
            collector.observe_b_withdrawal(
                sessions=lambda: db, withdrawal_ref="synthetic-withdrawal"
            )
        assert collector._b_revocation is None
    assert events == ["rollback", "close"]
