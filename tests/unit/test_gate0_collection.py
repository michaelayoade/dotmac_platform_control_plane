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
from vendor_cp.deployment.gate0_framing import (
    FramedChannel,
    ServiceRefused,
    canonical,
    strict_object,
)


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
        "owner-missing",
        "owner-read-failure",
        "reference-mismatch",
        "pending-budget",
        "expired-window",
        "wrong-event",
        "wrong-withdrawal-ref",
        "owner-wrong-request",
        "conflict",
        "null-conflict",
        "many-null-conflicts",
        "missing-revocation",
        "cleanup",
    ],
)
def test_withdrawal_requires_exact_committed_owner_effect_and_confirmed_cleanup(
    monkeypatch, change
):
    from datetime import UTC, datetime
    from types import SimpleNamespace
    from uuid import UUID

    from vendor_cp.approvals import adapter as approvals
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
        withdrawal_ref=str(UUID(int=3)),
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

    if change == "wrong-event":
        row.event_id = UUID(int=99)
    if change == "wrong-withdrawal-ref":
        row.withdrawal_ref = "human-reference-is-not-event-id"
    withdrawn = approvals.WithdrawalIdentityEvidence(
        UUID(int=99) if change == "owner-wrong-request" else UUID(int=1),
        UUID(int=3),
        UUID(int=4),
        "synthetic-human-route",
        datetime.now(UTC),
        datetime.now(UTC),
        "human-reference-is-not-event-id",
    )

    owner_reads = []
    if change == "expired-window":

        def expired():
            raise ServiceRefused()

        collector._b_expected.window_freshness.require_open = expired

    def withdrawal(db, *, request_id, external_ref):
        owner_reads.append(request_id)
        if change == "owner-read-failure":
            raise RuntimeError("sensitive-owner-read-detail")
        if change == "reference-mismatch":
            from dotmac_kernel import ConflictError

            raise ConflictError("sensitive-other-human-reference")
        assert request_id == UUID(int=1)
        assert external_ref == "human-reference-is-not-event-id"
        return None if change == "owner-missing" else withdrawn

    relay_reads = []

    def rows(db, event_id, *, limit):
        relay_reads.append(event_id)
        assert event_id == UUID(int=3) and type(limit) is int and limit == 3
        if change in ("direct-revoke", "pending-budget"):
            return ()
        if change in ("null-conflict", "many-null-conflicts"):
            conflicts = [
                SimpleNamespace(
                    event_id=event_id,
                    approval_request_id=None,
                    withdrawal_ref=None,
                    disposition=owner.WithdrawalDisposition.SECURITY_CONFLICT,
                )
                for _ in range(1 if change == "null-conflict" else 8)
            ]
            # Model the bounded owner query, retaining NULL-coordinate rows.
            return tuple([row, *conflicts][:limit])
        return (row,)

    monkeypatch.setattr(approvals, "withdrawal_for_reference", withdrawal)
    monkeypatch.setattr(owner, "outcomes_for_event", rows)
    events = []

    def close():
        events.append("close")
        if change == "cleanup":
            raise RuntimeError("sensitive-cleanup")

    db = SimpleNamespace(rollback=lambda: events.append("rollback"), close=close)
    if change in ("none", "direct-revoke", "owner-missing", "pending-budget"):
        found = collector.observe_b_withdrawal(
            sessions=lambda: db, external_ref="human-reference-is-not-event-id"
        )
        assert found is (change == "none")
        assert (collector._b_revocation is not None) is found
        if found:
            evidence = strict_object(collector._b_revocation)
            assert evidence["event_id"] == evidence["withdrawal_id"] == str(UUID(int=3))
            assert evidence["external_ref"] == "human-reference-is-not-event-id"
            assert evidence["withdrawal_ref"] != evidence["external_ref"]
            assert "reason" not in evidence
    else:
        with pytest.raises(ServiceRefused):
            collector.observe_b_withdrawal(
                sessions=lambda: db, external_ref="human-reference-is-not-event-id"
            )
        assert collector._b_revocation is None
    if change == "pending-budget":
        for _ in range(15):
            assert not collector.observe_b_withdrawal(
                sessions=lambda: db, external_ref="human-reference-is-not-event-id"
            )
        with pytest.raises(ServiceRefused):
            collector.observe_b_withdrawal(
                sessions=lambda: db, external_ref="human-reference-is-not-event-id"
            )
        assert len(owner_reads) == 16 and collector._withdrawal_reads == 17
        assert events == ["rollback", "close"] * 17
    else:
        assert events == ["rollback", "close"]
    if change == "expired-window":
        assert not owner_reads
    if change in (
        "owner-missing",
        "reference-mismatch",
        "owner-read-failure",
        "expired-window",
        "owner-wrong-request",
    ):
        assert not relay_reads
