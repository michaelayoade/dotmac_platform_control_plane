"""Focused synthetic components only; no installed origin or live E acceptance."""

import base64
import hashlib
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from test_gate0_runtime_providers import jwt_case, synthetic_http_only  # noqa: F401
from test_gate0_window import window_document  # noqa: F401

from vendor_cp.approvals.adapter import (
    DecisionIdentityEvidence,
    RequestIdentityEvidence,
    WithdrawalIdentityEvidence,
)
from vendor_cp.deployment import gate0_collection_api as api
from vendor_cp.deployment import gate0_collection_projection as owner
from vendor_cp.deployment.gate0_framing import canonical, strict_object
from vendor_cp.deployment.gate0_github_jwt import verify_github_claims
from vendor_cp.deployment.gate0_role_custody import ProviderRefused
from vendor_cp.deployment.gate0_window import FrozenIssuerWindow
from vendor_cp.deployment.issuer_receipts import issued_authorization_refs
from vendor_cp.relay.withdrawal_outcomes import WithdrawalDisposition


@pytest.fixture
def case(window_document, monkeypatch):  # noqa: F811
    import dotmac_deployment_control as control

    document = window_document
    document["case_kind"] = "withdrawal_later_use"
    window = FrozenIssuerWindow.parse(canonical(document))
    target = SimpleNamespace(
        id=UUID(document["target"]["id"]),
        target_ref=document["target"]["ref"],
        environment="rehearsal",
    )
    plan = SimpleNamespace(
        id=UUID(int=1),
        target_id=target.id,
        purpose=document["purpose"],
        operation="deploy",
        plan_digest="sha256:" + "5" * 64,
        descriptor_digest=document["plan_inputs"]["descriptor_digest"],
        execution_plan_digest=document["plan_inputs"]["execution_plan_digest"],
        approval_policy_code="synthetic-policy",
        approval_policy_version=1,
        requires_approval=True,
        approval_decision_ref=str(UUID(int=3)),
        authorized_images=[
            SimpleNamespace(digest=SimpleNamespace(canonical="sha256:" + "6" * 64))
        ],
        snapshot={
            "spec": {"gate0_window_v1": document},
            "plan_purpose": document["purpose"],
            "target_ref": target.target_ref,
            "environment": "rehearsal",
        },
    )
    selected = owner.CollectionSelection(
        "sha256:" + "7" * 64,
        document["window_id"],
        window.digest,
        plan.id,
        target.id,
        "withdrawal_later_use",
    )
    role = {
        "key_id": "synthetic",
        "public_key_b64": base64.b64encode(bytes(32)).decode(),
        "source_revision": "a" * 40,
        "image_digest": "sha256:" + "b" * 64,
        "profile_digest": "sha256:" + "c" * 64,
    }
    shared = canonical(
        {
            "schema": "Gate0RunIdentity.v1",
            "run_id": document["github"]["run_id"],
            "run_attempt": document["github"]["run_attempt"],
            "case_kind": document["case_kind"],
            "not_before": document["not_before"],
            "expires_at": document["expires_at"],
            "capture": {
                "window_digest": window.digest,
                "plan_id": str(plan.id),
                "plan_digest": plan.plan_digest,
                "target_id": str(target.id),
                "approval_request_id": plan.approval_decision_ref,
            },
            "roles": {"issuer": role, "attester": role},
            "controller_ca_fingerprint": document["controller"]["ca_fingerprint"],
            "management_key_fingerprint": document["controller"]["fingerprint"],
        }
    )
    selected = replace(
        selected, launch_packet_digest="sha256:" + hashlib.sha256(shared).hexdigest()
    )
    now = datetime.now(UTC)
    case_clock = owner.CollectionCaseClock(
        now,
        time.monotonic(),
        datetime.fromisoformat(document["not_before"].replace("Z", "+00:00")),
        datetime.fromisoformat(document["expires_at"].replace("Z", "+00:00")),
    )
    configured = owner.CollectionCase(
        selected, case_clock, shared, window.canonical_bytes
    )
    now = datetime.now(UTC)
    decided = now - timedelta(seconds=2)
    identity = RequestIdentityEvidence(
        UUID(int=3),
        owner.SUBJECT_TYPE,
        owner.issuer_approval_subject(plan),
        plan.plan_digest,
        "synthetic-policy",
        1,
        "withdrawn",
        decided,
        (DecisionIdentityEvidence(UUID(int=4), UUID(int=5), "approve", decided),),
    )
    claims = dict(
        document["github"],
        iat=int(now.timestamp()),
        nbf=int(now.timestamp()),
        exp=int((now + timedelta(seconds=30)).timestamp()),
        jti="synthetic",
    )
    monkeypatch.setattr(control, "get_plan", lambda db, plan_id: plan)
    monkeypatch.setattr(control, "get_target", lambda db, target_id: target)
    monkeypatch.setattr(
        owner, "request_identity_evidence", lambda db, request_id: identity
    )
    return SimpleNamespace(
        selected=selected,
        configured=configured,
        plan=plan,
        window=window,
        identity=identity,
        claims=claims,
        decided=decided,
    )


def test_scope_matches_every_frozen_claim_before_approval_read(case, monkeypatch):
    for key in case.window.document["github"]:
        claims = dict(case.claims, **{key: "other"})
        monkeypatch.setattr(
            owner,
            "request_identity_evidence",
            lambda *a: pytest.fail("identity read before workload match"),
        )
        with pytest.raises(ProviderRefused):
            owner._owner_scope(object(), case.selected, claims)


def test_scope_refuses_foreign_owner_and_window(case, monkeypatch):
    with pytest.raises(ProviderRefused):
        owner._owner_scope(
            object(),
            replace(case.selected, window_digest="sha256:" + "0" * 64),
            case.claims,
        )
    monkeypatch.setattr(
        owner,
        "request_identity_evidence",
        lambda *a: replace(case.identity, subject_id="foreign"),
    )
    with pytest.raises(ProviderRefused):
        owner._owner_scope(object(), case.selected, case.claims)


def test_approval_snapshot_is_captured_inside_existing_hold(case, monkeypatch):
    identity = replace(case.identity, state="approved")
    monkeypatch.setattr(owner, "request_identity_evidence", lambda *a: identity)
    calls = []

    def hold(db, **kwargs):
        calls.append(kwargs["request_id"])
        return kwargs["transition"](object())

    monkeypatch.setattr(owner, "held_transition", hold)
    monkeypatch.setattr(
        owner,
        "approved_request_evidence",
        lambda *a, **k: SimpleNamespace(decided_at=case.decided),
    )
    result = owner._approval(object(), case.selected, case.claims)
    assert calls == [case.identity.request_id]
    assert result["approval"]["state"] == "approved"
    assert result["binding"]["window_digest"] == case.window.digest
    assert len(result["approval"]["decisions"]) == 1


@pytest.mark.parametrize("state", ["pending_withdrawal", "pending_relay", "applied"])
def test_withdrawn_scope_reads_original_owner_evidence_without_current_hold(
    case, monkeypatch, state
):
    withdrawal = WithdrawalIdentityEvidence(
        case.identity.request_id,
        UUID(int=8),
        UUID(int=9),
        "synthetic-authority",
        case.decided,
        datetime.now(UTC),
        "private-reference",
    )
    monkeypatch.setattr(
        owner,
        "held_transition",
        lambda *a, **k: pytest.fail("withdrawal requires no standing hold"),
    )
    monkeypatch.setattr(
        owner,
        "withdrawal_for_reference",
        lambda *a, **k: None if state == "pending_withdrawal" else withdrawal,
    )
    row = SimpleNamespace(
        disposition=WithdrawalDisposition.APPLIED,
        event_type="approval.withdrawn",
        approval_request_id=case.identity.request_id,
        event_id=withdrawal.withdrawal_id,
        withdrawal_ref=str(withdrawal.withdrawal_id),
        payload_digest="sha256:" + "a" * 64,
        subject_type=case.identity.subject_type,
        subject_id=case.identity.subject_id,
        plan_id=case.plan.id,
        evidence={"authorizations_revoked": ["authorization"]},
    )
    monkeypatch.setattr(
        owner,
        "outcomes_for_event",
        lambda db, event_id, *, limit: (
            [row] if state == "applied" and limit == 3 else []
        ),
    )

    def refs(db, plan_id, *, max_count):
        assert max_count == 2
        return ("authorization",)

    monkeypatch.setattr(owner, "issued_authorization_refs", refs)
    result = owner._withdrawal(
        object(), case.selected, case.claims, "private-reference"
    )
    assert result["state"] == state
    if state == "applied":
        assert result["relay"]["event_id"] == str(withdrawal.withdrawal_id)
        assert result["relay"]["withdrawal_ref"] != withdrawal.external_ref


@pytest.mark.parametrize("mismatch", ["event", "revocation", "history", "disposition"])
def test_withdrawal_mismatches_never_become_pending_or_applied(
    case, monkeypatch, mismatch
):
    withdrawal = WithdrawalIdentityEvidence(
        case.identity.request_id,
        UUID(int=8),
        UUID(int=9),
        "authority",
        case.decided,
        datetime.now(UTC),
        "ref",
    )
    if mismatch == "history":
        withdrawal = replace(
            withdrawal, approved_at=case.decided - timedelta(seconds=1)
        )
    monkeypatch.setattr(owner, "withdrawal_for_reference", lambda *a, **k: withdrawal)
    row = SimpleNamespace(
        disposition=WithdrawalDisposition.SECURITY_CONFLICT
        if mismatch == "disposition"
        else WithdrawalDisposition.APPLIED,
        event_type="approval.withdrawn",
        approval_request_id=case.identity.request_id,
        event_id=UUID(int=88) if mismatch == "event" else withdrawal.withdrawal_id,
        withdrawal_ref=str(withdrawal.withdrawal_id),
        payload_digest="sha256:" + "a" * 64,
        subject_type=case.identity.subject_type,
        subject_id=case.identity.subject_id,
        plan_id=case.plan.id,
        evidence={
            "authorizations_revoked": ["foreign"]
            if mismatch == "revocation"
            else ["authorization"]
        },
    )
    monkeypatch.setattr(owner, "outcomes_for_event", lambda *a, **k: [row])
    monkeypatch.setattr(
        owner, "issued_authorization_refs", lambda *a, **k: ("authorization",)
    )
    with pytest.raises(ProviderRefused):
        owner._withdrawal(object(), case.selected, case.claims, "ref")


@pytest.mark.parametrize("failure", [None, "read", "rollback", "close"])
@pytest.mark.parametrize("withdrawal", [False, True])
def test_response_requires_confirmed_cleanup_and_correct_transaction_mode(
    case, monkeypatch, failure, withdrawal
):
    calls = []

    class Session:
        def get_bind(self):
            return SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))

        def execute(self, statement, *args):
            calls.append(str(statement))

        def rollback(self):
            calls.append("rollback")
            if failure == "rollback":
                raise RuntimeError()

        def close(self):
            calls.append("close")
            if failure == "close":
                raise RuntimeError()

    installation = object.__new__(owner.CollectionInstallation)
    object.__setattr__(
        installation, "runtime", SimpleNamespace(platform_session_factory=Session)
    )
    object.__setattr__(installation, "cases", (case.configured,))

    def read(*a):
        calls.append("read")
        if failure == "read":
            raise RuntimeError()
        return {"schema": "synthetic"}

    monkeypatch.setattr(owner, "_approval", read)
    monkeypatch.setattr(owner, "_withdrawal", read)
    if failure is None:
        assert strict_object(
            owner.project(
                installation,
                case.configured,
                case.claims,
                external_ref="ref" if withdrawal else None,
            )
        ) == {"schema": "synthetic"}
    else:
        with pytest.raises(ProviderRefused):
            owner.project(
                installation,
                case.configured,
                case.claims,
                external_ref="ref" if withdrawal else None,
            )
    assert calls[-2:] == ["rollback", "close"]
    assert ("SET TRANSACTION READ ONLY" in calls) is withdrawal


def test_shared_verifier_retains_signature_fixed_claims_and_no_cache(jwt_case):  # noqa: F811
    admission, _, transport, token = jwt_case
    kwargs = {"transport": admission._transport, "deadline": admission._deadline}
    assert verify_github_claims(token(), **kwargs)["run_id"] == "22"
    with pytest.raises(ProviderRefused):
        verify_github_claims(token({"repository_id": "foreign"}), **kwargs)
    transport.document = {"keys": []}
    with pytest.raises(ProviderRefused):
        verify_github_claims(token(), **kwargs)


def test_absent_installation_and_private_query_refuse_before_db():
    app = FastAPI()
    app.include_router(api.router)
    client = TestClient(app)
    base = "/platform/vendor/gate0/collection/windows/unknown"
    assert client.get(base + "/approval").status_code == 403
    assert client.get(base + "/withdrawal?external_ref=private").status_code == 403


def test_receipt_optional_bound_is_native_and_defaults_unchanged():
    queries = []
    db = SimpleNamespace(
        execute=lambda query: queries.append(query) or [("one",), ("two",)]
    )
    assert issued_authorization_refs(db, UUID(int=1), max_count=2) == ("one", "two")
    assert queries[-1]._limit_clause.value == 2
    issued_authorization_refs(db, UUID(int=1))
    assert queries[-1]._limit_clause is None
    for invalid in (True, 0, 65, "2"):
        with pytest.raises(ValueError):
            issued_authorization_refs(db, UUID(int=1), max_count=invalid)


def test_exact_header_operation_and_invalid_jwt_before_projection(case, monkeypatch):
    installation = object.__new__(owner.CollectionInstallation)
    object.__setattr__(installation, "cases", (case.configured,))
    app = FastAPI()
    app.include_router(api.router)
    app.state.gate0_collection_installation = installation
    calls = []

    def authenticate(self, selected_case, token):
        assert selected_case is case.configured
        calls.append("jwt")
        if token != "synthetic":
            raise ProviderRefused()
        return case.claims

    monkeypatch.setattr(owner.CollectionInstallation, "authenticate", authenticate)

    def project(*a, **kwargs):
        calls.append(("project", kwargs["external_ref"]))
        return canonical({"schema": "synthetic"})

    monkeypatch.setattr(api, "project", project)
    client = TestClient(app)
    path = "/platform/vendor/gate0/collection/windows/" + case.selected.window_id
    headers = {
        "Authorization": "Bearer synthetic",
        "X-Dotmac-Gate0-Withdrawal-Reference": "private-reference",
    }
    assert client.get(path + "/withdrawal", headers=headers).status_code == 200
    assert calls == ["jwt", ("project", "private-reference")]
    calls.clear()
    assert (
        client.get(
            path + "/withdrawal", headers=dict(headers, Authorization="Bearer bad")
        ).status_code
        == 403
    )
    assert calls == ["jwt"]
    assert (
        client.get(
            path + "/withdrawal?external_ref=private", headers=headers
        ).status_code
        == 403
    )
    assert client.get(path + "/approval", headers=headers).status_code == 403


def test_independent_case_clocks_future_b_and_original_intersection(monkeypatch):
    base = datetime.now(UTC)
    current = [0.0]

    class ClockDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return base + timedelta(seconds=current[0])

    monkeypatch.setattr(owner, "datetime", ClockDateTime)
    monkeypatch.setattr(owner.time, "monotonic", lambda: 1000 + current[0])
    # Structural validation accepts future B without activating either interval.
    # Construct with real datetime identity before replacing the time reader.
    monkeypatch.setattr(owner, "datetime", datetime)
    a = owner.CollectionCaseClock(base, 1000.0, base, base + timedelta(seconds=30))
    b = owner.CollectionCaseClock(
        base, 1000.0, base + timedelta(seconds=40), base + timedelta(seconds=70)
    )
    monkeypatch.setattr(owner, "datetime", ClockDateTime)
    a.require_open()
    with pytest.raises(ProviderRefused):
        b.require_open()
    original = (a.start, a.deadline, b.start, b.deadline)
    current[0] = 45
    with pytest.raises(ProviderRefused):
        a.require_open()
    b.require_open()
    assert original == (a.start, a.deadline, b.start, b.deadline)
    # exp beyond B's end is accepted only in the intersection.
    b.require_open({"exp": int((base + timedelta(seconds=200)).timestamp())})
    current[0] = 70
    with pytest.raises(ProviderRefused):
        b.require_open({"exp": int((base + timedelta(seconds=200)).timestamp())})
    current[0] = 50
    with pytest.raises(ProviderRefused):
        b.require_open({"exp": int((base + timedelta(seconds=49)).timestamp())})


def test_projection_rejects_jwt_expiry_during_confirmed_cleanup(case, monkeypatch):
    calls = []

    class Session:
        def get_bind(self):
            return SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))

        def execute(self, *a):
            pass

        def rollback(self):
            calls.append("rollback")

        def close(self):
            calls.append("close")
            case.claims["exp"] = 1

    installation = object.__new__(owner.CollectionInstallation)
    object.__setattr__(
        installation, "runtime", SimpleNamespace(platform_session_factory=Session)
    )
    object.__setattr__(installation, "cases", (case.configured,))
    monkeypatch.setattr(owner, "_approval", lambda *a: {"schema": "synthetic"})
    with pytest.raises(ProviderRefused):
        owner.project(installation, case.configured, case.claims)
    assert calls == ["rollback", "close"]


def test_api_scope_accepts_jwt_exp_beyond_frozen_end_but_not_stale_iat(case):
    claims = dict(case.claims, exp=int(datetime.now(UTC).timestamp()) + 300)
    assert owner._owner_scope(object(), case.selected, claims)[2] == case.window
    claims["iat"] = 1
    with pytest.raises(ProviderRefused):
        owner._owner_scope(object(), case.selected, claims)


def test_selected_frozen_scope_refuses_wrong_run_before_owner_database(
    case, monkeypatch
):
    installation = object.__new__(owner.CollectionInstallation)
    object.__setattr__(installation, "cases", (case.configured,))
    object.__setattr__(installation, "jwks", object())
    monkeypatch.setattr(
        owner, "verify_github_claims", lambda *a, **k: dict(case.claims, run_id="999")
    )
    with pytest.raises(ProviderRefused):
        installation.authenticate(case.configured, "synthetic")
