"""Hosted-only finite worker dispatch and single-install checks."""

import time
from types import SimpleNamespace
from uuid import UUID

import pytest

from vendor_cp.deployment import gate0_services as services
from vendor_cp.deployment.gate0_composition import PhaseResult
from vendor_cp.deployment.gate0_framing import ServiceRefused


class SyntheticManagementChannel:
    def __init__(self, requests):
        self.requests = iter(requests)
        self.output = []
        self.deadline = time.monotonic() + 120

    def receive(self, allow_eof=False):
        return next(self.requests, None)

    def send(self, document):
        self.output.append(document)


def test_one_install_is_retained_across_issue_and_consume(monkeypatch):
    installations, calls = [], []
    plan_id = UUID(int=1)

    class SyntheticComposition:
        def issue(self, command):
            calls.append(("issue", command.actor_ref, command.plan_id))
            return PhaseResult(
                "sha256:" + "a" * 64,
                "synthetic-authorization",
                "synthetic-lease",
                b"synthetic-owner-envelope",
            )

        def consume(self, selected, document):
            calls.append(("consume", selected, document))
            return PhaseResult(
                "sha256:" + "b" * 64,
                "synthetic-authorization",
                "synthetic-lease",
                single_use_reference="synthetic-consumed",
            )

    composition = SyntheticComposition()

    def assemble(**kwargs):
        installations.append(kwargs)
        return composition

    monkeypatch.setattr(services, "assemble_gate0_composition", assemble)
    startup = SimpleNamespace(
        database_qualified=True,
        sessions=lambda: pytest.fail("synthetic dispatch must not open a session"),
        require_frozen_window=False,  # Explicit synthetic dispatch mechanism.
        custody=None,
        actor_ref="synthetic-management-actor",
        verifier=SimpleNamespace(_require_open=lambda: None),
        admission=None,
        signer=object(),
        authorization_verifier=object(),
        authorization_ttl=object(),
    )
    worker = services.IssuerWorker(startup)
    channel = SyntheticManagementChannel(
        [
            {
                "schema": "Gate0IssuerSubmission.v1",
                "operation": "issue",
                "workload_token": "synthetic-token",
                "plan_id": str(plan_id),
                "command_id": "synthetic-command",
                "proof": {},
            },
            {
                "schema": "Gate0IssuerSubmission.v1",
                "operation": "consume",
                "workload_token": "synthetic-token",
                "plan_id": str(plan_id),
                "authorization": "c3ludGhldGljLW93bmVyLWVudmVsb3Bl",
                "proof": {},
            },
        ]
    )
    worker.run(channel)
    assert len(installations) == 1
    assert installations[0]["sessions"] is startup.sessions
    assert worker.composition is composition
    assert calls == [
        ("issue", "synthetic-management-actor", plan_id),
        ("consume", plan_id, b"synthetic-owner-envelope"),
    ]
    assert [value["operation"] for value in channel.output] == ["issue", "consume"]
    assert all(value["readiness_accepted"] is False for value in channel.output)


def test_unqualified_database_refuses_before_owner_install(monkeypatch):
    installations = []
    monkeypatch.setattr(
        services,
        "assemble_gate0_composition",
        lambda **kwargs: installations.append(kwargs),
    )
    with pytest.raises(ServiceRefused):
        services.IssuerWorker(SimpleNamespace(database_qualified=False))
    assert installations == []


def test_request_cannot_select_actor_code_or_database(monkeypatch):
    calls = []
    monkeypatch.setattr(
        services,
        "assemble_gate0_composition",
        lambda **kwargs: SimpleNamespace(issue=lambda command: calls.append(command)),
    )
    startup = SimpleNamespace(
        database_qualified=True,
        sessions=lambda: pytest.fail("synthetic dispatch must not open a session"),
        require_frozen_window=False,  # Explicit synthetic dispatch mechanism.
        custody=None,
        actor_ref="synthetic-management",
        verifier=SimpleNamespace(_require_open=lambda: None),
        signer=object(),
        authorization_verifier=object(),
        authorization_ttl=object(),
    )
    worker = services.IssuerWorker(startup)
    request = {
        "schema": "Gate0IssuerSubmission.v1",
        "operation": "issue",
        "workload_token": "synthetic-token",
        "plan_id": str(UUID(int=1)),
        "command_id": "synthetic-command",
        "proof": {},
        "actor_ref": "invented-human",
    }
    with pytest.raises(ServiceRefused):
        worker.run(SyntheticManagementChannel([request]))
    assert calls == []


def test_committed_mutation_with_lost_response_is_incomplete(monkeypatch):
    monkeypatch.setattr(
        services,
        "assemble_gate0_composition",
        lambda **kwargs: SimpleNamespace(
            issue=lambda command: PhaseResult(
                "sha256:" + "a" * 64,
                "synthetic-authorization",
                "synthetic-lease",
                b"synthetic-envelope",
            )
        ),
    )
    startup = SimpleNamespace(
        database_qualified=True,
        sessions=lambda: pytest.fail("synthetic dispatch must not open a session"),
        require_frozen_window=False,  # Explicit synthetic dispatch mechanism.
        custody=None,
        actor_ref="synthetic-management",
        verifier=SimpleNamespace(_require_open=lambda: None),
        signer=object(),
        authorization_verifier=object(),
        authorization_ttl=object(),
    )
    worker = services.IssuerWorker(startup)

    class BrokenOutput(SyntheticManagementChannel):
        def send(self, document):
            raise BrokenPipeError()

    request = {
        "schema": "Gate0IssuerSubmission.v1",
        "operation": "issue",
        "workload_token": "synthetic-token",
        "plan_id": str(UUID(int=1)),
        "command_id": "synthetic-command",
        "proof": {},
    }
    with pytest.raises(services.ServiceIncomplete):
        worker.run(BrokenOutput([request]))


@pytest.mark.parametrize("admission_phase", ["issue", "consume"])
def test_standing_bridge_forwards_actual_envelope_only_for_consume(admission_phase):
    """The retained proof phase controls admission; standing still keeps bytes."""
    calls = []

    class Admission:
        def admit(self, token, phase, plan_id, authorization_document=None):
            calls.append((token, phase, plan_id, authorization_document))
            return "synthetic-expectation"

    worker = object.__new__(services.IssuerWorker)
    worker._startup = SimpleNamespace(admission=Admission())
    worker._request = {
        "operation": "standing",
        "workload_token": "synthetic",
        "authorization": services.encode(b"actual-owner-envelope"),
    }
    assert worker._admit(admission_phase, UUID(int=1)) == "synthetic-expectation"
    assert calls == [
        (
            "synthetic",
            admission_phase,
            UUID(int=1),
            b"actual-owner-envelope" if admission_phase == "consume" else None,
        )
    ]
    assert worker._request["authorization"] == services.encode(b"actual-owner-envelope")
    assert "workload_token" not in worker._request


def test_missing_startup_sessions_refuses_before_owner_install(monkeypatch):
    installs = []
    monkeypatch.setattr(
        services, "assemble_gate0_composition", lambda **kwargs: installs.append(kwargs)
    )
    with pytest.raises(ServiceRefused):
        services.IssuerWorker(
            SimpleNamespace(
                database_qualified=True, actor_ref="synthetic-actor", sessions=None
            )
        )
    assert installs == []


@pytest.mark.parametrize("matching_factory", [False, True])
def test_production_sessions_must_be_the_owner_reader_runtime_factory(
    monkeypatch, matching_factory
):
    from vendor_cp.deployment.gate0_workload_admission import OwnerWorkloadAdmission

    installs = []
    monkeypatch.setattr(
        services, "assemble_gate0_composition", lambda **kwargs: installs.append(kwargs)
    )
    # Sensitivity: even a caller that asserts qualification and passes an
    # exact owner-admission instance cannot substitute the mutation factory.
    # This synthetic boundary test constructs an incomplete provider only to
    # isolate factory identity; its positive is not live DB qualification.
    admission = object.__new__(OwnerWorkloadAdmission)

    def trusted_factory():
        pytest.fail("session provenance check must not open the trusted database")

    admission._reader = SimpleNamespace(
        _runtime=SimpleNamespace(platform_session_factory=trusted_factory)
    )
    startup = SimpleNamespace(
        database_qualified=True,
        actor_ref="synthetic-actor",
        require_frozen_window=True,
        admission=admission,
        sessions=trusted_factory
        if matching_factory
        else lambda: pytest.fail("unrelated database was opened"),
        verifier=object(),
        signer=object(),
        authorization_verifier=object(),
        authorization_ttl=object(),
    )
    if matching_factory:
        services.IssuerWorker(startup)
        assert len(installs) == 1 and installs[0]["sessions"] is trusted_factory
    else:
        with pytest.raises(ServiceRefused):
            services.IssuerWorker(startup)
        assert installs == []


@pytest.fixture
def refusal_association_case(monkeypatch):
    """Synthetic identities isolate exact service attribution, not cryptography."""
    from datetime import UTC, datetime

    from dotmac_deployment_control import (
        RehearsalIssuerIssuanceRefusalCode,
        RehearsalIssuerIssuanceRefusedError,
    )

    from vendor_cp.deployment.gate0_framing import canonical
    from vendor_cp.deployment.gate0_runtime import ProofRegistrationRefused

    plan = UUID(int=1)
    expected = SimpleNamespace(
        operation=SimpleNamespace(plan_id=str(plan), phase="consume"),
        window_digest=services.digest(b"synthetic-window"),
    )
    owner = b"synthetic-new-owner-proof"
    new_digest = services.digest(owner)
    old_digest = services.digest(b"synthetic-old-owner-proof")
    old_bundle = canonical({"synthetic_bundle": "old"})
    new_document = {"synthetic_bundle": "new"}
    new_bundle = canonical(new_document)
    registered = {old_digest, new_digest}
    state = {"mode": "before-proof", "registrations": 0, "calls": 0}
    worker_box = {}

    def exported(selected):
        if selected not in registered:
            raise ProofRegistrationRefused()
        return SimpleNamespace(context=expected.operation)

    def register(produced, operation):
        state["registrations"] += 1
        if state["mode"] == "registration-failed":
            raise ProofRegistrationRefused()
        if state["mode"] == "registration-interrupted":
            raise services.ServiceCancelled()
        registered.add(new_digest)
        return new_digest

    def admit(*args):
        if state["mode"] == "before-proof":
            from vendor_cp.deployment.gate0_window import (
                AuthenticatedApprovalWithdrawal,
            )

            raise AuthenticatedApprovalWithdrawal(
                SimpleNamespace(
                    window=SimpleNamespace(digest=expected.window_digest),
                    plan_id=plan,
                    phase=expected.operation.phase,
                )
            )
        return expected

    verifier = SimpleNamespace(
        _require_open=lambda: None,
        export_registered=exported,
        _register=register,
        _retained_bytes=0,
        _key_id="synthetic-attester",
        _public_key=b"synthetic",
        _trust=None,
    )

    def refused():
        raise RehearsalIssuerIssuanceRefusedError(
            RehearsalIssuerIssuanceRefusalCode.ENVELOPE_MISMATCH,
            "sensitive-owner-detail",
        )

    def mutate(*args):
        state["calls"] += 1
        worker = worker_box["worker"]
        worker._admit(expected.operation.phase, plan)
        if state["mode"] != "before-proof":
            worker._proof(expected)
        refused()

    def standing(authorization, selected):
        state["calls"] += 1
        worker_box["worker"]._admit("consume", plan)
        refused()

    monkeypatch.setattr(
        services,
        "assemble_gate0_composition",
        lambda **kwargs: SimpleNamespace(
            issue=mutate, consume=mutate, standing=standing
        ),
    )
    monkeypatch.setattr(
        services,
        "parse_bundle",
        lambda document: (
            SimpleNamespace(
                control_document=canonical({"canonical_bytes": services.encode(owner)})
            ),
            object(),
        ),
    )
    monkeypatch.setattr(services, "verify_observation", lambda **kwargs: None)
    worker = services.IssuerWorker(
        SimpleNamespace(
            database_qualified=True,
            actor_ref="synthetic-actor",
            sessions=lambda: None,
            require_frozen_window=False,
            custody=None,
            verifier=verifier,
            admission=SimpleNamespace(
                admit=admit,
                window_record_digest=lambda packet: expected.window_digest,
            ),
            signer=None,
            authorization_verifier=None,
            authorization_ttl=None,
            now=lambda: datetime.now(UTC),
        )
    )
    worker_box["worker"] = worker
    worker._bundles = {old_digest: old_bundle, new_digest: new_bundle}
    worker._bundle_bytes = len(old_bundle) + len(new_bundle)

    def request(operation="consume", selected=old_digest):
        value = {
            "schema": "Gate0IssuerSubmission.v1",
            "operation": operation,
            "workload_token": "sensitive-synthetic-token",
        }
        if operation == "standing":
            value.update(
                authorization=services.encode(b"synthetic-authorization"),
                evidence_digest=selected,
            )
        elif operation == "issue":
            value.update(
                plan_id=str(plan), command_id="synthetic-command", proof=new_document
            )
        else:
            value.update(
                plan_id=str(plan),
                authorization=services.encode(b"synthetic-authorization"),
                proof=new_document,
            )
        return value

    return SimpleNamespace(
        worker=worker,
        state=state,
        expected=expected,
        request=request,
        old_digest=old_digest,
        new_digest=new_digest,
        old_bundle=old_bundle,
        new_bundle=new_bundle,
        registered=registered,
    )


def assert_terminal_exact(case, request, proof_digest, bundle_digest):
    from vendor_cp.deployment.gate0_collection import request_identity
    from vendor_cp.deployment.gate0_framing import canonical

    class CountedChannel(SyntheticManagementChannel):
        reads = 0

        def receive(self, allow_eof=False):
            self.reads += 1
            return super().receive(allow_eof)

    identity = request_identity(request)
    channel = CountedChannel([request, dict(request)])
    with pytest.raises(services.ServiceOwnerRefused) as caught:
        case.worker.run(channel)
    outcome = caught.value.outcome
    assert outcome.ordinal == 1 and outcome.request_digest == identity
    assert (
        outcome.proof_digest == proof_digest and outcome.bundle_digest == bundle_digest
    )
    assert channel.reads == 1 and len(channel.output) == 1
    assert b"sensitive" not in canonical(channel.output[0])
    assert case.worker._current_proof_identity is None
    assert case.worker._request is None
    with pytest.raises(ServiceRefused):
        case.worker.run(channel)
    assert channel.reads == 1
    return outcome


def test_standing_refusal_keeps_selected_earlier_same_phase_proof(
    refusal_association_case,
):
    case = refusal_association_case
    assert_terminal_exact(
        case,
        case.request("standing"),
        case.old_digest,
        services.digest(case.old_bundle),
    )
    assert case.state["registrations"] == 0


@pytest.mark.parametrize("operation", ["issue", "consume"])
def test_pre_registration_refusal_cannot_acquire_historical_identity(
    refusal_association_case, operation
):
    case = refusal_association_case
    case.expected.operation.phase = operation
    # Simulate the previous frame's identity; accepted-frame reset must erase it.
    case.worker._current_proof_identity = (
        case.new_digest,
        services.digest(case.new_bundle),
    )
    outcome = assert_terminal_exact(case, case.request(operation), None, None)
    assert outcome.owner_namespace == "approvals"
    assert case.state["registrations"] == 0


def test_new_registration_refusal_uses_only_current_proof(refusal_association_case):
    case = refusal_association_case
    case.state["mode"] = "after-proof"
    del case.worker._bundles[case.new_digest]
    case.registered.remove(case.new_digest)
    assert_terminal_exact(
        case, case.request(), case.new_digest, services.digest(case.new_bundle)
    )
    assert case.state["registrations"] == 1


@pytest.mark.parametrize("selection", ["invalid", "unregistered", "missing-bundle"])
def test_invalid_standing_selection_cannot_borrow_retained_identity(
    refusal_association_case, selection
):
    case = refusal_association_case
    selected = (
        "sha256:" + "z" * 64 if selection == "invalid" else services.digest(b"unknown")
    )
    if selection == "missing-bundle":
        selected = case.old_digest
        del case.worker._bundles[selected]
    channel = SyntheticManagementChannel([case.request("standing", selected)])
    with pytest.raises(ValueError):
        case.worker.run(channel)
    assert channel.output == [] and case.state["calls"] == 0
    assert case.worker._current_proof_identity is None


def test_exact_replay_retains_exact_current_digest(refusal_association_case):
    from dotmac_deployment_control import RehearsalIssuerIssuanceRefusalCode

    case = refusal_association_case
    case.state["mode"] = "after-proof"
    outcome = assert_terminal_exact(
        case, case.request(), case.new_digest, services.digest(case.new_bundle)
    )
    assert (
        outcome.owner_code == RehearsalIssuerIssuanceRefusalCode.ENVELOPE_MISMATCH.value
    )
    assert case.state["registrations"] == 1


@pytest.mark.parametrize(
    "failure",
    [
        "registration-failed",
        "registration-interrupted",
        "retention-budget",
        "bundle-conflict",
    ],
)
def test_failed_proof_registration_or_retention_never_sets_current_identity(
    refusal_association_case, failure
):
    case = refusal_association_case
    case.state["mode"] = failure
    if failure == "retention-budget":
        del case.worker._bundles[case.new_digest]
        case.worker._bundle_bytes = 512 * 1024
    if failure == "bundle-conflict":
        case.worker._bundles[case.new_digest] = b"different-exact-bundle"
    channel = SyntheticManagementChannel([case.request(), case.request()])
    with pytest.raises((ValueError, services.ServiceCancelled)):
        case.worker.run(channel)
    assert channel.output == [] and case.worker._current_proof_identity is None
    assert next(channel.requests)["operation"] == "consume"
    with pytest.raises(ServiceRefused):
        case.worker.run(channel)
