"""Hosted-only finite worker dispatch and single-install checks."""

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
        require_frozen_window=False,  # Explicit synthetic dispatch mechanism.
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
        require_frozen_window=False,  # Explicit synthetic dispatch mechanism.
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
        require_frozen_window=False,  # Explicit synthetic dispatch mechanism.
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
