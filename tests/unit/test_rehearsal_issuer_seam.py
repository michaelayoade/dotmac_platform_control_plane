"""The leaf carries only Control a14's request fields and opaque evidence."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, fields
from uuid import UUID

import pytest

from vendor_cp.deployment.rehearsal_issuer_seam import (
    RehearsalIssuerCommand,
    RehearsalIssuerInvocation,
)

PLAN_ID = UUID("8f548790-5957-46f8-8438-6d1ec7240499")


def test_command_has_only_three_fields_and_exact_control_request_keys() -> None:
    assert tuple(field.name for field in fields(RehearsalIssuerCommand)) == (
        "command_id",
        "plan_id",
        "actor_ref",
    )
    command = RehearsalIssuerCommand("command-1", PLAN_ID, "operator-1")

    assert dict(command.to_control_request()) == {
        "command_id": "command-1",
        "plan_id": PLAN_ID,
        "actor_ref": "operator-1",
    }
    assert command.to_control_request()["plan_id"] is PLAN_ID


def test_invocation_has_only_command_and_opaque_evidence_fields() -> None:
    assert tuple(field.name for field in fields(RehearsalIssuerInvocation)) == (
        "command",
        "harness_evidence_document",
    )


def test_absent_actor_is_omitted_and_request_cannot_be_rewritten() -> None:
    command = RehearsalIssuerCommand("command-1", PLAN_ID)
    request = command.to_control_request()

    assert dict(request) == {"command_id": "command-1", "plan_id": PLAN_ID}
    assert "actor_ref" not in request
    with pytest.raises(TypeError):
        request["command_id"] = "rewritten"  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        command.command_id = "rewritten"  # type: ignore[misc]


@pytest.mark.parametrize("blank", ["", " ", "\t\n"])
def test_blank_command_id_is_refused(blank: str) -> None:
    with pytest.raises(ValueError, match="command_id"):
        RehearsalIssuerCommand(blank, PLAN_ID)


@pytest.mark.parametrize("blank", ["", " ", "\t\n"])
def test_blank_actor_ref_is_refused(blank: str) -> None:
    with pytest.raises(ValueError, match="actor_ref"):
        RehearsalIssuerCommand("command-1", PLAN_ID, blank)


def test_non_string_command_id_has_deterministic_type_refusal() -> None:
    with pytest.raises(TypeError, match="^command_id must be a string$"):
        RehearsalIssuerCommand(123, PLAN_ID)  # type: ignore[arg-type]


def test_non_uuid_plan_id_has_deterministic_type_refusal() -> None:
    with pytest.raises(TypeError, match="^plan_id must be a UUID$"):
        RehearsalIssuerCommand("command-1", str(PLAN_ID))  # type: ignore[arg-type]


def test_non_string_actor_ref_has_deterministic_type_refusal() -> None:
    with pytest.raises(TypeError, match="^actor_ref must be a string when present$"):
        RehearsalIssuerCommand("command-1", PLAN_ID, 123)  # type: ignore[arg-type]


def test_nonblank_values_are_carried_without_normalization() -> None:
    command = RehearsalIssuerCommand(" command-1 ", PLAN_ID, " actor-1 ")
    assert dict(command.to_control_request()) == {
        "command_id": " command-1 ",
        "plan_id": PLAN_ID,
        "actor_ref": " actor-1 ",
    }


def test_invocation_preserves_opaque_evidence_identity_without_interpretation() -> None:
    class OpaqueEvidence:
        def __getattribute__(self, name: str) -> object:
            raise AssertionError(f"evidence was inspected: {name}")

    evidence = OpaqueEvidence()
    command = RehearsalIssuerCommand("command-1", PLAN_ID)
    invocation = RehearsalIssuerInvocation(command, evidence)

    assert invocation.harness_evidence_document is evidence
    assert dict(invocation.to_control_request()) == {
        "command_id": "command-1",
        "plan_id": PLAN_ID,
    }
    with pytest.raises(FrozenInstanceError):
        invocation.harness_evidence_document = object()  # type: ignore[misc]


def test_invocation_refuses_fake_command_without_calling_it() -> None:
    class FakeCommand:
        def to_control_request(self) -> object:
            raise AssertionError("fake command was executed")

    with pytest.raises(TypeError, match="^command must be a RehearsalIssuerCommand$"):
        RehearsalIssuerInvocation(FakeCommand(), object())  # type: ignore[arg-type]


def test_invocation_refuses_command_subclass_without_calling_override() -> None:
    class MaliciousCommand(RehearsalIssuerCommand):
        def to_control_request(self) -> object:  # type: ignore[override]
            raise AssertionError("subclass callback was executed")

    command = MaliciousCommand("command-1", PLAN_ID)
    with pytest.raises(TypeError, match="^command must be a RehearsalIssuerCommand$"):
        RehearsalIssuerInvocation(command, object())
