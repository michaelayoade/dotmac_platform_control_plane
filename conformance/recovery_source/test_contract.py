"""Explicit sibling-source qualification only; no installed/native assertion."""

import json
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from importlib.metadata import version
from uuid import UUID, uuid4

import dotmac_deployment_control as control
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from vendor_cp.deployment import materials_producer as cp
from vendor_cp.deployment.verification_identities import (
    AuthorizationEd25519Verifier,
    PinnedVerificationIdentity,
)


def identity(key, purpose):
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    text = cp._b64url(raw)
    return PinnedVerificationIdentity(
        purpose,
        "ed25519",
        purpose,
        raw,
        text,
        control.PublicKeyFingerprintV1.from_public_key_b64(text).canonical,
    )


@pytest.fixture
def invocation():
    auth, dispatch = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    signed = []

    def sign(message):
        signed.append(message)
        return dispatch.sign(message)

    custody = cp.Custody(
        identity(auth, "deployment_authorization"),
        identity(dispatch, "deployment_dispatch"),
        auth.sign,
        sign,
    )
    now = datetime.now(UTC)
    fields = dict(
        authorization_id=str(uuid4()),
        execution_sequence=1,
        rollout_ref="original",
        plan_id=str(uuid4()),
        target_id=str(uuid4()),
        target_ref="fixture",
        product_code="fixture",
        environment="test",
        operation="deploy",
        release_ref="fixture@sha256:" + "aa" * 32,
        authorized_images=[
            dict(service="app", repository="fixture/app", digest="sha256:" + "aa" * 32)
        ],
        plan_digest="sha256:" + "bb" * 32,
        descriptor_digest="sha256:" + "cc" * 32,
        execution_plan_digest="sha256:" + "dd" * 32,
        approval_policy_code="fixture",
        approval_policy_version=1,
        approval_decision_ref=str(uuid4()),
        approval_decision_status="granted",
        approved_at=now - timedelta(minutes=2),
        issued_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(minutes=20),
    )
    envelope = control.issue_authorization_envelope(
        fields, signer=cp._AuthorizationSigner(custody)
    )
    expectation = control.DispatchResumeExpectation(
        rollout_id=UUID(fields["authorization_id"]),
        plan_id=UUID(fields["plan_id"]),
        rollout_ref="original",
        rollout_command_id="original-string-command",
        dispatch_command_id="unused-string-command",
        execution_sequence=1,
        original_authorization=envelope,
    )
    original = cp.IssueDispatchRequest(
        expectation.plan_id,
        "original",
        expectation.rollout_command_id,
        expectation.dispatch_command_id,
        fields["expires_at"],
        "SHA256:fixture",
        "host",
        "incarnation",
        str(uuid4()),
    )
    request = cp.RecoverDispatchRequest(
        original,
        expectation,
        "fixture-session",
        now - timedelta(seconds=1),
        now + timedelta(minutes=4),
    )
    return request, custody, signed


def projection(request):
    original = asdict(request.original_request)
    original["plan_id"] = str(original["plan_id"])
    original["authorization_expires_at"] = original[
        "authorization_expires_at"
    ].isoformat()
    return dict(
        original_request=original,
        resume_expectation=request.expectation.as_mapping(),
        session_id=request.session_id,
        not_before=request.not_before.isoformat(),
        deadline=request.deadline.isoformat(),
    )


def test_closed_projection_round_trip_and_original_signature(invocation, tmp_path):
    request, custody, _ = invocation
    path = tmp_path / "public-projection.json"
    path.write_text(json.dumps(projection(request)))
    parsed = cp.load_recovery_request(
        str(path), expected_sha256=sha256(path.read_bytes()).hexdigest()
    )
    assert parsed == request
    assert (
        control.verify_authorization_envelope(
            parsed.expectation.original_authorization,
            verifier=AuthorizationEd25519Verifier(custody.authorization_identity),
        )
        == request.expectation.original_authorization
    )


@pytest.mark.parametrize(
    "change",
    [
        "extra",
        "bool-command",
        "naive",
        "changed-host",
        "changed-expiry",
        "changed-command",
    ],
)
def test_projection_boundaries(invocation, tmp_path, change):
    request, _, _ = invocation
    value = projection(request)
    if change == "extra":
        value["extra"] = False
    elif change == "bool-command":
        value["original_request"]["rollout_command_id"] = True
    elif change == "naive":
        value["deadline"] = datetime.now().isoformat()
    elif change == "changed-host":
        value["original_request"]["host_id"] = ""
    elif change == "changed-expiry":
        value["original_request"]["authorization_expires_at"] = (
            request.deadline.isoformat()
        )
    else:
        value["original_request"]["dispatch_command_id"] = "altered"
    path = tmp_path / "projection.json"
    path.write_text(json.dumps(value))
    with pytest.raises(cp.FoundationBindingsUnavailable):
        cp.load_recovery_request(
            str(path), expected_sha256=sha256(path.read_bytes()).hexdigest()
        )


def test_signer_uses_owner_parser_actual_version_and_verifies_signature(invocation):
    request, custody, signed = invocation
    envelope = control.issue_dispatch_envelope(
        authorization_envelope=request.expectation.original_authorization,
        dispatch_id=str(uuid4()),
        attempt_no=1,
        issued_at=datetime.now(UTC),
        signer=cp._RecoveryDispatchSigner(custody, request),
    )
    assert len(signed) == 1
    assert envelope.statement.control_version == version("dotmac-deployment-control")
    assert custody.dispatch_identity.verify_signature(signed[0], envelope.signature)
    assert (
        envelope.statement.authorization_envelope_digest
        == "sha256:"
        + sha256(request.expectation.original_authorization.canonical_bytes).hexdigest()
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("rollout_ref", "different"),
        ("attempt_no", 2),
        ("dispatch_id", str(UUID(int=0))),
        ("control_version", "other"),
    ],
)
def test_owner_binding_refuses_changed_unsigned_input_before_custody(
    invocation, field, value
):
    request, custody, signed = invocation
    envelope = control.issue_dispatch_envelope(
        authorization_envelope=request.expectation.original_authorization,
        dispatch_id=str(uuid4()),
        attempt_no=1,
        issued_at=datetime.now(UTC),
        signer=cp._DispatchSigner(custody),
    )
    signed.clear()
    altered = replace(envelope.statement, **{field: value})
    signer = cp._RecoveryDispatchSigner(custody, request)
    with pytest.raises(control.DispatchEnvelopeRefusedError):
        signer.sign_dispatch(altered.canonical_bytes)
    assert signed == []
    with pytest.raises(cp.FoundationBindingsUnavailable):
        signer.sign_dispatch(envelope.statement.canonical_bytes)
    assert signed == []


def test_bad_original_signature_refuses_before_rollout_or_dispatch(invocation):
    request, custody, signed = invocation
    envelope = replace(
        request.expectation.original_authorization, signature=cp._b64url(bytes(64))
    )
    expectation = replace(request.expectation, original_authorization=envelope)

    class NoDatabase:
        def __getattr__(self, name):
            raise AssertionError("invalid original authorization reached DB")

    with pytest.raises(control.AuthorizationEnvelopeRefusedError):
        cp.recover_dispatch_materials(
            NoDatabase(), replace(request, expectation=expectation), custody=custody
        )
    assert signed == []


def test_noncanonical_input_never_reaches_custody(invocation):
    request, custody, signed = invocation
    envelope = control.issue_dispatch_envelope(
        authorization_envelope=request.expectation.original_authorization,
        dispatch_id=str(uuid4()),
        attempt_no=1,
        issued_at=datetime.now(UTC),
        signer=cp._DispatchSigner(custody),
    )
    signed.clear()
    noncanonical = json.dumps(envelope.statement.as_mapping(), indent=2).encode()
    with pytest.raises(cp.FoundationBindingsUnavailable):
        cp._RecoveryDispatchSigner(custody, request).sign_dispatch(noncanonical)
    assert signed == []
