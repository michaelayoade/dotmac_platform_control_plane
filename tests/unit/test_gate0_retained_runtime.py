"""Historical signed facts; no backdated live producer/verifier fixtures."""

from __future__ import annotations

import copy
import subprocess
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    SSHCertificateBuilder,
    SSHCertificateType,
)

from vendor_cp.deployment import gate0_runtime
from vendor_cp.deployment.gate0_attester import (
    ProducedAttestation,
    ssh_public_fingerprint,
)
from vendor_cp.deployment.gate0_framing import canonical, strict_object
from vendor_cp.deployment.gate0_github_jwt import _FIXED_CLAIMS
from vendor_cp.deployment.gate0_observation import (
    SignedSessionObservation,
    bundle_document,
    decode,
    digest,
    encode,
    observation_message,
)
from vendor_cp.deployment.gate0_runtime import (
    AdmittedOperation,
    AttestationContext,
    BoundedHarnessVerifier,
    CompanionAttestation,
    ProofRegistrationRefused,
    companion_message,
    verify_retained_bundle,
)
from vendor_cp.deployment.gate0_window import FrozenIssuerWindow
from vendor_cp.deployment.rehearsal_issuer_trust_state import parse_trust_snapshot


@pytest.fixture
def historical_bundle(tmp_path: Path):
    at = datetime(2025, 1, 1, tzinfo=UTC)
    controller, ca, attester = (Ed25519PrivateKey.generate() for _ in range(3))
    public = attester.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    cert = (
        SSHCertificateBuilder()
        .public_key(controller.public_key())
        .type(SSHCertificateType.USER)
        .key_id(b"gate0:1:2:1")
        .valid_principals([b"dotmac-gate0-controller"])
        .valid_after(int(at.timestamp()) - 1)
        .valid_before(int(at.timestamp()) + 120)
        .sign(ca)
        .public_bytes()
    )
    operation = AdmittedOperation(
        repository_id=_FIXED_CLAIMS["repository_id"],
        run_id="2",
        run_attempt="1",
        window_id="historical",
        phase="issue",
        authorization_digest=None,
        authorization_issued_at=None,
        lease_id="lease",
        controller_fingerprint=ssh_public_fingerprint(controller.public_key()),
        target_ref="target",
        plan_id="00000000-0000-0000-0000-000000000001",
        plan_digest=digest(b"plan"),
        plan_purpose="rehearsal_issuer_operation",
        operation="deploy",
        execution_plan_digest=digest(b"execution"),
        certificate_digest=digest(cert),
        ca_fingerprint=ssh_public_fingerprint(ca.public_key()),
    )
    # Certificate key-id is derived from the same independently fixed run packet.
    cert = (
        SSHCertificateBuilder()
        .public_key(controller.public_key())
        .type(SSHCertificateType.USER)
        .key_id(f"gate0:{operation.repository_id}:2:1".encode())
        .valid_principals([b"dotmac-gate0-controller"])
        .valid_after(int(at.timestamp()) - 1)
        .valid_before(int(at.timestamp()) + 120)
        .sign(ca)
        .public_bytes()
    )
    operation = replace(operation, certificate_digest=digest(cert))
    window_doc = dict(
        schema="Gate0IssuerWindow.v1",
        case_kind="consume_replay",
        window_id="historical",
        not_before=(at - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        expires_at=(at + timedelta(seconds=120)).isoformat().replace("+00:00", "Z"),
        purpose="rehearsal_issuer_operation",
        allowed_phases=["issue", "consume"],
        github=dict(
            _FIXED_CLAIMS,
            run_id="2",
            run_attempt="1",
            sub="exact-sub",
            workflow_sha="a" * 40,
            environment_node_id="node",
        ),
        target=dict(
            id=operation.plan_id,
            ref="target",
            environment="rehearsal",
            operation="deploy",
        ),
        approval_policy=dict(code="policy", version=1),
        plan_inputs=dict(
            source_ref="source",
            config_ref="config",
            descriptor_digest=digest(b"descriptor"),
            execution_plan_digest=operation.execution_plan_digest,
        ),
        controller=dict(
            lease_id="lease",
            fingerprint=operation.controller_fingerprint,
            certificate_digest=operation.certificate_digest,
            ca_fingerprint=operation.ca_fingerprint,
            principal="dotmac-gate0-controller",
            certificate_ttl_ceiling_seconds=600,
        ),
        prerequisite_evidence_refs=[digest(b"prerequisite")],
        authorization_binding="control_parsed_full_envelope_v1",
    )
    window = FrozenIssuerWindow.parse(canonical(window_doc))
    challenge = canonical(
        dict(
            schema="Gate0PossessionChallenge.v1",
            instance_id="1" * 64,
            challenge_id="2" * 64,
            nonce="3" * 64,
            context=asdict(operation),
            expires_at=(at + timedelta(seconds=20)).isoformat().replace("+00:00", "Z"),
        )
    )
    key_path = tmp_path / "controller"
    key_path.write_bytes(
        controller.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())
    )
    key_path.chmod(0o600)
    signed = subprocess.run(  # noqa: S603 -- fixed synthetic native SSHSIG fixture
        [
            "/usr/bin/ssh-keygen",
            "-Y",
            "sign",
            "-f",
            str(key_path),
            "-n",
            "dotmac-gate0-possession-v1",
        ],
        input=challenge,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=2,
        check=True,
    ).stdout
    transcript = canonical(
        dict(
            schema="Gate0PublicProofTranscript.v1",
            certificate=encode(cert),
            challenge=encode(challenge),
            sshsig=encode(signed),
        )
    )
    context = AttestationContext(
        **asdict(operation),
        challenge_digest=digest(challenge),
        proof_transcript_digest=digest(transcript),
    )
    owner = canonical(
        dict(
            schema="dotmac.deployment_control.rehearsal_harness_evidence",
            version=1,
            lease_id="lease",
            controller_fingerprint=operation.controller_fingerprint,
            target_ref="target",
            environment="rehearsal",
            issued_at=at.isoformat().replace("+00:00", "Z"),
            valid_until=(at + timedelta(seconds=30)).isoformat().replace("+00:00", "Z"),
        )
    )
    companion = companion_message(context, owner)
    proof = ProducedAttestation(
        canonical(
            dict(
                canonical_bytes=encode(owner),
                signature=dict(
                    key_id="attester",
                    algorithm="ed25519",
                    signature=encode(attester.sign(owner)),
                ),
            )
        ),
        CompanionAttestation(companion, attester.sign(companion)),
        context,
        transcript,
    )
    observation = observation_message(
        proof=proof,
        operation=operation,
        window_record_digest=window.digest,
        invocation_id="4" * 64,
        observed_from=at - timedelta(milliseconds=100),
        observed_until=at + timedelta(milliseconds=100),
    )
    raw = canonical(
        bundle_document(
            proof, SignedSessionObservation(observation, attester.sign(observation))
        )
    )
    snapshot = parse_trust_snapshot(
        dict(
            version=1, trusted_key_ids={"attester": digest(public)}, revoked_key_ids=[]
        ),
        minimum_version=1,
    )
    return dict(
        raw=raw,
        expected=operation,
        frozen_window=window,
        key_id="attester",
        public_key=public,
        trust_state=snapshot,
        at=at,
        attester=attester,
    )


def verify(fixture, **updates):
    terms = {
        key: value for key, value in fixture.items() if key not in {"at", "attester"}
    }
    terms.update(updates)
    return verify_retained_bundle(**terms)


def test_historical_verification_is_not_current_eligibility(
    historical_bundle, monkeypatch
):
    expected_at = historical_bundle["at"]
    result = verify(historical_bundle)
    assert result.observed_from < expected_at < result.observed_until
    assert result.invocation_id == "4" * 64
    assert result.proof_digest == digest(
        decode(strict_object(result.proof.control_document)["canonical_bytes"], 8192)
    )
    assert not hasattr(result, "verify_rehearsal_harness_evidence")
    with pytest.raises(ProofRegistrationRefused):
        BoundedHarnessVerifier(
            key_id="attester",
            public_key=historical_bundle["public_key"],
            trust_state=None,
            expires_at=expected_at + timedelta(seconds=120),
        )

    def forbidden(*_args, **_kwargs):
        raise AssertionError(
            "historical verification constructed a live clock capability"
        )

    monkeypatch.setattr(gate0_runtime, "BoundedHarnessVerifier", forbidden)
    monkeypatch.setattr(gate0_runtime, "ProtectedHarnessVerifier", forbidden)
    monkeypatch.setattr(gate0_runtime, "_utc_now", forbidden)
    assert verify(historical_bundle).bundle_digest == digest(historical_bundle["raw"])


@pytest.mark.parametrize(
    "field",
    [
        "companion_signature",
        "observation_signature",
        "control_document",
        "transcript",
        "context",
    ],
)
def test_each_retained_proof_layer_tamper_refuses(historical_bundle, field):
    document = strict_object(historical_bundle["raw"])
    if field == "context":
        document[field]["run_id"] = "3"
    else:
        raw = bytearray(decode(document[field], 128 * 1024))
        raw[-1] ^= 1
        document[field] = encode(bytes(raw))
    with pytest.raises(ProofRegistrationRefused):
        verify(historical_bundle, raw=canonical(document))


def test_historical_trust_revoked_wins_and_wrong_key_refuses(historical_bundle):
    snapshot = parse_trust_snapshot(
        dict(
            version=1,
            trusted_key_ids={"attester": digest(historical_bundle["public_key"])},
            revoked_key_ids=["attester"],
        ),
        minimum_version=1,
    )
    with pytest.raises(ProofRegistrationRefused):
        verify(historical_bundle, trust_state=snapshot)
    with pytest.raises(ProofRegistrationRefused):
        verify(historical_bundle, public_key=bytes(32))


def test_original_window_cannot_be_replaced_with_a_new_current_window(
    historical_bundle,
):
    document = copy.deepcopy(historical_bundle["frozen_window"].document)
    now = datetime.now(UTC).replace(microsecond=0)
    document["not_before"] = now.isoformat().replace("+00:00", "Z")
    document["expires_at"] = (
        (now + timedelta(seconds=120)).isoformat().replace("+00:00", "Z")
    )
    with pytest.raises(ProofRegistrationRefused):
        verify(
            historical_bundle,
            frozen_window=FrozenIssuerWindow.parse(canonical(document)),
        )


def test_live_registration_keeps_clock_guards_and_budget_outside_shared_predicate():
    """Structural sensitivity guard for historical/live authority separation."""
    import ast
    import inspect
    import textwrap

    tree = ast.parse(
        textwrap.dedent(
            inspect.getsource(gate0_runtime.BoundedHarnessVerifier._prepare)
        )
    )
    calls = [
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    ]
    assert calls.count("_require_open") >= 2
    register = inspect.getsource(gate0_runtime.BoundedHarnessVerifier._register)
    assert "len(self._entries) >= 4" in register
    assert "512 * 1024" in register
    historical = ast.parse(textwrap.dedent(inspect.getsource(verify_retained_bundle)))
    forbidden = {
        "BoundedHarnessVerifier",
        "ProtectedHarnessVerifier",
        "WindowFreshness",
    }
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in forbidden
        for node in ast.walk(historical)
    )


@pytest.mark.parametrize(
    "field,value",
    [("target_ref", "swapped"), ("environment", "production"), ("lease_id", "other")],
)
def test_even_resigned_owner_must_match_the_frozen_context(
    historical_bundle, field, value
):
    document = strict_object(historical_bundle["raw"])
    envelope = strict_object(decode(document["control_document"], 128 * 1024))
    owner = strict_object(decode(envelope["canonical_bytes"], 8192))
    owner[field] = value
    owner_bytes = canonical(owner)
    signer = historical_bundle["attester"]
    envelope["canonical_bytes"] = encode(owner_bytes)
    envelope["signature"]["signature"] = encode(signer.sign(owner_bytes))
    document["control_document"] = encode(canonical(envelope))
    context = AttestationContext(**document["context"])
    companion = companion_message(context, owner_bytes)
    document["companion"] = encode(companion)
    document["companion_signature"] = encode(signer.sign(companion))
    with pytest.raises(ProofRegistrationRefused):
        verify(historical_bundle, raw=canonical(document))


def test_resigned_transcript_does_not_replace_actual_native_possession(
    historical_bundle,
):
    document = strict_object(historical_bundle["raw"])
    transcript = strict_object(decode(document["transcript"], 128 * 1024))
    transcript["sshsig"] = encode(b"not-an-SSHSIG")
    transcript_bytes = canonical(transcript)
    document["transcript"] = encode(transcript_bytes)
    document["context"]["proof_transcript_digest"] = digest(transcript_bytes)
    owner_envelope = strict_object(decode(document["control_document"], 128 * 1024))
    owner = decode(owner_envelope["canonical_bytes"], 8192)
    context = AttestationContext(**document["context"])
    companion = companion_message(context, owner)
    document["companion"] = encode(companion)
    document["companion_signature"] = encode(
        historical_bundle["attester"].sign(companion)
    )
    with pytest.raises(ProofRegistrationRefused):
        verify(historical_bundle, raw=canonical(document))


def test_retained_root_validator_cannot_manufacture_a_live_process_owner():
    import ast
    import inspect
    import textwrap

    from vendor_cp.deployment.gate0_runner_collector_handoff import (
        verify_retained_root_case,
    )

    tree = ast.parse(textwrap.dedent(inspect.getsource(verify_retained_root_case)))
    forbidden = {
        "OwnedCollectorHandoff",
        "OwnedIssuerSession",
        "OwnedAttesterSession",
        "InstalledRunnerCase",
        "RunnerProjectionCase",
        "WindowFreshness",
    }
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in forbidden
        for node in ast.walk(tree)
    )


def test_historical_public_seam_detaches_mutable_snapshot_input(
    historical_bundle, monkeypatch
):
    from vendor_cp.deployment.rehearsal_issuer_trust_state import TrustStateSnapshot

    trusted = {"attester": digest(historical_bundle["public_key"])}
    revoked = set()
    caller_snapshot = TrustStateSnapshot(1, trusted, revoked)
    actual_prepare = gate0_runtime._prepare_proof_bytes

    def mutate_after_public_entry(*args, **kwargs):
        # The input's backing containers change after entry, before the immutable
        # signature adapter is built. Verification must use the detached original.
        trusted.clear()
        revoked.add("attester")
        return actual_prepare(*args, **kwargs)

    monkeypatch.setattr(
        gate0_runtime, "_prepare_proof_bytes", mutate_after_public_entry
    )
    assert (
        verify(historical_bundle, trust_state=caller_snapshot).invocation_id == "4" * 64
    )
    assert not trusted and revoked == {"attester"}


def test_historical_signature_adapter_deep_detaches_direct_snapshot(historical_bundle):
    from vendor_cp.deployment.gate0_observation import parse_bundle
    from vendor_cp.deployment.rehearsal_issuer_trust_state import TrustStateSnapshot

    proof, _ = parse_bundle(strict_object(historical_bundle["raw"]))
    trusted = {"attester": digest(historical_bundle["public_key"])}
    revoked = set()
    snapshot = TrustStateSnapshot(1, trusted, revoked)
    adapter = gate0_runtime._RetainedHarnessSignature(
        "attester",
        historical_bundle["public_key"],
        snapshot,
        proof.context,
        proof.companion,
    )
    trusted["attester"] = digest(bytes(32))
    revoked.add("attester")
    envelope = strict_object(proof.control_document)
    assert adapter.verify_rehearsal_harness_evidence(
        key_id="attester",
        algorithm="ed25519",
        purpose="deployment_rehearsal_harness_evidence",
        canonical_bytes=decode(envelope["canonical_bytes"], 8192),
        signature=decode(envelope["signature"]["signature"], 64),
    )
    with pytest.raises(TypeError):
        adapter.trust_state.trusted_key_ids["attester"] = "changed"
    assert type(adapter.trust_state.revoked_key_ids) is frozenset
    assert "attester" not in adapter.trust_state.revoked_key_ids


@pytest.mark.parametrize(
    "version,trusted,revoked",
    [
        (True, {}, frozenset()),
        (0, {}, frozenset()),
        (1, {"bad key ": "fingerprint"}, frozenset()),
        (1, {}, ["duplicate", "duplicate"]),
        (1, {}, {"bad key "}),
    ],
)
def test_manual_snapshot_does_not_skip_existing_record_validation(
    version, trusted, revoked
):
    from vendor_cp.deployment.rehearsal_issuer_trust_state import TrustStateSnapshot

    with pytest.raises(ValueError):
        gate0_runtime._detach_retained_trust(
            TrustStateSnapshot(version, trusted, revoked)
        )
