"""Synthetic, non-authorizing composition inputs. Execute only in hosted CI."""

import base64
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    SSHCertificateBuilder,
    SSHCertificateType,
)

from vendor_cp.deployment.gate0_attester import (
    ProducedAttestation,
    ssh_public_fingerprint,
)
from vendor_cp.deployment.gate0_composition import (
    AdmissionExpectation,
    CompositionRefused,
    Gate0Composition,
    authorization_binding,
)
from vendor_cp.deployment.gate0_runtime import (
    AdmittedOperation,
    AttestationContext,
    BoundedHarnessVerifier,
    CompanionAttestation,
    ProofRegistrationRefused,
    companion_message,
)
from vendor_cp.deployment.rehearsal_issuer_seam import RehearsalIssuerCommand
from vendor_cp.deployment.rehearsal_issuer_trust_state import RehearsalIssuerTrustState


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


@pytest.fixture
def registry_fixture():
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    controller, ca = (Ed25519PrivateKey.generate() for _ in range(2))
    wall, elapsed = [datetime(2026, 10, 15, tzinfo=UTC)], [100.0]
    trust = RehearsalIssuerTrustState.start(
        minimum_version=2,
        read_record=lambda: {
            "version": 2,
            "trusted_key_ids": {"fixture-attester": digest(public)},
            "revoked_key_ids": [],
        },
    )
    registry = BoundedHarnessVerifier(
        key_id="fixture-attester",
        public_key=public,
        trust_state=trust,
        expires_at=wall[0] + timedelta(seconds=120),
        now=lambda: wall[0],
        monotonic_clock=lambda: elapsed[0],
    )

    stamp = int(wall[0].timestamp())
    certificate = (
        SSHCertificateBuilder()
        .public_key(controller.public_key())
        .type(SSHCertificateType.USER)
        .key_id(b"gate0:1:2:1")
        .valid_principals([b"dotmac-gate0-controller"])
        .valid_after(stamp - 1)
        .valid_before(stamp + 120)
        .sign(ca)
        .public_bytes()
    )

    def proof(index=0):
        operation = AdmittedOperation(
            repository_id="1",
            run_id="2",
            run_attempt="1",
            window_id="fixture-window",
            phase="issue",
            authorization_digest=None,
            authorization_issued_at=None,
            lease_id=f"fixture-lease-{index}",
            controller_fingerprint=ssh_public_fingerprint(controller.public_key()),
            target_ref="fixture-target",
            plan_id="00000000-0000-0000-0000-000000000001",
            plan_digest=digest(b"plan"),
            plan_purpose="rehearsal_issuer_operation",
            operation="deploy",
            execution_plan_digest=digest(b"execution"),
            certificate_digest=digest(certificate),
            ca_fingerprint=ssh_public_fingerprint(ca.public_key()),
        )
        challenge = canonical(
            {
                "schema": "Gate0PossessionChallenge.v1",
                "instance_id": "1" * 64,
                "challenge_id": "2" * 64,
                "nonce": "3" * 64,
                "context": asdict(operation),
                "expires_at": min(
                    wall[0] + timedelta(seconds=30),
                    datetime(2026, 10, 15, tzinfo=UTC) + timedelta(seconds=120),
                )
                .isoformat()
                .replace("+00:00", "Z"),
            }
        )
        transcript = canonical(
            {
                "schema": "Gate0PublicProofTranscript.v1",
                "certificate": base64.b64encode(certificate).decode(),
                "challenge": base64.b64encode(challenge).decode(),
                "sshsig": base64.b64encode(b"fixture-signature").decode(),
            }
        )
        context = AttestationContext(
            **asdict(operation),
            challenge_digest=digest(challenge),
            proof_transcript_digest=digest(transcript),
        )
        owner = canonical(
            {
                "schema": "dotmac.deployment_control.rehearsal_harness_evidence",
                "version": 1,
                "lease_id": operation.lease_id,
                "controller_fingerprint": operation.controller_fingerprint,
                "target_ref": operation.target_ref,
                "environment": "rehearsal",
                "issued_at": wall[0].isoformat().replace("+00:00", "Z"),
                "valid_until": min(
                    wall[0] + timedelta(seconds=30),
                    datetime(2026, 10, 15, tzinfo=UTC) + timedelta(seconds=120),
                )
                .isoformat()
                .replace("+00:00", "Z"),
            }
        )
        envelope = canonical(
            {
                "canonical_bytes": base64.b64encode(owner).decode(),
                "signature": {
                    "key_id": "fixture-attester",
                    "algorithm": "ed25519",
                    "signature": base64.b64encode(key.sign(owner)).decode(),
                },
            }
        )
        message = companion_message(context, owner)
        result = ProducedAttestation(
            envelope,
            CompanionAttestation(message, key.sign(message)),
            context,
            transcript,
        )
        return operation, result, owner, key.sign(owner)

    return registry, proof, wall, elapsed, trust, key


def test_registry_unknown_then_registered_and_every_call_checks_live_trust(
    registry_fixture,
):
    registry, proof, _, _, trust, _ = registry_fixture
    operation, result, owner, signature = proof()
    arguments = dict(
        key_id="fixture-attester",
        algorithm="ed25519",
        purpose="deployment_rehearsal_harness_evidence",
        canonical_bytes=owner,
        signature=signature,
    )
    assert registry.verify_rehearsal_harness_evidence(**arguments) is False
    evidence = registry._register(result, operation)
    assert evidence == digest(owner)
    assert registry.verify_rehearsal_harness_evidence(**arguments) is True
    trust.refresh(
        read_record=lambda: {
            "version": 3,
            "trusted_key_ids": {},
            "revoked_key_ids": ["fixture-attester"],
        }
    )
    assert registry.verify_rehearsal_harness_evidence(**arguments) is False


def test_equal_registration_concurrently_counts_once_and_fifth_refuses(
    registry_fixture,
):
    registry, proof, *_ = registry_fixture
    operation, result, *_ = proof()
    with ThreadPoolExecutor(max_workers=2) as pool:
        values = list(
            pool.map(lambda _: registry._register(result, operation), range(2))
        )
    assert values[0] == values[1]
    for i in range(1, 4):
        op, packet, *_ = proof(i)
        registry._register(packet, op)
    op, packet, *_ = proof(4)
    with pytest.raises(ProofRegistrationRefused):
        registry._register(packet, op)
    assert registry._retained_count == 4


def test_same_owner_hash_different_original_envelope_is_conflict(registry_fixture):
    registry, proof, *_ = registry_fixture
    op, packet, *_ = proof()
    registry._register(packet, op)
    modified = replace(packet, control_document=b" " + packet.control_document)
    with pytest.raises(ProofRegistrationRefused):
        registry._register(modified, op)
    assert (
        registry._evidence(digest(proof()[2])).owner_envelope == packet.control_document
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("phase", "consume"),
        ("window_id", "other-window"),
        ("run_attempt", "2"),
        ("repository_id", "9"),
        ("run_id", "9"),
        ("plan_id", str(UUID(int=9))),
        ("execution_plan_digest", digest(b"other-execution")),
        ("lease_id", "other-lease"),
        ("controller_fingerprint", "SHA256:" + "A" * 43),
        ("target_ref", "other-target"),
        ("certificate_digest", digest(b"other-certificate")),
        (
            "ca_fingerprint",
            "SHA256:" + base64.b64encode(b"B" * 32).decode().rstrip("="),
        ),
        ("plan_digest", digest(b"other-plan")),
    ],
)
def test_authentic_packet_cannot_override_independent_operation(
    registry_fixture, field, value
):
    registry, proof, *_ = registry_fixture
    op, packet, *_ = proof()
    if field == "phase":
        changed = replace(
            op,
            phase=value,
            authorization_digest=digest(b"issued"),
            authorization_issued_at="2026-10-14T00:00:00Z",
        )
    else:
        changed = replace(op, **{field: value})
    with pytest.raises(ProofRegistrationRefused):
        registry._register(packet, changed)
    assert registry._retained_count == 0


@pytest.mark.parametrize("where", ["transcript", "challenge", "companion", "signature"])
def test_tampered_retained_proof_refuses(registry_fixture, where):
    registry, proof, *_ = registry_fixture
    op, packet, *_ = proof()
    if where == "transcript":
        packet = replace(
            packet, public_proof_transcript=packet.public_proof_transcript + b" "
        )
    elif where == "challenge":
        transcript = json.loads(packet.public_proof_transcript)
        transcript["challenge"] = "!!!!"
        packet = replace(packet, public_proof_transcript=canonical(transcript))
    elif where == "companion":
        packet = replace(
            packet,
            companion=replace(
                packet.companion,
                canonical_bytes=packet.companion.canonical_bytes + b" ",
            ),
        )
    else:
        packet = replace(
            packet, companion=replace(packet.companion, signature=b"0" * 64)
        )
    with pytest.raises(ProofRegistrationRefused):
        registry._register(packet, op)


def test_enclosing_monotonic_deadline_cannot_reset_at_late_registration(
    registry_fixture,
):
    registry, proof, wall, elapsed, *_ = registry_fixture
    wall[0] += timedelta(seconds=90)
    elapsed[0] = 200.0
    op, packet, owner, signature = proof()
    evidence = registry._register(packet, op)
    entry = registry._evidence(evidence)
    args = dict(
        key_id="fixture-attester",
        algorithm="ed25519",
        purpose="deployment_rehearsal_harness_evidence",
        canonical_bytes=owner,
        signature=signature,
    )
    assert registry.verify_rehearsal_harness_evidence(**args) is True
    wall[0] += timedelta(seconds=10)
    elapsed[0] = 220.0
    # A late-created leaf alone remains open until monotonic230. The original
    # dispatcher deadline220 must win, despite the shorter elapsed wall time.
    assert entry.leaf.verify_rehearsal_harness_evidence(**args) is True
    assert registry.verify_rehearsal_harness_evidence(**args) is False
    with pytest.raises(ProofRegistrationRefused):
        registry._register(packet, op)


def test_unconfigured_admission_refuses_before_any_database(registry_fixture):
    registry, *_ = registry_fixture
    calls = []
    driver = Gate0Composition(
        sessions=lambda: calls.append("db"),
        admission=None,
        proof_resolver=None,
        verifier=registry,
    )
    with pytest.raises(CompositionRefused):
        driver.issue(RehearsalIssuerCommand("fixture", UUID(int=1)))
    assert calls == []


def test_canonical_authorization_decoder_refuses_duplicate_keys_before_owner():
    with pytest.raises(CompositionRefused):
        authorization_binding(b'{"statement":{},"statement":{}}')
    with pytest.raises(CompositionRefused):
        authorization_binding(b'{"statement":NaN}')


def test_registry_protocol_matches_installed_owner():
    import inspect

    from dotmac_deployment_control import RehearsalHarnessEvidenceVerifier

    def shape(method):
        return [
            (key, value.kind)
            for key, value in inspect.signature(method).parameters.items()
        ]

    assert shape(BoundedHarnessVerifier.verify_rehearsal_harness_evidence) == shape(
        RehearsalHarnessEvidenceVerifier.verify_rehearsal_harness_evidence
    )


@pytest.fixture
def authorized_vector(registry_fixture):
    from dotmac_deployment_control import (
        A6ProvenanceKind,
        RehearsalIssuerAuthorizationStatementV1,
        RehearsalIssuerAuthorizationV1,
    )

    _, proof, wall, *_ = registry_fixture
    operation, _, *_ = proof()
    derived = A6ProvenanceKind.DERIVED
    statement = RehearsalIssuerAuthorizationStatementV1(
        authorization_id="fixture-authorization",
        immutable_reference=operation.plan_id,
        target_id=str(UUID(int=2)),
        target_ref=operation.target_ref,
        target_provenance=derived,
        desired_state_digest=operation.plan_digest,
        desired_state_provenance=derived,
        profile_digest=digest(b"descriptor"),
        profile_provenance=derived,
        authorized_image_digests=(),
        authorized_images_provenance=derived,
        execution_plan_digest=operation.execution_plan_digest,
        execution_plan_provenance=derived,
        controller_fingerprint=operation.controller_fingerprint,
        key_id="fixture-issuer",
        algorithm="ed25519",
        public_key_fingerprint=digest(b"fixture-issuer-public"),
        lease_id=operation.lease_id,
        single_use_reference="fixture-single-use",
        environment="rehearsal",
        not_before=wall[0],
        issued_at=wall[0],
        expires_at=wall[0] + timedelta(seconds=120),
        control_version="0.1.0a17",
    )
    return RehearsalIssuerAuthorizationV1(statement, "synthetic-signature")


def test_full_parsed_authorization_digest_vectors(authorized_vector):
    document = authorized_vector.as_mapping()
    original = canonical(document)
    expected = "sha256:" + hashlib.sha256(original).hexdigest()
    binding = authorization_binding(json.dumps(document, indent=3).encode())
    assert binding.encoded == original and binding.digest == expected
    assert binding.issued_at == "2026-10-15T00:00:00Z"
    assert binding.digest != digest(authorized_vector.statement.canonical_bytes())
    changed = {**document, "signature": "changed-synthetic-signature"}
    assert authorization_binding(canonical(changed)).digest != binding.digest
    changed = {
        **document,
        "statement": {**document["statement"], "key_id": "other-key"},
    }
    assert authorization_binding(canonical(changed)).digest != binding.digest


@pytest.fixture
def driver_fixture(registry_fixture, monkeypatch):
    from types import SimpleNamespace

    import dotmac_deployment_control as control

    import vendor_cp.deployment.gate0_composition as module

    registry, proof, *_ = registry_fixture
    operation, packet, *_ = proof()
    expected = AdmissionExpectation(
        operation, UUID(int=2), "rehearsal", UUID(int=3), "fixture-policy", 1
    )
    state = {"expected": expected, "proof": packet, "sessions": [], "issued_calls": 0}
    plan = SimpleNamespace(
        id=UUID(operation.plan_id),
        target_id=expected.target_id,
        purpose=operation.plan_purpose,
        operation=operation.operation,
        plan_digest=operation.plan_digest,
        execution_plan_digest=operation.execution_plan_digest,
        descriptor_digest=digest(b"descriptor"),
        requires_approval=True,
        approval_decision_ref=str(expected.approval_request_id),
        approval_policy_code=expected.approval_policy_code,
        approval_policy_version=1,
    )
    target = SimpleNamespace(
        id=expected.target_id, target_ref=operation.target_ref, environment="rehearsal"
    )

    class FixtureSession:
        def __init__(self):
            self.read = False
            self.closed = False
            self.commits = 0
            self.rollbacks = 0

        def close(self):
            self.closed = True

        def commit(self):
            self.commits += 1

        def rollback(self):
            self.rollbacks += 1

    def sessions():
        session = FixtureSession()
        state["sessions"].append(session)
        return session

    def get_plan(db, plan_id):
        db.read = True
        return plan

    def get_target(db, target_id):
        db.read = True
        return target

    monkeypatch.setattr(control, "get_plan", get_plan)
    monkeypatch.setattr(control, "get_target", get_target)
    driver = Gate0Composition(
        sessions=sessions,
        admission=lambda phase, plan_id: state["expected"],
        proof_resolver=lambda _: state["proof"],
        verifier=registry,
    )
    state.update(
        driver=driver,
        plan=plan,
        target=target,
        module=module,
        sessions_factory=sessions,
    )
    return state


@pytest.mark.parametrize(
    "subject,field,value",
    [
        ("plan", "target_id", UUID(int=9)),
        ("target", "environment", "other"),
        ("target", "target_ref", "other-target"),
        ("target", "id", UUID(int=9)),
        ("plan", "approval_decision_ref", str(UUID(int=9))),
        ("plan", "approval_policy_code", "other"),
        ("plan", "approval_policy_version", 2),
        ("plan", "purpose", "deployment"),
        ("plan", "operation", "recover"),
        ("plan", "plan_digest", digest(b"other")),
        ("plan", "execution_plan_digest", digest(b"other")),
        ("plan", "requires_approval", False),
    ],
)
def test_actual_public_plan_binding_substitution_refuses_before_proof(
    driver_fixture, subject, field, value
):
    state = driver_fixture
    setattr(state[subject], field, value)
    reached = []

    def forbidden_proof(_):
        reached.append("proof")
        return state["proof"]

    state["driver"]._resolver = forbidden_proof
    with pytest.raises(CompositionRefused):
        state["driver"].issue(RehearsalIssuerCommand("fixture", UUID(int=1)))
    assert reached == [] and state["driver"]._verifier._retained_count == 0
    assert all(session.closed and session.commits == 0 for session in state["sessions"])


def test_preflight_positive_and_standing_has_no_pre_read(
    driver_fixture, authorized_vector, monkeypatch
):
    import dotmac_deployment_control as control

    state = driver_fixture
    driver = state["driver"]
    driver._preflight(state["expected"], None)
    evidence = driver._proof(state["expected"])

    def standing(db, **kwargs):
        assert db.read is False
        assert all(session.closed for session in state["sessions"][:-1])
        return "synthetic-standing"

    monkeypatch.setattr(control, "rehearsal_issuer_standing_for", standing)
    assert (
        driver.standing(canonical(authorized_vector.as_mapping()), evidence)
        == "synthetic-standing"
    )


def test_issue_commits_once_and_returns_detached_nonreadiness(
    driver_fixture, authorized_vector, monkeypatch
):
    state = driver_fixture
    monkeypatch.setattr(
        state["module"], "issue_authorization", lambda db, invocation: authorized_vector
    )
    result = state["driver"].issue(RehearsalIssuerCommand("fixture", UUID(int=1)))
    assert result.authorization_document == canonical(authorized_vector.as_mapping())
    assert result.readiness_accepted is False
    assert sum(session.commits for session in state["sessions"]) == 1
    assert all(session.closed for session in state["sessions"])


def test_commit_failure_is_incomplete_not_success(
    driver_fixture, authorized_vector, monkeypatch
):
    from vendor_cp.deployment.gate0_composition import CompositionIncomplete

    state = driver_fixture
    original = state["sessions_factory"]

    def sessions():
        session = original()

        def broken():
            raise RuntimeError("sensitive-synthetic-commit-error")

        session.commit = broken
        return session

    state["driver"]._sessions = sessions
    monkeypatch.setattr(
        state["module"], "issue_authorization", lambda db, invocation: authorized_vector
    )
    with pytest.raises(CompositionIncomplete) as caught:
        state["driver"].issue(RehearsalIssuerCommand("fixture", UUID(int=1)))
    assert (
        str(caught.value) == "gate0_composition_incomplete"
        and caught.value.__context__ is None
    )
    assert state["sessions"][-1].rollbacks == 1 and state["sessions"][-1].closed


def test_owner_refusal_rolls_back_without_intermediate_commit(
    driver_fixture, monkeypatch
):
    state = driver_fixture

    class FixtureOwnerRefusal(Exception):
        pass

    def refused(db, invocation):
        raise FixtureOwnerRefusal()

    monkeypatch.setattr(state["module"], "issue_authorization", refused)
    with pytest.raises(FixtureOwnerRefusal):
        state["driver"].issue(RehearsalIssuerCommand("fixture", UUID(int=1)))
    assert state["sessions"][-1].rollbacks == 1
    assert sum(session.commits for session in state["sessions"]) == 0


def test_maximum_retained_payload_and_one_byte_over_are_sensitized(registry_fixture):
    registry, proof, *_ = registry_fixture
    for index in range(4):
        op, packet, *_ = proof(index)
        ordinary = registry._prepare(packet, op)
        padding = 128 * 1024 - ordinary.size
        bounded = replace(
            packet, control_document=b" " * padding + packet.control_document
        )
        assert registry._prepare(bounded, op).size == 128 * 1024
        if index == 0:
            too_large = replace(
                bounded, control_document=b" " + bounded.control_document
            )
            with pytest.raises(ProofRegistrationRefused):
                registry._register(too_large, op)
            assert registry._retained_count == 0
        registry._register(bounded, op)
    assert registry._retained_bytes == 512 * 1024 and registry._retained_count == 4


def test_mutating_callback_owned_packet_after_registration_cannot_change_retention(
    registry_fixture,
):
    registry, proof, *_ = registry_fixture
    op, packet, owner, signature = proof()
    original = packet.control_document
    evidence = registry._register(packet, op)
    object.__setattr__(packet, "control_document", b"tampered")
    object.__setattr__(packet, "public_proof_transcript", b"tampered")
    object.__setattr__(packet.context, "window_id", "mutated")
    assert registry._evidence(evidence).owner_envelope == original
    assert registry._evidence(evidence).context.window_id == "fixture-window"
    assert (
        registry.verify_rehearsal_harness_evidence(
            key_id="fixture-attester",
            algorithm="ed25519",
            purpose="deployment_rehearsal_harness_evidence",
            canonical_bytes=owner,
            signature=signature,
        )
        is True
    )


def test_clock_callbacks_are_never_invoked_under_cache_lock(registry_fixture):
    registry, proof, wall, elapsed, *_ = registry_fixture

    def unlocked_wall():
        assert registry._lock.acquire(blocking=False)
        registry._lock.release()
        return wall[0]

    def unlocked_monotonic():
        assert registry._lock.acquire(blocking=False)
        registry._lock.release()
        return elapsed[0]

    registry._now = unlocked_wall
    registry._monotonic = unlocked_monotonic
    op, packet, owner, signature = proof()
    registry._register(packet, op)
    assert (
        registry.verify_rehearsal_harness_evidence(
            key_id="fixture-attester",
            algorithm="ed25519",
            purpose="deployment_rehearsal_harness_evidence",
            canonical_bytes=owner,
            signature=signature,
        )
        is True
    )


def test_resolver_cannot_mutate_frozen_driver_admission_or_command(
    driver_fixture, authorized_vector, monkeypatch
):
    state = driver_fixture
    command = RehearsalIssuerCommand("fixture", UUID(int=1))

    def resolver(expected):
        object.__setattr__(expected, "approval_policy_code", "malicious-change")
        object.__setattr__(command, "plan_id", UUID(int=99))
        return state["proof"]

    state["driver"]._resolver = resolver
    seen = []

    def issue(db, invocation):
        seen.append(invocation.command.plan_id)
        return authorized_vector

    monkeypatch.setattr(state["module"], "issue_authorization", issue)
    state["driver"].issue(command)
    assert seen == [UUID(int=1)]


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -1.0, True, "100"])
def test_invalid_dispatcher_clock_readback_cannot_validate_cached_entry(
    registry_fixture, value
):
    registry, proof, *_ = registry_fixture
    op, packet, owner, signature = proof()
    registry._register(packet, op)
    registry._monotonic = lambda: value
    assert (
        registry.verify_rehearsal_harness_evidence(
            key_id="fixture-attester",
            algorithm="ed25519",
            purpose="deployment_rehearsal_harness_evidence",
            canonical_bytes=owner,
            signature=signature,
        )
        is False
    )


@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt])
@pytest.mark.parametrize("cleanup", ["rollback", "close"])
def test_owner_refusal_and_unconfirmed_cleanup_is_incomplete(
    driver_fixture, failure, cleanup
):
    from vendor_cp.deployment.gate0_composition import CompositionIncomplete

    state = driver_fixture
    original = state["sessions_factory"]
    attempts = []

    def sessions():
        db = original()

        def rollback():
            attempts.append("rollback")
            if cleanup == "rollback":
                raise failure("sensitive-cleanup")

        def close():
            attempts.append("close")
            if cleanup == "close":
                raise failure("sensitive-cleanup")

        db.rollback, db.close = rollback, close
        return db

    state["driver"]._sessions = sessions

    def refused(db):
        raise ValueError("sensitive-owner")

    with pytest.raises(CompositionIncomplete) as caught:
        state["driver"]._mutate(state["expected"], None, refused)
    assert str(caught.value) == "gate0_composition_incomplete"
    assert caught.value.__context__ is None and caught.value.__cause__ is None
    assert attempts == ["rollback", "close"]
    assert all(db.commits == 0 for db in state["sessions"])


def test_cancellation_with_confirmed_cleanup_preserves_cancellation(driver_fixture):
    state = driver_fixture

    def cancelled(db):
        raise KeyboardInterrupt("fixture-cancelled")

    with pytest.raises(KeyboardInterrupt):
        state["driver"]._mutate(state["expected"], None, cancelled)
    db = state["sessions"][-1]
    assert db.rollbacks == 1 and db.closed and db.commits == 0


def test_successful_commit_with_failed_close_is_incomplete(driver_fixture):
    from vendor_cp.deployment.gate0_composition import (
        CompositionIncomplete,
        PhaseResult,
    )

    state = driver_fixture
    original = state["sessions_factory"]
    attempts = []

    def sessions():
        db = original()

        def close():
            attempts.append("close")
            raise RuntimeError("sensitive-close")

        db.close = close
        return db

    state["driver"]._sessions = sessions
    with pytest.raises(CompositionIncomplete) as caught:
        state["driver"]._mutate(
            state["expected"], None, lambda db: PhaseResult("digest", "auth", "lease")
        )
    assert caught.value.__context__ is None
    assert attempts == ["close"] and state["sessions"][-1].commits == 1


def rebind_packet(packet, key, operation):
    """Authentic fixture producer assertion; leaves exact owner bytes unchanged."""
    transcript = json.loads(packet.public_proof_transcript)
    challenge = json.loads(base64.b64decode(transcript["challenge"]))
    challenge["context"] = asdict(operation)
    transcript["challenge"] = base64.b64encode(canonical(challenge)).decode()
    transcript_bytes = canonical(transcript)
    context = AttestationContext(
        **asdict(operation),
        challenge_digest=digest(canonical(challenge)),
        proof_transcript_digest=digest(transcript_bytes),
    )
    owner = base64.b64decode(json.loads(packet.control_document)["canonical_bytes"])
    companion = companion_message(context, owner)
    return replace(
        packet,
        context=context,
        public_proof_transcript=transcript_bytes,
        companion=CompanionAttestation(companion, key.sign(companion)),
    )


def test_authentic_conflicting_companion_preserves_first_entry(registry_fixture):
    registry, proof, _, _, _, key = registry_fixture
    op, packet, *_ = proof()
    evidence = registry._register(packet, op)
    retained = registry._evidence(evidence)
    changed = replace(op, window_id="other-authentic-window")
    conflicting = rebind_packet(packet, key, changed)
    assert registry._prepare(conflicting, changed).owner_bytes == retained.owner_bytes
    with pytest.raises(ProofRegistrationRefused):
        registry._register(conflicting, changed)
    assert registry._evidence(evidence) == retained and registry._retained_count == 1


@pytest.mark.parametrize(
    "missing", ["signer", "authorization_verifier", "admission", "proof_resolver"]
)
def test_startup_missing_port_refuses_before_owner_install(
    registry_fixture, monkeypatch, missing
):
    import dotmac_deployment_control as control

    from vendor_cp.deployment.gate0_composition import assemble_gate0_composition

    registry, *_ = registry_fixture
    monkeypatch.setattr(
        control,
        "install_rehearsal_issuer_security",
        lambda **kwargs: pytest.fail("missing port must not install"),
    )
    arguments = dict(
        sessions=lambda: pytest.fail("no session"),
        admission=lambda *args: None,
        proof_resolver=lambda *args: None,
        verifier=registry,
        signer=object(),
        authorization_verifier=object(),
        authorization_ttl=timedelta(seconds=10),
    )
    arguments[missing] = None
    with pytest.raises(CompositionRefused):
        assemble_gate0_composition(**arguments)


def consume_expectation(state, document):
    binding = authorization_binding(document)
    return replace(
        state["expected"],
        operation=replace(
            state["expected"].operation,
            phase="consume",
            authorization_digest=binding.digest,
            authorization_issued_at=binding.issued_at,
        ),
    )


@pytest.mark.parametrize(
    "plant",
    ["statement-only", "raw-whitespace", "signature", "key", "issued-time", "phase"],
)
def test_consume_independent_authorization_binding_refuses_before_proof(
    driver_fixture, authorized_vector, plant
):
    state = driver_fixture
    document = canonical(authorized_vector.as_mapping())
    expected = consume_expectation(state, document)
    if plant == "statement-only":
        expected = replace(
            expected,
            operation=replace(
                expected.operation,
                authorization_digest=digest(
                    authorized_vector.statement.canonical_bytes()
                ),
            ),
        )
    elif plant == "raw-whitespace":
        expected = replace(
            expected,
            operation=replace(
                expected.operation, authorization_digest=digest(b" " + document)
            ),
        )
    elif plant in ("signature", "key"):
        changed = authorized_vector.as_mapping()
        if plant == "signature":
            changed["signature"] = "other-synthetic-signature"
        else:
            changed["statement"]["key_id"] = "other-issuer"
        document = canonical(changed)
    elif plant == "issued-time":
        expected = replace(
            expected,
            operation=replace(
                expected.operation, authorization_issued_at="2026-10-15T00:00:01Z"
            ),
        )
    else:
        expected = state["expected"]
    state["expected"] = expected
    state["driver"]._resolver = lambda _: pytest.fail("binding refusal precedes proof")
    with pytest.raises(CompositionRefused):
        state["driver"].consume(UUID(int=1), document)
    assert state["driver"]._verifier._retained_count == 0
    assert all(db.closed and db.commits == 0 for db in state["sessions"])


@pytest.mark.parametrize("document", [None, b"", b"{}", b"not-json"])
def test_consume_missing_or_malformed_authorization_cannot_resolve_proof(
    driver_fixture, document
):
    state = driver_fixture
    state["driver"]._resolver = lambda _: pytest.fail(
        "malformed authorization precedes proof"
    )
    with pytest.raises(CompositionRefused):
        state["driver"].consume(UUID(int=1), document)
    assert state["sessions"] == []


@pytest.mark.parametrize("later", [False, True])
def test_consume_actual_proof_issuance_time_must_be_strictly_later(
    driver_fixture, registry_fixture, authorized_vector, monkeypatch, later
):
    import dotmac_deployment_control as control

    state = driver_fixture
    registry, proof, wall, _, _, key = registry_fixture
    document = canonical(authorized_vector.as_mapping())
    state["expected"] = consume_expectation(state, document)
    if later:
        wall[0] += timedelta(microseconds=1)  # synthetic clock; authentic proof uses it
    _, packet, *_ = proof()
    state["proof"] = rebind_packet(packet, key, state["expected"].operation)
    calls = []

    def consumed(db, **kwargs):
        calls.append("consume")
        return control.RehearsalIssuerConsumptionStaged(
            "fixture-authorization",
            "fixture-single-use",
            state["expected"].operation.lease_id,
        )

    monkeypatch.setattr(state["module"], "consume_authorization", consumed)
    if later:
        result = state["driver"].consume(UUID(int=1), document)
        assert result.readiness_accepted is False and calls == ["consume"]
        assert sum(db.commits for db in state["sessions"]) == 1
    else:
        with pytest.raises(CompositionRefused):
            state["driver"].consume(UUID(int=1), document)
        assert calls == [] and all(db.commits == 0 for db in state["sessions"])
    assert registry._retained_count == 1


def test_consume_entrypoint_rejects_authentic_issue_proof(
    driver_fixture, authorized_vector, monkeypatch
):
    state = driver_fixture
    document = canonical(authorized_vector.as_mapping())
    state["expected"] = consume_expectation(state, document)
    calls = []
    original = state["driver"]._resolver

    def resolve(expected):
        calls.append("proof")
        return original(expected)

    state["driver"]._resolver = resolve
    monkeypatch.setattr(
        state["module"],
        "consume_authorization",
        lambda *args, **kwargs: pytest.fail("phase swap must precede owner mutation"),
    )
    with pytest.raises(CompositionRefused):
        state["driver"].consume(UUID(int=1), document)
    assert calls == ["proof"] and state["driver"]._verifier._retained_count == 0
    assert all(db.closed and db.commits == 0 for db in state["sessions"])
