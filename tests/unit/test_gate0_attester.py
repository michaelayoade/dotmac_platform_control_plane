"""Hosted-CI-only synthetic possession round trips; no protected E receipt."""

import base64
import hashlib
import json
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta

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

from vendor_cp.deployment.gate0_attester import (
    AttesterProofProducer,
    AttesterRefused,
    ssh_public_fingerprint,
)
from vendor_cp.deployment.gate0_runtime import (
    AdmittedOperation,
    ProtectedHarnessVerifier,
)
from vendor_cp.deployment.rehearsal_issuer_trust_state import RehearsalIssuerTrustState


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


@pytest.fixture
def proof_setup(tmp_path):
    now = datetime(2026, 10, 15, tzinfo=UTC)
    wall, elapsed = [now], [100.0]
    controller, ca, attester = (Ed25519PrivateKey.generate() for _ in range(3))
    public = attester.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ca_public = ca.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
    calls = []

    def sign(message):
        calls.append(message)
        return attester.sign(message)

    trust = RehearsalIssuerTrustState.start(
        minimum_version=2,
        read_record=lambda: {
            "version": 2,
            "trusted_key_ids": {"synthetic-attester": digest(public)},
            "revoked_key_ids": [],
        },
    )

    def certificate(**changes):
        values = dict(
            key=controller.public_key(),
            ca=ca,
            type=SSHCertificateType.USER,
            principals=[b"dotmac-gate0-controller"],
            key_id=b"gate0:1:2:1",
            after=int(now.timestamp()) - 1,
            before=int(now.timestamp()) + 120,
            critical=False,
            extension=False,
        )
        values.update(changes)
        builder = (
            SSHCertificateBuilder()
            .public_key(values["key"])
            .type(values["type"])
            .key_id(values["key_id"])
            .valid_after(values["after"])
            .valid_before(values["before"])
        )
        builder = (
            builder.valid_for_all_principals()
            if values["principals"] is None
            else builder.valid_principals(values["principals"])
        )
        if values["critical"]:
            builder = builder.add_critical_option(b"force-command", b"true")
        if values["extension"]:
            builder = builder.add_extension(b"permit-pty", b"")
        return builder.sign(values["ca"]).public_bytes()

    cert = certificate()
    operation = AdmittedOperation(
        repository_id="1",
        run_id="2",
        run_attempt="1",
        window_id="synthetic-window",
        phase="issue",
        authorization_digest=None,
        authorization_issued_at=None,
        lease_id="synthetic-lease",
        controller_fingerprint=ssh_public_fingerprint(controller.public_key()),
        target_ref="synthetic-target",
        plan_id="00000000-0000-0000-0000-000000000001",
        plan_digest=digest(b"plan"),
        plan_purpose="rehearsal_issuer_operation",
        operation="deploy",
        execution_plan_digest=digest(b"operation"),
        certificate_digest=digest(cert),
        ca_fingerprint=ssh_public_fingerprint(ca.public_key()),
    )

    def producer(
        operation=operation,
        signer=sign,
        purpose="deployment_rehearsal_harness_evidence",
    ):
        return AttesterProofProducer(
            admitted=operation,
            ca_public_key=ca_public,
            key_id="synthetic-attester",
            signer_purpose=purpose,
            attester_public_key=public,
            trust_state=trust,
            sign=signer,
            expires_at=now + timedelta(seconds=120),
            now=lambda: wall[0],
            monotonic_clock=lambda: elapsed[0],
        )

    key_path = tmp_path / "synthetic-controller"
    key_path.write_bytes(
        controller.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())
    )
    key_path.chmod(0o600)

    def sshsig(message, namespace="dotmac-gate0-possession-v1", private_key=None):
        selected_path = key_path
        if private_key is not None:
            selected_path = tmp_path / "synthetic-other-controller"
            selected_path.write_bytes(
                private_key.private_bytes(
                    Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()
                )
            )
            selected_path.chmod(0o600)
        result = subprocess.run(  # noqa: S603 -- fixed public test protocol with synthetic key
            [
                "/usr/bin/ssh-keygen",
                "-Y",
                "sign",
                "-f",
                str(selected_path),
                "-n",
                namespace,
            ],
            input=message,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=2,
            check=True,
        )
        return result.stdout

    return dict(
        now=now,
        sign=sign,
        wall=wall,
        elapsed=elapsed,
        certificate=certificate,
        cert=cert,
        operation=operation,
        producer=producer,
        sshsig=sshsig,
        calls=calls,
        trust=trust,
        public=public,
        ca=ca,
        controller=controller,
    )


def test_real_certificate_sshsig_producer_to_public_consumer(proof_setup):
    p = proof_setup
    producer = p["producer"]()
    challenge = producer.begin_challenge(p["cert"])
    result = producer.complete_challenge(
        challenge.challenge_id, p["sshsig"](challenge.canonical_bytes)
    )
    assert len(p["calls"]) == 2
    envelope = json.loads(result.control_document)
    owner = base64.b64decode(envelope["canonical_bytes"])
    assert set(json.loads(owner)) == {
        "schema",
        "version",
        "lease_id",
        "controller_fingerprint",
        "target_ref",
        "environment",
        "issued_at",
        "valid_until",
    }
    assert result.context.window_id == p["operation"].window_id
    assert result.context.phase == "issue"
    verifier = ProtectedHarnessVerifier(
        key_id="synthetic-attester",
        public_key=p["public"],
        trust_state=p["trust"],
        context=result.context,
        read_companion=lambda _: result.companion,
        expires_at=p["now"] + timedelta(seconds=120),
        now=lambda: p["wall"][0],
        monotonic_clock=lambda: p["elapsed"][0],
    )
    assert (
        verifier.verify_rehearsal_harness_evidence(
            key_id="synthetic-attester",
            algorithm="ed25519",
            purpose="deployment_rehearsal_harness_evidence",
            canonical_bytes=owner,
            signature=base64.b64decode(envelope["signature"]["signature"]),
        )
        is True
    )
    from dotmac_deployment_control import (
        parse_signed_rehearsal_harness_evidence,
        verify_rehearsal_harness_evidence_signature,
    )

    parsed = parse_signed_rehearsal_harness_evidence(
        json.loads(result.control_document)
    )
    assert parsed.canonical_bytes == owner
    verify_rehearsal_harness_evidence_signature(
        parsed, verifier=verifier, at=p["wall"][0]
    )
    transcript = json.loads(result.public_proof_transcript)
    assert (
        digest(result.public_proof_transcript) == result.context.proof_transcript_digest
    )
    assert base64.b64decode(transcript["challenge"]) == challenge.canonical_bytes
    assert "PRIVATE KEY" not in result.public_proof_transcript.decode()
    with pytest.raises(AttesterRefused):
        producer.complete_challenge(
            challenge.challenge_id, p["sshsig"](challenge.canonical_bytes)
        )
    assert len(p["calls"]) == 2


@pytest.mark.parametrize(
    "change",
    [
        "ca",
        "key",
        "principal",
        "all_principals",
        "id",
        "host",
        "critical",
        "extension",
        "expired",
        "future",
        "ttl",
    ],
)
def test_certificate_refusals_never_sign(proof_setup, change):
    p = proof_setup
    changes = {
        "ca": dict(ca=Ed25519PrivateKey.generate()),
        "key": dict(key=Ed25519PrivateKey.generate().public_key()),
        "principal": dict(principals=[b"dotmac-gate0-controller", b"other"]),
        "all_principals": dict(principals=None),
        "id": dict(key_id=b"gate0:1:2:2"),
        "host": dict(type=SSHCertificateType.HOST),
        "critical": dict(critical=True),
        "extension": dict(extension=True),
        "expired": dict(before=int(p["now"].timestamp())),
        "future": dict(after=int(p["now"].timestamp()) + 1),
        "ttl": dict(
            after=int(p["now"].timestamp()), before=int(p["now"].timestamp()) + 601
        ),
    }
    cert = p["certificate"](**changes[change])
    operation = replace(p["operation"], certificate_digest=digest(cert))
    with pytest.raises(AttesterRefused):
        p["producer"](operation=operation).begin_challenge(cert)
    assert p["calls"] == []


@pytest.mark.parametrize("proof", ["message", "namespace", "garbage"])
def test_invalid_actual_sshsig_terminal_without_signer(proof_setup, proof):
    p = proof_setup
    producer = p["producer"]()
    challenge = producer.begin_challenge(p["cert"])
    response = {
        "message": lambda: p["sshsig"](challenge.canonical_bytes + b"tampered"),
        "namespace": lambda: p["sshsig"](challenge.canonical_bytes, "wrong-domain"),
        "garbage": lambda: b"invalid synthetic sshsig",
    }[proof]()
    with pytest.raises(AttesterRefused):
        producer.complete_challenge(challenge.challenge_id, response)
    with pytest.raises(AttesterRefused):
        producer.complete_challenge(
            challenge.challenge_id, p["sshsig"](challenge.canonical_bytes)
        )
    assert p["calls"] == []


def test_concurrent_completion_has_one_bundle_and_no_repeated_signing(proof_setup):
    p = proof_setup
    producer = p["producer"]()
    challenge = producer.begin_challenge(p["cert"])
    response = p["sshsig"](challenge.canonical_bytes)

    def complete(_):
        try:
            return producer.complete_challenge(challenge.challenge_id, response)
        except AttesterRefused:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(complete, range(2)))
    assert sum(result is not None for result in results) == 1
    assert len(p["calls"]) == 2


def test_restart_old_challenge_unknown(proof_setup):
    p = proof_setup
    first = p["producer"]()
    challenge = first.begin_challenge(p["cert"])
    second = p["producer"]()
    with pytest.raises(AttesterRefused):
        second.complete_challenge(
            challenge.challenge_id, p["sshsig"](challenge.canonical_bytes)
        )
    assert p["calls"] == []


def test_signer_failure_returns_no_bundle_and_challenge_stays_terminal(proof_setup):
    p = proof_setup
    calls = []

    def broken(message):
        calls.append(message)
        return b"invalid"

    producer = p["producer"](signer=broken)
    challenge = producer.begin_challenge(p["cert"])
    response = p["sshsig"](challenge.canonical_bytes)
    with pytest.raises(AttesterRefused):
        producer.complete_challenge(challenge.challenge_id, response)
    with pytest.raises(AttesterRefused):
        producer.complete_challenge(challenge.challenge_id, response)
    assert len(calls) == 1


@pytest.mark.parametrize("clock", ["wall", "elapsed", "backward"])
def test_challenge_expiry_without_signing(proof_setup, clock):
    p = proof_setup
    producer = p["producer"]()
    challenge = producer.begin_challenge(p["cert"])
    response = p["sshsig"](challenge.canonical_bytes)
    if clock == "wall":
        p["wall"][0] += timedelta(seconds=30)
    elif clock == "elapsed":
        p["elapsed"][0] += 30
    else:
        p["wall"][0] -= timedelta(seconds=1)
    with pytest.raises(AttesterRefused):
        producer.complete_challenge(challenge.challenge_id, response)
    assert p["calls"] == []


def test_consumption_needs_actual_later_clock_and_authorization_binding(proof_setup):
    p = proof_setup
    operation = replace(
        p["operation"],
        phase="consume",
        authorization_digest=digest(b"issued authorization"),
        authorization_issued_at=p["now"].isoformat(),
    )
    producer = p["producer"](operation=operation)
    challenge = producer.begin_challenge(p["cert"])
    response = p["sshsig"](challenge.canonical_bytes)
    with pytest.raises(AttesterRefused):
        producer.complete_challenge(challenge.challenge_id, response)
    assert p["calls"] == []
    p["wall"][0] += timedelta(seconds=1)
    challenge = producer.begin_challenge(p["cert"])
    result = producer.complete_challenge(
        challenge.challenge_id, p["sshsig"](challenge.canonical_bytes)
    )
    assert result.context.authorization_digest == digest(b"issued authorization")


def test_registry_limits_and_active_challenge_refuse(proof_setup):
    p = proof_setup
    producer = p["producer"]()
    challenge = producer.begin_challenge(p["cert"])
    with pytest.raises(AttesterRefused):
        producer.begin_challenge(p["cert"])
    for _ in range(16):
        with pytest.raises(AttesterRefused):
            producer.complete_challenge(challenge.challenge_id, b"bad")
        if _ < 15:
            challenge = producer.begin_challenge(p["cert"])
    with pytest.raises(AttesterRefused):
        producer.begin_challenge(p["cert"])
    assert p["calls"] == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("window_id", "different-window"),
        ("lease_id", "different-lease"),
        ("target_ref", "different-target"),
        ("plan_digest", digest(b"different-plan")),
    ],
)
def test_proof_for_other_frozen_context_cannot_be_reused(proof_setup, field, value):
    p = proof_setup
    first = p["producer"]().begin_challenge(p["cert"])
    changed = replace(p["operation"], **{field: value})
    second = p["producer"](operation=changed)
    challenge = second.begin_challenge(p["cert"])
    with pytest.raises(AttesterRefused):
        second.complete_challenge(
            challenge.challenge_id, p["sshsig"](first.canonical_bytes)
        )
    assert p["calls"] == []


def test_phase_change_invalidates_prior_actual_proof(proof_setup):
    p = proof_setup
    first = p["producer"]().begin_challenge(p["cert"])
    changed = replace(
        p["operation"],
        phase="consume",
        authorization_digest=digest(b"actual-issued"),
        authorization_issued_at=(p["now"] - timedelta(seconds=1)).isoformat(),
    )
    second = p["producer"](operation=changed)
    challenge = second.begin_challenge(p["cert"])
    with pytest.raises(AttesterRefused):
        second.complete_challenge(
            challenge.challenge_id, p["sshsig"](first.canonical_bytes)
        )
    assert p["calls"] == []


def test_certificate_signature_is_verified_not_just_its_ca_label(proof_setup):
    p = proof_setup
    key_type, blob = p["cert"].split(b" ", 1)
    body = bytearray(base64.b64decode(blob))
    body[-1] ^= 1
    forged = key_type + b" " + base64.b64encode(body)
    with pytest.raises(AttesterRefused):
        p["producer"]().begin_challenge(forged)
    assert p["calls"] == []


def test_certificate_digest_uses_public_library_canonical_form(proof_setup):
    p = proof_setup
    challenge = p["producer"]().begin_challenge(
        p["cert"] + b" harmless-public-comment\n"
    )
    context = json.loads(challenge.canonical_bytes)["context"]
    assert context["certificate_digest"] == digest(p["cert"])


@pytest.mark.parametrize("advance", ["elapsed", "wall", "trust"])
def test_time_or_trust_change_during_child_verification_refuses(
    proof_setup, monkeypatch, advance
):
    import vendor_cp.deployment.gate0_attester as module

    p = proof_setup
    producer = p["producer"]()
    challenge = producer.begin_challenge(p["cert"])
    response = p["sshsig"](challenge.canonical_bytes)

    def late(*args, **kwargs):
        if advance == "elapsed":
            p["elapsed"][0] += 30
        elif advance == "wall":
            p["wall"][0] += timedelta(seconds=30)
        else:
            p["trust"].refresh(
                read_record=lambda: {
                    "version": 3,
                    "trusted_key_ids": {},
                    "revoked_key_ids": ["synthetic-attester"],
                }
            )
        return subprocess.CompletedProcess(args[0], 0)

    monkeypatch.setattr(module.subprocess, "run", late)
    with pytest.raises(AttesterRefused):
        producer.complete_challenge(challenge.challenge_id, response)
    assert p["calls"] == []


def test_failed_trust_refresh_refuses_before_signing(proof_setup):
    from vendor_cp.deployment.rehearsal_issuer_trust_state import TrustStateInstallError

    p = proof_setup
    producer = p["producer"]()
    challenge = producer.begin_challenge(p["cert"])
    response = p["sshsig"](challenge.canonical_bytes)
    with pytest.raises(TrustStateInstallError):
        p["trust"].refresh(read_record=lambda: None)
    with pytest.raises(AttesterRefused):
        producer.complete_challenge(challenge.challenge_id, response)
    assert p["calls"] == []


@pytest.mark.parametrize("failure", ["timeout", "nonzero", "launch"])
def test_child_failure_is_sanitized_terminal_and_never_signs(
    proof_setup, monkeypatch, failure
):
    import vendor_cp.deployment.gate0_attester as module

    p = proof_setup
    producer = p["producer"]()
    challenge = producer.begin_challenge(p["cert"])
    response = p["sshsig"](challenge.canonical_bytes)

    def failed(argv, **kwargs):
        if failure == "timeout":
            raise subprocess.TimeoutExpired(
                argv, 2, output=b"sensitive-synthetic-sentinel"
            )
        if failure == "launch":
            raise OSError("sensitive-synthetic-sentinel")
        return subprocess.CompletedProcess(argv, 1)

    monkeypatch.setattr(module.subprocess, "run", failed)
    with pytest.raises(AttesterRefused) as caught:
        producer.complete_challenge(challenge.challenge_id, response)
    assert str(caught.value) == "gate0_attester_refused"
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None
    with pytest.raises(AttesterRefused):
        producer.complete_challenge(challenge.challenge_id, response)
    assert p["calls"] == []


def test_fixed_child_contract_only_public_files_bounded_discarded_output(
    proof_setup, monkeypatch
):
    from pathlib import Path

    import vendor_cp.deployment.gate0_attester as module

    p = proof_setup
    producer = p["producer"]()
    challenge = producer.begin_challenge(p["cert"])
    response = p["sshsig"](challenge.canonical_bytes)
    paths = []

    def inspect_child(argv, **kwargs):
        assert argv[0:3] == ["/usr/bin/ssh-keygen", "-Y", "verify"]
        assert argv[5:9] == [
            "-I",
            "gate0-controller",
            "-n",
            "dotmac-gate0-possession-v1",
        ]
        assert kwargs["input"] == challenge.canonical_bytes
        assert kwargs["shell"] is False
        assert 0 < kwargs["timeout"] <= 2
        assert (
            kwargs["stdout"] == subprocess.DEVNULL
            and kwargs["stderr"] == subprocess.DEVNULL
        )
        assert kwargs["env"] == {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
        allowed, signed = Path(argv[4]), Path(argv[10])
        paths.extend([allowed, signed])
        assert allowed.parent.stat().st_mode & 0o777 == 0o700
        assert allowed.stat().st_mode & 0o777 == 0o600
        assert signed.stat().st_mode & 0o777 == 0o600
        line = allowed.read_bytes()
        assert line.startswith(
            b'gate0-controller namespaces="dotmac-gate0-possession-v1" ssh-ed25519 '
        )
        assert b"cert-authority" not in line and b"PRIVATE" not in line
        assert signed.read_bytes() == response
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(module.subprocess, "run", inspect_child)
    producer.complete_challenge(challenge.challenge_id, response)
    assert paths and all(not path.exists() for path in paths)


@pytest.mark.parametrize("late_call", [1, 2])
def test_signer_elapsed_time_refuses_without_partial_bundle(proof_setup, late_call):
    p = proof_setup
    calls = []

    def late_sign(message):
        calls.append(message)
        valid = p["sign"](message)
        if len(calls) == late_call:
            p["elapsed"][0] += 30
        return valid

    producer = p["producer"](signer=late_sign)
    challenge = producer.begin_challenge(p["cert"])
    response = p["sshsig"](challenge.canonical_bytes)
    with pytest.raises(AttesterRefused):
        producer.complete_challenge(challenge.challenge_id, response)
    with pytest.raises(AttesterRefused):
        producer.complete_challenge(challenge.challenge_id, response)
    assert len(calls) == late_call


def test_second_signature_failure_returns_no_bundle_and_no_retry(proof_setup):
    p = proof_setup
    original = p["producer"]()
    signer = original._sign
    calls = []

    def second_bad(message):
        calls.append(message)
        return signer(message) if len(calls) == 1 else b"bad"

    producer = p["producer"](signer=second_bad)
    challenge = producer.begin_challenge(p["cert"])
    response = p["sshsig"](challenge.canonical_bytes)
    with pytest.raises(AttesterRefused):
        producer.complete_challenge(challenge.challenge_id, response)
    with pytest.raises(AttesterRefused):
        producer.complete_challenge(challenge.challenge_id, response)
    assert len(calls) == 2


@pytest.mark.parametrize("where", ["certificate", "signature"])
def test_public_input_bounds_refuse(proof_setup, where):
    p = proof_setup
    producer = p["producer"]()
    if where == "certificate":
        with pytest.raises(AttesterRefused):
            producer.begin_challenge(b"x" * (16 * 1024 + 1))
    else:
        challenge = producer.begin_challenge(p["cert"])
        with pytest.raises(AttesterRefused):
            producer.complete_challenge(challenge.challenge_id, b"x" * (16 * 1024 + 1))
    assert p["calls"] == []


def test_actual_sshsig_from_substituted_key_refuses(proof_setup):
    p = proof_setup
    producer = p["producer"]()
    challenge = producer.begin_challenge(p["cert"])
    response = p["sshsig"](
        challenge.canonical_bytes, private_key=Ed25519PrivateKey.generate()
    )
    with pytest.raises(AttesterRefused):
        producer.complete_challenge(challenge.challenge_id, response)
    assert p["calls"] == []


def test_wrong_attester_key_cannot_produce_bundle(proof_setup):
    p = proof_setup
    producer = p["producer"](signer=Ed25519PrivateKey.generate().sign)
    challenge = producer.begin_challenge(p["cert"])
    with pytest.raises(AttesterRefused):
        producer.complete_challenge(
            challenge.challenge_id, p["sshsig"](challenge.canonical_bytes)
        )


def test_unconfigured_or_wrong_purpose_signer_refuses(proof_setup):
    p = proof_setup
    with pytest.raises(AttesterRefused):
        p["producer"](signer=None)
    with pytest.raises(AttesterRefused):
        p["producer"](purpose="deployment_rehearsal_issuer")
    assert p["calls"] == []


def test_new_instance_challenge_nonce_and_identity_are_fresh(proof_setup):
    p = proof_setup
    first = p["producer"]().begin_challenge(p["cert"])
    second = p["producer"]().begin_challenge(p["cert"])
    a, b = json.loads(first.canonical_bytes), json.loads(second.canonical_bytes)
    assert first.challenge_id != second.challenge_id
    assert a["instance_id"] != b["instance_id"] and a["nonce"] != b["nonce"]
    assert len(bytes.fromhex(a["nonce"])) == 32


def test_exact_dependency_and_public_tool_identity_recorded(record_property):
    from importlib.metadata import version
    from pathlib import Path

    assert version("cryptography") == "50.0.0"
    executable = Path("/usr/bin/ssh-keygen")
    record_property("ssh_keygen_sha256", digest(executable.read_bytes()))
    result = subprocess.run(  # noqa: S603 -- fixed public installed-tool version query
        ["/usr/bin/ssh", "-V"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=2,
        check=True,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    assert len(result.stderr) <= 512 and b"OpenSSH" in result.stderr
    record_property("openssh_version", result.stderr.decode("ascii").strip())


def test_file_staging_cannot_launch_child_after_deadline(proof_setup, monkeypatch):
    import vendor_cp.deployment.gate0_attester as module

    p = proof_setup
    producer = p["producer"]()
    challenge = producer.begin_challenge(p["cert"])
    response = p["sshsig"](challenge.canonical_bytes)
    original = module._write_public

    def late_write(path, value):
        original(path, value)
        p["elapsed"][0] += 30

    launched = []
    monkeypatch.setattr(module, "_write_public", late_write)
    monkeypatch.setattr(
        module.subprocess, "run", lambda *args, **kwargs: launched.append(args)
    )
    with pytest.raises(AttesterRefused):
        producer.complete_challenge(challenge.challenge_id, response)
    assert launched == [] and p["calls"] == []


def test_two_valid_proofs_at_same_clock_cannot_publish_conflicting_companions(
    proof_setup,
):
    p = proof_setup
    producer = p["producer"]()
    first = producer.begin_challenge(p["cert"])
    result = producer.complete_challenge(
        first.challenge_id, p["sshsig"](first.canonical_bytes)
    )
    second = producer.begin_challenge(p["cert"])
    with pytest.raises(AttesterRefused):
        producer.complete_challenge(
            second.challenge_id, p["sshsig"](second.canonical_bytes)
        )
    assert len(p["calls"]) == 2
    p["wall"][0] += timedelta(seconds=1)
    third = producer.begin_challenge(p["cert"])
    later = producer.complete_challenge(
        third.challenge_id, p["sshsig"](third.canonical_bytes)
    )
    assert (
        json.loads(result.control_document)["canonical_bytes"]
        != json.loads(later.control_document)["canonical_bytes"]
    )
    assert len(p["calls"]) == 4


def test_partial_signer_failure_retains_owner_hash_reservation(proof_setup):
    p = proof_setup
    calls = []

    def failed_once(message):
        calls.append(message)
        if len(calls) == 1:
            return b"bad"
        return p["sign"](message)

    producer = p["producer"](signer=failed_once)
    first = producer.begin_challenge(p["cert"])
    with pytest.raises(AttesterRefused):
        producer.complete_challenge(
            first.challenge_id, p["sshsig"](first.canonical_bytes)
        )
    second = producer.begin_challenge(p["cert"])
    with pytest.raises(AttesterRefused):
        producer.complete_challenge(
            second.challenge_id, p["sshsig"](second.canonical_bytes)
        )
    assert len(calls) == 1
