"""Synthetic session semantics; execute only on the hosted source runner."""

import json
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace

import pytest
from test_gate0_attester import proof_setup as _shared_proof_setup

from vendor_cp.deployment.gate0_framing import ServiceRefused, canonical
from vendor_cp.deployment.gate0_observation import (
    DOMAIN,
    SignedSessionObservation,
    bundle_document,
    decode,
    digest,
    encode,
    observation_message,
    parse_bundle,
    verify_observation,
)
from vendor_cp.deployment.gate0_session import AttesterSession, parse_auth_info

proof_setup = _shared_proof_setup


def produced(setup):
    producer = setup["producer"]()
    challenge = producer.begin_challenge(setup["cert"])
    return producer.complete_challenge(
        challenge.challenge_id, setup["sshsig"](challenge.canonical_bytes)
    )


def observation(setup, proof):
    message = observation_message(
        proof=proof,
        operation=setup["operation"],
        window_record_digest=digest(b"synthetic-independent-window"),
        invocation_id="a" * 64,
        observed_from=setup["now"],
        observed_until=setup["now"],
    )
    return SignedSessionObservation(message, setup["sign"](message))


def verify(setup, proof, sidecar, **changes):
    values = dict(
        proof=proof,
        observation=sidecar,
        operation=setup["operation"],
        window_record_digest=digest(b"synthetic-independent-window"),
        key_id="synthetic-attester",
        public_key=setup["public"],
        trust_state=setup["trust"],
        now=setup["now"],
    )
    values.update(changes)
    verify_observation(**values)


def test_sidecar_roundtrip_preserves_exact_owner_and_public_transcript(proof_setup):
    setup = proof_setup
    proof = produced(setup)
    sidecar = observation(setup, proof)
    restored, restored_observation = parse_bundle(bundle_document(proof, sidecar))
    assert restored == proof
    assert restored_observation == sidecar
    verify(setup, restored, restored_observation)
    assert set(json.loads(proof.public_proof_transcript)) == {
        "schema",
        "certificate",
        "challenge",
        "sshsig",
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("command", "sh"),
        ("phase", "consume"),
        ("certificate_digest", digest(b"different")),
        ("window_record_digest", digest(b"wrong")),
        ("extra", True),
    ],
)
def test_even_validly_signed_semantic_drift_refuses(proof_setup, field, value):
    setup = proof_setup
    proof = produced(setup)
    record = json.loads(observation(setup, proof).canonical_bytes[len(DOMAIN) :])
    record[field] = value
    message = DOMAIN + canonical(record)
    with pytest.raises(ServiceRefused):
        verify(setup, proof, SignedSessionObservation(message, setup["sign"](message)))


def test_stale_observation_and_wrong_phase_refuse(proof_setup):
    setup = proof_setup
    proof = produced(setup)
    sidecar = observation(setup, proof)
    with pytest.raises(ServiceRefused):
        verify(setup, proof, sidecar, now=setup["now"] + timedelta(seconds=31))
    with pytest.raises(ServiceRefused):
        verify(
            setup,
            proof,
            sidecar,
            operation=replace(setup["operation"], window_id="other-window"),
        )


def test_auth_metadata_is_exact_actual_certificate(proof_setup):
    cert = proof_setup["cert"]
    assert parse_auth_info(b"publickey " + cert + b"\n") == cert
    with pytest.raises(ServiceRefused):
        parse_auth_info(b"publickey " + cert + b" extra\n")


class SyntheticExchange:
    def __init__(self, setup, extra=False):
        self.setup, self.extra = setup, extra
        self.reads = 0
        self.output = []

    def require_open(self):
        return None

    def send(self, document):
        self.output.append(document)

    def receive(self, allow_eof=False):
        self.reads += 1
        if self.reads == 1:
            return {
                "schema": "Gate0SessionBegin.v1",
                "phase": "issue",
                "plan_id": self.setup["operation"].plan_id,
                "workload_token": "synthetic-jwt",
                "authorization": None,
            }
        if self.reads == 2:
            challenge = self.output[0]
            return {
                "schema": "Gate0SessionResponse.v1",
                "challenge_id": challenge["challenge_id"],
                "sshsig": encode(
                    self.setup["sshsig"](decode(challenge["challenge"], 8192))
                ),
            }
        return {"extra": True} if self.extra else None


def session(setup):
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    admission = SimpleNamespace(
        admit=lambda *args: SimpleNamespace(operation=setup["operation"]),
        window_record_digest=lambda expected: digest(b"synthetic-independent-window"),
    )
    return AttesterSession(
        admission,
        setup["ca"].public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH),
        "synthetic-attester",
        setup["public"],
        setup["trust"],
        setup["sign"],
        setup["now"] + timedelta(seconds=120),
        lambda: setup["now"],
    )


def test_completed_same_channel_exchange_produces_signed_observation(proof_setup):
    setup = proof_setup
    exchange = SyntheticExchange(setup)
    session(setup).run(exchange, setup["cert"])
    proof, sidecar = parse_bundle(exchange.output[-1])
    verify(setup, proof, sidecar)
    assert len(setup["calls"]) == 3


def test_additional_frame_terminates_before_any_signature(proof_setup):
    setup = proof_setup
    with pytest.raises(ServiceRefused):
        session(setup).run(SyntheticExchange(setup, extra=True), setup["cert"])
    assert not setup["calls"]


def test_reader_rejects_wrong_uid_symlink_and_group_writable_file(
    proof_setup, tmp_path
):
    import os

    from vendor_cp.deployment.gate0_session import SshdSessionReader

    name = "sshauth.XXXXXXXXXabcdef"
    path = tmp_path / name
    path.write_bytes(b"publickey " + proof_setup["cert"] + b"\n")
    path.chmod(0o600)
    directory = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        reader = SshdSessionReader(directory, os.geteuid())
        environment = {"SSH_USER_AUTH": "/tmp/" + name}  # noqa: S108 -- exact metadata fixture lookup
        assert reader.read(environment) == proof_setup["cert"]
        with pytest.raises(ServiceRefused):
            SshdSessionReader(directory, os.geteuid() + 1).read(environment)
        with pytest.raises(ServiceRefused):
            reader.read(dict(environment, SSH_ORIGINAL_COMMAND="sh"))
        with pytest.raises(ServiceRefused):
            reader.read({"SSH_USER_AUTH": "/tmp/../" + name})  # noqa: S108 -- deliberate traversal rejection
        path.chmod(0o620)
        with pytest.raises(ServiceRefused):
            reader.read(environment)
        path.unlink()
        path.symlink_to(tmp_path / "outside")
        with pytest.raises(OSError):
            reader.read(environment)
    finally:
        os.close(directory)


def test_same_uid_can_fabricate_auth_file_parser_is_not_an_authenticator(
    proof_setup, tmp_path
):
    """Honest boundary: parser checks shape, not daemon-created provenance."""
    import os

    from vendor_cp.deployment.gate0_session import SshdSessionReader

    name = "sshauth.XXXXXXXXXabcdef"
    fabricated = tmp_path / name
    fabricated.write_bytes(b"publickey " + proof_setup["cert"] + b"\n")
    fabricated.chmod(0o600)
    directory = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert (
            SshdSessionReader(directory, os.geteuid()).read(
                {"SSH_USER_AUTH": "/tmp/" + name}  # noqa: S108 -- explicit forged same-UID fixture
            )
            == proof_setup["cert"]
        )  # noqa: S108 -- explicit forged same-UID fixture
    finally:
        os.close(directory)
