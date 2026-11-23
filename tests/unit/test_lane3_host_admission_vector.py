"""CP-5: Starter's fixed host-admission.json vector, against REAL Control a17.

Starter PR #1104 (`tests/unit/test_lane3_host_admission.py`) pins the presentation
statement bytes and signature of a synthetic fixture and says: "CP-5 reproduces the
statement with Control a17's `HostAdmissionPresentationStatementV1(...)
.canonical_bytes` and verifies the signature with Control's verifier; any difference
is a contract drift". This is that check. The constants below are copied from that
test; the seed, digests and instants are synthetic.

The target-side tool and Control are two implementations of one wire contract that
could not import each other, so this is the only place they meet.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime

import dotmac_deployment_control as control  # noqa: E402 - a missing wheel must FAIL, never skip
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

VECTOR_SEED = bytes(range(97, 129))
VECTOR_PUBLIC = "iC0Oo7KGTnpYfz5pjOpEWZmDEuZV4F-l6LURnYuqyM0"
DISPATCH_ID = "6f1c2f4e-52a8-4d0e-9a1b-2f0c7e6d9b11"
VECTOR_BYTES = (
    '{"audience":"dotmac.deployment-control",'
    '"candidate_attestation_envelope_digest":"sha256:' + "1" * 64 + '",'
    '"dispatch_id":"6f1c2f4e-52a8-4d0e-9a1b-2f0c7e6d9b11",'
    '"expires_at":"2026-11-19T10:09:58Z",'
    '"installed_attestation_envelope_digest":"sha256:' + "2" * 64 + '",'
    '"issued_at":"2026-11-19T10:04:58Z",'
    '"key_id":"presentation-key-1",'
    '"presentation_id":"presentation-vector-0001",'
    '"purpose":"dotmac.control.host-admission-presentation.v1",'
    '"schema":"dotmac.control.host-admission-presentation",'
    '"version":1}'
)
VECTOR_SIGNATURE = (
    "MSlN7XT7SIx41-icMqx0C9ghozgZf0Ezc_V52Xu3h9EV7jLAaKqMhjTjDAZyAehLS6FCem3Dnuq9E_"
    "XddXmADg"
)


def _statement() -> object:
    return control.HostAdmissionPresentationStatementV1(
        presentation_id="presentation-vector-0001",
        key_id="presentation-key-1",
        dispatch_id=DISPATCH_ID,
        candidate_attestation_envelope_digest="sha256:" + "1" * 64,
        installed_attestation_envelope_digest="sha256:" + "2" * 64,
        issued_at=datetime(2026, 11, 19, 10, 4, 58, tzinfo=UTC),
        expires_at=datetime(2026, 11, 19, 10, 9, 58, tzinfo=UTC),
    )


def _unpadded(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def test_the_seed_derives_the_vectors_public_key() -> None:
    key = Ed25519PrivateKey.from_private_bytes(VECTOR_SEED)
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    assert _unpadded(raw) == VECTOR_PUBLIC


def test_control_a17_renders_exactly_the_vectors_statement_bytes() -> None:
    assert _statement().canonical_bytes.decode("ascii") == VECTOR_BYTES  # type: ignore[attr-defined]


def test_the_vectors_signature_is_ed25519_over_those_bytes_unpadded_base64url() -> None:
    assert "=" not in VECTOR_SIGNATURE
    key = Ed25519PrivateKey.from_private_bytes(VECTOR_SEED)
    assert _unpadded(key.sign(VECTOR_BYTES.encode())) == VECTOR_SIGNATURE
    raw = base64.urlsafe_b64decode(VECTOR_SIGNATURE + "==")
    key.public_key().verify(raw, VECTOR_BYTES.encode())
    with pytest.raises(InvalidSignature):
        key.public_key().verify(raw, VECTOR_BYTES.encode() + b" ")


def test_control_parses_the_vectors_presentation_and_roundtrips_it() -> None:
    document = {
        "statement": _statement().as_mapping(),  # type: ignore[attr-defined]
        "signature": VECTOR_SIGNATURE,
    }
    parsed = control.HostAdmissionPresentationV1.parse(document)
    assert parsed.as_mapping() == document
    assert parsed.statement.canonical_bytes.decode("ascii") == VECTOR_BYTES


def test_control_refuses_a_drifted_statement() -> None:
    document = {
        "statement": {**_statement().as_mapping(), "version": 2},  # type: ignore[attr-defined]
        "signature": VECTOR_SIGNATURE,
    }
    with pytest.raises(control.HostAdmissionPresentationRefusedError):
        control.HostAdmissionPresentationV1.parse(document)


def test_the_statement_member_set_is_the_closed_eleven() -> None:
    assert set(_statement().as_mapping()) == {  # type: ignore[attr-defined]
        "schema",
        "version",
        "purpose",
        "audience",
        "presentation_id",
        "key_id",
        "dispatch_id",
        "candidate_attestation_envelope_digest",
        "installed_attestation_envelope_digest",
        "issued_at",
        "expires_at",
    }
