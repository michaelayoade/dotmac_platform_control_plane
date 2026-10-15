"""CP-only signed observation of one completed attester SSH proof invocation.

This observes the fixed attester command, not deployment or target action.
Control evidence and Gate0PublicProofTranscript.v1 remain unchanged.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import asdict, dataclass, fields
from datetime import UTC, datetime
from typing import cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vendor_cp.deployment.gate0_attester import ProducedAttestation
from vendor_cp.deployment.gate0_framing import ServiceRefused, canonical, strict_object
from vendor_cp.deployment.gate0_runtime import (
    AdmittedOperation,
    AttestationContext,
    CompanionAttestation,
)
from vendor_cp.deployment.rehearsal_issuer_trust_state import (
    RehearsalIssuerTrustState,
    TrustEligibility,
)

DOMAIN = b"dotmac.cp.gate0.ssh-session-observation.v1\x00"
COMMAND = "dotmac-platform gate0 attester-session"


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def decode(value: object, maximum: int) -> bytes:
    if not isinstance(value, str) or len(value) > 4 * ((maximum + 2) // 3):
        raise ServiceRefused()
    try:
        result = base64.b64decode(value, validate=True)
        if (
            not result
            or len(result) > maximum
            or base64.b64encode(result).decode("ascii") != value
        ):
            raise ServiceRefused()
        return result
    except ValueError:
        raise ServiceRefused() from None


def encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


@dataclass(frozen=True, slots=True)
class SignedSessionObservation:
    canonical_bytes: bytes
    signature: bytes


def observation_message(
    *,
    proof: ProducedAttestation,
    operation: AdmittedOperation,
    window_record_digest: str,
    invocation_id: str,
    observed_from: datetime,
    observed_until: datetime,
) -> bytes:
    if (
        re.fullmatch(r"sha256:[0-9a-f]{64}", window_record_digest) is None
        or re.fullmatch(r"[0-9a-f]{64}", invocation_id) is None
    ):
        raise ServiceRefused()
    if (
        observed_from.tzinfo is None
        or observed_until.tzinfo is None
        or not 0 <= (observed_until - observed_from).total_seconds() <= 30
    ):
        raise ServiceRefused()
    envelope = strict_object(proof.control_document, 128 * 1024)
    owner = decode(envelope.get("canonical_bytes"), 8192)
    document = {
        "schema": "Gate0SshSessionObservation.v1",
        "owner_canonical_digest": digest(owner),
        "proof_transcript_digest": digest(proof.public_proof_transcript),
        "window_record_digest": window_record_digest,
        "operation_digest": digest(canonical(asdict(operation))),
        "phase": operation.phase,
        "invocation_id": invocation_id,
        "controller_fingerprint": operation.controller_fingerprint,
        "certificate_digest": operation.certificate_digest,
        "ca_fingerprint": operation.ca_fingerprint,
        "command": COMMAND,
        "observed_from": observed_from.astimezone(UTC).isoformat(),
        "observed_until": observed_until.astimezone(UTC).isoformat(),
    }
    return DOMAIN + canonical(document)


def verify_observation(
    *,
    proof: ProducedAttestation,
    observation: SignedSessionObservation,
    operation: AdmittedOperation,
    window_record_digest: str,
    key_id: str,
    public_key: bytes,
    trust_state: RehearsalIssuerTrustState,
    now: datetime,
) -> None:
    """Verify signature and exact semantic record before returning proof to CP.

    The public runtime independently revalidates owner, companion and transcript.
    This sidecar authenticates only the precise session observation semantics.
    """
    if (
        trust_state.eligibility(
            key_id=key_id, public_key_fingerprint=digest(public_key)
        )
        != TrustEligibility.ELIGIBLE
    ):
        raise ServiceRefused()
    if (
        type(observation) is not SignedSessionObservation
        or type(observation.canonical_bytes) is not bytes
        or type(observation.signature) is not bytes
        or not 0 < len(observation.canonical_bytes) <= 8192
        or len(observation.signature) != 64
        or not observation.canonical_bytes.startswith(DOMAIN)
    ):
        raise ServiceRefused()
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            observation.signature, observation.canonical_bytes
        )
        document = strict_object(observation.canonical_bytes[len(DOMAIN) :], 8192)
        start = datetime.fromisoformat(str(document.get("observed_from")))
        end = datetime.fromisoformat(str(document.get("observed_until")))
        if (
            now.tzinfo is None
            or not start <= end <= now
            or (now - end).total_seconds() > 30
        ):
            raise ServiceRefused()
        expected = observation_message(
            proof=proof,
            operation=operation,
            window_record_digest=window_record_digest,
            invocation_id=str(document.get("invocation_id")),
            observed_from=start,
            observed_until=end,
        )
        if expected != observation.canonical_bytes:
            raise ServiceRefused()
        owner = strict_object(
            decode(strict_object(proof.control_document).get("canonical_bytes"), 8192)
        )
        issued = datetime.fromisoformat(str(owner.get("issued_at")))
        if not start <= issued <= end:
            raise ServiceRefused()
        if (
            trust_state.eligibility(
                key_id=key_id, public_key_fingerprint=digest(public_key)
            )
            != TrustEligibility.ELIGIBLE
        ):
            raise ServiceRefused()
    except Exception:
        raise ServiceRefused() from None


def bundle_document(
    proof: ProducedAttestation, observation: SignedSessionObservation
) -> dict[str, object]:
    return {
        "schema": "Gate0SessionProofBundle.v1",
        "control_document": encode(proof.control_document),
        "companion": encode(proof.companion.canonical_bytes),
        "companion_signature": encode(proof.companion.signature),
        "context": asdict(proof.context),
        "transcript": encode(proof.public_proof_transcript),
        "observation": encode(observation.canonical_bytes),
        "observation_signature": encode(observation.signature),
    }


def _context(document: object) -> AttestationContext:
    if type(document) is not dict or set(document) != {
        field.name for field in fields(AttestationContext)
    }:
        raise ServiceRefused()
    values = cast(dict[str, object], document)

    def string(key: str) -> str:
        value = values[key]
        if type(value) is not str:
            raise ServiceRefused()
        return value

    def optional_string(key: str) -> str | None:
        value = values[key]
        if value is not None and type(value) is not str:
            raise ServiceRefused()
        return value

    return AttestationContext(
        repository_id=string("repository_id"),
        run_id=string("run_id"),
        run_attempt=string("run_attempt"),
        window_id=string("window_id"),
        phase=string("phase"),
        authorization_digest=optional_string("authorization_digest"),
        authorization_issued_at=optional_string("authorization_issued_at"),
        lease_id=string("lease_id"),
        controller_fingerprint=string("controller_fingerprint"),
        target_ref=string("target_ref"),
        plan_id=string("plan_id"),
        plan_digest=string("plan_digest"),
        plan_purpose=string("plan_purpose"),
        operation=string("operation"),
        execution_plan_digest=string("execution_plan_digest"),
        certificate_digest=string("certificate_digest"),
        ca_fingerprint=string("ca_fingerprint"),
        challenge_digest=string("challenge_digest"),
        proof_transcript_digest=string("proof_transcript_digest"),
    )


def parse_bundle(
    document: object,
) -> tuple[ProducedAttestation, SignedSessionObservation]:
    if (
        type(document) is not dict
        or set(document)
        != {
            "schema",
            "control_document",
            "companion",
            "companion_signature",
            "context",
            "transcript",
            "observation",
            "observation_signature",
        }
        or document["schema"] != "Gate0SessionProofBundle.v1"
        or type(document["context"]) is not dict
    ):
        raise ServiceRefused()
    try:
        context = _context(document["context"])
        proof = ProducedAttestation(
            decode(document["control_document"], 128 * 1024),
            CompanionAttestation(
                decode(document["companion"], 8192),
                decode(document["companion_signature"], 64),
            ),
            context,
            decode(document["transcript"], 128 * 1024),
        )
        observation = SignedSessionObservation(
            decode(document["observation"], 8192),
            decode(document["observation_signature"], 64),
        )
        return proof, observation
    except Exception:
        raise ServiceRefused() from None
