"""Nonresumable Gate-0 SSH possession producer; transport/custody unconfigured.

The caller must independently admit the frozen operation. This proves the
certified key signed that operation's challenge, not GitHub approval or its
later controller session. Control alone owns authorization/lease consumption.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import secrets
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Lock
from time import monotonic

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    SSHCertificate,
    SSHCertificateType,
    load_ssh_public_identity,
    load_ssh_public_key,
)

from vendor_cp.deployment.gate0_runtime import (
    AdmittedOperation,
    AttestationContext,
    CompanionAttestation,
    _aware_datetime,
    _finite_monotonic,
    companion_message,
)
from vendor_cp.deployment.rehearsal_issuer_trust_state import (
    RehearsalIssuerTrustState,
    TrustEligibility,
)

_NAMESPACE = "dotmac-gate0-possession-v1"
_SSH_KEYGEN = "/usr/bin/ssh-keygen"
_MAX_PUBLIC_INPUT = 16 * 1024


class AttesterRefused(ValueError):
    """Fixed sanitized refusal; no key, proof, callback or subprocess output."""

    def __init__(self) -> None:
        super().__init__("gate0_attester_refused")


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _canonical(document: object) -> bytes:
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def ssh_public_fingerprint(public_key: Ed25519PublicKey) -> str:
    """OpenSSH wire-key blob hash, never raw Ed25519 or certificate bytes."""
    encoded = public_key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
    blob = base64.b64decode(encoded.split(b" ")[1], validate=True)
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode(
        "ascii"
    ).rstrip("=")


@dataclass(frozen=True, slots=True)
class PossessionChallenge:
    challenge_id: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class ProducedAttestation:
    control_document: bytes
    companion: CompanionAttestation
    context: AttestationContext
    public_proof_transcript: bytes


@dataclass(frozen=True, slots=True)
class _Pending:
    challenge: PossessionChallenge
    certificate: bytes
    expires_at: datetime
    monotonic_deadline: float


def _write_public(path: Path, value: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(value)


def _verify_sshsig(
    public_key: Ed25519PublicKey,
    message: bytes,
    signature: bytes,
    remaining_budget: Callable[[], float],
) -> bool:
    """Fixed executable/namespace/identity; only public owner-created temp files.

    subprocess.run kills and reaps its owned direct child on timeout. Output is
    discarded; no shell, agent, private-key flag or caller-controlled argv.
    A cancelled hosted process/window is nonresumable and must be torn down by
    the operational supervisor; no durable pending state can be restored.
    """
    public = public_key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
    with tempfile.TemporaryDirectory(prefix="gate0-public-proof-") as directory:
        root = Path(directory)
        allowed = root / "allowed_signers"
        signed = root / "proof.sig"
        _write_public(
            allowed,
            b'gate0-controller namespaces="dotmac-gate0-possession-v1" '
            + public
            + b"\n",
        )
        _write_public(signed, signature)
        # Public-file staging consumes the same absolute child/challenge budget.
        timeout = remaining_budget()
        if not math.isfinite(timeout) or not 0 < timeout <= 2:
            return False
        result = subprocess.run(  # noqa: S603 -- fixed executable/options, generated public paths
            [
                _SSH_KEYGEN,
                "-Y",
                "verify",
                "-f",
                str(allowed),
                "-I",
                "gate0-controller",
                "-n",
                _NAMESPACE,
                "-s",
                str(signed),
            ],
            input=message,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
            shell=False,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
        return result.returncode == 0


class AttesterProofProducer:
    """Construct once with role-local signer and independently admitted context.

    At most 16 challenges in one <=600s lifetime, one active challenge for this
    fixed lease/phase, <=30s each. Terminal records are retained until shutdown;
    failures never rearm. New instances have fresh IDs and cannot resume state.
    Signer callbacks must enforce their own bounded operation/cancellation;
    postchecks prevent late acceptance but cannot interrupt a blocked signer.
    """

    def __init__(
        self,
        *,
        admitted: AdmittedOperation,
        ca_public_key: bytes,
        key_id: str,
        signer_purpose: str,
        attester_public_key: bytes,
        trust_state: RehearsalIssuerTrustState,
        sign: Callable[[bytes], bytes] | None,
        expires_at: datetime,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        monotonic_clock: Callable[[], float] = monotonic,
    ) -> None:
        if (
            type(admitted) is not AdmittedOperation
            or not callable(sign)
            or signer_purpose != "deployment_rehearsal_harness_evidence"
        ):
            raise AttesterRefused()
        if type(attester_public_key) is not bytes or len(attester_public_key) != 32:
            raise AttesterRefused()
        if (
            not isinstance(key_id, str)
            or not key_id
            or key_id != key_id.strip()
            or len(key_id) > 512
        ):
            raise AttesterRefused()
        failed = False
        try:
            started = now()
            origin = monotonic_clock()
            if not _aware_datetime(started) or not _aware_datetime(expires_at):
                raise ValueError
            duration = (expires_at - started).total_seconds()
            if (
                not _finite_monotonic(origin)
                or not math.isfinite(duration)
                or not 0 < duration <= 600
            ):
                raise ValueError
            deadline = origin + duration
            if not math.isfinite(deadline) or deadline <= origin:
                raise ValueError
            if (
                type(ca_public_key) is not bytes
                or len(ca_public_key) > _MAX_PUBLIC_INPUT
            ):
                raise ValueError
            ca = load_ssh_public_key(ca_public_key)
            if (
                not isinstance(ca, Ed25519PublicKey)
                or ssh_public_fingerprint(ca) != admitted.ca_fingerprint
            ):
                raise ValueError
            attester = Ed25519PublicKey.from_public_bytes(attester_public_key)
            if (
                trust_state.eligibility(
                    key_id=key_id, public_key_fingerprint=_digest(attester_public_key)
                )
                != TrustEligibility.ELIGIBLE
            ):
                raise ValueError
        except Exception:
            failed = True
        if failed:
            raise AttesterRefused()
        self._admitted = admitted
        self._ca = ca.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
        self._key_id = key_id
        self._attester = attester
        self._fingerprint = _digest(attester_public_key)
        self._trust = trust_state
        self._sign = sign
        self._now = now
        self._monotonic = monotonic_clock
        self._started = started
        self._origin = origin
        self._expires = expires_at
        self._deadline = deadline
        self._instance = secrets.token_hex(32)
        self._lock = Lock()
        self._records: dict[str, tuple[_Pending, str]] = {}
        self._evidence_digests: set[str] = set()

    def _clock(self) -> tuple[datetime, float]:
        wall, elapsed = self._now(), self._monotonic()
        if (
            not _aware_datetime(wall)
            or not self._started <= wall < self._expires
            or not _finite_monotonic(elapsed)
            or not self._origin <= elapsed < self._deadline
            or self._trust.eligibility(
                key_id=self._key_id, public_key_fingerprint=self._fingerprint
            )
            != TrustEligibility.ELIGIBLE
        ):
            raise AttesterRefused()
        return wall, elapsed

    def _certificate(self, encoded: bytes, wall: datetime) -> SSHCertificate:
        if (
            type(encoded) is not bytes
            or not encoded
            or len(encoded) > _MAX_PUBLIC_INPUT
        ):
            raise AttesterRefused()
        cert = load_ssh_public_identity(encoded)
        if not isinstance(cert, SSHCertificate):
            raise AttesterRefused()
        cert.verify_cert_signature()
        ca = cert.signature_key()
        controller = cert.public_key()
        if not isinstance(ca, Ed25519PublicKey) or not isinstance(
            controller, Ed25519PublicKey
        ):
            raise AttesterRefused()
        expected_key_id = (
            f"gate0:{self._admitted.repository_id}:"
            f"{self._admitted.run_id}:{self._admitted.run_attempt}"
        ).encode("ascii")
        if (
            ca.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH) != self._ca
            or cert.type != SSHCertificateType.USER
            or cert.valid_principals != [b"dotmac-gate0-controller"]
            or cert.key_id != expected_key_id
            or cert.critical_options
            or cert.extensions
            or not 0 < cert.valid_before - cert.valid_after <= 600
            or not cert.valid_after <= wall.timestamp() < cert.valid_before
            or ssh_public_fingerprint(controller)
            != self._admitted.controller_fingerprint
            or _digest(cert.public_bytes()) != self._admitted.certificate_digest
        ):
            raise AttesterRefused()
        return cert

    def begin_challenge(self, certificate_bytes: bytes) -> PossessionChallenge:
        failed = False
        try:
            wall, _ = self._clock()
            cert = self._certificate(certificate_bytes, wall)
            with self._lock:
                wall, elapsed = self._clock()
                if len(self._records) >= 16 or any(
                    state != "terminal" for _, state in self._records.values()
                ):
                    raise AttesterRefused()
                expires = min(
                    wall + timedelta(seconds=30),
                    self._expires,
                    datetime.fromtimestamp(cert.valid_before, UTC),
                )
                duration = (expires - wall).total_seconds()
                if duration <= 0:
                    raise AttesterRefused()
                challenge_id = secrets.token_hex(32)
                message = _canonical(
                    {
                        "schema": "Gate0PossessionChallenge.v1",
                        "instance_id": self._instance,
                        "challenge_id": challenge_id,
                        "nonce": secrets.token_hex(32),
                        "context": asdict(self._admitted),
                        "expires_at": _timestamp(expires),
                    }
                )
                if len(message) > 8192 or challenge_id in self._records:
                    raise AttesterRefused()
                challenge = PossessionChallenge(challenge_id, message)
                pending = _Pending(
                    challenge,
                    cert.public_bytes(),
                    expires,
                    min(self._deadline, elapsed + duration),
                )
                self._records[challenge_id] = (pending, "pending")
                return challenge
        except Exception:
            failed = True
        if failed:
            raise AttesterRefused()
        raise AttesterRefused()

    def complete_challenge(
        self, challenge_id: str, sshsig_bytes: bytes
    ) -> ProducedAttestation:
        # Atomically take before verification or irreversible external signing.
        with self._lock:
            if not isinstance(challenge_id, str) or len(challenge_id) != 64:
                raise AttesterRefused()
            entry = self._records.get(challenge_id)
            if entry is None or entry[1] != "pending":
                raise AttesterRefused()
            pending = entry[0]
            self._records[challenge_id] = (pending, "inflight")
        failed = False
        try:
            result = self._complete(pending, sshsig_bytes)
        except Exception:
            failed = True
        finally:
            with self._lock:
                self._records[challenge_id] = (pending, "terminal")
        if failed:
            raise AttesterRefused()
        return result

    def _current(self, pending: _Pending) -> tuple[datetime, float, SSHCertificate]:
        wall, elapsed = self._clock()
        if wall >= pending.expires_at or elapsed >= pending.monotonic_deadline:
            raise AttesterRefused()
        return wall, elapsed, self._certificate(pending.certificate, wall)

    def _sign_checked(self, message: bytes, pending: _Pending) -> bytes:
        self._current(pending)
        signature = self._sign(message)
        if type(signature) is not bytes or len(signature) != 64:
            raise AttesterRefused()
        self._attester.verify(signature, message)
        self._current(pending)
        return signature

    def _complete(self, pending: _Pending, signature: bytes) -> ProducedAttestation:
        wall, elapsed, cert = self._current(pending)
        if (
            type(signature) is not bytes
            or not signature
            or len(signature) > _MAX_PUBLIC_INPUT
        ):
            raise AttesterRefused()
        child_deadline = min(pending.monotonic_deadline, elapsed + 2.0)

        def remaining_budget() -> float:
            current_wall, current_elapsed = self._clock()
            return min(
                2.0,
                child_deadline - current_elapsed,
                (pending.expires_at - current_wall).total_seconds(),
            )

        public = cert.public_key()
        if not isinstance(public, Ed25519PublicKey) or not _verify_sshsig(
            public, pending.challenge.canonical_bytes, signature, remaining_budget
        ):
            raise AttesterRefused()
        wall, _, cert = self._current(pending)
        if self._admitted.phase == "consume":
            issued = self._admitted.authorization_issued_at
            if issued is None or wall <= datetime.fromisoformat(issued):
                raise AttesterRefused()
        valid_until = min(
            self._expires,
            datetime.fromtimestamp(cert.valid_before, UTC),
            wall + timedelta(seconds=30),
        )
        if valid_until <= wall:
            raise AttesterRefused()
        canonical = _canonical(
            {
                "schema": "dotmac.deployment_control.rehearsal_harness_evidence",
                "version": 1,
                "lease_id": self._admitted.lease_id,
                "controller_fingerprint": self._admitted.controller_fingerprint,
                "target_ref": self._admitted.target_ref,
                "environment": "rehearsal",
                "issued_at": _timestamp(wall),
                "valid_until": _timestamp(valid_until),
            }
        )
        transcript = _canonical(
            {
                "schema": "Gate0PublicProofTranscript.v1",
                "certificate": base64.b64encode(pending.certificate).decode("ascii"),
                "challenge": base64.b64encode(pending.challenge.canonical_bytes).decode(
                    "ascii"
                ),
                "sshsig": base64.b64encode(signature).decode("ascii"),
            }
        )
        context = AttestationContext(
            **asdict(self._admitted),
            challenge_digest=_digest(pending.challenge.canonical_bytes),
            proof_transcript_digest=_digest(transcript),
        )
        companion = companion_message(context, canonical)
        # The downstream companion resolver is keyed by exact owner digest.
        # Keep its bounded local reservation even if a later signer fails;
        # otherwise a frozen wall instant could publish conflicting companions.
        with self._lock:
            evidence_digest = _digest(canonical)
            if evidence_digest in self._evidence_digests:
                raise AttesterRefused()
            self._evidence_digests.add(evidence_digest)
        owner_signature = self._sign_checked(canonical, pending)
        companion_signature = self._sign_checked(companion, pending)
        self._current(pending)
        envelope = _canonical(
            {
                "canonical_bytes": base64.b64encode(canonical).decode("ascii"),
                "signature": {
                    "key_id": self._key_id,
                    "algorithm": "ed25519",
                    "signature": base64.b64encode(owner_signature).decode("ascii"),
                },
            }
        )
        return ProducedAttestation(
            envelope,
            CompanionAttestation(companion, companion_signature),
            context,
            transcript,
        )
