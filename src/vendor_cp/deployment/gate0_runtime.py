"""Fixed public-key adapter for Control a17's existing verifier port.

No private keys, authority ledger, owner-schema extension or transport default.
A configured, independently authorized attester must first validate SSH key
possession, certificate/CA and provenance before signing the CP companion.
This consumer authenticates that attestation; it does not perform SSH proof.
Installing this adapter alone does not complete E or authorize a protected run.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from time import monotonic
from typing import TYPE_CHECKING, cast
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vendor_cp.deployment.rehearsal_issuer_trust_state import (
    RehearsalIssuerTrustState,
    TrustEligibility,
)

if TYPE_CHECKING:
    from vendor_cp.deployment.gate0_attester import ProducedAttestation

_DOMAIN = b"dotmac.cp.gate0.companion.v1\x00"
_PURPOSE = "deployment_rehearsal_harness_evidence"
_OWNER_KEYS = {
    "schema",
    "version",
    "lease_id",
    "controller_fingerprint",
    "target_ref",
    "environment",
    "issued_at",
    "valid_until",
}
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _ssh_fingerprint(value: str) -> bool:
    if not isinstance(value, str) or not value.startswith("SHA256:"):
        return False
    encoded = value[7:]
    try:
        raw = base64.b64decode(encoded + "=", validate=True)
    except (ValueError, binascii.Error):
        return False
    return len(raw) == 32 and base64.b64encode(raw).decode().rstrip("=") == encoded


@dataclass(frozen=True, slots=True)
class AdmittedOperation:
    """Frozen admission packet; never derived from untrusted owner evidence.

    Plan bindings must be checked against the real frozen Control plan by the
    composing caller. A route body or runner job metadata is not an oracle.
    """

    repository_id: str
    run_id: str
    run_attempt: str
    window_id: str
    phase: str
    authorization_digest: str | None
    authorization_issued_at: str | None
    lease_id: str
    controller_fingerprint: str
    target_ref: str
    plan_id: str
    plan_digest: str
    plan_purpose: str
    operation: str
    execution_plan_digest: str
    certificate_digest: str
    ca_fingerprint: str

    def __post_init__(self) -> None:
        values = asdict(self)
        if any(
            not isinstance(value, str)
            or not value
            or value != value.strip()
            or len(value) > 512
            for key, value in values.items()
            if key not in ("authorization_digest", "authorization_issued_at")
        ):
            raise ValueError("invalid frozen attestation context")
        if any(
            re.fullmatch(r"[1-9][0-9]{0,19}", value) is None
            for value in (self.repository_id, self.run_id, self.run_attempt)
        ):
            raise ValueError("invalid attestation run coordinate")
        if self.phase not in ("issue", "consume"):
            raise ValueError("expected issue or consume phase")
        if self.phase == "issue":
            if (
                self.authorization_digest is not None
                or self.authorization_issued_at is not None
            ):
                raise ValueError("issuance cannot name an existing authorization")
        else:
            if (
                not isinstance(self.authorization_digest, str)
                or _DIGEST.fullmatch(self.authorization_digest) is None
            ):
                raise ValueError("consumption requires actual authorization digest")
            if (
                not isinstance(self.authorization_issued_at, str)
                or len(self.authorization_issued_at) > 64
                or self.authorization_issued_at != self.authorization_issued_at.strip()
            ):
                raise ValueError(
                    "consumption requires actual authorization issuance time"
                )
            issued = datetime.fromisoformat(self.authorization_issued_at)
            if not _aware_datetime(issued):
                raise ValueError("expected aware authorization issuance time")
        if str(UUID(self.plan_id)) != self.plan_id:
            raise ValueError("expected canonical Control plan UUID")
        if self.plan_purpose != "rehearsal_issuer_operation":
            raise ValueError("expected issuer-operation plan purpose")
        if self.operation != "deploy" or any(
            _DIGEST.fullmatch(value) is None
            for value in (
                self.plan_digest,
                self.execution_plan_digest,
                self.certificate_digest,
            )
        ):
            raise ValueError("invalid attestation plan binding")
        if not _ssh_fingerprint(self.controller_fingerprint) or not _ssh_fingerprint(
            self.ca_fingerprint
        ):
            raise ValueError("expected actual OpenSSH public-key fingerprints")


@dataclass(frozen=True, slots=True)
class AttestationContext(AdmittedOperation):
    """Admitted operation plus exact producer-generated challenge/proof binding."""

    challenge_digest: str
    proof_transcript_digest: str

    def __post_init__(self) -> None:
        AdmittedOperation.__post_init__(self)
        if any(
            _DIGEST.fullmatch(value) is None
            for value in (
                self.challenge_digest,
                self.proof_transcript_digest,
            )
        ):
            raise ValueError("expected exact challenge and public proof digests")


@dataclass(frozen=True, slots=True)
class CompanionAttestation:
    canonical_bytes: bytes
    signature: bytes


def companion_message(context: AttestationContext, control_bytes: bytes) -> bytes:
    """Domain-separated CP transcript binding the EXACT owner evidence bytes.

    Never append repository/plan/certificate fields to Control's v1 schema.
    The same enrolled attester authenticates owner evidence and this companion;
    the issuer signing identity cannot act as the attester.
    """
    if (
        type(control_bytes) is not bytes
        or not control_bytes
        or len(control_bytes) > 8192
    ):
        raise ValueError("invalid owner evidence bounds")
    document = {
        "schema": "Gate0CompanionAttestation.v1",
        "context": asdict(context),
        "control_evidence_digest": "sha256:"
        + hashlib.sha256(control_bytes).hexdigest(),
    }
    encoded = _DOMAIN + json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    if len(encoded) > 8192:
        raise ValueError("invalid companion evidence bounds")
    return encoded


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate owner key")
        document[key] = value
    return document


def _aware_datetime(value: object) -> bool:
    return (
        type(value) is datetime
        and value.tzinfo is not None
        and value.utcoffset() is not None
    )


def _finite_monotonic(value: object) -> bool:
    if type(value) not in (int, float):
        return False
    number = cast(int | float, value)
    return math.isfinite(number) and number >= 0


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class ProtectedHarnessVerifier:
    """Construct once at authorized startup and install through Control's owner.

    `read_companion` is an injected read-only adapter to an adopted transport;
    None fails closed. The lookup key is the exact Control evidence digest.
    No protected transport is supplied by this source. The callback must return
    retained signed bytes, never manufacture assertions from runner metadata.
    The adopted transport must enforce its own bounded I/O deadline and
    cancellation. Synchronous callbacks cannot be interrupted here; post-lookup
    checks prevent late acceptance but do not bound blocked callback execution.
    """

    key_id: str
    public_key: bytes
    trust_state: RehearsalIssuerTrustState
    context: AttestationContext
    read_companion: Callable[[str], CompanionAttestation | None] | None
    expires_at: datetime
    now: Callable[[], datetime] = _utc_now
    monotonic_clock: Callable[[], float] = monotonic
    _started_at: datetime = field(init=False, repr=False)
    _monotonic_start: float = field(init=False, repr=False)
    _monotonic_deadline: float = field(init=False, repr=False)
    _public: Ed25519PublicKey = field(init=False, repr=False, compare=False)
    _fingerprint: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.key_id, str)
            or not self.key_id
            or len(self.key_id) > 512
        ):
            raise ValueError("invalid configured attester identity")
        if type(self.public_key) is not bytes or len(self.public_key) != 32:
            raise ValueError("expected configured Ed25519 attester public key")
        started_at = self.now()
        if not _aware_datetime(self.expires_at) or not _aware_datetime(started_at):
            raise ValueError("expected aware runtime clocks")
        duration = (self.expires_at - started_at).total_seconds()
        monotonic_start = self.monotonic_clock()
        if not math.isfinite(duration) or not 0 < duration <= 600:
            raise ValueError("runtime window must be positive and at most 600 seconds")
        if not _finite_monotonic(monotonic_start):
            raise ValueError("expected finite nonnegative monotonic clock")
        monotonic_deadline = monotonic_start + duration
        if (
            not math.isfinite(monotonic_deadline)
            or monotonic_deadline <= monotonic_start
        ):
            raise ValueError("invalid monotonic runtime deadline")
        # Exactly one startup-derived elapsed deadline. Verification never resets it.
        object.__setattr__(self, "_started_at", started_at)
        object.__setattr__(self, "_monotonic_start", monotonic_start)
        object.__setattr__(self, "_monotonic_deadline", monotonic_deadline)
        object.__setattr__(
            self, "_public", Ed25519PublicKey.from_public_bytes(self.public_key)
        )
        object.__setattr__(
            self,
            "_fingerprint",
            "sha256:" + hashlib.sha256(self.public_key).hexdigest(),
        )
        if (
            self.trust_state.eligibility(
                key_id=self.key_id, public_key_fingerprint=self._fingerprint
            )
            != TrustEligibility.ELIGIBLE
        ):
            raise ValueError("configured attester is not publicly eligible")

    def _within_window(self) -> bool:
        wall = self.now()
        elapsed = self.monotonic_clock()
        return (
            _aware_datetime(wall)
            and self._started_at <= wall < self.expires_at
            and _finite_monotonic(elapsed)
            and self._monotonic_start <= elapsed < self._monotonic_deadline
        )

    def verify_rehearsal_harness_evidence(
        self,
        *,
        key_id: str,
        algorithm: str,
        purpose: str,
        canonical_bytes: bytes,
        signature: bytes,
    ) -> bool:
        """Control public protocol, unchanged. Any incomplete input refuses."""
        try:
            return self._verify(key_id, algorithm, purpose, canonical_bytes, signature)
        except Exception:
            # Adapter failures never expose input/transport details through Control.
            return False

    def _verify(
        self,
        key_id: str,
        algorithm: str,
        purpose: str,
        canonical_bytes: bytes,
        signature: bytes,
    ) -> bool:
        if (
            key_id != self.key_id
            or algorithm != "ed25519"
            or purpose != _PURPOSE
            or self.read_companion is None
            or not self._within_window()
            or type(canonical_bytes) is not bytes
            or len(canonical_bytes) > 8192
            or type(signature) is not bytes
            or len(signature) != 64
        ):
            return False
        if (
            self.trust_state.eligibility(
                key_id=self.key_id, public_key_fingerprint=self._fingerprint
            )
            != TrustEligibility.ELIGIBLE
        ):
            return False
        # Owner separately validates canonical form, timestamps, standing and ledger.
        self._public.verify(signature, canonical_bytes)
        document = json.loads(canonical_bytes, object_pairs_hook=_unique_object)
        if not isinstance(document, dict) or set(document) != _OWNER_KEYS:
            return False
        if (
            document["schema"] != "dotmac.deployment_control.rehearsal_harness_evidence"
            or type(document["version"]) is not int
            or document["version"] != 1
            or document["environment"] != "rehearsal"
            or document["lease_id"] != self.context.lease_id
            or document["controller_fingerprint"] != self.context.controller_fingerprint
            or document["target_ref"] != self.context.target_ref
        ):
            return False
        lookup = "sha256:" + hashlib.sha256(canonical_bytes).hexdigest()
        companion = self.read_companion(lookup)
        if (
            type(companion) is not CompanionAttestation
            or type(companion.canonical_bytes) is not bytes
            or len(companion.canonical_bytes) > 8192
            or type(companion.signature) is not bytes
            or len(companion.signature) != 64
            or companion.canonical_bytes
            != companion_message(self.context, canonical_bytes)
        ):
            return False
        try:
            self._public.verify(companion.signature, companion.canonical_bytes)
        except InvalidSignature:
            return False
        # Fail closed if refresh/revocation occurred during transport verification.
        return (
            self._within_window()
            and self.trust_state.eligibility(
                key_id=self.key_id,
                public_key_fingerprint=self._fingerprint,
            )
            == TrustEligibility.ELIGIBLE
        )


class ProofRegistrationRefused(ValueError):
    """Bounded sanitized proof-cache refusal; never an authority verdict."""

    def __init__(self) -> None:
        super().__init__("gate0_proof_registration_refused")


@dataclass(frozen=True, slots=True)
class RegisteredProofExport:
    """Immutable private evidence readback, with no live verifier capability."""

    evidence_digest: str
    owner_envelope: bytes
    owner_bytes: bytes
    owner_signature: bytes
    key_id: str
    algorithm: str
    context: AttestationContext
    companion: CompanionAttestation
    transcript: bytes
    metadata: bytes


@dataclass(frozen=True, slots=True)
class _RetainedProof:
    owner_envelope: bytes
    owner_bytes: bytes
    owner_signature: bytes
    key_id: str
    algorithm: str
    context: AttestationContext
    companion: CompanionAttestation
    transcript: bytes
    metadata: bytes
    leaf: ProtectedHarnessVerifier = field(compare=False, repr=False)

    @property
    def size(self) -> int:
        return sum(
            len(value)
            for value in (
                self.owner_envelope,
                self.owner_bytes,
                self.owner_signature,
                self.companion.canonical_bytes,
                self.companion.signature,
                self.transcript,
                self.metadata,
            )
        )


def _strict_json(encoded: bytes, maximum: int) -> object:
    if type(encoded) is not bytes or not encoded or len(encoded) > maximum:
        raise ProofRegistrationRefused()
    return json.loads(
        encoded.decode("utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=_reject_nonfinite,
    )


def _reject_nonfinite(_: str) -> object:
    raise ProofRegistrationRefused()


def _bounded_base64(value: object, maximum: int) -> bytes:
    if not isinstance(value, str) or len(value) > 4 * ((maximum + 2) // 3):
        raise ProofRegistrationRefused()
    decoded = base64.b64decode(value, validate=True)
    if (
        not decoded
        or len(decoded) > maximum
        or base64.b64encode(decoded).decode("ascii") != value
    ):
        raise ProofRegistrationRefused()
    return decoded


def _sha256(encoded: bytes) -> str:
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


class BoundedHarnessVerifier:
    """Startup-fixed four-proof dispatcher; Control remains the spend owner.

    Private registration is called only by the composed driver, never a route.
    No eviction/reset/reinstall, mutable current phase or cached verification
    flag. Every verification invokes the existing immutable leaf again.
    """

    def __init__(
        self,
        *,
        key_id: str,
        public_key: bytes,
        trust_state: RehearsalIssuerTrustState,
        expires_at: datetime,
        now: Callable[[], datetime] = _utc_now,
        monotonic_clock: Callable[[], float] = monotonic,
        deadline: float | None = None,
    ) -> None:
        from threading import Lock

        started, origin = now(), monotonic_clock()
        if not _aware_datetime(started) or not _aware_datetime(expires_at):
            raise ProofRegistrationRefused()
        started, expires_at = started.astimezone(UTC), expires_at.astimezone(UTC)
        duration = (expires_at - started).total_seconds()
        if (
            not _finite_monotonic(origin)
            or not math.isfinite(duration)
            or not 0 < duration <= 600
        ):
            raise ProofRegistrationRefused()
        mapped_deadline = origin + duration
        if deadline is not None:
            if not _finite_monotonic(deadline) or deadline <= origin:
                raise ProofRegistrationRefused()
            mapped_deadline = min(mapped_deadline, deadline)
        deadline = mapped_deadline
        if not math.isfinite(deadline) or deadline <= origin:
            raise ProofRegistrationRefused()
        if (
            type(public_key) is not bytes
            or len(public_key) != 32
            or not isinstance(key_id, str)
            or not key_id
            or key_id != key_id.strip()
            or len(key_id) > 512
        ):
            raise ProofRegistrationRefused()
        if (
            trust_state.eligibility(
                key_id=key_id, public_key_fingerprint=_sha256(public_key)
            )
            != TrustEligibility.ELIGIBLE
        ):
            raise ProofRegistrationRefused()
        self._key_id, self._public_key, self._trust = key_id, public_key, trust_state
        self._expires, self._now, self._monotonic = expires_at, now, monotonic_clock
        self._started, self._origin, self._deadline = started, origin, deadline
        self._lock = Lock()
        self._entries: dict[str, _RetainedProof] = {}
        self._retained_bytes = 0

    def _samples(self) -> tuple[datetime, float]:
        wall, elapsed = self._now(), self._monotonic()
        if not _aware_datetime(wall):
            raise ProofRegistrationRefused()
        wall = wall.astimezone(UTC)  # no caller tzinfo callback under the cache lock
        if not self._samples_open(wall, elapsed):
            raise ProofRegistrationRefused()
        return wall, elapsed

    def _samples_open(self, wall: datetime, elapsed: float) -> bool:
        return (
            _aware_datetime(wall)
            and self._started <= wall < self._expires
            and _finite_monotonic(elapsed)
            and self._origin <= elapsed < self._deadline
        )

    def _require_open(self) -> None:
        self._samples()

    def require_window(self, *, expires_at: datetime, deadline: float) -> None:
        """Check this verifier fits an original window without remapping it."""
        if (
            not _aware_datetime(expires_at)
            or not _finite_monotonic(deadline)
            or self._expires > expires_at.astimezone(UTC)
            or self._deadline > deadline
        ):
            raise ProofRegistrationRefused()
        self._require_open()

    @property
    def _retained_count(self) -> int:
        with self._lock:
            return len(self._entries)

    def _evidence(self, digest: str) -> _RetainedProof:
        self._require_open()
        with self._lock:
            entry = self._entries.get(digest)
        if entry is None:
            raise ProofRegistrationRefused()
        self._require_open()
        return entry

    def export_registered(self, digest: str) -> RegisteredProofExport:
        """Export only already registered exact bytes within existing budgets.

        Evidence export deliberately does not refresh trust, extend eligibility
        or expose registration/leaf verification. Never send this aggregate in
        a frame; fixed service outcomes refer to collector-held bundle digests.
        """
        if type(digest) is not str or _DIGEST.fullmatch(digest) is None:
            raise ProofRegistrationRefused()
        with self._lock:
            entry = self._entries.get(digest)
        if entry is None:
            raise ProofRegistrationRefused()
        return RegisteredProofExport(
            digest,
            entry.owner_envelope,
            entry.owner_bytes,
            entry.owner_signature,
            entry.key_id,
            entry.algorithm,
            AttestationContext(**asdict(entry.context)),
            CompanionAttestation(
                entry.companion.canonical_bytes, entry.companion.signature
            ),
            entry.transcript,
            entry.metadata,
        )

    def _prepare(
        self, proof: ProducedAttestation, expected: AdmittedOperation
    ) -> _RetainedProof:
        from cryptography.hazmat.primitives.serialization import (
            SSHCertificate,
            load_ssh_public_identity,
        )
        from dotmac_deployment_control import (
            parse_signed_rehearsal_harness_evidence,
            verify_rehearsal_harness_evidence_signature,
        )

        from vendor_cp.deployment.gate0_attester import ProducedAttestation

        self._require_open()
        if (
            type(proof) is not ProducedAttestation
            or type(expected) is not AdmittedOperation
        ):
            raise ProofRegistrationRefused()
        if (
            type(proof.context) is not AttestationContext
            or type(proof.companion) is not CompanionAttestation
        ):
            raise ProofRegistrationRefused()
        owner_envelope = proof.control_document
        companion_bytes = proof.companion.canonical_bytes
        companion_signature = proof.companion.signature
        transcript_bytes = proof.public_proof_transcript
        context_input = proof.context
        raw_fields = (
            owner_envelope,
            companion_bytes,
            companion_signature,
            transcript_bytes,
        )
        if (
            any(type(value) is not bytes for value in raw_fields)
            or sum(map(len, raw_fields)) > 128 * 1024
        ):
            raise ProofRegistrationRefused()
        # Round-trip only the CP context; exact owner/proof bytes remain untouched.
        context_values = asdict(context_input)
        metadata = json.dumps(
            context_values,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        if len(metadata) > 8192:
            raise ProofRegistrationRefused()
        context = AttestationContext(**json.loads(metadata))
        actual_operation = {
            key: value
            for key, value in context_values.items()
            if key not in {"challenge_digest", "proof_transcript_digest"}
        }
        if actual_operation != asdict(expected):
            raise ProofRegistrationRefused()
        envelope = _strict_json(owner_envelope, 128 * 1024)
        parsed = parse_signed_rehearsal_harness_evidence(envelope)
        if (
            len(parsed.canonical_bytes) > 8192
            or len(parsed.signature) != 64
            or parsed.key_id != self._key_id
            or parsed.algorithm != "ed25519"
            or len(companion_bytes) > 8192
            or len(companion_signature) != 64
        ):
            raise ProofRegistrationRefused()
        transcript = _strict_json(transcript_bytes, 128 * 1024)
        if (
            not isinstance(transcript, dict)
            or set(transcript) != {"schema", "certificate", "challenge", "sshsig"}
            or transcript["schema"] != "Gate0PublicProofTranscript.v1"
        ):
            raise ProofRegistrationRefused()
        certificate = _bounded_base64(transcript["certificate"], 16384)
        challenge = _bounded_base64(transcript["challenge"], 8192)
        _bounded_base64(transcript["sshsig"], 16384)
        cert = load_ssh_public_identity(certificate)
        if (
            not isinstance(cert, SSHCertificate)
            or cert.public_bytes() != certificate
            or _sha256(certificate) != expected.certificate_digest
        ):
            raise ProofRegistrationRefused()
        challenge_document = _strict_json(challenge, 8192)
        if not isinstance(challenge_document, dict) or set(challenge_document) != {
            "schema",
            "instance_id",
            "challenge_id",
            "nonce",
            "context",
            "expires_at",
        }:
            raise ProofRegistrationRefused()
        if challenge_document[
            "schema"
        ] != "Gate0PossessionChallenge.v1" or challenge_document["context"] != asdict(
            expected
        ):
            raise ProofRegistrationRefused()
        if any(
            not isinstance(challenge_document[name], str)
            or re.fullmatch(r"[0-9a-f]{64}", challenge_document[name]) is None
            for name in ("instance_id", "challenge_id", "nonce")
        ):
            raise ProofRegistrationRefused()
        expiry_value = challenge_document["expires_at"]
        if not isinstance(expiry_value, str):
            raise ProofRegistrationRefused()
        challenge_expiry = datetime.fromisoformat(expiry_value)
        if (
            not _aware_datetime(challenge_expiry)
            or not parsed.issued_at < challenge_expiry <= self._expires
            or parsed.valid_until > self._expires
            or parsed.valid_until.timestamp() > cert.valid_before
            or parsed.issued_at.timestamp() < cert.valid_after
        ):
            raise ProofRegistrationRefused()
        if (
            _sha256(challenge) != context.challenge_digest
            or _sha256(transcript_bytes) != context.proof_transcript_digest
        ):
            raise ProofRegistrationRefused()
        companion = CompanionAttestation(companion_bytes, companion_signature)
        lookup = _sha256(parsed.canonical_bytes)
        leaf = ProtectedHarnessVerifier(
            key_id=self._key_id,
            public_key=self._public_key,
            trust_state=self._trust,
            context=context,
            read_companion=lambda requested: companion if requested == lookup else None,
            expires_at=self._expires,
            now=self._now,
            monotonic_clock=self._monotonic,
        )
        verify_rehearsal_harness_evidence_signature(
            parsed, verifier=leaf, at=self._now()
        )
        self._require_open()
        entry = _RetainedProof(
            owner_envelope,
            parsed.canonical_bytes,
            parsed.signature,
            parsed.key_id,
            parsed.algorithm,
            context,
            companion,
            transcript_bytes,
            metadata,
            leaf,
        )
        if entry.size > 128 * 1024:
            raise ProofRegistrationRefused()
        return entry

    def _register(self, proof: ProducedAttestation, expected: AdmittedOperation) -> str:
        failed = False
        try:
            entry = self._prepare(proof, expected)
            key = _sha256(entry.owner_bytes)
            samples = self._samples()  # All caller clocks/crypto run outside the lock.
            with self._lock:
                if not self._samples_open(*samples):
                    raise ProofRegistrationRefused()
                prior = self._entries.get(key)
                if prior is not None:
                    if prior != entry:
                        raise ProofRegistrationRefused()
                else:
                    if (
                        len(self._entries) >= 4
                        or self._retained_bytes + entry.size > 512 * 1024
                    ):
                        raise ProofRegistrationRefused()
                    self._entries[key] = entry
                    self._retained_bytes += entry.size
            # A clock can cross while awaiting the short lock; never return late.
            # Retention grants nothing and remains append-only even on late refusal.
            self._require_open()
            return key
        except Exception:
            failed = True
        if failed:
            raise ProofRegistrationRefused()
        raise ProofRegistrationRefused()

    def verify_rehearsal_harness_evidence(
        self,
        *,
        key_id: str,
        algorithm: str,
        purpose: str,
        canonical_bytes: bytes,
        signature: bytes,
    ) -> bool:
        try:
            self._require_open()
            if (
                key_id != self._key_id
                or algorithm != "ed25519"
                or purpose != _PURPOSE
                or type(canonical_bytes) is not bytes
                or not canonical_bytes
                or len(canonical_bytes) > 8192
                or type(signature) is not bytes
                or len(signature) != 64
            ):
                return False
            entry = self._evidence(_sha256(canonical_bytes))
            if (
                entry.owner_bytes != canonical_bytes
                or entry.owner_signature != signature
                or entry.key_id != key_id
                or entry.algorithm != algorithm
            ):
                return False
            verified = entry.leaf.verify_rehearsal_harness_evidence(
                key_id=key_id,
                algorithm=algorithm,
                purpose=purpose,
                canonical_bytes=canonical_bytes,
                signature=signature,
            )
            self._require_open()
            return verified
        except Exception:
            return False
