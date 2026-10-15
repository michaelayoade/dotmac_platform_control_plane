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
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vendor_cp.deployment.rehearsal_issuer_trust_state import (
    RehearsalIssuerTrustState,
    TrustEligibility,
)

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
class AttestationContext:
    """Frozen admission packet; never derived from untrusted owner evidence.

    Plan bindings must be checked against the real frozen Control plan by the
    composing caller. A route body or runner job metadata is not an oracle.
    """

    repository_id: str
    run_id: str
    run_attempt: str
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
            for value in values.values()
        ):
            raise ValueError("invalid frozen attestation context")
        if any(
            re.fullmatch(r"[1-9][0-9]{0,19}", value) is None
            for value in (self.repository_id, self.run_id, self.run_attempt)
        ):
            raise ValueError("invalid attestation run coordinate")
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
    return _DOMAIN + json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


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
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


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
