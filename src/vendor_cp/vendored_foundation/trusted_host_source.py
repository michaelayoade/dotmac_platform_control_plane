"""Fail-closed contract for independently-custodied host provenance.

This module does not admit an executor. Until 0.4.0a2 has independently
produced candidate and host attestations, mutating executors retain their
explicit ``require_host_source(receipt=None)`` refusal. These types freeze the
successor contract; they hold no private key, discover no file, and do no I/O.

The candidate signer is the protected Starter release-workflow identity; the
host signer is a distinct target-local host-attestation workload identity.
Platform transports only. Control will later bind public-key fingerprints,
purposes and custody domains. A key-id label is never an authority.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Final, Protocol, runtime_checkable

from .digest import Digest
from .errors import PreconditionFailed, SpecError

__all__ = [
    "ATTESTATION_SCHEMA",
    "CANDIDATE_ATTESTATION_PURPOSE",
    "INSTALLED_OBSERVATION_PURPOSE",
    "attestation_envelope_digest",
    "ATTESTATIONS_DISAGREE",
    "AUDIENCE_MISMATCH",
    "FUTURE",
    "KEY_NOT_TRUSTED",
    "OBSERVATION_ABSENT",
    "OBSERVATION_ID_MISMATCH",
    "OBSERVATION_MALFORMED",
    "PACKAGE_MISMATCH",
    "ROOT_BINDING_MISMATCH",
    "ROOT_NOT_VALID",
    "ROOT_PURPOSE_MISMATCH",
    "ROOT_REVOKED",
    "SIGNATURE_INVALID",
    "STALE",
    "SUBJECT_MISMATCH",
    "TRUST_ROOTS_NOT_DISTINCT",
    "SAME_KEY_SIGNED_BOTH",
    "AttestationEnvelopeV2",
    "AttestationPairVerificationResultV1",
    "AttestationTrustPolicy",
    "AttestationTrustRootV2",
    "AttestationVerifiedRootV1",
    "AttestationVerifier",
    "CandidateAttestationSubjectV2",
    "InstalledHostAttestationSubjectV2",
    "candidate_subject_digest",
    "verify_attestation_pair",
    "verify_candidate_attestation",
]

ATTESTATION_SCHEMA: Final = "TrustedHostAttestation.v2"
CANDIDATE_ATTESTATION_PURPOSE: Final = "dotmac.foundation.candidate-artifact.v2"
INSTALLED_OBSERVATION_PURPOSE: Final = "dotmac.foundation.installed-host.v2"
OBSERVATION_ABSENT: Final = "trusted-host-source-attestation-absent"
OBSERVATION_MALFORMED: Final = "trusted-host-source-attestation-malformed"
TRUST_ROOTS_NOT_DISTINCT: Final = "trusted-host-source-trust-roots-not-distinct"
SAME_KEY_SIGNED_BOTH: Final = "trusted-host-source-same-key-signed-both"
KEY_NOT_TRUSTED: Final = "trusted-host-source-key-not-trusted"
SIGNATURE_INVALID: Final = "trusted-host-source-signature-invalid"
ATTESTATIONS_DISAGREE: Final = "trusted-host-source-attestations-disagree"
OBSERVATION_ID_MISMATCH: Final = "trusted-host-source-observation-id-mismatch"
PACKAGE_MISMATCH: Final = "trusted-host-source-package-mismatch"
ROOT_PURPOSE_MISMATCH: Final = "trusted-host-source-root-purpose-mismatch"
ROOT_BINDING_MISMATCH: Final = "trusted-host-source-root-binding-mismatch"
ROOT_REVOKED: Final = "trusted-host-source-root-revoked"
ROOT_NOT_VALID: Final = "trusted-host-source-root-not-valid"
AUDIENCE_MISMATCH: Final = "trusted-host-source-audience-mismatch"
STALE: Final = "trusted-host-source-stale"
FUTURE: Final = "trusted-host-source-future"
SUBJECT_MISMATCH: Final = "trusted-host-source-subject-mismatch"
_FINGERPRINT = re.compile(r"^sha256:[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_UTC_RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")


def _required(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise SpecError(f"{name} is required", code=OBSERVATION_MALFORMED)
    return value


def _instant(value: str, name: str) -> datetime:
    if not isinstance(value, str) or not _UTC_RFC3339.fullmatch(value):
        raise SpecError(
            f"{name} must be canonical UTC RFC3339", code=OBSERVATION_MALFORMED
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SpecError(f"{name} must be RFC3339", code=OBSERVATION_MALFORMED) from exc
    return parsed.astimezone(UTC)


def _mapping(value: object, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or isinstance(value, str | bytes):
        raise SpecError(f"{name} must be a mapping", code=OBSERVATION_MALFORMED)
    if any(not isinstance(key, str) for key in value):
        raise SpecError(f"{name} keys must be strings", code=OBSERVATION_MALFORMED)
    return value


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def _wire_digest(value: object, name: str) -> Digest:
    text = _required(value, name)
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", text):
        raise SpecError(
            f"{name} must use canonical sha256:<lowercase hex> form",
            code=OBSERVATION_MALFORMED,
        )
    return Digest.parse(text, where=name)


@dataclasses.dataclass(frozen=True, slots=True)
class CandidateAttestationSubjectV2:
    """Complete release subject, including CandidateArtifact.v1 coordinates."""

    package: str
    version: str
    wheel_sha256: Digest
    source_revision: str
    repository: str
    run_id: str
    artifact_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.wheel_sha256, Digest):
            raise SpecError(
                "candidate wheel_sha256 must be a Digest",
                code=OBSERVATION_MALFORMED,
            )
        for name in (
            "package",
            "version",
            "source_revision",
            "repository",
            "run_id",
            "artifact_id",
        ):
            _required(getattr(self, name), f"candidate subject {name}")
        if not _REVISION.fullmatch(self.source_revision):
            raise SpecError(
                "candidate source_revision must be a 40-hex commit",
                code=OBSERVATION_MALFORMED,
            )

    def canonical_document(self) -> dict[str, str]:
        return {
            "package": self.package,
            "version": self.version,
            "wheel_sha256": str(self.wheel_sha256),
            "source_revision": self.source_revision,
            "repository": self.repository,
            "run_id": self.run_id,
            "artifact_id": self.artifact_id,
        }

    @classmethod
    def from_mapping(cls, value: object) -> CandidateAttestationSubjectV2:
        value = _mapping(value, "candidate subject")
        if set(value) != {
            "package",
            "version",
            "wheel_sha256",
            "source_revision",
            "repository",
            "run_id",
            "artifact_id",
        }:
            raise SpecError(
                "candidate subject is incomplete or widened", code=OBSERVATION_MALFORMED
            )
        return cls(
            _required(value["package"], "candidate package"),
            _required(value["version"], "candidate version"),
            _wire_digest(value["wheel_sha256"], "candidate wheel_sha256"),
            _required(value["source_revision"], "candidate source_revision"),
            _required(value["repository"], "candidate repository"),
            _required(value["run_id"], "candidate run_id"),
            _required(value["artifact_id"], "candidate artifact_id"),
        )


@dataclasses.dataclass(frozen=True, slots=True)
class InstalledHostAttestationSubjectV2:
    """Host observation bound to one candidate and an expected host identity."""

    host_identity: str
    package: str
    version: str
    wheel_sha256: Digest
    candidate_subject_digest: Digest

    def __post_init__(self) -> None:
        if not isinstance(self.wheel_sha256, Digest) or not isinstance(
            self.candidate_subject_digest, Digest
        ):
            raise SpecError(
                "installed digests must be Digest values",
                code=OBSERVATION_MALFORMED,
            )
        for name in ("host_identity", "package", "version"):
            _required(getattr(self, name), f"installed subject {name}")

    def canonical_document(self) -> dict[str, str]:
        return {
            "host_identity": self.host_identity,
            "package": self.package,
            "version": self.version,
            "wheel_sha256": str(self.wheel_sha256),
            "candidate_subject_digest": str(self.candidate_subject_digest),
        }

    @classmethod
    def from_mapping(cls, value: object) -> InstalledHostAttestationSubjectV2:
        value = _mapping(value, "installed subject")
        expected = {
            "host_identity",
            "package",
            "version",
            "wheel_sha256",
            "candidate_subject_digest",
        }
        if set(value) != expected:
            raise SpecError(
                "installed subject is incomplete or widened", code=OBSERVATION_MALFORMED
            )
        candidate_digest = _required(
            value["candidate_subject_digest"], "installed candidate_subject_digest"
        )
        if not candidate_digest.startswith("sha256:"):
            raise SpecError(
                "installed candidate_subject_digest must use canonical sha256: form",
                code=OBSERVATION_MALFORMED,
            )
        return cls(
            _required(value["host_identity"], "installed host_identity"),
            _required(value["package"], "installed package"),
            _required(value["version"], "installed version"),
            _wire_digest(value["wheel_sha256"], "installed wheel_sha256"),
            _wire_digest(candidate_digest, "installed candidate_subject_digest"),
        )


@dataclasses.dataclass(frozen=True, slots=True)
class AttestationEnvelopeV2:
    """Parsed signed v2 evidence, never an authority or admission result."""

    schema: str
    purpose: str
    issuer: str
    key_id: str
    algorithm: str
    public_key_fingerprint: str
    custody_domain: str
    trust_root_version: str
    issued_at: str
    expires_at: str
    audience: str
    observation_id: str
    subject: Mapping[str, Any]
    signature: str
    _subject_bytes: bytes = dataclasses.field(init=False, repr=False)

    def __post_init__(self) -> None:
        for name in (
            "schema",
            "purpose",
            "issuer",
            "key_id",
            "algorithm",
            "public_key_fingerprint",
            "custody_domain",
            "trust_root_version",
            "issued_at",
            "expires_at",
            "audience",
            "observation_id",
            "signature",
        ):
            _required(getattr(self, name), f"attestation {name}")
        if self.schema != ATTESTATION_SCHEMA:
            raise SpecError(
                f"attestation schema must be {ATTESTATION_SCHEMA}",
                code=OBSERVATION_MALFORMED,
            )
        if not _FINGERPRINT.fullmatch(self.public_key_fingerprint):
            raise SpecError(
                "attestation fingerprint must be sha256:<64 lower-case hex>",
                code=OBSERVATION_MALFORMED,
            )
        if not isinstance(self.subject, Mapping) or isinstance(self.subject, str):
            raise SpecError(
                "attestation subject must be parsed object", code=OBSERVATION_MALFORMED
            )
        try:
            subject_bytes = _canonical(dict(self.subject))
            json.loads(subject_bytes)
        except (TypeError, ValueError) as exc:
            raise SpecError(
                "attestation subject must contain JSON-only values",
                code=OBSERVATION_MALFORMED,
            ) from exc
        object.__setattr__(self, "_subject_bytes", subject_bytes)
        if _instant(self.expires_at, "expires_at") <= _instant(
            self.issued_at, "issued_at"
        ):
            raise SpecError(
                "expires_at must follow issued_at", code=OBSERVATION_MALFORMED
            )

    def signed_bytes(self) -> bytes:
        document = self.canonical_document()
        document.pop("signature")
        return _canonical(document)

    def canonical_document(self) -> dict[str, Any]:
        """Return the complete parsed envelope mapping, including signature."""
        fields = (
            "schema",
            "purpose",
            "issuer",
            "key_id",
            "algorithm",
            "public_key_fingerprint",
            "custody_domain",
            "trust_root_version",
            "issued_at",
            "expires_at",
            "audience",
            "observation_id",
            "subject",
            "signature",
        )
        document = {name: getattr(self, name) for name in fields if name != "subject"}
        document["subject"] = json.loads(self._subject_bytes)
        return document

    def subject_mapping(self) -> Mapping[str, Any]:
        value = json.loads(self._subject_bytes)
        if not isinstance(value, Mapping):
            raise SpecError(
                "attestation subject snapshot is malformed", code=OBSERVATION_MALFORMED
            )
        return value

    @classmethod
    def from_mapping(cls, value: object) -> AttestationEnvelopeV2:
        value = _mapping(value, "attestation envelope")
        fields = {field.name for field in dataclasses.fields(cls) if field.init}
        if set(value) != fields:
            raise SpecError(
                "attestation envelope has missing or unknown members",
                code=OBSERVATION_MALFORMED,
            )
        return cls(**{name: value[name] for name in fields})


@dataclasses.dataclass(frozen=True, slots=True)
class AttestationTrustRootV2:
    """Control-provided public verification identity; labels confer no trust."""

    public_key_fingerprint: str
    public_key_base64: str
    issuer: str
    key_id: str
    purpose: str
    custody_domain: str
    algorithm: str
    trust_root_version: str
    not_before: str
    not_after: str
    revoked: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.revoked, bool):
            raise SpecError(
                "trust root revoked must be boolean", code=OBSERVATION_MALFORMED
            )
        for name in (
            "public_key_fingerprint",
            "public_key_base64",
            "issuer",
            "key_id",
            "purpose",
            "custody_domain",
            "algorithm",
            "trust_root_version",
            "not_before",
            "not_after",
        ):
            _required(getattr(self, name), f"trust root {name}")
        if not _FINGERPRINT.fullmatch(self.public_key_fingerprint):
            raise SpecError(
                "trust-root fingerprint must be sha256:<64 lower-case hex>",
                code=OBSERVATION_MALFORMED,
            )
        try:
            material = base64.b64decode(self.public_key_base64, validate=True)
        except ValueError as exc:
            raise SpecError(
                "trust-root public_key_base64 is not strict base64",
                code=OBSERVATION_MALFORMED,
            ) from exc
        if not material or (
            f"sha256:{hashlib.sha256(material).hexdigest()}"
            != self.public_key_fingerprint
        ):
            raise SpecError(
                "trust-root public material does not match its fingerprint",
                code=OBSERVATION_MALFORMED,
            )
        if _instant(self.not_after, "root not_after") <= _instant(
            self.not_before, "root not_before"
        ):
            raise SpecError(
                "root not_after must follow not_before", code=OBSERVATION_MALFORMED
            )


@dataclasses.dataclass(frozen=True, slots=True)
class AttestationTrustPolicy:
    """Immutable roots with disjoint public material and custody domains."""

    candidate_roots: tuple[AttestationTrustRootV2, ...]
    installed_roots: tuple[AttestationTrustRootV2, ...]
    candidate_audience: str
    installed_audience: str

    def __post_init__(self) -> None:
        try:
            candidate_roots = tuple(self.candidate_roots)
            installed_roots = tuple(self.installed_roots)
        except TypeError as exc:
            raise SpecError(
                "trust-root roles must be collections",
                code=OBSERVATION_MALFORMED,
            ) from exc
        object.__setattr__(self, "candidate_roots", candidate_roots)
        object.__setattr__(self, "installed_roots", installed_roots)
        all_roots = (*self.candidate_roots, *self.installed_roots)
        if any(not isinstance(root, AttestationTrustRootV2) for root in all_roots):
            raise SpecError(
                "trust roots must be AttestationTrustRootV2 values",
                code=OBSERVATION_MALFORMED,
            )
        if not self.candidate_roots or not self.installed_roots:
            raise SpecError(
                "both trust-root roles are required", code=OBSERVATION_MALFORMED
            )
        _required(self.candidate_audience, "candidate audience")
        _required(self.installed_audience, "installed audience")
        candidate_fps = {r.public_key_fingerprint for r in self.candidate_roots}
        installed_fps = {r.public_key_fingerprint for r in self.installed_roots}
        candidate_domains = {r.custody_domain for r in self.candidate_roots}
        installed_domains = {r.custody_domain for r in self.installed_roots}
        if candidate_fps & installed_fps or candidate_domains & installed_domains:
            raise SpecError(
                "trust roots overlap in public material or custody",
                code=TRUST_ROOTS_NOT_DISTINCT,
            )
        if len(candidate_fps) != len(self.candidate_roots) or len(installed_fps) != len(
            self.installed_roots
        ):
            raise SpecError(
                "a custody role declares duplicate public-key material",
                code=TRUST_ROOTS_NOT_DISTINCT,
            )


@runtime_checkable
class AttestationVerifier(Protocol):
    """Pure crypto seam; executors must not accept this or preverified evidence."""

    def verify(
        self,
        *,
        public_key: bytes,
        algorithm: str,
        message: bytes,
        signature: str,
    ) -> bool: ...


def _verify(
    envelope: AttestationEnvelopeV2,
    verifier: AttestationVerifier,
    roots: tuple[AttestationTrustRootV2, ...],
    purpose: str,
    audience: str,
    now: datetime,
) -> AttestationTrustRootV2:
    matches = [
        root
        for root in roots
        if root.public_key_fingerprint == envelope.public_key_fingerprint
    ]
    if not matches:
        raise PreconditionFailed(
            "attestation public-key material is unknown", code=KEY_NOT_TRUSTED
        )
    root = matches[0]
    if root.revoked:
        raise PreconditionFailed("attestation root is revoked", code=ROOT_REVOKED)
    root_not_before, root_not_after = (
        _instant(root.not_before, "root not_before"),
        _instant(root.not_after, "root not_after"),
    )
    if not root_not_before <= now < root_not_after:
        raise PreconditionFailed(
            "attestation root is not currently valid", code=ROOT_NOT_VALID
        )
    if envelope.purpose != purpose or root.purpose != purpose:
        raise PreconditionFailed(
            "attestation purpose does not match its trusted role",
            code=ROOT_PURPOSE_MISMATCH,
        )
    mismatches = [
        name
        for name in (
            "issuer",
            "key_id",
            "algorithm",
            "custody_domain",
            "trust_root_version",
        )
        if getattr(envelope, name) != getattr(root, name)
    ]
    if mismatches:
        raise PreconditionFailed(
            f"attestation root binding differs in {', '.join(mismatches)}",
            code=ROOT_BINDING_MISMATCH,
        )
    if envelope.audience != audience:
        raise PreconditionFailed(
            f"attestation audience differs from expected role audience {audience!r}",
            code=AUDIENCE_MISMATCH,
        )
    issued, expires = (
        _instant(envelope.issued_at, "issued_at"),
        _instant(envelope.expires_at, "expires_at"),
    )
    if issued > now:
        raise PreconditionFailed("attestation is issued in the future", code=FUTURE)
    if now >= expires:
        raise PreconditionFailed("attestation is stale or expired", code=STALE)
    if not root_not_before <= issued < root_not_after or expires > root_not_after:
        raise PreconditionFailed(
            "attestation lifetime is outside its root validity", code=ROOT_NOT_VALID
        )
    try:
        verified = verifier.verify(
            public_key=base64.b64decode(root.public_key_base64, validate=True),
            algorithm=envelope.algorithm,
            message=envelope.signed_bytes(),
            signature=envelope.signature,
        )
    except Exception as exc:
        raise PreconditionFailed(
            "attestation signature verification failed", code=SIGNATURE_INVALID
        ) from exc
    if not verified:
        raise PreconditionFailed(
            "attestation signature is invalid", code=SIGNATURE_INVALID
        )
    return root


def _verify_candidate_and_root(
    *,
    candidate: AttestationEnvelopeV2,
    verifier: AttestationVerifier,
    trust_policy: AttestationTrustPolicy,
    now: datetime,
) -> tuple[CandidateAttestationSubjectV2, AttestationTrustRootV2]:
    """The one candidate verification code path.

    Both ``verify_candidate_attestation`` (the public seam) and
    ``verify_attestation_pair`` call this exact function — there is exactly
    one candidate verification code path in this module, not two that could
    drift apart. The only difference from the public wrapper is that this
    also returns the matched trust root, which ``verify_attestation_pair``
    needs to echo back in its widened result.
    """
    if not isinstance(candidate, AttestationEnvelopeV2):
        raise SpecError(
            "candidate attestation must be a parsed AttestationEnvelopeV2",
            code=OBSERVATION_MALFORMED,
        )
    if not isinstance(trust_policy, AttestationTrustPolicy):
        raise SpecError(
            "trust_policy must be an AttestationTrustPolicy",
            code=OBSERVATION_MALFORMED,
        )
    if not isinstance(verifier, AttestationVerifier):
        raise SpecError(
            "verifier must implement AttestationVerifier",
            code=OBSERVATION_MALFORMED,
        )
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise SpecError(
            "verification now must be timezone-aware", code=OBSERVATION_MALFORMED
        )
    now = now.astimezone(UTC)
    root = _verify(
        candidate,
        verifier,
        trust_policy.candidate_roots,
        CANDIDATE_ATTESTATION_PURPOSE,
        trust_policy.candidate_audience,
        now,
    )
    return CandidateAttestationSubjectV2.from_mapping(candidate.subject_mapping()), root


def verify_candidate_attestation(
    *,
    candidate: AttestationEnvelopeV2,
    verifier: AttestationVerifier,
    trust_policy: AttestationTrustPolicy,
    now: datetime,
) -> CandidateAttestationSubjectV2:
    """The one seam that turns a candidate envelope into an authenticated subject.

    A trusted host workload does not get to trust a parsed
    ``CandidateReceipt`` — that type is a plain, publicly-constructible
    dataclass and carries no authority (see ``host_source.py``'s
    ``CandidateReceipt``, which stays that way). This function is what a host
    calls INSTEAD: it authenticates the signed ``AttestationEnvelopeV2``
    against Control-resolved candidate trust roots and returns the subject
    that survived that check — never a subject the caller supplied.

    The signature makes the bypass inexpressible rather than merely
    discouraged: there is no parameter for a subject, a digest, a receipt, or
    an ad hoc root. The only inputs are the envelope to authenticate and the
    trust configuration Control already resolved (``verifier`` stays
    injected, per this facility's zero-runtime-dependency crypto seam;
    ``trust_policy`` is the whole immutable, internally-validated root set,
    not a caller-editable list). This is a thin wrapper over
    ``_verify_candidate_and_root`` — the same private function
    ``verify_attestation_pair`` calls for its candidate half — so there is
    exactly one candidate verification code path in this module, not two
    that could drift apart.
    """
    subject, _root = _verify_candidate_and_root(
        candidate=candidate, verifier=verifier, trust_policy=trust_policy, now=now
    )
    return subject


def candidate_subject_digest(candidate: CandidateAttestationSubjectV2) -> Digest:
    """The one computation that binds an installed observation to the
    candidate subject it was measured against.

    A host-side signer needs this SAME value to populate `InstalledHost
    AttestationSubjectV2.candidate_subject_digest` before this module's own
    `verify_attestation_pair` recomputes it (below) for comparison. Exposing
    it here, rather than leaving each side to restate `json.dumps(...,
    sort_keys=True, ...)` by hand, is what makes drift between the producer
    and the verifier impossible rather than merely unlikely — the exact
    property `execution_plan.py`/`recovery_plan.py` already hold for PLAN
    canonicalization via `canonical_plan.canonical_plan_bytes`, generalised
    to this module's own subject documents. `_canonical` stays private:
    nothing outside this module needs the raw bytes, only this one digest.
    """
    if not isinstance(candidate, CandidateAttestationSubjectV2):
        raise SpecError(
            "candidate_subject_digest requires a CandidateAttestationSubjectV2",
            code=OBSERVATION_MALFORMED,
        )
    return Digest.of(_canonical(candidate.canonical_document()))


def attestation_envelope_digest(envelope: AttestationEnvelopeV2) -> Digest:
    """Digest the complete parsed envelope mapping, including its signature."""
    if not isinstance(envelope, AttestationEnvelopeV2):
        raise SpecError(
            "attestation_envelope_digest requires an AttestationEnvelopeV2",
            code=OBSERVATION_MALFORMED,
        )
    return Digest.of(_canonical(envelope.canonical_document()))


@dataclasses.dataclass(frozen=True, slots=True)
class AttestationVerifiedRootV1:
    """The specific trust root that actually matched and authenticated one
    half of the attestation pair -- echoed back so Control can compare it
    against what it itself resolved, the same way the envelope digests
    already are. Not the whole `AttestationTrustRootV2` (which also carries
    `public_key_base64`/`not_before`/`not_after`/`revoked` -- policy
    configuration Control already has from its own resolution, not something
    that needs echoing back as "what was verified against")."""

    public_key_fingerprint: str
    trust_root_version: str
    key_id: str
    algorithm: str
    purpose: str
    custody_domain: str
    issuer: str


@dataclasses.dataclass(frozen=True, slots=True)
class AttestationPairVerificationResultV1:
    """Non-authorizing verification evidence -- never a HostSource or execution
    token. Foundation verifies statelessly; only Control decides consequence.

    Reports EVERYTHING actually verified, not only digests: the caller-
    supplied expectations that were checked, the audiences the trust policy
    declared, and the specific root that matched each half. This is what
    lets Control compare Foundation's real verification against what Control
    itself resolved, instead of trusting a caller-supplied echo of its own
    input back at it unchanged."""

    candidate_attestation_envelope_digest: str
    installed_attestation_envelope_digest: str
    verification_context_digest: str
    expected_host_identity: str
    expected_observation_id: str
    expected_package: str
    candidate_audience: str
    installed_audience: str
    candidate_root: AttestationVerifiedRootV1
    installed_root: AttestationVerifiedRootV1


def verify_attestation_pair(
    *,
    candidate: AttestationEnvelopeV2 | None,
    installed: AttestationEnvelopeV2 | None,
    verifier: AttestationVerifier,
    trust_policy: AttestationTrustPolicy,
    expected_host_identity: str,
    expected_observation_id: str,
    expected_package: str,
    verification_context_digest: str,
    now: datetime,
) -> AttestationPairVerificationResultV1:
    """Verify v2 evidence; success creates no caller-constructible authority."""
    if candidate is None:
        raise PreconditionFailed(
            "candidate attestation is missing", code=OBSERVATION_ABSENT
        )
    if installed is None:
        raise PreconditionFailed(
            "installed-host attestation is missing", code=OBSERVATION_ABSENT
        )
    if not isinstance(candidate, AttestationEnvelopeV2) or not isinstance(
        installed, AttestationEnvelopeV2
    ):
        raise SpecError(
            "attestations must be parsed AttestationEnvelopeV2 values",
            code=OBSERVATION_MALFORMED,
        )
    # This verifier-level refusal is deliberately independent of the supplied
    # policy: a single signing key can never author both custody roles.  Use
    # the authenticated public-key fingerprint, not the advisory key label.
    if candidate.public_key_fingerprint == installed.public_key_fingerprint:
        raise PreconditionFailed(
            "candidate and installed attestations use the same signing key",
            code=SAME_KEY_SIGNED_BOTH,
        )
    # The candidate half is authenticated through the one shared seam: this
    # is what makes it impossible for this function to drift from what a
    # trusted host workload gets when it calls verify_candidate_attestation
    # directly (that public wrapper is itself a thin call to this same
    # private function).
    candidate_subject, candidate_root = _verify_candidate_and_root(
        candidate=candidate, verifier=verifier, trust_policy=trust_policy, now=now
    )
    expected_host_identity = _required(expected_host_identity, "expected_host_identity")
    verification_context_digest = _required(
        verification_context_digest, "verification_context_digest"
    )
    now = now.astimezone(UTC)
    if trust_policy.installed_audience != expected_host_identity:
        raise PreconditionFailed(
            "installed role audience does not match expected host identity",
            code=AUDIENCE_MISMATCH,
        )
    installed_root = _verify(
        installed,
        verifier,
        trust_policy.installed_roots,
        INSTALLED_OBSERVATION_PURPOSE,
        expected_host_identity,
        now,
    )
    installed_subject = InstalledHostAttestationSubjectV2.from_mapping(
        installed.subject_mapping()
    )
    expected_observation_id = _required(
        expected_observation_id, "expected_observation_id"
    )
    if installed.observation_id != expected_observation_id:
        raise PreconditionFailed(
            "installed observation does not match expected Control dispatch",
            code=OBSERVATION_ID_MISMATCH,
        )
    expected_package = _required(expected_package, "expected_package")
    if candidate_subject.package != expected_package:
        raise PreconditionFailed(
            "candidate package does not match expected package",
            code=PACKAGE_MISMATCH,
        )
    if installed_subject.package != expected_package:
        raise PreconditionFailed(
            "installed package does not match expected package",
            code=PACKAGE_MISMATCH,
        )
    expected = candidate_subject_digest(candidate_subject)
    if installed_subject.candidate_subject_digest != expected:
        raise PreconditionFailed(
            "installed host does not bind candidate subject", code=SUBJECT_MISMATCH
        )
    if installed_subject.host_identity != expected_host_identity:
        raise PreconditionFailed(
            "installed host subject does not match expected host identity",
            code=SUBJECT_MISMATCH,
        )
    if (
        candidate_subject.package,
        candidate_subject.version,
        candidate_subject.wheel_sha256,
    ) != (
        installed_subject.package,
        installed_subject.version,
        installed_subject.wheel_sha256,
    ):
        raise PreconditionFailed(
            "candidate and host attest different package bytes",
            code=ATTESTATIONS_DISAGREE,
        )
    return AttestationPairVerificationResultV1(
        candidate_attestation_envelope_digest=str(
            attestation_envelope_digest(candidate)
        ),
        installed_attestation_envelope_digest=str(
            attestation_envelope_digest(installed)
        ),
        verification_context_digest=verification_context_digest,
        expected_host_identity=expected_host_identity,
        expected_observation_id=expected_observation_id,
        expected_package=expected_package,
        candidate_audience=trust_policy.candidate_audience,
        installed_audience=trust_policy.installed_audience,
        candidate_root=AttestationVerifiedRootV1(
            public_key_fingerprint=candidate_root.public_key_fingerprint,
            trust_root_version=candidate_root.trust_root_version,
            key_id=candidate_root.key_id,
            algorithm=candidate_root.algorithm,
            purpose=candidate_root.purpose,
            custody_domain=candidate_root.custody_domain,
            issuer=candidate_root.issuer,
        ),
        installed_root=AttestationVerifiedRootV1(
            public_key_fingerprint=installed_root.public_key_fingerprint,
            trust_root_version=installed_root.trust_root_version,
            key_id=installed_root.key_id,
            algorithm=installed_root.algorithm,
            purpose=installed_root.purpose,
            custody_domain=installed_root.custody_domain,
            issuer=installed_root.issuer,
        ),
    )
