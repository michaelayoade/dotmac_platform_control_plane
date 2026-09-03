"""Installed Foundation bindings for the Platform control plane.

The Foundation owns execution. Deployment Control owns authorization. This
assembly supplies the deliberately small translation between their published
types and the product-specific host effects. The module is imported only from
the external deployment-tool environment through package metadata; the
long-running application image does not install the Foundation.

The authorization file is one delivery intent reduced to the two values the
target needs::

    {
      "schema": "PlatformCpExecutionAuthorization.v1",
      "authorization_envelope": { ... Control a10 envelope ... },
      "attempt_no": 1
    }

The envelope is verified before any field is translated. ``attempt_no`` is
Control's dispatch result and is not signed inside the earlier rollout
envelope, so both are carried together and Foundation binds the resulting pair
into its execution grant and receipt.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from dotmac_deployment_control import (
    AUTHORIZATION_PURPOSE,
    AuthorizationEnvelopeRefusalCode,
    AuthorizationEnvelopeRefusedError,
    PublicKeyFingerprintV1,
    verify_authorization_envelope,
)
from dotmac_deployment_foundation import PreconditionFailed, SpecError
from dotmac_deployment_foundation.evidence import TrustPolicy
from dotmac_deployment_foundation.execution_bindings import ExecutionBindings

from vendor_cp.deployment.effects import build_platform_cp_effects
from vendor_cp.deployment.signers import RELEASE_EVIDENCE_PURPOSE

__all__ = [
    "AUTHORIZATION_DOCUMENT_SCHEMA",
    "PROVIDER",
    "ControlAuthorizationAdapter",
    "Ed25519AuthorizationVerifier",
    "Ed25519EvidenceVerifier",
    "PublicVerificationIdentity",
    "execution_bindings",
]

PROVIDER: Final = "platform-cp"
AUTHORIZATION_DOCUMENT_SCHEMA: Final = "PlatformCpExecutionAuthorization.v1"
DEFAULT_AUTHORIZATION_KEY_FILE: Final = Path(
    "/etc/dotmac/platform-cp/authorization-verification.json"
)
DEFAULT_RELEASE_EVIDENCE_KEY_FILE: Final = Path(
    "/etc/dotmac/platform-cp/release-evidence-verification.json"
)
RELEASE_EVIDENCE_REPOSITORY: Final = "michaelayoade/dotmac_platform_control_plane"
_KEY_SCHEMA: Final = "PlatformCpPublicVerificationIdentity.v1"
_ED25519: Final = "ed25519"
_KEY_BYTES: Final = 32
_MAX_IDENTITY_BYTES: Final = 16 * 1024


def _decode(value: str, *, field: str) -> bytes:
    if not value or value != value.strip() or "=" in value:
        raise SpecError(f"{field} must be canonical unpadded base64url")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as error:
        raise SpecError(f"{field} is not valid base64url") from error
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        raise SpecError(f"{field} is not canonical unpadded base64url")
    return raw


@dataclass(frozen=True, slots=True)
class PublicVerificationIdentity:
    """One purpose-bound public key loaded once from a root-owned file."""

    key_id: str
    algorithm: str
    purpose: str
    public_key_b64url: str
    public_key_fingerprint: str

    def __post_init__(self) -> None:
        if not self.key_id or self.key_id != self.key_id.strip():
            raise SpecError("verification key_id must be non-empty exact text")
        if self.algorithm != _ED25519:
            raise SpecError(
                f"verification algorithm must be {_ED25519!r}, got "
                f"{self.algorithm!r}"
            )
        raw = _decode(self.public_key_b64url, field="public_key_b64url")
        if len(raw) != _KEY_BYTES:
            raise SpecError(
                f"public_key_b64url decodes to {len(raw)} bytes; "
                f"Ed25519 requires {_KEY_BYTES}"
            )
        derived = PublicKeyFingerprintV1.from_public_key_b64(
            self.public_key_b64url
        ).canonical
        if self.public_key_fingerprint != derived:
            raise SpecError(
                "public_key_fingerprint does not identify public_key_b64url"
            )

    @property
    def public_key(self) -> Ed25519PublicKey:
        return Ed25519PublicKey.from_public_bytes(
            _decode(self.public_key_b64url, field="public_key_b64url")
        )

    @classmethod
    def read(
        cls,
        path: Path,
        *,
        purpose: str,
        expected_owner_uid: int = 0,
    ) -> PublicVerificationIdentity:
        """Read one fixed trust root without following a replaceable link.

        ``expected_owner_uid`` is an explicit test seam. The installed entry
        point never changes it from root, and production paths are fixed below
        rather than selected from environment variables.
        """
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(path, flags)
        except OSError as error:
            raise PreconditionFailed(
                f"public verification identity {path} is unreadable: {error}"
            ) from error
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise PreconditionFailed(
                    f"public verification identity {path} is not a regular file"
                )
            if metadata.st_uid != expected_owner_uid:
                raise PreconditionFailed(
                    f"public verification identity {path} is owned by uid "
                    f"{metadata.st_uid}, expected {expected_owner_uid}"
                )
            if metadata.st_mode & 0o022:
                raise PreconditionFailed(
                    f"public verification identity {path} is group/other writable"
                )
            raw = os.read(fd, _MAX_IDENTITY_BYTES + 1)
            if len(raw) > _MAX_IDENTITY_BYTES:
                raise PreconditionFailed(
                    f"public verification identity {path} exceeds "
                    f"{_MAX_IDENTITY_BYTES} bytes"
                )
        finally:
            os.close(fd)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except UnicodeDecodeError as error:
            raise PreconditionFailed(
                f"public verification identity {path} is not UTF-8"
            ) from error
        except json.JSONDecodeError as error:
            raise PreconditionFailed(
                f"public verification identity {path} is not JSON: {error}"
            ) from error
        required = {
            "schema",
            "key_id",
            "algorithm",
            "purpose",
            "public_key_b64url",
            "public_key_fingerprint",
        }
        if not isinstance(payload, Mapping) or set(payload) != required:
            actual = sorted(payload) if isinstance(payload, Mapping) else []
            raise PreconditionFailed(
                f"public verification identity {path} has keys {actual}; "
                f"expected {sorted(required)}"
            )
        if payload["schema"] != _KEY_SCHEMA:
            raise PreconditionFailed(
                f"public verification identity {path} has unknown schema "
                f"{payload['schema']!r}"
            )
        if payload["purpose"] != purpose:
            raise PreconditionFailed(
                f"public verification identity {path} declares purpose "
                f"{payload['purpose']!r}, expected {purpose!r}"
            )
        return cls(
            key_id=str(payload["key_id"]),
            algorithm=str(payload["algorithm"]),
            purpose=str(payload["purpose"]),
            public_key_b64url=str(payload["public_key_b64url"]),
            public_key_fingerprint=str(payload["public_key_fingerprint"]),
        )


def _verify_signature(
    identity: PublicVerificationIdentity, message: bytes, signature: str
) -> bool:
    try:
        encoded = _decode(signature, field="signature")
        identity.public_key.verify(encoded, message)
    except (InvalidSignature, ValueError, SpecError):
        return False
    return True


class Ed25519AuthorizationVerifier:
    """The public half of Control's authorization signer."""

    def __init__(self, identity: PublicVerificationIdentity) -> None:
        if identity.purpose != AUTHORIZATION_PURPOSE:
            raise SpecError(
                "the authorization verifier requires a deployment authorization key"
            )
        self._identity = identity

    def verify(
        self,
        *,
        key_id: str,
        algorithm: str,
        purpose: str,
        public_key_fingerprint: str,
        canonical_bytes: bytes,
        signature: str,
    ) -> bool:
        identity = self._identity
        if (
            key_id != identity.key_id
            or algorithm != identity.algorithm
            or purpose != identity.purpose
            or public_key_fingerprint != identity.public_key_fingerprint
        ):
            return False
        return _verify_signature(identity, canonical_bytes, signature)


class Ed25519EvidenceVerifier:
    """Foundation's narrower verifier for signed release evidence."""

    def __init__(self, identity: PublicVerificationIdentity) -> None:
        if identity.purpose != RELEASE_EVIDENCE_PURPOSE:
            raise SpecError(
                "the release-evidence verifier requires a release-evidence key"
            )
        self._identity = identity

    @property
    def key_id(self) -> str:
        return self._identity.key_id

    def verify(self, *, key_id: str, message: bytes, signature: str) -> bool:
        if key_id != self._identity.key_id:
            return False
        return _verify_signature(self._identity, message, signature)


class ControlAuthorizationAdapter:
    """Authenticate a10 material, then expose only Foundation receipt terms."""

    def __init__(self, verifier: Ed25519AuthorizationVerifier) -> None:
        self._verifier = verifier
        self._target: str | None = None

    @property
    def target(self) -> str:
        if self._target is None:
            raise PreconditionFailed(
                "the effects factory ran before an authorization was attested"
            )
        return self._target

    def attest(self, material: Mapping[str, Any]) -> Mapping[str, Any]:
        required = {"schema", "authorization_envelope", "attempt_no"}
        if set(material) != required:
            raise PreconditionFailed(
                "Platform CP authorization wrapper keys differ: "
                f"missing={sorted(required - set(material))}, "
                f"unknown={sorted(set(material) - required)}"
            )
        if material["schema"] != AUTHORIZATION_DOCUMENT_SCHEMA:
            raise PreconditionFailed(
                f"unsupported Platform CP authorization wrapper "
                f"{material['schema']!r}"
            )
        attempt_no = material["attempt_no"]
        if (
            not isinstance(attempt_no, int)
            or isinstance(attempt_no, bool)
            or attempt_no < 1
        ):
            raise PreconditionFailed("attempt_no must be a positive integer")
        envelope = verify_authorization_envelope(
            material["authorization_envelope"], verifier=self._verifier
        )
        statement = envelope.statement
        if statement.product_code != "dotmac_vendor_control_plane":
            raise PreconditionFailed(
                f"authorization names product {statement.product_code!r}, not "
                "dotmac_vendor_control_plane"
            )
        if statement.environment != "production":
            raise PreconditionFailed(
                f"authorization names environment {statement.environment!r}, "
                "not production"
            )
        required_values = {
            "approval_policy_code": statement.approval_policy_code,
            "approval_policy_version": statement.approval_policy_version,
            "approval_decision_ref": statement.approval_decision_ref,
            "approved_at": statement.approved_at,
        }
        absent = sorted(key for key, value in required_values.items() if value is None)
        if absent:
            raise PreconditionFailed(
                f"Platform CP authorization lacks approval term(s) {absent}"
            )
        if self._target is not None and self._target != statement.target_ref:
            raise PreconditionFailed(
                "one process attested authorizations for two different targets"
            )
        self._target = statement.target_ref
        approved_at = statement.approved_at
        if approved_at is None:  # guarded above; keeps the type and gate aligned
            raise AuthorizationEnvelopeRefusedError(
                AuthorizationEnvelopeRefusalCode.APPROVAL_NOT_STANDING,
                "the authorization has no approval timestamp",
            )
        return {
            "plan_id": statement.plan_id,
            "target_ref": statement.target_ref,
            "descriptor_digest": statement.descriptor_digest,
            "execution_plan_digest": statement.execution_plan_digest,
            "execution_sequence": statement.execution_sequence,
            "attempt_no": attempt_no,
            "control_plan_digest": statement.plan_digest,
            "policy_code": statement.approval_policy_code,
            "policy_version": statement.approval_policy_version,
            "decision_ref": statement.approval_decision_ref,
            "approved_at": approved_at.isoformat().replace("+00:00", "Z"),
            "expires_at": statement.expires_at.isoformat().replace("+00:00", "Z"),
            "control_version": statement.control_version,
            "operation": statement.operation,
        }


def execution_bindings(
    *,
    authorization_key_file: Path = DEFAULT_AUTHORIZATION_KEY_FILE,
    release_evidence_key_file: Path = DEFAULT_RELEASE_EVIDENCE_KEY_FILE,
    expected_owner_uid: int = 0,
) -> ExecutionBindings:
    """Entry-point factory loaded by Foundation a5 on ``--execute`` only."""

    authorization_identity = PublicVerificationIdentity.read(
        authorization_key_file,
        purpose=AUTHORIZATION_PURPOSE,
        expected_owner_uid=expected_owner_uid,
    )
    release_identity = PublicVerificationIdentity.read(
        release_evidence_key_file,
        purpose=RELEASE_EVIDENCE_PURPOSE,
        expected_owner_uid=expected_owner_uid,
    )
    authorization = ControlAuthorizationAdapter(
        Ed25519AuthorizationVerifier(authorization_identity)
    )
    evidence = Ed25519EvidenceVerifier(release_identity)

    def build_effects(spec: Any, deploy_dir: Path) -> Any:
        return build_platform_cp_effects(
            spec,
            deploy_dir,
            target=authorization.target,
        )

    return ExecutionBindings(
        provider=PROVIDER,
        build_effects=build_effects,
        authorization_verifier=authorization,
        evidence_policy=TrustPolicy(
            accepted_key_ids=frozenset({evidence.key_id}),
            repository=RELEASE_EVIDENCE_REPOSITORY,
        ),
        evidence_verifier=evidence,
    )
