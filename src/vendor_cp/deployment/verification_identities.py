"""Pinned public verification identities and the Ed25519 verifiers over them.

The target verifies three kinds of signature it did not make: Control's
deployment authorization, Control's dispatch envelope and Platform CP's release
evidence. Each is checked against a PUBLIC identity that was installed on the
host, root-owned, by the custody ceremony
(`docs/design/signing-identity-mint-dossier.md`, step 6b), schema
`PlatformCpPublicVerificationIdentity.v1`. Nothing here reads a key from the
document being judged, and a document never nominates its own verifier.

What a loaded identity proves is closed and small:

* the file is a regular, root-owned, non-writable-by-others file under 16 KiB;
* its document has exactly the contract's fields and the requested PURPOSE;
* the key is a canonical 32-byte Ed25519 key and the fingerprint is the one
  Deployment Control's own `PublicKeyFingerprintV1` derives from it (Control
  owns that derivation; it is never reimplemented here).

Signatures are unpadded canonical base64url over the stated message, which is
the encoding this product's release-evidence producer already emits. Anything
else, any wrong key id / purpose / algorithm / fingerprint, any wrong length,
verifies False and the caller refuses.
"""

from __future__ import annotations

import base64
import binascii
import errno
import json
import os
import stat
from dataclasses import dataclass
from typing import Final

from vendor_cp.deployment.target_refusals import (
    FoundationBindingsUnavailable,
    TargetRefusal,
)

__all__ = [
    "IDENTITY_SCHEMA",
    "MAX_IDENTITY_BYTES",
    "AuthorizationEd25519Verifier",
    "DispatchEd25519Verifier",
    "HostAdmissionPresentationEd25519Verifier",
    "PinnedVerificationIdentity",
    "ReleaseEvidenceEd25519Verifier",
    "decode_b64url",
]

IDENTITY_SCHEMA: Final = "PlatformCpPublicVerificationIdentity.v1"
MAX_IDENTITY_BYTES: Final = 16 * 1024
_FIELDS: Final = frozenset(
    {
        "schema",
        "key_id",
        "algorithm",
        "purpose",
        "public_key_b64url",
        "public_key_fingerprint",
    }
)


def _refuse(what: str, code: TargetRefusal) -> FoundationBindingsUnavailable:
    return FoundationBindingsUnavailable(what, code=code)


def decode_b64url(value: object, *, length: int) -> bytes | None:
    """Canonical unpadded base64url of exactly `length` bytes, else None."""
    if (
        not isinstance(value, str)
        or not value
        or "=" in value
        or value != value.strip()
    ):
        return None
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        return None
    if len(raw) != length:
        return None
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        return None
    return raw


@dataclass(frozen=True, slots=True)
class PinnedVerificationIdentity:
    """One installed public identity: who may be believed for one purpose."""

    key_id: str
    algorithm: str
    purpose: str
    public_key: bytes
    public_key_b64url: str
    public_key_fingerprint: str

    @classmethod
    def read(
        cls, path: str, *, purpose: str, what: str, owner_uid: int = 0
    ) -> PinnedVerificationIdentity:
        """Load and prove one identity, or refuse naming `what` only."""
        refused = TargetRefusal.VERIFICATION_IDENTITY_REFUSED
        # The directory must not be replaceable by anyone but its owner, and the
        # file is opened without following links and judged on the DESCRIPTOR,
        # so nothing can be swapped between the check and the read.
        parent = os.path.dirname(os.path.abspath(path))
        try:
            parent_info = os.lstat(parent)
        except OSError:
            raise _refuse(f"{what} cannot be read", refused) from None
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != owner_uid
            or parent_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise _refuse(
                f"{what} sits in a directory that is not owner-only writable", refused
            )
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as error:
            if error.errno == errno.ELOOP:
                raise _refuse(f"{what} is not a regular file", refused) from None
            raise _refuse(f"{what} cannot be read", refused) from None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise _refuse(f"{what} is not a regular file", refused)
            if info.st_uid != owner_uid:
                raise _refuse(f"{what} is not owned by the required owner", refused)
            if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise _refuse(f"{what} is writable by group or others", refused)
            if info.st_size > MAX_IDENTITY_BYTES:
                raise _refuse(f"{what} exceeds the size bound", refused)
            raw = os.read(fd, MAX_IDENTITY_BYTES + 1)
        finally:
            os.close(fd)
        try:
            document = json.loads(raw.decode("utf-8"))
        except Exception:
            raise _refuse(f"{what} is not a JSON document", refused) from None
        if not isinstance(document, dict) or set(document) != _FIELDS:
            raise _refuse(f"{what} does not match the closed contract", refused)
        if document["schema"] != IDENTITY_SCHEMA:
            raise _refuse(f"{what} is not a {IDENTITY_SCHEMA} document", refused)
        if document["purpose"] != purpose:
            raise _refuse(f"{what} declares a different purpose", refused)
        if document["algorithm"] != "ed25519":
            raise _refuse(f"{what} declares an unsupported algorithm", refused)
        key_id = document["key_id"]
        if not isinstance(key_id, str) or not key_id.strip() or len(key_id) > 200:
            raise _refuse(f"{what} carries an unusable key id", refused)
        key_text = document["public_key_b64url"]
        key = decode_b64url(key_text, length=32)
        if key is None:
            raise _refuse(f"{what} carries a non-canonical public key", refused)
        fingerprint = document["public_key_fingerprint"]
        try:
            from dotmac_deployment_control import PublicKeyFingerprintV1
        except ImportError:
            raise _refuse(
                "Control fingerprint derivation is unavailable",
                refused,
            ) from None
        try:
            derived = PublicKeyFingerprintV1.from_public_key_b64(key_text).canonical
        except Exception:
            raise _refuse(
                f"{what} public key does not derive a fingerprint", refused
            ) from None
        if derived != fingerprint:
            raise _refuse(f"{what} fingerprint does not identify its key", refused)
        return cls(
            key_id=key_id,
            algorithm="ed25519",
            purpose=purpose,
            public_key=key,
            public_key_b64url=key_text,
            public_key_fingerprint=fingerprint,
        )

    def matches(
        self,
        *,
        key_id: str,
        algorithm: str,
        purpose: str,
        public_key_fingerprint: str,
    ) -> bool:
        return (
            key_id == self.key_id
            and algorithm == self.algorithm
            and purpose == self.purpose
            and public_key_fingerprint == self.public_key_fingerprint
        )

    def verify_signature(self, message: bytes, signature: str) -> bool:
        return _ed25519(self.public_key, message, signature)


def _ed25519(public_key: bytes, message: bytes, signature: str) -> bool:
    raw = decode_b64url(signature, length=64)
    if raw is None:
        return False
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        Ed25519PublicKey.from_public_bytes(public_key).verify(raw, message)
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


class AuthorizationEd25519Verifier:
    """Control's `AuthorizationVerifier` port over one pinned identity."""

    def __init__(self, identity: PinnedVerificationIdentity) -> None:
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
        return self._identity.matches(
            key_id=key_id,
            algorithm=algorithm,
            purpose=purpose,
            public_key_fingerprint=public_key_fingerprint,
        ) and self._identity.verify_signature(canonical_bytes, signature)


class DispatchEd25519Verifier:
    """Control's `DispatchVerifier` port over one pinned identity."""

    def __init__(self, identity: PinnedVerificationIdentity) -> None:
        self._identity = identity

    def verify_dispatch(
        self,
        *,
        key_id: str,
        algorithm: str,
        purpose: str,
        public_key_fingerprint: str,
        canonical_bytes: bytes,
        signature: str,
    ) -> bool:
        return self._identity.matches(
            key_id=key_id,
            algorithm=algorithm,
            purpose=purpose,
            public_key_fingerprint=public_key_fingerprint,
        ) and self._identity.verify_signature(canonical_bytes, signature)


class ReleaseEvidenceEd25519Verifier:
    """Foundation's `SignatureVerifier` over one pinned release-evidence identity."""

    def __init__(self, identity: PinnedVerificationIdentity) -> None:
        self._identity = identity

    def verify(self, *, key_id: str, message: bytes, signature: str) -> bool:
        return key_id == self._identity.key_id and self._identity.verify_signature(
            message, signature
        )


class HostAdmissionPresentationEd25519Verifier:
    """Control's `HostAdmissionPresentationVerifier` port.

    Unlike the three pinned identities above, the presentation key is not
    pinned on the host: Control resolves it from its own enrolled trust root
    and hands it in with the fingerprint it is stored under. This verifier
    therefore proves what it is given rather than trusting it: the algorithm is
    Ed25519, the purpose is the one Control passes for this boundary, the key is
    a canonical 32-byte key, and Control's own derivation maps that key to the
    stated fingerprint. A mismatch verifies False.
    """

    def __init__(self, *, expected_purpose: str) -> None:
        self._purpose = expected_purpose

    def verify_host_admission_presentation(
        self,
        *,
        key_id: str,
        algorithm: str,
        purpose: str,
        public_key_fingerprint: str,
        public_key_b64: str,
        canonical_bytes: bytes,
        signature: str,
    ) -> bool:
        if algorithm != "ed25519" or purpose != self._purpose or not key_id:
            return False
        key = decode_b64url(public_key_b64, length=32)
        if key is None:
            return False
        try:
            from dotmac_deployment_control import PublicKeyFingerprintV1

            derived = PublicKeyFingerprintV1.from_public_key_b64(
                public_key_b64
            ).canonical
        except Exception:
            return False
        if derived != public_key_fingerprint:
            return False
        return _ed25519(key, canonical_bytes, signature)
