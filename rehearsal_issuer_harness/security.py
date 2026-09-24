"""Ephemeral, purpose-separated Ed25519 keys for disposable rehearsals only."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from dotmac_deployment_control.rehearsal_harness_evidence import (
    REHEARSAL_HARNESS_EVIDENCE_PURPOSE,
    REHEARSAL_HARNESS_EVIDENCE_SCHEMA,
    REHEARSAL_HARNESS_EVIDENCE_VERSION,
)
from dotmac_deployment_control.rehearsal_issuer_authorization import (
    REHEARSAL_ISSUER_PURPOSE,
    REHEARSAL_ONLY_ENVIRONMENT,
    RehearsalIssuerAuthorizationSignature,
    RehearsalIssuerAuthorizationSignerIdentity,
)

_ALGORITHM = "ed25519"


def _identity(public: Ed25519PublicKey) -> tuple[str, str]:
    raw = public.public_bytes(Encoding.Raw, PublicFormat.Raw)
    fingerprint = "sha256:" + hashlib.sha256(raw).hexdigest()
    return "rehearsal-" + fingerprint[7:23], fingerprint


@dataclass(slots=True)
class _Key:
    private: Ed25519PrivateKey = field(repr=False)
    purpose: str

    @classmethod
    def fresh(cls, purpose: str) -> _Key:
        return cls(Ed25519PrivateKey.generate(), purpose)

    @property
    def public(self) -> Ed25519PublicKey:
        return self.private.public_key()

    @property
    def key_id(self) -> str:
        return _identity(self.public)[0]

    @property
    def fingerprint(self) -> str:
        return _identity(self.public)[1]

    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            self.public.verify(signature, data)
        except (InvalidSignature, ValueError):
            return False
        return True


class AuthorizationSecurity:
    def __init__(self) -> None:
        self._key = _Key.fresh(REHEARSAL_ISSUER_PURPOSE)

    @property
    def rehearsal_issuer_identity(self) -> RehearsalIssuerAuthorizationSignerIdentity:
        return RehearsalIssuerAuthorizationSignerIdentity(
            self._key.key_id, _ALGORITHM, self._key.fingerprint
        )

    def sign_rehearsal_issuer_authorization(
        self, canonical_bytes: bytes
    ) -> RehearsalIssuerAuthorizationSignature:
        signature = base64.b64encode(self._key.private.sign(canonical_bytes)).decode()
        return RehearsalIssuerAuthorizationSignature(
            self._key.key_id,
            _ALGORITHM,
            REHEARSAL_ISSUER_PURPOSE,
            self._key.fingerprint,
            signature,
        )

    def verify_rehearsal_issuer_authorization(
        self,
        *,
        key_id: str,
        algorithm: str,
        purpose: str,
        public_key_fingerprint: str,
        canonical_bytes: bytes,
        signature: str,
    ) -> bool:
        if (
            key_id != self._key.key_id
            or algorithm != _ALGORITHM
            or purpose != self._key.purpose
            or public_key_fingerprint != self._key.fingerprint
        ):
            return False
        try:
            raw = base64.b64decode(signature, validate=True)
        except (ValueError, binascii.Error):
            return False
        return self._key.verify(canonical_bytes, raw)


class HarnessSecurity:
    def __init__(self) -> None:
        self._key = _Key.fresh(REHEARSAL_HARNESS_EVIDENCE_PURPOSE)

    @property
    def controller_fingerprint(self) -> str:
        return self._key.fingerprint

    def verify_rehearsal_harness_evidence(
        self,
        *,
        key_id: str,
        algorithm: str,
        purpose: str,
        canonical_bytes: bytes,
        signature: bytes,
    ) -> bool:
        if (
            key_id != self._key.key_id
            or algorithm != _ALGORITHM
            or purpose != self._key.purpose
        ):
            return False
        return self._key.verify(canonical_bytes, signature)

    def document(
        self,
        *,
        lease_id: str,
        target_ref: str,
        issued_at: datetime | None = None,
        valid_for: timedelta = timedelta(hours=2),
        controller_fingerprint: str | None = None,
    ) -> dict[str, object]:
        now = (issued_at or datetime.now(UTC)).astimezone(UTC)
        document = {
            "schema": REHEARSAL_HARNESS_EVIDENCE_SCHEMA,
            "version": REHEARSAL_HARNESS_EVIDENCE_VERSION,
            "lease_id": lease_id,
            "controller_fingerprint": controller_fingerprint
            or self.controller_fingerprint,
            "target_ref": target_ref,
            "environment": REHEARSAL_ONLY_ENVIRONMENT,
            "issued_at": now.isoformat().replace("+00:00", "Z"),
            "valid_until": (now + valid_for).isoformat().replace("+00:00", "Z"),
        }
        canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        return {
            "canonical_bytes": base64.b64encode(canonical).decode(),
            "signature": {
                "key_id": self._key.key_id,
                "algorithm": _ALGORITHM,
                "signature": base64.b64encode(
                    self._key.private.sign(canonical)
                ).decode(),
            },
        }
