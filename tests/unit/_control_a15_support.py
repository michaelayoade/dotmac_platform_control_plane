"""A real Ed25519 `AuthorizationSigner` for tests that drive Control directly.

`dotmac_deployment_control 0.1.0a15`'s own test suite ships a
non-cryptographic hash-based double (`tests/authorization_support.py`,
`TestAuthorizationSigner`) because `request_rollout` never verifies a
signature itself — it only calls `signer.sign(canonical_bytes)`. This module
uses real `cryptography` Ed25519 instead, the same primitive
`vendor_cp.licensing.signing_adapter` already uses for signing (CP carries
`cryptography` through the kernel's `licensing` extra), so a test exercising
"CP drives Control's authorization envelope" is exercising the same signing
primitive CP's own issuance path uses, not a parallel test-only algorithm.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from dotmac_deployment_control import (
    AUTHORIZATION_PURPOSE,
    AuthorizationSignature,
    AuthorizationSignerIdentity,
    PublicKeyFingerprintV1,
)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


@dataclass
class Ed25519TestSigner:
    """One generated-in-memory Ed25519 keypair, never persisted.

    Conforms to `dotmac_deployment_control.AuthorizationSigner`: an `identity`
    property known before any bytes are signed, and a `sign` method producing
    an `AuthorizationSignature` over the module's own canonical bytes.
    """

    _private_key: Ed25519PrivateKey
    identity: AuthorizationSignerIdentity

    @classmethod
    def generate(cls, *, key_id: str = "test-a15-key") -> Ed25519TestSigner:
        private_key = Ed25519PrivateKey.generate()
        public_b64 = _b64url(
            private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        )
        identity = AuthorizationSignerIdentity(
            key_id=key_id,
            algorithm="ed25519",
            public_key_fingerprint=PublicKeyFingerprintV1.from_public_key_b64(
                public_b64
            ).canonical,
        )
        return cls(_private_key=private_key, identity=identity)

    def sign(self, canonical_bytes: bytes) -> AuthorizationSignature:
        signature = self._private_key.sign(canonical_bytes)
        return AuthorizationSignature(
            key_id=self.identity.key_id,
            algorithm=self.identity.algorithm,
            public_key_fingerprint=self.identity.public_key_fingerprint,
            signature=_b64url(signature),
            purpose=AUTHORIZATION_PURPOSE,
        )


#: One shared signer per process. Tests need a signer, not a KEY MANAGEMENT
#: story — a fresh keypair per call would work identically and only add
#: noise to a diff between two test runs.
TEST_SIGNER: Ed25519TestSigner = Ed25519TestSigner.generate()

__all__ = ["Ed25519TestSigner", "TEST_SIGNER"]
