"""The licence signing seam — EPHEMERAL ONLY in this phase.

Signing is the vendor control plane's job: the kernel deliberately ships no
signer (it verifies only), so the Ed25519 signing lives here. What does NOT
live here is key custody — `LicenceSignerProvider` is a narrow protocol
(`key_id`, `public_key_b64`, `sign`), so the material's source is swappable
without touching issuance logic.

Two modes behind `VENDOR_LICENCE_SIGNING_MODE`, mirroring the D3
fake-provider posture:

- **`ephemeral`** (default, and the ONLY mode accepted this phase) — a keypair
  generated in memory at construction. Never persisted, never a real issuer
  key: dev/test only.
- **`configured`** (later slice) — material resolved from a reference whose
  canonical source is OpenBao (`secret/dotmac/licensing/signing-key`); the
  value never appears in code, config files, logs, or the database. Selecting
  it today FAILS LOUDLY rather than silently signing with a throwaway key.

The envelope format is the kernel's (`dotmac-licence-envelope/1`, Ed25519 over
the exact payload bytes); issuance proves compatibility by round-tripping every
signed envelope through the pinned kernel's `verify_licence`.
"""

from __future__ import annotations

import base64
from typing import Protocol, runtime_checkable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from vendor_cp.config import vendor_settings

EPHEMERAL_MODE = "ephemeral"


class SigningModeNotPermittedError(RuntimeError):
    """Raised at startup if a signing mode this phase cannot honour is set."""


@runtime_checkable
class LicenceSignerProvider(Protocol):
    """What issuance needs from a signer — and nothing more. Deliberately no
    key export, no rotation control: those belong to custody/ops."""

    @property
    def key_id(self) -> str: ...

    @property
    def public_key_b64(self) -> str: ...

    def sign(self, payload: bytes) -> bytes: ...


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class EphemeralLicenceSigner:
    """An in-memory Ed25519 signer. The private key exists only for this
    process's lifetime and is never written anywhere."""

    def __init__(self, key_id: str = "vendor-ephemeral-1") -> None:
        self._key_id = key_id
        self._private_key = Ed25519PrivateKey.generate()

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def public_key_b64(self) -> str:
        return _b64url(
            self._private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        )

    def sign(self, payload: bytes) -> bytes:
        return self._private_key.sign(payload)


def build_licence_signer(key_id: str | None = None) -> LicenceSignerProvider:
    """Return the phase-appropriate signer. A non-`ephemeral`
    `VENDOR_LICENCE_SIGNING_MODE` raises `SigningModeNotPermittedError` —
    real key custody is a later, design-gated slice."""
    mode = vendor_settings.licence_signing_mode
    if mode != EPHEMERAL_MODE:
        raise SigningModeNotPermittedError(
            f"VENDOR_LICENCE_SIGNING_MODE={mode!r} — only {EPHEMERAL_MODE!r} is "
            "permitted in this phase; production key custody (OpenBao-referenced) "
            "is not wired yet."
        )
    return EphemeralLicenceSigner(key_id or "vendor-ephemeral-1")


__all__ = [
    "EPHEMERAL_MODE",
    "SigningModeNotPermittedError",
    "LicenceSignerProvider",
    "EphemeralLicenceSigner",
    "build_licence_signer",
]
