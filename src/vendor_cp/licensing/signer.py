"""The licence signing seam — EPHEMERAL ONLY in this phase.

Signing is the vendor control plane's job: the kernel deliberately ships no
signer (it verifies only), so the Ed25519 signing lives here. What does NOT
live here is key custody — `LicenceSignerProvider` is a narrow protocol
(`key_id`, `public_key_b64`, `sign`), so the material's source is swappable
without touching issuance logic.

Two modes behind `VENDOR_LICENCE_SIGNING_MODE`, mirroring the D3
fake-provider posture:

- **`ephemeral`** (default) — a keypair generated in memory at construction.
  Never persisted, never a real issuer key: dev/test only.
- **`configured`** — the private key is read from a file whose CANONICAL source
  is OpenBao (`secret/dotmac/licensing/signing-key`), materialised at 0600 by
  deploy tooling. The value never appears in code, config, logs, the database,
  or an exception message: every failure below reports the PATH and the shape
  problem, never the bytes. Anything missing, unreadable, or malformed FAILS
  STARTUP rather than falling back to a throwaway key.

**Rotation overlap.** Set `VENDOR_LICENCE_OVERLAP_KEY_FILE`/`_KEY_ID` to
double-sign every document with a second key. That is what makes rotation
non-breaking: deployments holding EITHER the old or the new keyring can verify
the same envelope, so the fleet can be updated at its own pace. Sequence:
publish the new key as `active` → set it as the overlap key (double-signing) →
wait for the fleet to import the new keyring → promote it to primary and mark
the old one `retired` → unset the overlap. `revoked` is for compromise only,
and requires re-issuance at a higher version.

The envelope format is the kernel's (`dotmac-licence-envelope/1`, Ed25519 over
the exact payload bytes); issuance proves compatibility by round-tripping every
signed envelope through the pinned kernel's `verify_licence`.
"""

from __future__ import annotations

import base64
import binascii
from pathlib import Path
from typing import Protocol, runtime_checkable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from vendor_cp.config import vendor_settings

EPHEMERAL_MODE = "ephemeral"
CONFIGURED_MODE = "configured"
_ED25519_PRIVATE_KEY_BYTES = 32


class SigningModeNotPermittedError(RuntimeError):
    """Raised at startup for an unknown signing mode."""


class SigningKeyUnavailableError(RuntimeError):
    """`configured` mode was selected but the key could not be loaded. The
    message names the PATH and the shape problem — never the key bytes."""


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


class ConfiguredLicenceSigner:
    """Signs with a private key loaded from a file (OpenBao-sourced).

    The key is read ONCE at construction and held in memory; the path is
    remembered only for error messages. Nothing here writes the key anywhere,
    and no error carries its value.
    """

    def __init__(self, *, key_id: str, key_file: str) -> None:
        if not key_id:
            raise SigningKeyUnavailableError(
                "a signing key id is required in configured mode "
                "(VENDOR_LICENCE_SIGNING_KEY_ID)"
            )
        if not key_file:
            raise SigningKeyUnavailableError(
                "a signing key file is required in configured mode "
                "(VENDOR_LICENCE_SIGNING_KEY_FILE)"
            )
        self._key_id = key_id
        self._private_key = _load_private_key(key_file)

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


def _load_private_key(key_file: str) -> Ed25519PrivateKey:
    """Read a base64url raw Ed25519 private key. Every failure path names the
    PATH and the problem, never the contents."""
    path = Path(key_file)
    try:
        raw = path.read_text().strip()
    except OSError as exc:
        raise SigningKeyUnavailableError(
            f"cannot read the licence signing key at {key_file!r}: {exc.strerror}. "
            "Its canonical source is OpenBao (secret/dotmac/licensing/signing-key)."
        ) from None
    if not raw:
        raise SigningKeyUnavailableError(
            f"the licence signing key at {key_file!r} is empty"
        )
    try:
        material = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except (binascii.Error, ValueError):
        raise SigningKeyUnavailableError(
            f"the licence signing key at {key_file!r} is not valid base64url"
        ) from None
    if len(material) != _ED25519_PRIVATE_KEY_BYTES:
        raise SigningKeyUnavailableError(
            f"the licence signing key at {key_file!r} is "
            f"{len(material)} bytes, expected {_ED25519_PRIVATE_KEY_BYTES} "
            "(raw Ed25519 private key)"
        )
    return Ed25519PrivateKey.from_private_bytes(material)


def build_licence_signer(key_id: str | None = None) -> LicenceSignerProvider:
    """The PRIMARY signer for this deployment, per
    `VENDOR_LICENCE_SIGNING_MODE`. Fails startup rather than falling back."""
    mode = vendor_settings.licence_signing_mode
    if mode == EPHEMERAL_MODE:
        return EphemeralLicenceSigner(key_id or "vendor-ephemeral-1")
    if mode == CONFIGURED_MODE:
        return ConfiguredLicenceSigner(
            key_id=key_id or vendor_settings.licence_signing_key_id,
            key_file=vendor_settings.licence_signing_key_file,
        )
    raise SigningModeNotPermittedError(
        f"VENDOR_LICENCE_SIGNING_MODE={mode!r} is not a signing mode — "
        f"expected {EPHEMERAL_MODE!r} or {CONFIGURED_MODE!r}."
    )


def build_overlap_signer() -> LicenceSignerProvider | None:
    """The optional SECOND signer used during a rotation overlap, or None.

    Only meaningful in `configured` mode: an ephemeral overlap key would be
    regenerated on every restart, so documents signed with it could not be
    verified by anything, which is worse than not overlapping at all.
    """
    if vendor_settings.licence_signing_mode != CONFIGURED_MODE:
        return None
    key_file = vendor_settings.licence_overlap_key_file
    key_id = vendor_settings.licence_overlap_key_id
    if not key_file and not key_id:
        return None
    if bool(key_file) != bool(key_id):
        raise SigningKeyUnavailableError(
            "a rotation overlap needs BOTH VENDOR_LICENCE_OVERLAP_KEY_FILE and "
            "VENDOR_LICENCE_OVERLAP_KEY_ID — configuring one without the other "
            "would silently disable double-signing mid-rotation."
        )
    return ConfiguredLicenceSigner(key_id=key_id, key_file=key_file)


__all__ = [
    "EPHEMERAL_MODE",
    "CONFIGURED_MODE",
    "SigningModeNotPermittedError",
    "SigningKeyUnavailableError",
    "LicenceSignerProvider",
    "EphemeralLicenceSigner",
    "ConfiguredLicenceSigner",
    "build_licence_signer",
    "build_overlap_signer",
]
