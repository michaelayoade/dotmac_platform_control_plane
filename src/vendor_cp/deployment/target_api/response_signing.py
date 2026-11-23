"""The CP response key and the `cp-target-response.v1` purpose.

Every response the target API sends is signed over
`contract.response_message(...)`: purpose, verb, path, the REQUEST's nonce, the
status and the body hash. Error bodies are signed too. The key is a distinct CP
response key pinned by the target at enrolment (RULING-agent-contract U13); it is
NOT Control's dispatch key, so no trust root widens.

A published test key can never be this key: the vector file publishes the
response seed, so its public key authenticates nobody. Construction refuses it.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from typing import Final, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from vendor_cp.deployment.target_api import contract as c

__all__ = [
    "RESPONSE_KEY_FILE_ENV",
    "RESPONSE_KEY_ID_ENV",
    "Ed25519ResponseSigner",
    "ResponseKeyUnavailable",
    "ResponseSigner",
    "load_response_signer",
]

#: Names only. The file holds the 32-byte Ed25519 seed as unpadded base64url.
RESPONSE_KEY_FILE_ENV: Final = "VENDOR_TARGET_API_RESPONSE_KEY_FILE"
RESPONSE_KEY_ID_ENV: Final = "VENDOR_TARGET_API_RESPONSE_KEY_ID"


class ResponseKeyUnavailable(RuntimeError):
    """The response key cannot be used. The message names a rule, never a value."""


class ResponseSigner(Protocol):
    @property
    def key_id(self) -> str: ...

    @property
    def public_key_b64u(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


class Ed25519ResponseSigner:
    def __init__(self, seed: bytes, *, key_id: str) -> None:
        if len(seed) != 32:
            raise ResponseKeyUnavailable("the response key seed is not 32 bytes")
        if not key_id or not key_id.strip():
            raise ResponseKeyUnavailable("the response key needs an id")
        key = Ed25519PrivateKey.from_private_bytes(seed)
        public = c.b64u_encode(
            key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        )
        if c.is_denied_public_key(public):
            raise ResponseKeyUnavailable(
                "the response key belongs to a published test seed"
            )
        self._key = key
        self._key_id = key_id
        self._public = public

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def public_key_b64u(self) -> str:
        return self._public

    def sign(self, message: bytes) -> bytes:
        return bytes(self._key.sign(message))


def load_response_signer(environ: Mapping[str, str]) -> Ed25519ResponseSigner:
    """The configured response key: a 0600 regular file owned by this process."""
    key_id = environ.get(RESPONSE_KEY_ID_ENV, "").strip()
    path = environ.get(RESPONSE_KEY_FILE_ENV, "").strip()
    missing = [
        name
        for name, value in (
            (RESPONSE_KEY_ID_ENV, key_id),
            (RESPONSE_KEY_FILE_ENV, path),
        )
        if not value
    ]
    if missing:
        raise ResponseKeyUnavailable(
            "response key settings unset: " + ", ".join(missing)
        )
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != os.geteuid()
            ):
                raise ResponseKeyUnavailable(
                    "the response key file must be a 0600 regular file we own"
                )
            material = source.read(256).decode("ascii").strip()
        seed = c.b64u_decode(material)
    except (OSError, UnicodeError, c.TargetApiError):
        raise ResponseKeyUnavailable("the response key file is unreadable") from None
    return Ed25519ResponseSigner(seed, key_id=key_id)
