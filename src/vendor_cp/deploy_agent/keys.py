"""Purpose-specific configured custody; private bytes never leave this object."""

import os
import stat

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .contracts import b64, identifier, require, unb64

POINTER = "secret/dotmac/platform-cp/desired-state/signing-key"


class ConfiguredDesiredSigner:
    def __init__(self, key_id: str, key_file: str, pointer: str = POINTER) -> None:
        identifier(key_id)
        require(pointer == POINTER, "signing_purpose_mismatch")
        self.key_id = key_id
        try:
            fd = os.open(key_file, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as source:
                info = os.fstat(source.fileno())
                require(
                    stat.S_ISREG(info.st_mode)
                    and stat.S_IMODE(info.st_mode) == 0o600
                    and info.st_uid == os.geteuid(),
                    "signing_key_permissions",
                )
                raw = unb64(source.read(256).decode().strip())
            require(len(raw) == 32, "signing_key_unavailable")
            self._key = Ed25519PrivateKey.from_private_bytes(raw)
        except (OSError, UnicodeError, ValueError):
            raise RuntimeError("desired-state signing key unavailable") from None
        self.public_key_b64 = b64(
            self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        )

    def sign(self, payload: bytes) -> bytes:
        return bytes(self._key.sign(payload))
