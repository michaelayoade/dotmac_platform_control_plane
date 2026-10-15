"""Candidate argument-free systemd credential entry; never a generic wrapper."""

from __future__ import annotations

import os
import stat

from vendor_cp.deployment.gate0_role_custody import ProviderRefused

_CREDENTIAL = "/run/credentials/dotmac-gate0-a9-collector.service/oidc-request-token"
_FIELD = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"


def run_installed_credential_collection() -> int:
    """Deliver only the fixed private credential to the existing same-process API.

    Systemd credential mount ownership/isolation and actual unit identity require
    native qualification. No credential value or hash is emitted or journaled.
    """
    descriptor = -1
    credential = b""
    try:
        if os.getuid() <= 0 or os.getuid() != os.geteuid() or _FIELD in os.environ:
            raise ProviderRefused()
        descriptor = os.open(_CREDENTIAL, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid not in (0, os.getuid())
            or info.st_mode & 0o077
            or not 0 < info.st_size <= 32768
        ):
            raise ProviderRefused()
        credential = os.read(descriptor, 32769)
        if (
            os.read(descriptor, 1)
            or len(credential) != info.st_size
            or any(c <= 32 or c >= 127 for c in credential)
        ):
            raise ProviderRefused()
        os.close(descriptor)
        descriptor = -1
        os.environ[_FIELD] = credential.decode("ascii")
        credential = b""
        from vendor_cp.deployment.gate0_collection import run_installed_collection

        return run_installed_collection()
    except Exception:
        return 3
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.environ.pop(_FIELD, None)
        credential = b""
