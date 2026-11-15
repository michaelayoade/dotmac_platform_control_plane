"""Install Deployment Control's verification security at bindings startup (E6, (b)).

Control refuses every host-admission resolve/finalize and every Foundation
dispatch consumption unless two installs ran once, at startup, by the composing
assembly: `install_host_admission_security` and
`install_foundation_consumption_security`. CP's production bindings called
neither, so Control refused in every placement (E3 audit, row 10). This module
is that composition.

What is installed, all fixed at startup and never selected by a request:

* host-admission presentation verifier: Ed25519 over the key Control resolves
  from its own enrolled trust root (`HostAdmissionPresentationEd25519Verifier`);
* authorization and dispatch verifiers: Ed25519 over the PUBLIC identities the
  custody ceremony installed on the host (`PinnedVerificationIdentity`);
* the clock for both: CP database time (`DatabaseClock`), never the local clock.

Environment names (values never echoed): `AUTHORIZATION_VERIFICATION_IDENTITY`,
`DISPATCH_VERIFICATION_IDENTITY`. A missing identity refuses naming the
variable. Control permits one install per process; a repeat with the same
identities is a no-op and a repeat with different ones refuses.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from threading import Lock
from typing import Any, Final

from vendor_cp.deployment.target_refusals import (
    FoundationBindingsUnavailable,
    TargetRefusal,
)
from vendor_cp.deployment.verification_identities import (
    AuthorizationEd25519Verifier,
    DispatchEd25519Verifier,
    HostAdmissionPresentationEd25519Verifier,
    PinnedVerificationIdentity,
)

__all__ = [
    "AUTHORIZATION_IDENTITY_ENV",
    "DISPATCH_IDENTITY_ENV",
    "ControlIdentities",
    "install_control_verification",
    "load_control_identities",
]

AUTHORIZATION_IDENTITY_ENV: Final = "AUTHORIZATION_VERIFICATION_IDENTITY"
DISPATCH_IDENTITY_ENV: Final = "DISPATCH_VERIFICATION_IDENTITY"

_LOCK = Lock()
_INSTALLED: tuple[str, str] | None = None


class _Clock:
    """Control's `.now()` port over any datetime-returning callable."""

    def __init__(self, source: Callable[[], datetime]) -> None:
        self._source = source

    def now(self) -> datetime:
        return self._source()


def _control_missing() -> FoundationBindingsUnavailable:
    return FoundationBindingsUnavailable(
        "dotmac-deployment-control is not installed in this environment; "
        "Control verification security cannot be installed",
        code=TargetRefusal.CONTROL_SECURITY_REFUSED,
    )


@dataclass(frozen=True, slots=True)
class ControlIdentities:
    """The two proven public identities Control's verification is installed with."""

    authorization: PinnedVerificationIdentity
    dispatch: PinnedVerificationIdentity


def load_control_identities(
    env: Mapping[str, str], *, owner_uid: int = 0
) -> ControlIdentities:
    """Load and prove both identities. Touches no database and installs nothing.

    Called before the first database connection, so a missing or malformed
    identity refuses before any credential is used.
    """
    missing = [
        name
        for name in (AUTHORIZATION_IDENTITY_ENV, DISPATCH_IDENTITY_ENV)
        if not env.get(name, "").strip()
    ]
    if missing:
        raise FoundationBindingsUnavailable(
            "Control verification security cannot be installed; missing: "
            + "; ".join(f"verification identity ({name} unset)" for name in missing),
            code=TargetRefusal.VERIFICATION_IDENTITY_MISSING,
        )
    try:
        from dotmac_deployment_control import AUTHORIZATION_PURPOSE, DISPATCH_PURPOSE
    except ImportError:
        raise _control_missing() from None
    return ControlIdentities(
        authorization=PinnedVerificationIdentity.read(
            env[AUTHORIZATION_IDENTITY_ENV].strip(),
            purpose=AUTHORIZATION_PURPOSE,
            what=f"authorization verification identity ({AUTHORIZATION_IDENTITY_ENV})",
            owner_uid=owner_uid,
        ),
        dispatch=PinnedVerificationIdentity.read(
            env[DISPATCH_IDENTITY_ENV].strip(),
            purpose=DISPATCH_PURPOSE,
            what=f"dispatch verification identity ({DISPATCH_IDENTITY_ENV})",
            owner_uid=owner_uid,
        ),
    )


def install_control_verification(
    env: Mapping[str, str],
    *,
    clock: Callable[[], datetime],
    owner_uid: int = 0,
    identities: ControlIdentities | None = None,
) -> None:
    """Install both Control security halves, or refuse naming what is missing."""
    proven = identities or load_control_identities(env, owner_uid=owner_uid)
    try:
        from dotmac_deployment_control import (
            HOST_ADMISSION_PRESENTATION_PURPOSE,
            install_foundation_consumption_security,
            install_host_admission_security,
        )
    except ImportError:
        raise _control_missing() from None
    authorization, dispatch = proven.authorization, proven.dispatch
    fingerprints = (
        authorization.public_key_fingerprint,
        dispatch.public_key_fingerprint,
    )
    global _INSTALLED
    with _LOCK:
        if _INSTALLED is not None:
            if _INSTALLED != fingerprints:
                raise FoundationBindingsUnavailable(
                    "Control verification security is already installed with "
                    "different identities",
                    code=TargetRefusal.CONTROL_SECURITY_REFUSED,
                )
            return
        control_clock: Any = _Clock(clock)
        try:
            install_host_admission_security(
                verifier=HostAdmissionPresentationEd25519Verifier(
                    expected_purpose=HOST_ADMISSION_PRESENTATION_PURPOSE
                ),
                clock=control_clock,
            )
            install_foundation_consumption_security(
                authorization_verifier=AuthorizationEd25519Verifier(authorization),
                dispatch_verifier=DispatchEd25519Verifier(dispatch),
                clock=control_clock,
            )
        except (RuntimeError, TypeError):
            raise FoundationBindingsUnavailable(
                "Control verification security was refused by Control "
                "(already installed or a port was not satisfied)",
                code=TargetRefusal.CONTROL_SECURITY_REFUSED,
            ) from None
        _INSTALLED = fingerprints
