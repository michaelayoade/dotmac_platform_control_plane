"""Provisioning provider wiring — FAKE ONLY in this phase (deny-case D3).

The vendor control plane consumes the kernel's `ProvisioningProvider` contract
(`dotmac_kernel.providers.provisioning`) and, for now, only the kernel's
`FakeProvisioningProvider`. Configuring a real provider FAILS STARTUP: the
control plane must not talk to real infrastructure until the provisioning runner
+ activation contracts land (a later, design-gated slice). This is a contract
laboratory, not a fleet driver — no fleet tables, no DeploymentRunner.
"""

from __future__ import annotations

from dotmac_kernel.providers.provisioning import ProvisioningProvider
from dotmac_kernel.testing import FakeProvisioningProvider

from vendor_cp.config import vendor_settings


class RealProviderNotPermittedError(RuntimeError):
    """Raised at startup if a non-fake provider mode is configured."""


def build_provisioning_provider(**kwargs: object) -> ProvisioningProvider:
    """Return the phase-appropriate `ProvisioningProvider`.

    Fake only. `**kwargs` (e.g. `fail_apply=`, `partial_first_apply=`) forward to
    the kernel fake so the provisioning contract suite can drive its behaviours.
    A non-`fake` `VENDOR_PROVIDER_MODE` raises `RealProviderNotPermittedError`.
    """
    if vendor_settings.provider_mode != "fake":
        raise RealProviderNotPermittedError(
            f"VENDOR_PROVIDER_MODE={vendor_settings.provider_mode!r} — only 'fake' "
            "is permitted in this phase; real provisioning providers are not wired."
        )
    return FakeProvisioningProvider(**kwargs)  # type: ignore[arg-type]
