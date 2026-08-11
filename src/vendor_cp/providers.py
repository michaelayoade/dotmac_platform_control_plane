"""Provisioning provider wiring — SIMULATION ONLY in this phase (deny-case D3).

The vendor control plane consumes the kernel's `ProvisioningProvider` contract
(`dotmac_kernel.providers.provisioning`) and supplies its own side-effect-free
laboratory implementation. Configuring a real provider FAILS STARTUP: the
control plane must not talk to real infrastructure until the provisioning
runner + activation contracts land (a later, design-gated slice). This is a
contract laboratory, not a fleet driver — no fleet tables, no DeploymentRunner.
"""

from __future__ import annotations

from dotmac_kernel.providers.provisioning import ProvisioningProvider

from vendor_cp.config import vendor_settings
from vendor_cp.provisioning.laboratory import LaboratoryProvisioningProvider


class RealProviderNotPermittedError(RuntimeError):
    """Raised at startup if a non-fake provider mode is configured."""


def build_provisioning_provider(
    *,
    steps: tuple[str, ...] = ("resource-a", "resource-b"),
    fail_plan: bool = False,
    fail_apply: bool = False,
    partial_first_apply: bool = False,
) -> ProvisioningProvider:
    """Return the phase-appropriate `ProvisioningProvider`.

    Simulation only. The explicit failure/partial controls let the kernel's
    test-only conformance suite drive the Vendor implementation. A non-`fake`
    `VENDOR_PROVIDER_MODE` raises `RealProviderNotPermittedError`.
    """
    if vendor_settings.provider_mode != "fake":
        raise RealProviderNotPermittedError(
            f"VENDOR_PROVIDER_MODE={vendor_settings.provider_mode!r} — only 'fake' "
            "is permitted in this phase; real provisioning providers are not wired."
        )
    return LaboratoryProvisioningProvider(
        steps=steps,
        fail_plan=fail_plan,
        fail_apply=fail_apply,
        partial_first_apply=partial_first_apply,
    )
