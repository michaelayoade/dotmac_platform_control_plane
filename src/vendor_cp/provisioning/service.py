"""The laboratory's thin driver over the kernel `ProvisioningProvider` contract.

Holds ONE shared Vendor-owned simulation provider for the process so an
operation's state (keyed by `operation_id`) survives across the plan → apply →
observe → cancel HTTP calls that exercise it. The provider keeps that state in
memory, which is the whole extent of the lab's "persistence" (no fleet tables,
no runner). It comes from `vendor_cp.providers.build_provisioning_provider`,
which FAILS for any non-fake mode (deny-case D3).

These are deliberately thin: each function is one contract invocation. There is
no orchestration loop here — driving apply→observe to convergence is the caller's
job (a human in the lab, or the kernel's conformance suite).
"""

from __future__ import annotations

from collections.abc import Mapping

from dotmac_kernel import PlatformScope
from dotmac_kernel.providers.provisioning import (
    ApplyResult,
    ObserveResult,
    PlanResult,
    ProvisioningProvider,
    ProvisioningRequest,
)

from vendor_cp.providers import build_provisioning_provider

#: The participant this laboratory speaks as. Kernel a98 made
#: `participant_code` and `scope` REQUIRED on `ProvisioningRequest`, and the
#: contract's own words are that scope is "explicit tenant or platform scope;
#: never ambient/nullable". Both are therefore named here, once.
#:
#: The scope is PLATFORM, and that is a fact about this assembly rather than a
#: default: the Vendor control plane holds no tenants, so there is no tenant to
#: be scoped to. Reaching for a `TenantScope` here would mean inventing a
#: sentinel tenant, which the dual-plane rule refuses outright.
PARTICIPANT_CODE = "dotmac-vendor-control-plane"
LABORATORY_SCOPE = PlatformScope()

_provider: ProvisioningProvider | None = None


def get_lab_provider() -> ProvisioningProvider:
    """The process-wide simulation backing the lab (created on first use)."""
    global _provider
    if _provider is None:
        _provider = build_provisioning_provider()
    return _provider


def reset_lab_provider() -> None:
    """Drop the shared provider (and its in-memory operations) — for tests."""
    global _provider
    _provider = None


def plan(intent_id: str, spec: Mapping[str, object]) -> PlanResult:
    return get_lab_provider().plan(
        ProvisioningRequest(
            participant_code=PARTICIPANT_CODE,
            scope=LABORATORY_SCOPE,
            intent_id=intent_id,
            spec=dict(spec),
        )
    )


def apply(
    intent_id: str, spec: Mapping[str, object], operation_id: str | None = None
) -> ApplyResult:
    return get_lab_provider().apply(
        ProvisioningRequest(
            participant_code=PARTICIPANT_CODE,
            scope=LABORATORY_SCOPE,
            intent_id=intent_id,
            spec=dict(spec),
            operation_id=operation_id,
        )
    )


def observe(operation_id: str) -> ObserveResult:
    return get_lab_provider().observe(operation_id)


def cancel(operation_id: str) -> ObserveResult:
    return get_lab_provider().cancel(operation_id)


__all__ = [
    "get_lab_provider",
    "reset_lab_provider",
    "plan",
    "apply",
    "observe",
    "cancel",
]
