"""The laboratory's thin driver over the kernel `ProvisioningProvider` contract.

Holds ONE shared FAKE provider for the process so an operation's state (keyed by
`operation_id`) survives across the plan → apply → observe → cancel HTTP calls
that exercise it — the fake keeps that state in memory, which is the whole extent
of the lab's "persistence" (no fleet tables, no runner). The provider comes from
`vendor_cp.providers.build_provisioning_provider`, which FAILS for any non-fake
mode (deny-case D3).

These are deliberately thin: each function is one contract invocation. There is
no orchestration loop here — driving apply→observe to convergence is the caller's
job (a human in the lab, or the kernel's conformance suite).
"""

from __future__ import annotations

from collections.abc import Mapping

from dotmac_kernel.providers.provisioning import (
    ApplyResult,
    ObserveResult,
    PlanResult,
    ProvisioningProvider,
    ProvisioningRequest,
)

from vendor_cp.providers import build_provisioning_provider

_provider: ProvisioningProvider | None = None


def get_lab_provider() -> ProvisioningProvider:
    """The process-wide fake provider backing the lab (created on first use)."""
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
        ProvisioningRequest(intent_id=intent_id, spec=dict(spec))
    )


def apply(
    intent_id: str, spec: Mapping[str, object], operation_id: str | None = None
) -> ApplyResult:
    return get_lab_provider().apply(
        ProvisioningRequest(
            intent_id=intent_id, spec=dict(spec), operation_id=operation_id
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
