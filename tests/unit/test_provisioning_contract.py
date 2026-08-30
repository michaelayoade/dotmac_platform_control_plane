"""Provisioning contract laboratory (slice 4 seed).

The vendor control plane consumes the kernel's `ProvisioningProvider` contract
and proves its provider factory honours it — via the kernel's own parametrized
`check_provisioning_provider_contract` (determinism, idempotency by
`operation_id`, partial-then-resume, failure injection, cancellation). No fleet
tables, no DeploymentRunner — a contract laboratory only.
"""

from __future__ import annotations

import pytest
from dotmac_kernel.messaging import (
    CommandEnvelope,  # noqa: F401  (typed-contract smoke)
)
from dotmac_kernel.providers.provisioning import ProvisioningRequest, ProvisioningStatus
from dotmac_kernel.testing import check_provisioning_provider_contract

import vendor_cp.config as config
import vendor_cp.providers as providers
from vendor_cp.providers import (
    RealProviderNotPermittedError,
    build_provisioning_provider,
)
from vendor_cp.provisioning.laboratory import LaboratoryProvisioningProvider
from vendor_cp.provisioning.service import LABORATORY_SCOPE, PARTICIPANT_CODE


def test_vendor_provider_factory_satisfies_kernel_contract() -> None:
    check_provisioning_provider_contract(build_provisioning_provider)


def test_runtime_laboratory_provider_is_vendor_owned() -> None:
    """The shipped lab must not execute a helper from the kernel test kit."""
    provider = build_provisioning_provider()
    assert type(provider) is LaboratoryProvisioningProvider
    assert LaboratoryProvisioningProvider.__mro__ == (
        LaboratoryProvisioningProvider,
        object,
    )


def test_failure_injection_resume_and_operation_id_idempotency() -> None:
    req = ProvisioningRequest(
        participant_code=PARTICIPANT_CODE,
        scope=LABORATORY_SCOPE,
        intent_id="i-1",
        spec={"size": 1},
    )

    # Failure injection -> terminal FAILED.
    failing = build_provisioning_provider(fail_apply=True)
    assert failing.apply(req).status is ProvisioningStatus.FAILED

    # Partial then resume by operation_id -> converges to SUCCEEDED.
    p = build_provisioning_provider(partial_first_apply=True)
    first = p.apply(req)
    assert first.is_partial
    resumed = p.apply(
        ProvisioningRequest(
            participant_code=PARTICIPANT_CODE,
            scope=LABORATORY_SCOPE,
            intent_id="i-1",
            spec={"size": 1},
            operation_id=first.operation_id,
        )
    )
    assert resumed.status is ProvisioningStatus.SUCCEEDED

    # Idempotency: re-applying a terminal operation returns the prior result.
    done = build_provisioning_provider()
    a = done.apply(req)
    b = done.apply(req)
    assert a.operation_id == b.operation_id and b.status is a.status


def test_real_provider_mode_fails_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    """Deny-case D3: a non-fake provider mode must FAIL, not silently no-op."""
    real = config.VendorSettings(provider_mode="real")
    monkeypatch.setattr(providers, "vendor_settings", real)
    with pytest.raises(RealProviderNotPermittedError):
        build_provisioning_provider()
