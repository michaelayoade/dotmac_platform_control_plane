"""Unit tests for the provisioning contract LABORATORY (slice 4).

The lab drives the kernel `ProvisioningProvider` contract (plan → apply → observe
→ cancel) against the FAKE provider — no persistence beyond the fake's in-memory
ledger. These cover the lab's own thin service + that the platform-admin routes
are mounted. (Contract CONFORMANCE of the provider factory itself is covered by
`test_provisioning_contract.py`.)
"""

from __future__ import annotations

import pytest
from dotmac_kernel import create_app
from dotmac_kernel.providers.provisioning import ProvisioningStatus

from vendor_cp.assembly import build_spec
from vendor_cp.provisioning import service


@pytest.fixture(autouse=True)
def _fresh_lab_provider():
    # The lab holds one process-wide provider; reset its in-memory ledger so each
    # test starts clean regardless of order.
    service.reset_lab_provider()
    yield
    service.reset_lab_provider()


def test_plan_returns_hash_and_steps() -> None:
    result = service.plan("i-1", {"size": 1})
    assert result.intent_id == "i-1"
    assert result.plan_hash  # a non-empty deterministic hash
    assert len(result.steps) >= 1


def test_apply_then_observe_reports_same_operation() -> None:
    applied = service.apply("i-1", {"size": 1})
    assert applied.operation_id
    observed = service.observe(applied.operation_id)
    assert observed.operation_id == applied.operation_id
    assert observed.status is applied.status


def test_apply_is_idempotent_by_operation_id() -> None:
    first = service.apply("i-1", {"size": 1})
    again = service.apply("i-1", {"size": 1}, operation_id=first.operation_id)
    assert again.operation_id == first.operation_id
    assert again.status is first.status


def test_cancel_settles_operation_to_cancelled() -> None:
    applied = service.apply("i-1", {"size": 1})
    cancelled = service.cancel(applied.operation_id)
    assert cancelled.operation_id == applied.operation_id
    assert cancelled.status is ProvisioningStatus.CANCELLED


def test_observe_unknown_operation_is_graceful_pending() -> None:
    # The lab must not blow up on a mistyped/unknown operation id.
    observed = service.observe("does-not-exist")
    assert observed.status is ProvisioningStatus.PENDING


def test_provisioning_routes_are_mounted() -> None:
    paths = {getattr(r, "path", "") for r in create_app(build_spec()).routes}
    assert "/platform/vendor/provisioning/plan" in paths
    assert "/platform/vendor/provisioning/apply" in paths
    assert "/platform/vendor/provisioning/operations/{operation_id}" in paths
