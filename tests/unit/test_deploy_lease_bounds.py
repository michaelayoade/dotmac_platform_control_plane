"""The TTL window one signed plan allows (WP5c; RULING-agent-contract, F1 shape).

No database. A role job (`operation = "run_job"`) is leased for at least
`timeout_seconds + 120` and at most Control's per-target
`role_job_lease_ceiling_seconds` (default 900, at most 3600); a serving plan has
no 900 s cap, only the lease store's 3600 s.
"""

from __future__ import annotations

from typing import Any

import pytest

from vendor_cp.deployment.deploy_lease import (
    DeployLeaseRefused,
    LeaseBounds,
    LeasePlanRefused,
    lease_bounds,
)


def _job(timeout: Any = 840) -> dict[str, Any]:
    return {"name": "import", "timeout_seconds": timeout}


def test_a_job_plan_is_leased_for_its_timeout_plus_120_up_to_the_default_ceiling() -> (
    None
):
    bounds = lease_bounds(
        operation="run_job", dispatched_job=_job(780), plan_lease_ttl_seconds=900
    )
    assert bounds == LeaseBounds(900, 900)
    short = lease_bounds(
        operation="run_job", dispatched_job=_job(60), plan_lease_ttl_seconds=900
    )
    assert short == LeaseBounds(180, 900)


def test_a_job_whose_timeout_does_not_fit_the_default_ceiling_is_refused() -> None:
    # the ruling's own F1 example (840 s) needs 960 s: over the default 900 ceiling
    with pytest.raises(LeasePlanRefused, match="job-timeout-out-of-bounds"):
        lease_bounds(
            operation="run_job", dispatched_job=_job(840), plan_lease_ttl_seconds=900
        )


def test_a_raised_ceiling_admits_a_longer_job_up_to_the_store_cap() -> None:
    bounds = lease_bounds(
        operation="run_job",
        dispatched_job=_job(840),
        plan_lease_ttl_seconds=1200,
        role_job_lease_ceiling_seconds=3600,
    )
    assert bounds == LeaseBounds(960, 1200)
    top = lease_bounds(
        operation="run_job",
        dispatched_job=_job(3480),
        plan_lease_ttl_seconds=3600,
        role_job_lease_ceiling_seconds=3600,
    )
    assert top == LeaseBounds(3600, 3600)


@pytest.mark.parametrize("timeout", [0, -1, 781, None, "60", 1.5, True])
def test_job_timeout_bounds(timeout: Any) -> None:
    with pytest.raises(LeasePlanRefused, match="job-timeout-out-of-bounds"):
        lease_bounds(
            operation="run_job",
            dispatched_job=_job(timeout),
            plan_lease_ttl_seconds=900,
        )


def test_a_plan_ttl_below_the_job_need_does_not_fit() -> None:
    with pytest.raises(LeasePlanRefused, match="job-lease-does-not-fit"):
        lease_bounds(
            operation="run_job", dispatched_job=_job(600), plan_lease_ttl_seconds=700
        )


@pytest.mark.parametrize("ceiling", [0, -5, 3601, None, "900", True])
def test_the_ceiling_is_bounded_by_control(ceiling: Any) -> None:
    with pytest.raises(LeasePlanRefused, match="ceiling-out-of-bounds"):
        lease_bounds(
            operation="run_job",
            dispatched_job=_job(60),
            plan_lease_ttl_seconds=900,
            role_job_lease_ceiling_seconds=ceiling,
        )


def test_a_serving_plan_has_no_900_second_cap() -> None:
    assert lease_bounds(
        operation="deploy", dispatched_job=None, plan_lease_ttl_seconds=3600
    ) == LeaseBounds(1, 3600)
    assert lease_bounds(
        operation="deploy", dispatched_job=None, plan_lease_ttl_seconds=1800
    ) == LeaseBounds(1, 1800)


def test_the_serving_ceiling_setting_does_not_apply_to_serving_plans() -> None:
    bounds = lease_bounds(
        operation="deploy",
        dispatched_job=None,
        plan_lease_ttl_seconds=2000,
        role_job_lease_ceiling_seconds=900,
    )
    assert bounds.max_ttl == 2000


def test_operation_and_dispatched_job_must_agree() -> None:
    with pytest.raises(LeasePlanRefused, match="run-job-without-dispatched-job"):
        lease_bounds(
            operation="run_job", dispatched_job=None, plan_lease_ttl_seconds=900
        )
    with pytest.raises(LeasePlanRefused, match="run-job-without-dispatched-job"):
        lease_bounds(operation="run_job", dispatched_job=[], plan_lease_ttl_seconds=900)
    with pytest.raises(LeasePlanRefused, match="dispatched-job-on-a-serving-plan"):
        lease_bounds(
            operation="deploy", dispatched_job=_job(), plan_lease_ttl_seconds=900
        )


@pytest.mark.parametrize("ttl", [0, -1, 3601, None, "900", True])
def test_the_plan_lease_ttl_is_bounded_by_the_store_cap(ttl: Any) -> None:
    for operation, job in (("deploy", None), ("run_job", _job(60))):
        with pytest.raises(LeasePlanRefused, match="plan-lease-ttl-out-of-bounds"):
            lease_bounds(
                operation=operation, dispatched_job=job, plan_lease_ttl_seconds=ttl
            )


@pytest.mark.parametrize("requested", [0, 1799, 3601, None, "900", 900.0, True])
def test_a_requested_ttl_outside_the_window_is_lease_ttl_invalid(
    requested: Any,
) -> None:
    window = LeaseBounds(1800, 3600)
    with pytest.raises(DeployLeaseRefused) as raised:
        window.check(requested)
    assert raised.value.code == "lease-ttl-invalid"


def test_a_requested_ttl_inside_the_window_is_returned() -> None:
    window = LeaseBounds(180, 900)
    assert window.check(180) == 180
    assert window.check(900) == 900
