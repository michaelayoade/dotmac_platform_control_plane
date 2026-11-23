"""The grant window and total one signed plan allows (WP5c; ruling Q-c/4).

No database. A plan carries `lease_ttl_seconds` (per grant, 120..900) and
`lease_max_seconds` (the total, renewals included, at most 10800). A job plan
(`operation = "run_job"`) has ttl = max = `timeout_seconds + 120`; a serving plan
is granted 120 up to its ttl and renewed up to its total.
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


def _job(timeout: Any = 600) -> dict[str, Any]:
    return {"name": "import", "timeout_seconds": timeout}


def test_a_job_plan_is_granted_exactly_its_ttl_and_is_class_run_job() -> None:
    bounds = lease_bounds(
        operation="run_job",
        dispatched_job=_job(600),
        lease_ttl_seconds=720,
        lease_max_seconds=720,
    )
    assert bounds == LeaseBounds(720, 720, 720, "run_job")
    long = lease_bounds(  # a job lease is not held to the 900 s per-grant cap
        operation="run_job",
        dispatched_job=_job(2400),
        lease_ttl_seconds=2520,
        lease_max_seconds=2520,
    )
    assert long == LeaseBounds(2520, 2520, 2520, "run_job")
    top = lease_bounds(
        operation="run_job",
        dispatched_job=_job(3480),
        lease_ttl_seconds=3600,
        lease_max_seconds=3600,
    )
    assert top.max_ttl == 3600


@pytest.mark.parametrize(
    ("ttl", "total", "reason"),
    [
        (719, 719, "job-lease-does-not-fit"),  # timeout 600 needs 720
        (720, 900, "job-lease-does-not-fit"),  # ttl must equal max
        (900, 720, "job-lease-does-not-fit"),
        (3601, 3601, "plan-lease-ttl-out-of-bounds"),  # a job lease is at most 3600
        (0, 0, "plan-lease-ttl-out-of-bounds"),
    ],
)
def test_a_job_lease_must_equal_its_total_cover_the_timeout_and_fit_3600(
    ttl: int, total: int, reason: str
) -> None:
    with pytest.raises(LeasePlanRefused, match=reason):
        lease_bounds(
            operation="run_job",
            dispatched_job=_job(600),
            lease_ttl_seconds=ttl,
            lease_max_seconds=total,
        )


@pytest.mark.parametrize("timeout", [0, -1, None, "60", 1.5, True])
def test_job_timeout_must_be_a_positive_int(timeout: Any) -> None:
    with pytest.raises(LeasePlanRefused, match="job-timeout-out-of-bounds"):
        lease_bounds(
            operation="run_job",
            dispatched_job=_job(timeout),
            lease_ttl_seconds=900,
            lease_max_seconds=900,
        )


def test_a_serving_plan_is_granted_120_to_its_ttl_and_renewed_to_its_total() -> None:
    bounds = lease_bounds(
        operation="deploy",
        dispatched_job=None,
        lease_ttl_seconds=600,
        lease_max_seconds=10800,
    )
    assert bounds == LeaseBounds(120, 600, 10800, "serving")
    assert bounds.check(120) == 120 and bounds.check(600) == 600
    for bad in (119, 601):
        with pytest.raises(DeployLeaseRefused):
            bounds.check(bad)


@pytest.mark.parametrize("ttl", [0, 119, 901, 3600, None, "600", True])
def test_the_serving_per_grant_ttl_is_120_to_900(ttl: Any) -> None:
    with pytest.raises(LeasePlanRefused, match="plan-lease-ttl-out-of-bounds"):
        lease_bounds(
            operation="deploy",
            dispatched_job=None,
            lease_ttl_seconds=ttl,
            lease_max_seconds=900,
        )


@pytest.mark.parametrize("total", [0, 599, 10801, None, "900", True])
def test_the_total_is_at_least_the_ttl_and_at_most_10800(total: Any) -> None:
    with pytest.raises(LeasePlanRefused, match="plan-lease-max-out-of-bounds"):
        lease_bounds(
            operation="deploy",
            dispatched_job=None,
            lease_ttl_seconds=600,
            lease_max_seconds=total,
        )


def test_operation_and_dispatched_job_must_agree() -> None:
    kw: dict[str, Any] = {"lease_ttl_seconds": 600, "lease_max_seconds": 600}
    with pytest.raises(LeasePlanRefused, match="run-job-without-dispatched-job"):
        lease_bounds(operation="run_job", dispatched_job=None, **kw)
    with pytest.raises(LeasePlanRefused, match="run-job-without-dispatched-job"):
        lease_bounds(operation="run_job", dispatched_job=[], **kw)
    with pytest.raises(LeasePlanRefused, match="dispatched-job-on-a-serving-plan"):
        lease_bounds(operation="deploy", dispatched_job=_job(), **kw)


@pytest.mark.parametrize("requested", [0, 119, 901, None, "600", 600.0, True])
def test_a_requested_ttl_outside_the_window_is_lease_ttl_invalid(
    requested: Any,
) -> None:
    with pytest.raises(DeployLeaseRefused) as raised:
        LeaseBounds(120, 900, 900, "serving").check(requested)
    assert raised.value.code == "lease-ttl-invalid"
