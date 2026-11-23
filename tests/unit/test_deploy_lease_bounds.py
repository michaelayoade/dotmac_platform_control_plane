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


def test_a_job_plan_is_granted_exactly_its_ttl() -> None:
    bounds = lease_bounds(
        operation="run_job",
        dispatched_job=_job(600),
        lease_ttl_seconds=720,
        lease_max_seconds=720,
    )
    assert bounds == LeaseBounds(720, 720, 720)
    top = lease_bounds(
        operation="run_job",
        dispatched_job=_job(780),
        lease_ttl_seconds=900,
        lease_max_seconds=900,
    )
    assert top == LeaseBounds(900, 900, 900)


@pytest.mark.parametrize(
    ("ttl", "total"),
    [(719, 719), (720, 900), (900, 720), (721, 721)],
)
def test_a_job_lease_must_equal_its_total_and_cover_timeout_plus_120(
    ttl: int, total: int
) -> None:
    # timeout 600 needs 720; ttl must equal max
    if ttl == total and ttl >= 720:
        assert (
            lease_bounds(
                operation="run_job",
                dispatched_job=_job(600),
                lease_ttl_seconds=ttl,
                lease_max_seconds=total,
            ).max_ttl
            == ttl
        )
        return
    with pytest.raises(LeasePlanRefused, match="job-lease-does-not-fit|max-out"):
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
    assert bounds == LeaseBounds(120, 600, 10800)
    assert bounds.check(120) == 120 and bounds.check(600) == 600
    for bad in (119, 601):
        with pytest.raises(DeployLeaseRefused):
            bounds.check(bad)


@pytest.mark.parametrize("ttl", [0, 119, 901, 3600, None, "600", True])
def test_the_per_grant_ttl_is_120_to_900(ttl: Any) -> None:
    for operation, job in (("deploy", None), ("run_job", _job(60))):
        with pytest.raises(LeasePlanRefused, match="plan-lease-ttl-out-of-bounds"):
            lease_bounds(
                operation=operation,
                dispatched_job=job,
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
        LeaseBounds(120, 900, 900).check(requested)
    assert raised.value.code == "lease-ttl-invalid"
