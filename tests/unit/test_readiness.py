"""Readiness answers a different question from liveness, and must keep doing so.

The defect this feature closes is not hypothetical: `docker compose up -d app
--wait` was satisfied by the kernel's `/health`, which by its own docstring does
not touch the database. So a container that could not reach its database
reported healthy, `scripts/deploy_production.sh` declared the deploy successful,
and the first request an operator made was what found out.

Two properties therefore matter more than the route's existence: it must FAIL
when the dependency is unreachable, and it must reveal nothing while doing so.
"""

from __future__ import annotations

import pytest
from dotmac_kernel import create_app
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from vendor_cp import assembly
from vendor_cp.deployment_profile import PROFILES, deployment_profile
from vendor_cp.readiness.service import (
    PROBE,
    ReadinessDetail,
    ReadinessReport,
    check_readiness,
)


class _UnreachableSession:
    """A session whose database is not there. The realistic failure, not a mock
    of a return value — `execute` is what raises when Postgres is unreachable."""

    def execute(self, statement: object) -> object:
        raise OperationalError("SELECT 1", {}, Exception("connection refused"))


class _ReachableSession:
    def __init__(self) -> None:
        self.statements: list[str] = []

    def execute(self, statement: object) -> object:
        self.statements.append(str(statement))
        return object()


def test_a_reachable_database_is_ready() -> None:
    session = _ReachableSession()
    report = check_readiness(session)  # type: ignore[arg-type]
    assert report == ReadinessReport(ready=True, detail=ReadinessDetail.READY)
    assert session.statements == [PROBE]


def test_an_unreachable_database_is_not_ready_and_does_not_raise() -> None:
    """Returning is the point. A probe that propagated the driver's exception
    would turn an expected, transient answer into a 500 in the logs of
    everything watching — the unreachable case is a NORMAL outcome of asking."""
    report = check_readiness(_UnreachableSession())  # type: ignore[arg-type]
    assert report.ready is False
    assert report.detail is ReadinessDetail.DATABASE_UNREACHABLE


def test_the_detail_vocabulary_is_closed_and_carries_no_driver_text() -> None:
    """An unauthenticated probe must not publish the host, the role or the
    failure mode. The vocabulary is members, never an exception string."""
    assert {member.value for member in ReadinessDetail} == {
        "ready",
        "database_unreachable",
    }
    report = check_readiness(_UnreachableSession())  # type: ignore[arg-type]
    assert "connection refused" not in report.detail.value
    assert isinstance(report.detail, ReadinessDetail)


def test_the_probe_is_the_cheapest_statement_that_proves_a_round_trip() -> None:
    """A readiness check that read the catalogue would be a load source of its
    own on every orchestrator poll."""
    assert PROBE == "SELECT 1"


@pytest.mark.parametrize("profile", [p.code for p in PROFILES])
def test_every_profile_publishes_readiness(profile: str) -> None:
    """No profile may withhold it.

    A readiness probe a deployment can switch off is a deployment that can go
    back to reporting healthy while unable to serve — which is the state this
    feature exists to end, so the ability to turn it off would reintroduce it.
    """
    app = create_app(assembly.build_spec(deployment_profile(profile)))
    paths = {getattr(route, "path", "") for route in app.routes}
    assert "/health/ready" in paths, profile
    assert "/health" in paths, f"{profile} lost liveness while gaining readiness"


def test_readiness_is_not_withholdable() -> None:
    from vendor_cp.deployment_profile import (
        VENDOR_SURFACE_CODES,
        WITHHOLDABLE_SURFACES,
    )

    assert "readiness" in VENDOR_SURFACE_CODES
    assert "readiness" not in WITHHOLDABLE_SURFACES


def test_the_route_answers_503_when_the_dependency_is_gone() -> None:
    """The status is what an orchestrator reads.

    A 200 carrying `{"ready": false}` is ready as far as every tool that
    matters is concerned, which is why the status code and not the body is the
    assertion here.
    """
    from dotmac_kernel.db import get_platform_db

    app = create_app(assembly.build_spec(deployment_profile("full")))
    app.dependency_overrides[get_platform_db] = lambda: _UnreachableSession()
    with TestClient(app) as client:
        response = client.get("/health/ready")
    assert response.status_code == 503
    payload = response.json()
    assert payload["ready"] is False
    assert payload["detail"] == "database_unreachable"


def test_the_route_answers_200_when_the_dependency_answers() -> None:
    """NON-VACUITY for the test above: a route that always 503'd would pass it."""
    from dotmac_kernel.db import get_platform_db

    app = create_app(assembly.build_spec(deployment_profile("full")))
    app.dependency_overrides[get_platform_db] = lambda: _ReachableSession()
    with TestClient(app) as client:
        response = client.get("/health/ready")
    assert response.status_code == 200
    assert response.json() == {"ready": True, "detail": "ready"}


def test_liveness_and_readiness_are_different_answers() -> None:
    """The whole reason this feature exists, as one assertion.

    With the database gone, liveness still says 200 — correctly, the process is
    alive — and readiness says 503. A deploy gated only on the first accepts a
    container that cannot serve.
    """
    from dotmac_kernel.db import get_platform_db

    app = create_app(assembly.build_spec(deployment_profile("full")))
    app.dependency_overrides[get_platform_db] = lambda: _UnreachableSession()
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/health/ready").status_code == 503
