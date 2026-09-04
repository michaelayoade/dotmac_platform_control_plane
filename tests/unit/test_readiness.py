"""Readiness answers a different question from liveness, and must keep doing so.

The defect this feature closes is not hypothetical: `docker compose up -d app
--wait` was satisfied by the kernel's `/health`, which by its own docstring does
not touch the database. So a container that could not reach its database
reported healthy, `scripts/deploy_production.sh` declared the deploy successful,
and the first request an operator made was what found out.

Two properties therefore matter more than the route's existence: it must FAIL
when the dependency is unreachable, and it must reveal nothing while doing so.

The second half of that gap was measured later: readiness reported DATABASE
liveness and nothing else, so a deployment whose platform outbox was not being
drained — an activated agreement producing no entitlement allocation — was
reported ready. The relay verdict is composed in for that reason, and the tests
below hold it to the same two properties: it must fail when the drain is
stalled, and it must publish a member rather than a number.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

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
from vendor_cp.relay.health import RelayHealth, RelayVerdict

# Deliberately the real clock, not a literal instant.
#
# The route under test is an ADAPTER: it supplies `datetime.now(UTC)` to
# `check_readiness`, which is correct production behaviour and not a seam worth
# breaking open for tests. So a fixture heartbeat pinned to a fixed instant is
# judged against a clock that keeps moving, and every route assertion below
# holds only while that literal is recent. It was `datetime(2026, 9, 4, 12, 0)`,
# and `check` went red 300 seconds after it — on a date nobody edited, on a
# documentation-only branch.
#
# Nothing in this module asserts anything about a calendar date. Every property
# here is an AGE compared against a window, so the honest fixture clock is the
# same one the adapter reads.
NOW = datetime.now(UTC)
WINDOW = timedelta(seconds=300)


class _UnreachableSession:
    """A session whose database is not there. The realistic failure, not a mock
    of a return value — `execute` is what raises when Postgres is unreachable."""

    def execute(self, statement: object) -> object:
        raise OperationalError("SELECT 1", {}, Exception("connection refused"))

    def scalar(self, statement: object) -> object:
        raise OperationalError("SELECT 1", {}, Exception("connection refused"))


class _ReachableSession:
    """Reachable, its relay alive, its outbox empty — a healthy idle deployment.

    A real shape rather than a patched decision: the readiness COMPOSITION is
    what is under test here, and stubbing the verdict would remove the thing
    being tested. `execute(...)` answers both shapes the observation needs — a
    `scalar_one()` count of 0, and a `one()` heartbeat row whose freshest poll
    is `now` — and `scalar` answers `None` for the timestamp lookups.
    """

    def __init__(self, *, heartbeat_at: datetime | None = NOW) -> None:
        self.statements: list[str] = []
        self._heartbeat_at = heartbeat_at

    def execute(self, statement: object) -> object:
        self.statements.append(str(statement))
        return _Row(self._heartbeat_at)

    def scalar(self, statement: object) -> object:
        self.statements.append(str(statement))
        return None


class _Row:
    """Answers `scalar_one()` as a count and `one()` as a heartbeat pair."""

    def __init__(self, heartbeat_at: datetime | None) -> None:
        self._heartbeat_at = heartbeat_at

    def scalar_one(self) -> int:
        return 0

    def one(self) -> tuple[datetime | None, datetime | None]:
        return (self._heartbeat_at, None)


def _check(session: object, *, now: datetime = NOW) -> ReadinessReport:
    return check_readiness(
        session,  # type: ignore[arg-type]
        now=now,
        overdue_after=WINDOW,
        stale_lease_after=WINDOW,
        heartbeat_stale_after=WINDOW,
        settled_within=WINDOW,
    )


# ── the database half ───────────────────────────────────────────────────────


def test_a_reachable_database_with_an_empty_outbox_is_ready() -> None:
    session = _ReachableSession()
    report = _check(session)
    assert report == ReadinessReport(ready=True, detail=ReadinessDetail.READY)
    assert PROBE in session.statements[0]


def test_an_unreachable_database_is_not_ready_and_does_not_raise() -> None:
    """Returning is the point. A probe that propagated the driver's exception
    would turn an expected, transient answer into a 500 in the logs of
    everything watching — the unreachable case is a NORMAL outcome of asking."""
    report = _check(_UnreachableSession())
    assert report.ready is False
    assert report.detail is ReadinessDetail.DATABASE_UNREACHABLE


def test_an_unreachable_database_is_not_reported_as_an_unreadable_outbox() -> None:
    """ORDER. The two questions have different repairs — one sends an operator
    to the network or the credential, the other to a privilege on one table —
    so the database probe is asked FIRST and its answer is not overwritten."""
    assert _check(_UnreachableSession()).detail is not (
        ReadinessDetail.RELAY_STATE_UNKNOWN
    )


def test_the_probe_is_the_cheapest_statement_that_proves_a_round_trip() -> None:
    """A readiness check that read the catalogue would be a load source of its
    own on every orchestrator poll."""
    assert PROBE == "SELECT 1"


# ── the relay half ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("verdict", "expected"),
    [
        (RelayVerdict.DRAINING, ReadinessDetail.READY),
        (RelayVerdict.RELAY_NOT_RUNNING, ReadinessDetail.RELAY_NOT_RUNNING),
        (RelayVerdict.RELAY_WEDGED, ReadinessDetail.RELAY_WEDGED),
        (
            RelayVerdict.ACTIVATION_BACKLOG_OVERDUE,
            ReadinessDetail.ACTIVATION_BACKLOG_OVERDUE,
        ),
        (RelayVerdict.ACTIVATION_LEASE_STALE, ReadinessDetail.ACTIVATION_LEASE_STALE),
        (
            RelayVerdict.ACTIVATION_DEAD_LETTERED,
            ReadinessDetail.ACTIVATION_DEAD_LETTERED,
        ),
        (RelayVerdict.RELAY_STATE_UNKNOWN, ReadinessDetail.RELAY_STATE_UNKNOWN),
    ],
)
def test_every_relay_verdict_reaches_readiness_unchanged(
    monkeypatch: pytest.MonkeyPatch,
    verdict: RelayVerdict,
    expected: ReadinessDetail,
) -> None:
    """One row per member, so a verdict added without a mapping fails here
    rather than silently taking whichever branch it falls through to."""
    monkeypatch.setattr(
        "vendor_cp.readiness.service.relay_health",
        lambda *_args, **_kwargs: RelayHealth(verdict=verdict),
    )
    report = _check(_ReachableSession())
    assert report.detail is expected
    assert report.ready is (expected is ReadinessDetail.READY)


def test_only_a_draining_relay_is_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    """The constraint in one line: an activated agreement that produces no
    allocation must not look complete."""
    for verdict in RelayVerdict:
        monkeypatch.setattr(
            "vendor_cp.readiness.service.relay_health",
            lambda *_args, _v=verdict, **_kwargs: RelayHealth(verdict=_v),
        )
        assert _check(_ReachableSession()).ready is (
            verdict is RelayVerdict.DRAINING
        ), verdict


# ── the vocabulary is closed and the two enums cannot drift ─────────────────


def test_the_detail_vocabulary_is_closed_and_carries_no_driver_text() -> None:
    """An unauthenticated probe must not publish the host, the role or the
    failure mode. The vocabulary is members, never an exception string."""
    assert {member.value for member in ReadinessDetail} == {
        "ready",
        "database_unreachable",
        "relay_not_running",
        "relay_wedged",
        "activation_backlog_overdue",
        "activation_lease_stale",
        "activation_dead_lettered",
        "relay_state_unknown",
    }
    report = _check(_UnreachableSession())
    assert "connection refused" not in report.detail.value
    assert isinstance(report.detail, ReadinessDetail)


def test_every_non_draining_relay_verdict_has_a_readiness_member() -> None:
    """Both directions, so the two vocabularies cannot drift apart. `DRAINING`
    is the one verdict that maps onto an existing member (`ready`) rather than
    contributing a value of its own."""
    published = {member.value for member in ReadinessDetail}
    for verdict in RelayVerdict:
        if verdict is RelayVerdict.DRAINING:
            continue
        assert verdict.value in published, verdict


def test_readiness_publishes_no_count(monkeypatch: pytest.MonkeyPatch) -> None:
    """The depths and ages exist on `RelayHealth` and stay there. This probe is
    unauthenticated; telling a caller how much work the control plane is
    carrying is not the same as telling it the deployment cannot serve."""
    monkeypatch.setattr(
        "vendor_cp.readiness.service.relay_health",
        lambda *_args, **_kwargs: RelayHealth(
            verdict=RelayVerdict.ACTIVATION_BACKLOG_OVERDUE,
            pending_total=4_512,
            overdue_total=4_512,
            oldest_overdue_age_seconds=98_765,
        ),
    )
    report = _check(_ReachableSession())
    rendered = f"{report.ready}{report.detail.value}"
    assert "4512" not in rendered
    assert "98765" not in rendered


# ── the route, and the profiles that may not withhold it ────────────────────


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
    """Route-bearing, so derivation alone would allow withholding it.

    `NEVER_WITHHELD_SURFACES` is the one hand-declared set left in the profile
    module, and this is the fact it exists for.
    """
    from vendor_cp.assembly import COMPOSED_MANIFESTS
    from vendor_cp.deployment_profile import (
        NEVER_WITHHELD_SURFACES,
        route_bearing_codes,
        withholdable_surfaces,
    )

    assert "readiness" in route_bearing_codes(COMPOSED_MANIFESTS)
    assert "readiness" in NEVER_WITHHELD_SURFACES
    assert "readiness" not in withholdable_surfaces(COMPOSED_MANIFESTS)


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


def test_the_route_answers_503_when_the_relay_is_stalled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reachable database is the point: this deployment can serve requests
    and still cannot complete an activation, and the orchestrator must see
    that."""
    from dotmac_kernel.db import get_platform_db

    monkeypatch.setattr(
        "vendor_cp.readiness.service.relay_health",
        lambda *_args, **_kwargs: RelayHealth(
            verdict=RelayVerdict.ACTIVATION_BACKLOG_OVERDUE
        ),
    )
    app = create_app(assembly.build_spec(deployment_profile("full")))
    app.dependency_overrides[get_platform_db] = lambda: _ReachableSession()
    with TestClient(app) as client:
        response = client.get("/health/ready")
    assert response.status_code == 503
    assert response.json() == {
        "ready": False,
        "detail": "activation_backlog_overdue",
    }


def test_the_route_answers_200_when_the_dependency_answers() -> None:
    """NON-VACUITY for the two tests above: a route that always 503'd would pass
    them."""
    from dotmac_kernel.db import get_platform_db

    app = create_app(assembly.build_spec(deployment_profile("full")))
    app.dependency_overrides[get_platform_db] = lambda: _ReachableSession()
    with TestClient(app) as client:
        response = client.get("/health/ready")
    assert response.status_code == 200
    assert response.json() == {"ready": True, "detail": "ready"}


def test_the_healthy_fixture_is_healthy_by_the_clock_the_route_reads() -> None:
    """The precondition every route assertion above rests on, asserted directly.

    A frozen fixture clock does not fail loudly; it makes the 503 tests pass for
    the wrong reason — an unreachable-database case and a stale-heartbeat case
    are indistinguishable when EVERY fixture is stale — and leaves only the
    non-vacuity test to notice. This puts the precondition under its own
    assertion, judged by `datetime.now(UTC)` exactly as the adapter judges it,
    so re-pinning `NOW` to a past literal fails here and immediately rather than
    at some later hour.
    """
    real_now = datetime.now(UTC)
    assert _check(_ReachableSession(), now=real_now) == ReadinessReport(
        ready=True, detail=ReadinessDetail.READY
    )
    # Sensitivity: the same check, same clock, an old heartbeat — the assertion
    # above is capable of failing, so its passing is a measurement.
    assert not _check(
        _ReachableSession(heartbeat_at=real_now - timedelta(days=1)), now=real_now
    ).ready


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


def test_a_stopped_relay_makes_the_probe_answer_503() -> None:
    """The deployment can serve requests and cannot complete an activation.

    A real shape rather than a patched verdict: the heartbeat is simply old, and
    the composition reaches `relay_not_running` on its own.
    """
    from dotmac_kernel.db import get_platform_db

    app = create_app(assembly.build_spec(deployment_profile("full")))
    stale = _ReachableSession(heartbeat_at=NOW - timedelta(days=1))
    app.dependency_overrides[get_platform_db] = lambda: stale
    with TestClient(app) as client:
        response = client.get("/health/ready")
    assert response.status_code == 503
    assert response.json() == {"ready": False, "detail": "relay_not_running"}


def test_a_relay_that_never_reported_makes_the_probe_answer_503() -> None:
    """A deployment whose relay has never started. The heartbeat table is
    readable and empty, which is a measurement rather than an unknown."""
    from dotmac_kernel.db import get_platform_db

    app = create_app(assembly.build_spec(deployment_profile("full")))
    never = _ReachableSession(heartbeat_at=None)
    app.dependency_overrides[get_platform_db] = lambda: never
    with TestClient(app) as client:
        response = client.get("/health/ready")
    assert response.status_code == 503
    assert response.json() == {"ready": False, "detail": "relay_not_running"}
