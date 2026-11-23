"""WP5c: the lease endpoints and covers-in-consume, over the REAL target-API router.

The router (authentication, replay, response signing) is lane 5b's, driven over HTTP
exactly as `test_target_api_auth.py` drives it. The store is a fake with the same
interface as `DeployLeaseStore` (its SQL is proven on a real PG16 in
`tests/migration/test_deploy_lease.py`); the `LeasePort` is a fake of 5b's
Control-backed dispatch source. What is proven here is the handler's own decisions:
which TTL a plan admits, that the host and principal come from the authenticated
target and never the request, that the reconcile marker cannot be supplied by a
caller, that a refusal answers typed while the nonce still commits, and that
`consume` is impossible without a covering lease.

Named tests for the section 2.9 rows `test_consume_requires_covering_lease`,
`test_agent_stops_on_lease_refusal`'s server half, and the job/serving TTL rulings.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from target_api_support import (
    BASE,
    STORE_NOW,
    TARGET,
    MemoryNonces,
    RecordingHandlers,
    StaticDirectory,
    b64u,
    build_runtime,
    client_for,
    record,
    request_headers,
    send,
)

from vendor_cp.deployment.deploy_lease import (
    DeployLease,
    DeployLeaseRefused,
    DeployStanding,
)
from vendor_cp.deployment.deploy_lease_handlers import (
    LeaseHandlers,
    LeasePlan,
    UnconfiguredLeasePort,
    refusal_http_status,
)
from vendor_cp.deployment.lease_store import REFUSAL_CODES
from vendor_cp.deployment.target_api.handlers import HandlerResult

_SEED_B64U = b64u(bytes(range(1, 33)))
_PUBLIC = b64u(
    Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    .public_key()
    .public_bytes(Encoding.Raw, PublicFormat.Raw)
)
_RESPONSE_SEED = b64u(bytes(range(100, 132)))
_NOW = datetime(2026, 11, 22, 10, 0, 0, tzinfo=UTC)
_LEASE = "11111111-1111-4111-8111-111111111111"
_MARKER = "sha256:" + "a" * 64
_SERVING = LeasePlan("deploy", None, 1800, 900)
_JOB = LeasePlan("run_job", {"timeout_seconds": 600}, 900, 900)


class FakePort:
    def __init__(self, plans: dict[str, LeasePlan], marker: str | None = None) -> None:
        self.plans = plans
        self.marker = marker
        self.asked: list[tuple[str, str]] = []

    def plan_for(
        self, db: Any, *, target_ref: str, dispatch_id: str, at: datetime
    ) -> LeasePlan | None:
        self.asked.append((target_ref, dispatch_id))
        return self.plans.get(dispatch_id)

    def reconcile_marker_for(
        self, db: Any, *, target_ref: str, at: datetime
    ) -> str | None:
        return self.marker


class FakeStore:
    """The `DeployLeaseStore` interface; records calls, answers or refuses."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.refuse: str | None = None
        self.fault: bool = False

    def _go(self, name: str, **kw: Any) -> None:
        self.calls.append((name, kw))
        if self.fault:
            raise DeployLeaseRefused("store-unreachable")
        if self.refuse:
            raise DeployLeaseRefused(self.refuse)

    def acquire(self, **kw: Any) -> DeployLease:
        self._go("acquire", **kw)
        return DeployLease(
            UUID(_LEASE), _NOW, _NOW + timedelta(seconds=kw["ttl_seconds"]), _NOW
        )

    def covers(self, **kw: Any) -> datetime:
        self._go("covers", **kw)
        return _NOW

    def release(self, **kw: Any) -> datetime:
        self._go("release", **kw)
        return _NOW

    def standing(self, host_id: str) -> DeployStanding:
        self._go("standing", host_id=host_id)
        return DeployStanding("held", UUID(_LEASE), _NOW + timedelta(seconds=60), _NOW)


class Rig:
    def __init__(
        self,
        plans: dict[str, LeasePlan] | None = None,
        marker: str | None = None,
        *,
        port: Any = None,
    ) -> None:
        self.store = FakeStore()
        self.inner = RecordingHandlers(HandlerResult(200, {"consumed": True}))
        self.nonces = MemoryNonces()
        self.savepoints = 0
        self.port = port or FakePort(plans or {"d-1": _SERVING}, marker)
        rig = self

        @contextmanager
        def savepoint(db: Any) -> Any:
            rig.savepoints += 1
            yield

        handlers = LeaseHandlers(
            inner=self.inner,
            port=self.port,
            store_factory=lambda db: self.store,
            savepoint=savepoint,
        )
        runtime = build_runtime(
            directory=StaticDirectory(record(public_key_b64u=_PUBLIC)),
            response_seed=_RESPONSE_SEED,
            nonces=self.nonces,
            handlers=handlers,
        )
        self.client = client_for(runtime)
        self._n = 0

    def call(self, method: str, route: str, body: Any = None) -> Any:
        self._n += 1
        path = f"{BASE}/targets/{TARGET}/{route}"
        raw = b"" if body is None else json.dumps(body).encode()
        headers = request_headers(
            _SEED_B64U,
            method=method,
            path=path,
            body=raw,
            nonce=f"{self._n:032x}",
        )
        return send(self.client, method=method, path=path, headers=headers, body=raw)


def _acquire(rig: Rig, ttl: Any, dispatch: str = "d-1") -> Any:
    return rig.call(
        "POST", "lease/acquire", {"dispatch_id": dispatch, "ttl_seconds": ttl}
    )


# ── acquire ─────────────────────────────────────────────────────────────────


def test_acquire_takes_the_host_and_principal_from_the_authenticated_target() -> None:
    rig = Rig()
    response = _acquire(rig, 600)
    assert response.status_code == 200
    body = response.json()
    assert body["lease_id"] == _LEASE
    assert body["expires_at"] == "2026-11-22T10:10:00Z"
    assert body["store_now"] == STORE_NOW  # the router's own CP-time stamp
    (name, kw), *rest = rig.store.calls
    assert (name, rest) == ("acquire", [])
    assert kw == {
        "target_ref": TARGET,
        "host_id": "host-a",  # the target ref's third segment, never a request field
        "dispatch_run": "d-1",
        "ttl_seconds": 600,
        "principal_ref": "target-credential:cred-0001",
        "reconcile_marker": None,
    }


@pytest.mark.parametrize(
    "extra",
    [{"host_id": "host-b"}, {"principal_ref": "x"}, {"reconcile_marker": _MARKER}],
)
def test_a_request_cannot_name_a_host_a_principal_or_a_marker(extra: Any) -> None:
    rig = Rig()
    body = {"dispatch_id": "d-1", "ttl_seconds": 600, **extra}
    response = rig.call("POST", "lease/acquire", body)
    assert response.status_code == 400
    assert response.json()["error"] == "bad_body"
    assert rig.store.calls == []


def test_the_reconcile_marker_comes_only_from_the_controls_issued_marker() -> None:
    rig = Rig(marker=_MARKER)
    assert _acquire(rig, 600).status_code == 200
    assert rig.store.calls[0][1]["reconcile_marker"] == _MARKER


def test_a_job_plan_is_leased_for_its_timeout_plus_120_up_to_the_ceiling() -> None:
    rig = Rig({"d-1": _JOB})  # timeout 600 -> 720 .. 900
    for ttl, status in ((719, 400), (720, 200), (900, 200), (901, 400)):
        response = _acquire(rig, ttl)
        assert response.status_code == status, ttl
        if status == 400:
            body = response.json()
            assert body["error"] == "lease-ttl-invalid"
            assert (body["min_ttl"], body["max_ttl"]) == (720, 900)


def test_a_serving_plan_has_no_900_second_cap() -> None:
    rig = Rig({"d-1": _SERVING})  # plan ttl 1800
    assert _acquire(rig, 1800).status_code == 200
    assert _acquire(rig, 1801).status_code == 400
    big = Rig({"d-1": LeasePlan("deploy", None, 3600, 900)})
    assert _acquire(big, 3600).status_code == 200


def test_a_job_plan_that_does_not_fit_the_ceiling_is_not_leasable() -> None:
    rig = Rig({"d-1": LeasePlan("run_job", {"timeout_seconds": 840}, 900, 900)})
    response = _acquire(rig, 900)
    assert response.status_code == 422
    assert response.json()["reason"] == "job-timeout-out-of-bounds"
    assert rig.store.calls == []


def test_an_unknown_dispatch_or_another_targets_is_404_and_asks_for_this_target() -> (
    None
):
    rig = Rig({"d-1": _SERVING})
    response = _acquire(rig, 600, dispatch="d-2")
    assert response.status_code == 404
    assert response.json()["error"] == "unknown_dispatch"
    assert rig.port.asked == [(TARGET, "d-2")]
    assert rig.store.calls == []


def test_an_unconfigured_lease_port_fails_closed() -> None:
    rig = Rig(port=UnconfiguredLeasePort())
    assert _acquire(rig, 600).status_code == 404
    assert rig.store.calls == []


@pytest.mark.parametrize("ttl", [None, "600", 600.0, True, -1, 0])
def test_a_ttl_that_is_not_an_int_in_the_window_is_refused(ttl: Any) -> None:
    rig = Rig()
    assert _acquire(rig, ttl).status_code == 400
    assert rig.store.calls == []


# ── refusals answer typed, and the nonce still commits ───────────────────────


@pytest.mark.parametrize(
    ("code", "status"),
    [
        ("lease-held-by-another-run", 409),
        ("lease-host-mutated", 409),
        ("lease-expired", 409),
        ("lease-foreign-run", 409),
        ("lease-already-released", 409),
        ("release-not-this-lease", 403),
        ("lease-role-unbound", 404),
        ("host-mutated-required", 400),
    ],
)
def test_a_store_refusal_is_a_typed_signed_answer_and_the_nonce_is_spent(
    code: str, status: int
) -> None:
    rig = Rig()
    rig.store.refuse = code
    response = _acquire(rig, 600)
    assert response.status_code == status
    assert response.json()["error"] == code
    assert "X-Dotmac-Response-Signature" in response.headers
    assert len(rig.nonces.spent) == 1
    assert rig.savepoints == 1


def test_a_store_fault_is_not_a_typed_answer() -> None:
    """Unreachable or an unmapped error rolls the whole request back: the router
    gives the caller an unsigned retryable fault and the nonce is NOT spent for it."""
    rig = Rig()
    rig.store.fault = True
    with pytest.raises(DeployLeaseRefused):
        _acquire(rig, 600)


def test_every_mapped_refusal_code_is_in_the_closed_set() -> None:
    from vendor_cp.deployment import deploy_lease_handlers as h

    assert set(h._STATUS) <= REFUSAL_CODES
    assert refusal_http_status("store-error") is None
    assert refusal_http_status("store-unreachable") is None


# ── covers, release, standing ───────────────────────────────────────────────


def test_covers_and_release_carry_the_run_and_the_principal() -> None:
    rig = Rig()
    covered = rig.call(
        "POST", "lease/covers", {"lease_id": _LEASE, "dispatch_id": "d-1"}
    )
    assert covered.status_code == 200 and covered.json()["covered"] is True
    released = rig.call(
        "POST",
        "lease/release",
        {"lease_id": _LEASE, "dispatch_id": "d-1", "host_mutated": True},
    )
    assert released.status_code == 200
    assert released.json()["released_at"] == "2026-11-22T10:00:00Z"
    assert [n for n, _ in rig.store.calls] == ["covers", "release"]
    assert rig.store.calls[1][1] == {
        "lease_id": _LEASE,
        "dispatch_run": "d-1",
        "principal_ref": "target-credential:cred-0001",
        "host_mutated": True,
    }


@pytest.mark.parametrize("mutated", [1, 0, "true", None])
def test_release_needs_a_real_bool(mutated: Any) -> None:
    rig = Rig()
    response = rig.call(
        "POST",
        "lease/release",
        {"lease_id": _LEASE, "dispatch_id": "d-1", "host_mutated": mutated},
    )
    assert response.status_code == 400
    assert rig.store.calls == []


@pytest.mark.parametrize("route", ["lease/covers", "lease/release"])
def test_covers_and_release_refuse_a_dispatch_that_is_not_this_targets(
    route: str,
) -> None:
    rig = Rig({"d-1": _SERVING})
    body: dict[str, Any] = {"lease_id": _LEASE, "dispatch_id": "d-9"}
    if route == "lease/release":
        body["host_mutated"] = False
    response = rig.call("POST", route, body)
    assert response.status_code == 404
    assert rig.store.calls == []


def test_a_malformed_lease_id_is_refused_before_the_store() -> None:
    rig = Rig()
    response = rig.call(
        "POST", "lease/covers", {"lease_id": "not-a-uuid", "dispatch_id": "d-1"}
    )
    assert response.status_code == 400
    assert rig.store.calls == []


def test_standing_reads_the_targets_own_host() -> None:
    rig = Rig()
    response = rig.call("GET", "lease/standing")
    assert response.status_code == 200
    assert response.json()["standing"] == "held"
    assert rig.store.calls == [("standing", {"host_id": "host-a"})]


def test_standing_of_a_never_leased_host_is_none_not_an_error() -> None:
    rig = Rig()
    rig.store.refuse = "lease-host-unknown"
    response = rig.call("GET", "lease/standing")
    assert response.status_code == 200
    assert response.json()["standing"] == "none"


def test_standing_of_a_host_held_by_the_rehearsal_class_is_a_conflict() -> None:
    rig = Rig()
    rig.store.refuse = "lease-host-mutated"
    assert rig.call("GET", "lease/standing").status_code == 409


# ── covers-in-consume ───────────────────────────────────────────────────────


def test_consume_requires_covering_lease() -> None:
    rig = Rig()
    body = {"lease_id": _LEASE, "dispatch_id": "d-1", "resolution_id": "r"}
    ok = rig.call("POST", "consume", body)
    assert ok.status_code == 200 and ok.json()["consumed"] is True
    assert rig.store.calls == [("covers", {"lease_id": _LEASE, "dispatch_run": "d-1"})]
    assert len(rig.inner.calls) == 1  # the wrapped consume ran, after the cover

    for refusal in (
        "lease-expired",
        "lease-foreign-run",
        "lease-role-unbound",
        "lease-already-released",
    ):
        rig = Rig()
        rig.store.refuse = refusal
        refused = rig.call("POST", "consume", body)
        assert refused.status_code == 409, refusal
        assert refused.json()["error"] == "no_covering_lease"
        assert refused.json()["reason"] == refusal
        assert rig.inner.calls == [], refusal  # consumption never reached
        assert len(rig.nonces.spent) == 1  # only the nonce committed


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"dispatch_id": "d-1"},
        {"lease_id": _LEASE},
        {"lease_id": "nope", "dispatch_id": "d-1"},
        {"lease_id": None, "dispatch_id": "d-1"},
    ],
)
def test_consume_without_a_named_lease_is_refused_no_covering_lease(
    payload: Any,
) -> None:
    rig = Rig()
    response = rig.call("POST", "consume", payload)
    assert response.status_code == 409
    assert response.json()["error"] == "no_covering_lease"
    assert rig.inner.calls == [] and rig.store.calls == []


def test_a_store_fault_in_consume_is_not_a_covering_lease() -> None:
    rig = Rig()
    rig.store.fault = True
    with pytest.raises(DeployLeaseRefused):
        rig.call("POST", "consume", {"lease_id": _LEASE, "dispatch_id": "d-1"})
    assert rig.inner.calls == []


@pytest.mark.parametrize(
    ("method", "route"),
    [
        ("GET", "materials"),
        ("POST", "observations"),
        ("POST", "resolve"),
        ("GET", "committed/d-1"),
    ],
)
def test_every_other_route_is_the_wrapped_handlers_and_needs_no_lease(
    method: str, route: str
) -> None:
    rig = Rig()
    body = None if method == "GET" else {"x": 1}
    response = rig.call(method, route, body)
    assert response.status_code == 200
    assert len(rig.inner.calls) == 1
    assert rig.store.calls == []
