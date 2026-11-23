"""WP5c: the lease endpoints, and covers-in-consume, over the REAL target-API router.

The router (authentication, replay, response signing) and the consume service are
lane 5b's, driven over HTTP exactly as `test_target_api_consumption.py` drives them.
The store is a fake with the same interface as `DeployLeaseStore` (its SQL is proven
on a real PG16 in `tests/migration/test_deploy_lease.py`); the `LeasePort` is a fake
of Control's pending-dispatch source. What is proven here is the handlers' own
decisions: which TTL a plan admits, that the host, principal and run come from the
authenticated target and never the request, that the reconcile marker cannot be
supplied by a caller, that a refusal answers typed while the nonce still commits,
and that `consume` is impossible without a covering lease.

Shapes follow architect ruling Q-c/4 (Control's `target_api_v2` is the authority once
it lands): acquire `{dispatch_run, ttl_seconds}` -> `{lease_id, ttl_seconds}`; covers
`{lease_id, dispatch_run}` -> `{covers}`; renew `{lease_id, dispatch_run}` ->
`{lease_id, ttl_seconds}`; release `{lease_id, host_mutated}` -> `{released, replay}`;
standing -> `{standing}`; a missing reconcile marker is a signed 409
`reconcile_marker_required`. `lease/renew` is not a route of the pinned v1 mirror, so
renew is driven through `LeaseHandlers.handle` with a hand-built authenticated call
until the v2 mirror is vendored.

Named rows: `test_consume_requires_covering_lease_through_the_deploy_class` (the
covers-in-consume wiring), the job/serving grant rules, and the server half of
`test_agent_stops_on_lease_refusal`.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from dotmac_kernel.testing import create_test_engine, isolated_session
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
    DeployRelease,
    DeployRenewal,
    DeployStanding,
)
from vendor_cp.deployment.deploy_lease_consume import LeaseCoveringBackend
from vendor_cp.deployment.deploy_lease_handlers import (
    LeaseHandlers,
    LeasePlan,
    UnconfiguredLeasePort,
    refusal_http_status,
)
from vendor_cp.deployment.lease_store import REFUSAL_CODES
from vendor_cp.deployment.target_api import contract as c
from vendor_cp.deployment.target_api.auth import AuthenticatedCall, TargetPrincipal
from vendor_cp.deployment.target_api.consumption import (
    ConsumptionService,
    MaterialsHandler,
    ObservationHandler,
    Resolution,
    TargetApiHandlers,
)
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
_RUN = f"{TARGET}#d-1"
_MARKER = "sha256:" + "a" * 64
_SERVING = LeasePlan("deploy", None, 600, 10800)
_JOB = LeasePlan("run_job", {"timeout_seconds": 600}, 720, 720)


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
        self.replay: bool = False

    def _go(self, name: str, **kw: Any) -> None:
        self.calls.append((name, kw))
        if self.fault:
            raise DeployLeaseRefused("store-unreachable")
        if self.refuse:
            raise DeployLeaseRefused(self.refuse)

    def acquire(self, **kw: Any) -> DeployLease:
        self._go("acquire", **kw)
        ttl = kw["ttl_seconds"]
        return DeployLease(UUID(_LEASE), ttl, _NOW, _NOW + timedelta(seconds=ttl), _NOW)

    def covers(self, **kw: Any) -> datetime:
        self._go("covers", **kw)
        return _NOW

    def renew(self, **kw: Any) -> DeployRenewal:
        self._go("renew", **kw)
        return DeployRenewal(UUID(_LEASE), 120, _NOW + timedelta(seconds=120), _NOW)

    def release(self, **kw: Any) -> DeployRelease:
        self._go("release", **kw)
        return DeployRelease(_NOW, self.replay)

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
        "POST", "lease/acquire", {"dispatch_run": dispatch, "ttl_seconds": ttl}
    )


# ── acquire ─────────────────────────────────────────────────────────────────


def test_acquire_takes_the_host_and_principal_from_the_authenticated_target() -> None:
    rig = Rig()
    response = _acquire(rig, 600)
    assert response.status_code == 200
    body = response.json()
    assert body["lease_id"] == _LEASE and body["ttl_seconds"] == 600
    assert body["store_now"] == STORE_NOW  # the router's own CP-time stamp
    (name, kw), *rest = rig.store.calls
    assert (name, rest) == ("acquire", [])
    assert kw == {
        "target_ref": TARGET,
        "host_id": "host-a",  # the target ref's third segment, never a request field
        "dispatch_run": _RUN,  # qualified by the authenticated target
        "ttl_seconds": 600,
        "max_seconds": 10800,  # the plan's total
        "principal_ref": "target-credential:cred-0001",
        "reconcile_marker": None,
    }


@pytest.mark.parametrize(
    "extra",
    [{"host_id": "host-b"}, {"principal_ref": "x"}, {"reconcile_marker": _MARKER}],
)
def test_a_request_cannot_name_a_host_a_principal_or_a_marker(extra: Any) -> None:
    rig = Rig()
    body = {"dispatch_run": "d-1", "ttl_seconds": 600, **extra}
    response = rig.call("POST", "lease/acquire", body)
    assert response.status_code == 400
    assert response.json()["error"] == "bad_body"
    assert rig.store.calls == []


def test_the_reconcile_marker_comes_only_from_the_controls_issued_marker() -> None:
    rig = Rig(marker=_MARKER)
    assert _acquire(rig, 600).status_code == 200
    assert rig.store.calls[0][1]["reconcile_marker"] == _MARKER


def test_a_missing_reconcile_marker_is_a_signed_409_reconcile_marker_required() -> None:
    rig = Rig()
    rig.store.refuse = "reconcile-marker-required"
    response = _acquire(rig, 600)
    assert response.status_code == 409
    assert response.json()["error"] == "reconcile_marker_required"
    assert "X-Dotmac-Response-Signature" in response.headers
    assert len(rig.nonces.spent) == 1  # the nonce still committed


def test_a_job_plan_is_granted_exactly_timeout_plus_120() -> None:
    rig = Rig({"d-1": _JOB})  # timeout 600 -> ttl = max = 720
    for ttl, status in ((719, 400), (720, 200), (721, 400)):
        response = _acquire(rig, ttl)
        assert response.status_code == status, ttl
        if status == 400:
            body = response.json()
            assert body["error"] == "lease_ttl_invalid"
            assert (body["min_ttl"], body["max_ttl"]) == (720, 720)
    assert rig.store.calls[0][1]["max_seconds"] == 720


def test_a_serving_plan_is_granted_120_to_its_ttl_with_a_larger_total() -> None:
    rig = Rig({"d-1": _SERVING})  # ttl 600, total 10800
    assert _acquire(rig, 120).status_code == 200
    assert _acquire(rig, 600).status_code == 200
    assert _acquire(rig, 119).status_code == 400
    assert _acquire(rig, 601).status_code == 400  # per-grant, not the total


def test_a_job_plan_that_does_not_fit_is_not_leasable() -> None:
    rig = Rig({"d-1": LeasePlan("run_job", {"timeout_seconds": 840}, 900, 900)})
    response = _acquire(rig, 900)
    assert response.status_code == 422
    assert response.json()["reason"] == "job-lease-does-not-fit"
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
    ("code", "status", "name"),
    [
        ("lease-held-by-another-run", 409, "lease_held"),
        ("lease-host-mutated", 409, "lease_held"),
        ("reconcile-marker-required", 409, "reconcile_marker_required"),
        ("reprovision-receipt-spent", 409, "reconcile_marker_required"),
        ("lease-role-unbound", 404, "lease_role_unbound"),
    ],
)
def test_a_store_refusal_is_a_typed_signed_answer_and_the_nonce_is_spent(
    code: str, status: int, name: str
) -> None:
    rig = Rig()
    rig.store.refuse = code
    response = _acquire(rig, 600)
    assert response.status_code == status
    assert response.json()["error"] == name
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
    for names in (h._RENEW_NAMES, h._RELEASE_NAMES, h._ACQUIRE_NAMES):
        assert set(names) <= REFUSAL_CODES
        assert {v for v in names.values() if v in h.LEASE_ERRORS} == set(names.values())
    assert refusal_http_status("store-error") is None
    assert refusal_http_status("store-unreachable") is None


# ── covers, release, standing ───────────────────────────────────────────────


def test_covers_answers_true_or_false_and_release_names_only_the_lease() -> None:
    rig = Rig()
    covered = rig.call(
        "POST", "lease/covers", {"lease_id": _LEASE, "dispatch_run": "d-1"}
    )
    assert covered.status_code == 200 and covered.json()["covers"] is True
    released = rig.call(
        "POST", "lease/release", {"lease_id": _LEASE, "host_mutated": True}
    )
    assert released.status_code == 200
    assert (released.json()["released"], released.json()["replay"]) == (True, False)
    assert [n for n, _ in rig.store.calls] == ["covers", "release"]
    assert rig.store.calls[0][1] == {"lease_id": _LEASE, "dispatch_run": _RUN}
    assert rig.store.calls[1][1] == {
        "lease_id": _LEASE,
        "target_ref": TARGET,  # the authenticated target and principal hold it
        "principal_ref": "target-credential:cred-0001",
        "host_mutated": True,
    }


def test_a_second_release_is_a_signed_200_replay() -> None:
    rig = Rig()
    rig.store.replay = True
    response = rig.call(
        "POST", "lease/release", {"lease_id": _LEASE, "host_mutated": False}
    )
    assert response.status_code == 200
    assert response.json()["replay"] is True
    assert "X-Dotmac-Response-Signature" in response.headers


@pytest.mark.parametrize(
    "refusal", ["lease-expired", "lease-foreign-run", "lease-role-unbound"]
)
def test_covers_is_false_not_an_error_when_no_lease_covers(refusal: str) -> None:
    rig = Rig()
    rig.store.refuse = refusal
    response = rig.call(
        "POST", "lease/covers", {"lease_id": _LEASE, "dispatch_run": "d-1"}
    )
    assert response.status_code == 200 and response.json()["covers"] is False
    assert len(rig.nonces.spent) == 1


@pytest.mark.parametrize("mutated", [1, 0, "true", None])
def test_release_needs_a_real_bool(mutated: Any) -> None:
    rig = Rig()
    response = rig.call(
        "POST", "lease/release", {"lease_id": _LEASE, "host_mutated": mutated}
    )
    assert response.status_code == 400
    assert rig.store.calls == []


@pytest.mark.parametrize(
    ("code", "name"),
    [
        ("release-not-this-lease", "lease_not_held"),
        ("lease-role-unbound", "lease_not_held"),
        ("lease-expired", "lease_expired"),
    ],
)
def test_release_refusals_are_the_contracts_signed_409s(code: str, name: str) -> None:
    rig = Rig()
    rig.store.refuse = code
    response = rig.call(
        "POST", "lease/release", {"lease_id": _LEASE, "host_mutated": True}
    )
    assert response.status_code == 409
    assert response.json()["error"] == name


def test_a_lease_id_that_is_not_a_uuid_is_a_lease_nobody_holds() -> None:
    """Never sent to the database; answered as the contract answers an unknown id."""
    rig = Rig()
    covers = rig.call(
        "POST", "lease/covers", {"lease_id": "lease-9999", "dispatch_run": "d-1"}
    )
    assert covers.status_code == 200 and covers.json()["covers"] is False
    release = rig.call(
        "POST", "lease/release", {"lease_id": "lease-9999", "host_mutated": True}
    )
    assert release.status_code == 409
    assert release.json()["error"] == "lease_not_held"
    assert rig.store.calls == []


@pytest.mark.parametrize(
    "body",
    [
        {"lease_id": 7, "dispatch_run": "d-1"},
        {"lease_id": "x"},
        {"lease_id": "x", "dispatch_run": "d-1", "ttl_seconds": 1},
    ],
)
def test_a_body_of_the_wrong_shape_is_a_400(body: Any) -> None:
    rig = Rig()
    assert rig.call("POST", "lease/covers", body).status_code == 400
    assert rig.store.calls == []


def test_standing_reads_the_targets_own_host() -> None:
    rig = Rig()
    response = rig.call("GET", "lease/standing")
    assert response.status_code == 200
    assert response.json()["standing"] == "held"
    assert rig.store.calls == [("standing", {"host_id": "host-a"})]


def test_standing_of_a_never_leased_host_is_free_not_an_error() -> None:
    rig = Rig()
    rig.store.refuse = "lease-host-unknown"
    response = rig.call("GET", "lease/standing")
    assert response.status_code == 200
    assert response.json()["standing"] == "free"


def test_standing_of_a_host_held_by_the_rehearsal_class_is_a_conflict() -> None:
    rig = Rig()
    rig.store.refuse = "lease-host-mutated"
    assert rig.call("GET", "lease/standing").status_code == 409


# ── renew (driven directly: not a route of the pinned v1 mirror) ─────────────


def _renew_call() -> Any:
    coordinates = c.RequestCoordinates(
        method="POST",
        path=f"{BASE}/targets/{TARGET}/lease/renew",
        target_ref=TARGET,
        route="lease/renew",
        dispatch_id=None,
        credential_id="cred-0001",
        issued_at=STORE_NOW,
        nonce="0" * 32,
        signature_b64u="",
        signed_message=b"",
        nonce_ledger_key="cred-0001/" + "0" * 32,
    )
    principal = TargetPrincipal(
        kind="target",
        principal_ref="target-credential:cred-0001",
        target_ref=TARGET,
        credential_id="cred-0001",
    )
    return AuthenticatedCall(
        principal=principal,
        coordinates=coordinates,
        store_now=_NOW,
        store_now_stamp=STORE_NOW,
    )


def _renew_rig() -> tuple[LeaseHandlers, FakeStore]:
    store = FakeStore()

    @contextmanager
    def savepoint(_db: Any) -> Any:
        yield

    handlers = LeaseHandlers(
        inner=RecordingHandlers(),
        port=FakePort({}),
        store_factory=lambda _db: store,
        savepoint=savepoint,
    )
    return handlers, store


def test_renew_returns_the_granted_ttl_for_this_targets_run() -> None:
    handlers, store = _renew_rig()
    result = handlers.handle(
        _renew_call(), None, {"lease_id": _LEASE, "dispatch_run": "d-1"}
    )
    assert result.status == 200
    assert dict(result.body) == {"lease_id": _LEASE, "ttl_seconds": 120}
    assert store.calls == [("renew", {"lease_id": _LEASE, "dispatch_run": _RUN})]


@pytest.mark.parametrize(
    ("code", "name"),
    [
        ("lease-role-unbound", "lease_not_held"),
        ("lease-foreign-run", "lease_not_held"),
        ("lease-already-released", "lease_not_held"),
        ("lease-expired", "lease_expired"),
        ("lease-max-reached", "lease_max_reached"),
    ],
)
def test_renew_refusals_are_the_contracts_three_signed_names(
    code: str, name: str
) -> None:
    handlers, store = _renew_rig()
    store.refuse = code
    result = handlers.handle(
        _renew_call(), None, {"lease_id": _LEASE, "dispatch_run": "d-1"}
    )
    assert result.status == 409
    assert result.body["error"] == name


def test_renew_needs_a_lease_and_a_run_and_nothing_else() -> None:
    handlers, store = _renew_rig()
    for body in (
        {"lease_id": _LEASE},
        {"lease_id": _LEASE, "dispatch_run": "d-1", "ttl_seconds": 999},
        None,
    ):
        assert handlers.handle(_renew_call(), None, body).status == 400
    unknown = handlers.handle(
        _renew_call(), None, {"lease_id": "lease-9999", "dispatch_run": "d-1"}
    )
    assert (unknown.status, unknown.body["error"]) == (409, "lease_not_held")
    assert store.calls == []


@pytest.mark.parametrize(
    ("method", "route"),
    [
        ("GET", "materials"),
        ("POST", "observations"),
        ("POST", "resolve"),
        ("POST", "consume"),
        ("GET", "committed/d-1"),
    ],
)
def test_every_other_route_is_the_wrapped_handlers_and_needs_no_lease_here(
    method: str, route: str
) -> None:
    rig = Rig()
    body = None if method == "GET" else {"x": 1}
    response = rig.call(method, route, body)
    assert response.status_code == 200
    assert len(rig.inner.calls) == 1
    assert rig.store.calls == []


# ── covers-in-consume, through 5b's real consume service ─────────────────────


class _Backend:
    """5b's `ConsumptionBackend` stand-in: resolve, re-verify and the finalizer."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def resolve(self, db: Any, *, request: Any, store_now: Any) -> Resolution:
        self.calls.append("resolve")
        return Resolution(
            dispatch_id=str(request["dispatch_id"]),
            target_ref=TARGET,
            resolution_id="res-1",
            context={"host": "host-a"},
        )

    def reverify_attestation(self, db: Any, *, resolution: Any, request: Any) -> None:
        self.calls.append("reverify")

    def covers_lease(self, db: Any, **kw: Any) -> bool:
        raise AssertionError("the deploy class must answer this, not the inner port")

    def commit_consumption(
        self, db: Any, *, resolution: Any, request: Any, store_now: Any
    ) -> Any:
        self.calls.append("commit_consumption")
        return {"consumption_ref": f"control-dispatch:{resolution.dispatch_id}"}


@pytest.fixture
def db() -> Iterator[Any]:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as session:
            yield session
    finally:
        engine.dispose()


def _consume_rig(db: Any) -> tuple[Any, FakeStore, _Backend, Any]:
    store, inner = FakeStore(), _Backend()

    @contextmanager
    def savepoint(_db: Any) -> Any:
        yield

    backend = LeaseCoveringBackend(
        inner, store_factory=lambda _db: store, savepoint=savepoint
    )
    handlers = TargetApiHandlers(
        consumption=ConsumptionService(backend),
        materials=MaterialsHandler(None),
        observations=ObservationHandler(None),
    )
    runtime = build_runtime(
        directory=StaticDirectory(record(public_key_b64u=_PUBLIC)),
        response_seed=_RESPONSE_SEED,
        handlers=handlers,
        session=db,
    )
    client = client_for(runtime)
    counter = iter(range(1, 1000))

    def consume(body: dict[str, Any]) -> Any:
        raw = json.dumps(body).encode()
        path = f"{BASE}/targets/{TARGET}/consume"
        return send(
            client,
            method="POST",
            path=path,
            body=raw,
            headers=request_headers(
                _SEED_B64U,
                method="POST",
                path=path,
                body=raw,
                nonce=f"{next(counter):032x}",
            ),
        )

    return consume, store, inner, backend


_CONSUME = {"dispatch_id": "d-1", "resolution_id": "res-1", "lease_id": _LEASE}


def test_consume_requires_covering_lease_through_the_deploy_class(db: Any) -> None:
    consume, store, inner, _ = _consume_rig(db)
    ok = consume(_CONSUME)
    assert ok.status_code == 200
    assert store.calls == [("covers", {"lease_id": _LEASE, "dispatch_run": _RUN})]
    assert inner.calls == ["resolve", "reverify", "commit_consumption"]

    for refusal in ("lease-expired", "lease-foreign-run", "lease-role-unbound"):
        consume, store, inner, _ = _consume_rig(db)
        store.refuse = refusal
        body = dict(_CONSUME, dispatch_id=f"d-{refusal}")
        refused = consume(body)
        assert refused.status_code == 409, refusal
        assert refused.json()["error"] == "no_covering_lease"
        assert "commit_consumption" not in inner.calls, refusal  # never consumed
        # and nothing was recorded: a later covered attempt consumes
        store.refuse = None
        assert consume(body).status_code == 200


def test_the_run_is_built_from_the_dispatchs_target_never_the_request(
    db: Any,
) -> None:
    consume, store, _, _ = _consume_rig(db)
    consume(dict(_CONSUME, target_ref="other/env/host-z", dispatch_run="x"))
    assert store.calls[0][1]["dispatch_run"] == _RUN


@pytest.mark.parametrize("lease_id", ["l-1", "", "nope", "11111111-1111-4111-8111"])
def test_a_lease_id_that_is_not_a_uuid_is_not_a_covering_lease(
    db: Any, lease_id: str
) -> None:
    consume, store, inner, _ = _consume_rig(db)
    response = consume(dict(_CONSUME, lease_id=lease_id))
    assert response.status_code in (400, 409)
    assert store.calls == []
    assert "commit_consumption" not in inner.calls


def test_a_store_fault_in_covers_is_not_a_missing_lease(db: Any) -> None:
    consume, store, inner, _ = _consume_rig(db)
    store.fault = True
    with pytest.raises(DeployLeaseRefused):
        consume(_CONSUME)
    assert "commit_consumption" not in inner.calls


def test_the_covering_backend_delegates_everything_else(db: Any) -> None:
    _, _, inner, backend = _consume_rig(db)
    res = backend.resolve(db, request={"dispatch_id": "d-1"}, store_now=_NOW)
    backend.reverify_attestation(db, resolution=res, request={})
    backend.commit_consumption(db, resolution=res, request={}, store_now=_NOW)
    assert inner.calls == ["resolve", "reverify", "commit_consumption"]
