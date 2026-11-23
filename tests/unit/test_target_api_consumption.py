"""Consumption endpoints (DESIGN-rev3 2.6.1): the section 2.9 Bindings/CP rows.

The router is the real one and the ledger is the Kernel's (`execute_once_platform`
on the in-memory SQLite lane; the concurrent proof is the PostgreSQL test in
`tests/migration/test_target_consume_concurrency.py`). `ConsumptionBackend` is the
port Control and Foundation fill; here a fake stands behind it so the endpoint's
OWN decisions (ownership, replay, ordering, refusals) are what is under test.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from datetime import datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from dotmac_kernel.testing import create_test_engine, isolated_session
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from target_api_support import (
    BASE,
    STORE_NOW,
    TARGET,
    SeedSigner,
    StaticDirectory,
    b64u,
    build_runtime,
    client_for,
    record,
    request_headers,
    send,
    stamp,
    vectors,
)

from vendor_cp.deployment.target_api import contract as c
from vendor_cp.deployment.target_api.client import (
    AlreadyConsumedError,
    ConsumptionClientError,
    ControlConsumptionClient,
    ControlRefusedError,
    DatabaseReachRefused,
    TransportResponse,
    refuse_database_environment,
)
from vendor_cp.deployment.target_api.consumption import (
    ConsumptionRefused,
    ConsumptionService,
    MaterialsHandler,
    ObservationHandler,
    Resolution,
    TargetApiHandlers,
    UnwiredBackend,
)

V = vectors()
_POP_SEED = bytes(range(1, 33))
_RESPONSE_SEED = b64u(bytes(range(100, 132)))
_POP_PUB = b64u(
    Ed25519PrivateKey.from_private_bytes(_POP_SEED)
    .public_key()
    .public_bytes(Encoding.Raw, PublicFormat.Raw)
)


class FakeBackend:
    def __init__(
        self,
        *,
        target_ref: str = TARGET,
        resolution_id: str = "res-1",
        lease_ok: bool = True,
        reverify: ConsumptionRefused | None = None,
        finalize: ConsumptionRefused | None = None,
        resolve_refusal: ConsumptionRefused | None = None,
    ) -> None:
        self.target_ref = target_ref
        self.resolution_id = resolution_id
        self.lease_ok = lease_ok
        self.reverify = reverify
        self.finalize_refusal = finalize
        self.resolve_refusal = resolve_refusal
        self.calls: list[str] = []
        self.finalized = 0

    def resolve(
        self, db: Session, *, request: Mapping[str, object], store_now: datetime
    ) -> Resolution:
        self.calls.append("resolve")
        if self.resolve_refusal:
            raise self.resolve_refusal
        return Resolution(
            dispatch_id=str(request["dispatch_id"]),
            target_ref=self.target_ref,
            resolution_id=self.resolution_id,
            context={"host": "host-a"},
        )

    def reverify_attestation(
        self, db: Session, *, resolution: Resolution, request: Mapping[str, object]
    ) -> None:
        self.calls.append("reverify")
        if self.reverify:
            raise self.reverify

    def covers_lease(
        self,
        db: Session,
        *,
        target_ref: str,
        dispatch_id: str,
        lease_id: str,
        store_now: datetime,
    ) -> bool:
        self.calls.append("covers")
        return self.lease_ok

    def finalize(
        self,
        db: Session,
        *,
        resolution: Resolution,
        request: Mapping[str, object],
        store_now: datetime,
    ) -> Mapping[str, object]:
        self.calls.append("finalize")
        if self.finalize_refusal:
            raise self.finalize_refusal
        self.finalized += 1
        return {"consumption_ref": f"control-dispatch:{resolution.dispatch_id}"}


class Rig:
    def __init__(self, backend: Any, session: Session) -> None:
        self.backend = backend
        directory = StaticDirectory(record(public_key_b64u=_POP_PUB))
        self.runtime = build_runtime(
            directory=directory,
            response_seed=_RESPONSE_SEED,
            handlers=TargetApiHandlers(
                consumption=ConsumptionService(backend),
                materials=MaterialsHandler(None),
                observations=ObservationHandler(None),
            ),
            session=session,
        )
        self.http = client_for(self.runtime)
        self._n = 0

    def nonce(self) -> str:
        self._n += 1
        return f"{self._n:032x}"

    def post(self, route: str, body: dict[str, Any]) -> Any:
        raw = json.dumps(body).encode()
        path = f"{BASE}/targets/{TARGET}/{route}"
        return send(
            self.http,
            method="POST",
            path=path,
            body=raw,
            headers=request_headers(
                _POP_SEED_B64U, method="POST", path=path, body=raw, nonce=self.nonce()
            ),
        )

    def get(self, route: str) -> Any:
        path = f"{BASE}/targets/{TARGET}/{route}"
        return send(
            self.http,
            method="GET",
            path=path,
            headers=request_headers(
                _POP_SEED_B64U, method="GET", path=path, nonce=self.nonce()
            ),
        )


_POP_SEED_B64U = b64u(_POP_SEED)
_CONSUME = {"dispatch_id": "dispatch-0001", "resolution_id": "res-1", "lease_id": "l-1"}


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as session:
            yield session
    finally:
        engine.dispose()


def test_resolve_returns_the_context_for_the_principals_own_dispatch(
    db: Session,
) -> None:
    rig = Rig(FakeBackend(), db)
    response = rig.post("resolve", {"dispatch_id": "dispatch-0001"})
    assert response.status_code == 200
    body = response.json()
    assert body["resolution_id"] == "res-1"
    assert body["context"] == {"host": "host-a"}
    assert body["store_now"] == STORE_NOW


def test_consume_commits_once_and_returns_the_marker(db: Session) -> None:
    backend = FakeBackend()
    rig = Rig(backend, db)
    response = rig.post("consume", _CONSUME)
    assert response.status_code == 200
    assert response.json()["committed"] == {
        "consumption_ref": "control-dispatch:dispatch-0001"
    }
    # the design's order: re-resolve, re-verify, covers, then the composer
    assert backend.calls == ["resolve", "reverify", "covers", "finalize"]


def test_second_consume_409_marker(db: Session) -> None:
    backend = FakeBackend()
    rig = Rig(backend, db)
    first = rig.post("consume", _CONSUME)
    second = rig.post("consume", _CONSUME)
    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json()["error"] == "already_consumed"
    assert second.json()["committed"] == first.json()["committed"]
    assert backend.finalized == 1
    # the replay never touched Control's resolve, which may no longer answer
    assert backend.calls.count("resolve") == 1


def test_consume_requires_covering_lease(db: Session) -> None:
    backend = FakeBackend(lease_ok=False)
    rig = Rig(backend, db)
    response = rig.post("consume", _CONSUME)
    assert response.status_code == 409
    assert response.json()["error"] == "no_covering_lease"
    assert "finalize" not in backend.calls
    assert backend.finalized == 0
    # and nothing was recorded: a later covered attempt consumes
    backend.lease_ok = True
    assert rig.post("consume", _CONSUME).status_code == 200


def test_consume_refuses_a_changed_resolution(db: Session) -> None:
    rig = Rig(FakeBackend(resolution_id="res-2"), db)
    response = rig.post("consume", _CONSUME)
    assert response.status_code == 409
    assert response.json()["error"] == "resolution_changed"
    assert rig.backend.finalized == 0


def test_consume_refuses_when_the_attestation_pair_does_not_reverify(
    db: Session,
) -> None:
    rig = Rig(FakeBackend(reverify=ConsumptionRefused("attestation_invalid")), db)
    response = rig.post("consume", _CONSUME)
    assert response.status_code == 409
    assert response.json()["error"] == "attestation_invalid"
    assert "covers" not in rig.backend.calls
    assert rig.backend.finalized == 0


@pytest.mark.parametrize(
    "code", ["approval_required", "rollout_superseded", "dispatch_expired"]
)
def test_consume_surfaces_the_finalizers_refusals_and_records_nothing(
    db: Session, code: str
) -> None:
    backend = FakeBackend(finalize=ConsumptionRefused(code))
    rig = Rig(backend, db)
    response = rig.post("consume", _CONSUME)
    assert response.status_code == 409
    assert response.json()["error"] == code
    # no ledger row: after the refusal clears, the dispatch consumes
    backend.finalize_refusal = None
    assert rig.post("consume", _CONSUME).status_code == 200


def test_another_targets_dispatch_is_refused(db: Session) -> None:
    rig = Rig(FakeBackend(target_ref="dotmac-erp-v2/production/host-b"), db)
    for route, body in (
        ("resolve", {"dispatch_id": "dispatch-0001"}),
        ("consume", _CONSUME),
    ):
        response = rig.post(route, body)
        assert response.status_code == 403, route
        assert response.json()["error"] == "dispatch_not_for_target"
    assert rig.backend.finalized == 0


def test_another_targets_committed_marker_is_not_readable_or_replayed(
    db: Session,
) -> None:
    owner = Rig(FakeBackend(), db)
    assert owner.post("consume", _CONSUME).status_code == 200
    # a principal of ANOTHER target, same database
    other_target = "dotmac-erp-v2/production/host-b"
    directory = StaticDirectory(
        record(public_key_b64u=_POP_PUB, target_ref=other_target)
    )
    runtime = build_runtime(
        directory=directory,
        response_seed=_RESPONSE_SEED,
        handlers=TargetApiHandlers(
            consumption=ConsumptionService(FakeBackend(target_ref=other_target)),
            materials=MaterialsHandler(None),
            observations=ObservationHandler(None),
        ),
        session=db,
    )
    client = client_for(runtime)
    path = f"{BASE}/targets/{other_target}/committed/dispatch-0001"
    response = send(
        client,
        method="GET",
        path=path,
        headers=request_headers(
            _POP_SEED_B64U,
            method="GET",
            path=path,
            target_ref=other_target,
            nonce=f"{99:032x}",
        ),
    )
    assert response.status_code == 403
    assert response.json()["error"] == "dispatch_not_for_target"


def test_an_unwired_backend_refuses_closed(db: Session) -> None:
    rig = Rig(UnwiredBackend(), db)
    for route, body in (
        ("resolve", {"dispatch_id": "dispatch-0001"}),
        ("consume", _CONSUME),
    ):
        response = rig.post(route, body)
        assert response.status_code == 503
        assert response.json()["error"] == "consumption_not_composed"


def test_consume_needs_a_well_formed_request(db: Session) -> None:
    rig = Rig(FakeBackend(), db)
    for body in (
        {},
        {"dispatch_id": "dispatch-0001"},
        {**_CONSUME, "dispatch_id": "../x"},
        {**_CONSUME, "lease_id": ""},
    ):
        response = rig.post("consume", body)
        assert response.status_code == 400, body
        assert response.json()["error"] == "bad_request"
    response = send(
        rig.http,
        method="POST",
        path=f"{BASE}/targets/{TARGET}/consume",
        body=b"[]",
        headers=request_headers(
            _POP_SEED_B64U,
            method="POST",
            path=f"{BASE}/targets/{TARGET}/consume",
            body=b"[]",
            nonce=rig.nonce(),
        ),
    )
    assert response.status_code == 400
    assert not rig.backend.calls


def test_lookup_committed_after_crash(db: Session) -> None:
    """The client consumed, lost the answer, asks again: the marker, no re-run."""
    backend = FakeBackend()
    rig = Rig(backend, db)
    assert rig.post("consume", _CONSUME).status_code == 200
    client = _client(rig)
    assert client.lookup_committed("dispatch-0001") == {
        "committed": {"consumption_ref": "control-dispatch:dispatch-0001"},
        "store_now": STORE_NOW,
    }
    assert client.lookup_committed("dispatch-9999") is None
    with pytest.raises(AlreadyConsumedError) as caught:
        client.consume(_CONSUME)
    assert caught.value.marker == {"consumption_ref": "control-dispatch:dispatch-0001"}
    assert backend.finalized == 1


# ── The client, against the real router ─────────────────────────────────────


class _LoopbackTransport:
    """The client's transport, answered by the real router through a TestClient."""

    def __init__(self, http: TestClient, *, tamper: Any = None) -> None:
        self._http = http
        self._tamper = tamper

    def request(
        self,
        method: str,
        path: str,
        headers: Any,
        body: bytes,
    ) -> TransportResponse:
        response = self._http.request(method, path, content=body, headers=list(headers))
        answer = TransportResponse(
            response.status_code, list(response.headers.items()), response.content
        )
        return self._tamper(answer) if self._tamper else answer


def _client(
    rig: Rig, *, tamper: Any = None, response_pub: str | None = None
) -> ControlConsumptionClient:
    return ControlConsumptionClient(
        transport=_LoopbackTransport(rig.http, tamper=tamper),
        target_ref=TARGET,
        credential_id="cred-0001",
        pop_seed=_POP_SEED,
        response_public_key_b64u=response_pub
        or SeedSigner(_RESPONSE_SEED).public_key_b64u,
        clock=lambda: stamp(STORE_NOW),
        nonce=_Nonces(),
    )


class _Nonces:
    def __init__(self) -> None:
        self.n = 1000

    def __call__(self) -> str:
        self.n += 1
        return f"{self.n:032x}"


def test_client_round_trip_resolve_consume_replay(db: Session) -> None:
    rig = Rig(FakeBackend(), db)
    client = _client(rig)
    resolved = client.resolve({"dispatch_id": "dispatch-0001"})
    assert resolved["resolution_id"] == "res-1"
    committed = client.consume(_CONSUME)
    assert committed["committed"]["consumption_ref"] == "control-dispatch:dispatch-0001"
    with pytest.raises(AlreadyConsumedError):
        client.consume(_CONSUME)
    with pytest.raises(ControlRefusedError) as refused:
        _client(Rig(FakeBackend(lease_ok=False), db)).consume(
            {**_CONSUME, "dispatch_id": "dispatch-0002"}
        )
    assert refused.value.code == "no_covering_lease"


def test_client_refuses_forged_unsigned_and_misbound_responses(db: Session) -> None:
    rig = Rig(FakeBackend(), db)

    def strip(answer: TransportResponse) -> TransportResponse:
        kept = [
            (k, v)
            for k, v in answer.headers
            if k.lower() != c.H_RESPONSE_SIGNATURE.lower()
        ]
        return TransportResponse(answer.status, kept, answer.body)

    def edit(answer: TransportResponse) -> TransportResponse:
        return TransportResponse(
            answer.status, answer.headers, answer.body.replace(b"res-1", b"res-9")
        )

    def unreachable(answer: TransportResponse) -> TransportResponse:
        return TransportResponse(503, [], b"")

    cases = [
        ("response_signature_invalid", strip),
        ("response_signature_invalid", edit),
        ("cp_unreachable", unreachable),
    ]
    for code, tamper in cases:
        with pytest.raises(ConsumptionClientError) as caught:
            _client(rig, tamper=tamper).resolve({"dispatch_id": "dispatch-0001"})
        assert caught.value.code == code
        assert caught.value.retryable is (code == "cp_unreachable")
    # a response signed by some OTHER key
    other = SeedSigner(b64u(bytes(range(40, 72)))).public_key_b64u
    with pytest.raises(ConsumptionClientError) as caught:
        _client(rig, response_pub=other).resolve({"dispatch_id": "dispatch-0001"})
    assert caught.value.code == "response_signature_invalid"


def test_client_refuses_a_published_test_key_as_the_response_key(db: Session) -> None:
    rig = Rig(FakeBackend(), db)
    with pytest.raises(ConsumptionClientError) as caught:
        _client(rig, response_pub=V["keys"]["response"]["public_b64u"])
    assert caught.value.code == "response_key_denied"


def test_client_refuses_a_host_clock_that_disagrees_with_signed_cp_time(
    db: Session,
) -> None:
    rig = Rig(FakeBackend(), db)
    client = ControlConsumptionClient(
        transport=_LoopbackTransport(rig.http),
        target_ref=TARGET,
        credential_id="cred-0001",
        pop_seed=_POP_SEED,
        response_public_key_b64u=SeedSigner(_RESPONSE_SEED).public_key_b64u,
        # issued_at is within 60 s of store_now, so CP accepts the request; the
        # client's clock then reads far from the signed time it is answered with
        clock=_TwoReads(),
        nonce=_Nonces(),
    )
    with pytest.raises(ConsumptionClientError) as caught:
        client.resolve({"dispatch_id": "dispatch-0001"})
    assert caught.value.code == "clock_skew"


class _TwoReads:
    def __init__(self) -> None:
        self.reads = 0

    def __call__(self) -> datetime:
        self.reads += 1
        base = stamp(STORE_NOW)
        return base if self.reads == 1 else base + timedelta(hours=1)


def test_bindings_refuse_any_db_dsn() -> None:
    refuse_database_environment({"HOME": "/x", "CREDENTIALS_DIRECTORY": "/y"})
    for name in (
        "DISPATCH_CONSUMPTION_DATABASE_URL",
        "DATABASE_URL",
        "PLATFORM_DATABASE_URL",
        "LANE3_LEASE_DATABASE_URL",
        "PGHOST",
        "PGPASSWORD",
        "PGSSLMODE",
    ):
        with pytest.raises(DatabaseReachRefused) as caught:
            refuse_database_environment({name: "value-not-to-be-echoed"})
        # names only, never the value
        assert name in str(caught.value)
        assert "value-not-to-be-echoed" not in str(caught.value)


# ── materials ───────────────────────────────────────────────────────────────


class _Materials:
    def __init__(self, pending: Mapping[str, object] | None) -> None:
        self._pending = pending

    def pending(self, db: Any, *, target_ref: str, store_now: datetime) -> Any:
        return self._pending


def _materials_rig(pending: Mapping[str, object] | None, db: Session) -> Rig:
    rig = Rig(FakeBackend(), db)
    rig.runtime = build_runtime(
        directory=StaticDirectory(record(public_key_b64u=_POP_PUB)),
        response_seed=_RESPONSE_SEED,
        handlers=TargetApiHandlers(
            consumption=ConsumptionService(UnwiredBackend()),
            materials=MaterialsHandler(_Materials(pending)),
            observations=ObservationHandler(None),
        ),
        session=db,
    )
    rig.http = client_for(rig.runtime)
    return rig


def test_mirror_materials_vectors() -> None:
    m = V["materials"]
    c.check_materials_shape(m["ok"])
    c.check_materials_shape(m["idle"])
    for row in m["refused"]:
        with pytest.raises(c.TargetApiError):
            c.check_materials_shape(row["document"])
    assert c.plan_snapshot_digest(m["ok"]["plan_snapshot"]) == m["plan_digest"]
    assert [list(r) for r in c.plan_roles(m["ok"]["plan_snapshot"])] == m["plan_roles"]
    assert c.expected_app_image(m["ok"]["plan_snapshot"]) == m["expected_app_image"]
    for row in m["archive_names"]:
        assert c.archive_name(row["service"], row["digest"]) == row["name"]
    assert set(m["always_keys"]) == c.MATERIALS_ALWAYS
    assert set(m["pending_keys"]) == c.MATERIALS_PENDING
    assert set(m["removed_keys"]) == c.MATERIALS_FORBIDDEN_KEYS
    assert set(m["statement_keys"]) == c.STATEMENT_KEYS
    assert m["schema"] == c.MATERIALS_SCHEMA


def test_router_replays_materials_vectors(db: Session) -> None:
    m = V["materials"]
    always = {k: m["ok"][k] for k in m["always_keys"]}
    # the pending document, exactly as the vector holds it
    pending = {k: m["ok"][k] for k in m["pending_keys"]}
    rig = _materials_rig(pending, db)
    response = rig.get("materials")
    assert response.status_code == 200
    assert response.json() == m["ok"]
    assert always["store_now"] == STORE_NOW

    idle = _materials_rig(None, db).get("materials")
    assert idle.status_code == 200
    assert idle.json() == m["idle"]

    # What the producer would emit is checked before it is sent: every refused
    # document either IS reproducible through the endpoint (and answers a signed
    # 500, which the agent retries) or is a defect of the always-keys the
    # endpoint writes itself, and is refused by the same shape check.
    built = {
        "schema": c.MATERIALS_SCHEMA,
        "pending": True,
        "store_now": STORE_NOW,
        "target_ref": TARGET,
    }
    reproduced = 0
    for row in m["refused"]:
        document = row["document"]
        if {k: document.get(k) for k in built} == built:
            extras = {k: v for k, v in document.items() if k not in built}
            response = _materials_rig(extras, db).get("materials")
            assert response.status_code == 500, row["reason"]
            assert response.json()["error"] == "materials_invalid", row["reason"]
            reproduced += 1
        else:
            with pytest.raises(c.TargetApiError):
                c.check_materials_shape(document)
    assert reproduced >= 10
