"""WP5c: Control's `target_api_v2` lease vectors, replayed through the REAL router.

`tests/fixtures/target_api/target_api_v2.json` is Control's
`contract/target_api_v2.json`, vendored byte-identical and pinned by sha256 (the
value the coordinator briefed; Control CI was still pending, so it is provisional:
a re-vendor changes the pin in the same change). Every lease scenario runs over
HTTP through lane 5b's `build_router` (authentication, replay, response signing),
into `LeaseHandlers`, into the REAL `cp_deploy_lease` functions on PG16 as the CP
runtime role, on the frozen database clock. Each step's status, signed error and
exact response key set are Control's.

One honest limit, stated rather than hidden: `lease/renew` is not a route of lane
5b's pinned v1 mirror, so the fixture adds it to the mirror's verb table
(`contract._VERBS`) for the run, exactly as the v2 mirror will; nothing else of 5b's
is touched.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sqlalchemy.orm import Session

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "unit"))
from target_api_support import (  # noqa: E402
    BASE,
    TARGET,
    RecordingHandlers,
    StaticDirectory,
    b64u,
    build_runtime,
    client_for,
    record,
    request_headers,
    send,
)

from vendor_cp.deployment.deploy_lease_handlers import (
    LEASE_ERRORS,
    LeaseHandlers,
    LeasePlan,
)
from vendor_cp.deployment.lease_store import REFUSAL_CODES
from vendor_cp.deployment.target_api import contract as c

VECTOR_FILE = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "target_api"
    / "target_api_v2.json"
)
#: Control `contract/target_api_v2.json`, control-a18-20261122 be74634 (provisional:
#: Control regenerates it again for inputs and apply_class).
PINNED_V2_SHA256 = "0fe9c6be1b49af5fb4b9267bce51dfaccc016e83b1c5dd8b2332916f698d834d"
V2 = json.loads(VECTOR_FILE.read_bytes())

_SEED = b64u(bytes(range(1, 33)))
_PUBLIC = b64u(
    Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    .public_key()
    .public_bytes(Encoding.Raw, PublicFormat.Raw)
)
_RESPONSE_SEED = b64u(bytes(range(100, 132)))
_MARKER = "sha256:" + "c" * 64
_ROUTES = {
    "acquire": ("POST", "lease/acquire"),
    "covers": ("POST", "lease/covers"),
    "renew": ("POST", "lease/renew"),
    "release": ("POST", "lease/release"),
    "standing": ("GET", "lease/standing"),
}


def test_the_vendored_v2_contract_is_byte_identical_to_the_pin() -> None:
    assert hashlib.sha256(VECTOR_FILE.read_bytes()).hexdigest() == PINNED_V2_SHA256
    assert V2["contract"] == "dotmac.target_api/2"
    assert V2["constants"]["endpoints_added"] == [["POST", "lease/renew", "agent"]]
    assert set(V2["constants"]["lease_errors"]) == LEASE_ERRORS
    assert set(V2["constants"]["lease_errors"].values()) == {409}
    assert len(V2["lease_scenarios"]) == 10


class _Port:
    def __init__(self) -> None:
        self.plan: LeasePlan | None = None
        self.marker: str | None = None

    def plan_for(self, db: Any, *, target_ref: str, dispatch_id: str, at: Any) -> Any:
        return self.plan

    def reconcile_marker_for(self, db: Any, *, target_ref: str, at: Any) -> Any:
        return self.marker


class _Replay:
    def __init__(self, db: Any, engine: Any, monkeypatch: Any) -> None:
        monkeypatch.setitem(c._VERBS, "lease/renew", "POST")
        self.db, self.engine, self.port = db, engine, _Port()
        self.ids: dict[str, str] = {}
        self.n = 0
        self.base = db.now()
        self.at = 0

        @contextmanager
        def sessions() -> Any:
            session = Session(engine)
            try:
                yield session
                session.commit()
            except BaseException:
                session.rollback()
                raise
            finally:
                session.close()

        runtime = build_runtime(
            directory=StaticDirectory(record(public_key_b64u=_PUBLIC)),
            response_seed=_RESPONSE_SEED,
            handlers=LeaseHandlers(inner=RecordingHandlers(), port=self.port),
        )
        self.client = client_for(dataclasses.replace(runtime, sessions=sessions))

    def clock_to(self, at: int) -> None:
        target = self.base.timestamp() + at
        now = self.db.now().timestamp()
        if target > now:
            self.db.advance(None, target - now)

    def call(self, name: str, args: dict[str, Any], body: Any = None) -> Any:
        method, route = _ROUTES[name]
        path = f"{BASE}/targets/{TARGET}/{route}"
        raw = b"" if method == "GET" else json.dumps(body).encode()
        self.n += 1
        return send(
            self.client,
            method=method,
            path=path,
            body=raw,
            headers=request_headers(
                _SEED, method=method, path=path, body=raw, nonce=f"{self.n:032x}"
            ),
        )


@pytest.fixture
def replay_factory(lane3_cases: Any, postgres_url: str, url_for: Any, monkeypatch: Any):
    from sqlalchemy import create_engine

    engines: list[Any] = []

    def make() -> _Replay:
        db = lane3_cases.new()
        engine = create_engine(
            url_for(postgres_url, db.admin.url.database, user="platform_api")
        )
        engines.append(engine)
        return _Replay(db, engine, monkeypatch)

    yield make
    for engine in engines:
        engine.dispose()


def _wire_body(
    replay: _Replay, name: str, args: dict[str, Any]
) -> dict[str, Any] | None:
    if name == "standing":
        return None
    body = {
        k: v
        for k, v in args.items()
        if k not in {"lease_max_seconds", "marker_present"}
    }
    if "lease_id" in body:
        body["lease_id"] = replay.ids.get(body["lease_id"], body["lease_id"])
    return body


@pytest.mark.parametrize("index", range(10))
def test_every_v2_lease_scenario_replays_through_the_real_router(
    replay_factory: Any, index: int
) -> None:
    scenario = V2["lease_scenarios"][index]
    replay: _Replay = replay_factory()
    for step in scenario["steps"]:
        args, name = step["args"], step["call"]
        replay.clock_to(step["at"])
        if name == "acquire":
            replay.port.plan = LeasePlan(
                "deploy", None, args["ttl_seconds"], args["lease_max_seconds"]
            )
            replay.port.marker = _MARKER if args["marker_present"] else None
        response = replay.call(name, args, _wire_body(replay, name, args))
        where = f"{scenario['name']} / {name} at {step['at']}"
        assert response.status_code == step["status"], where
        assert "X-Dotmac-Response-Signature" in response.headers, where
        got = response.json()
        got.pop("store_now")  # the router's own CP-time stamp, not a lease field
        if "error" in step:
            assert got == {"error": step["error"]}, where
            assert step["error"] in LEASE_ERRORS, where
            continue
        want = dict(step["body"])
        if name == "acquire":
            replay.ids[want["lease_id"]] = got["lease_id"]
        if "lease_id" in want:
            want["lease_id"] = replay.ids.get(want["lease_id"], want["lease_id"])
        assert got == want, where  # the exact key set and values, nothing extra


def test_every_refused_v2_request_body_is_a_400_before_the_database(
    replay_factory: Any,
) -> None:
    replay: _Replay = replay_factory()
    replay.port.plan = LeasePlan("deploy", None, 600, 1500)
    by_route = {route: name for name, (_, route) in _ROUTES.items()}
    refused = [
        v for v in V2["lease_body_vectors"]["refused"] if v["direction"] == "request"
    ]
    assert len(refused) == 6
    for vector in refused:
        if vector["route"] not in by_route:  # `lease/lock`: not a route at all
            continue
        response = replay.call(by_route[vector["route"]], {}, vector["body"])
        assert response.status_code == 400, vector
        assert response.json()["error"] in {"bad_body", "lease_ttl_invalid"}, vector
    unknown = next(v for v in refused if v["route"] not in by_route)
    path = f"{BASE}/targets/{TARGET}/{unknown['route']}"
    raw = json.dumps(unknown["body"]).encode()
    response = send(
        replay.client,
        method="POST",
        path=path,
        body=raw,
        headers=request_headers(
            _SEED, method="POST", path=path, body=raw, nonce=f"{99:032x}"
        ),
    )
    assert response.status_code == 404  # an unknown route never reaches a handler


def test_the_replayed_error_names_are_the_contracts_and_codes_are_closed() -> None:
    from vendor_cp.deployment import deploy_lease_handlers as h

    named = {
        *h._ACQUIRE_NAMES.values(),
        *h._RENEW_NAMES.values(),
        *h._RELEASE_NAMES.values(),
    }
    assert named <= LEASE_ERRORS
    for table in (h._ACQUIRE_NAMES, h._RENEW_NAMES, h._RELEASE_NAMES):
        assert set(table) <= REFUSAL_CODES
