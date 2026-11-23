"""Control's `contract/target_api_v2.json` (a delta over v1), vendored next to v1.

Sha-pinned and never edited. The groups that exercise this assembly's SERVER are
replayed over HTTP through the real router (observations). The rest belong to
other owners or to later lanes and are listed with the reason, so a group added
by a later Control release cannot be skipped.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from dotmac_kernel.testing import create_test_engine, isolated_session
from sqlalchemy.orm import Session
from target_api_support import (
    BASE,
    TARGET,
    StaticDirectory,
    build_runtime,
    client_for,
    record,
    request_headers,
    send,
)

from vendor_cp.deployment.target_api.consumption import (
    ConsumptionService,
    MaterialsHandler,
    ObservationHandler,
    Resolution,
    TargetApiHandlers,
    UnwiredBackend,
)
from vendor_cp.deployment.target_api.credentials import (
    ControlObservationSink,
    observation_claims,
)

V2_FILE = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "target_api"
    / ("target_api_v2.json")
)
PINNED_V2_SHA256 = "95756ba1d9a1e4c12cafef82ba4fb7e343c29c677772087bec2dd3bbc5374988"
V2: dict[str, Any] = json.loads(V2_FILE.read_bytes())
KEY = V2["agent_observation"]["key"]
_RESPONSE_SEED = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"

ROUTER_REPLAYED = {
    "agent_observation": "test_router_replays_agent_observation_*",
    "binding": "test_resolve_replays_the_binding_vectors_with_control_plan_key_names",
}
LATER_OR_OTHER_OWNER = {
    "job_arg_schema": "Control + agent: dispatched_job argument schema and io",
    "attestation_pair": "consume backend, once #270 pins an a18 with the pair verifier",
    "constants": "lease constants and endpoints_added: lane 5c (lease API)",
    "lease_body_vectors": "lane 5c",
    "lease_scenarios": "lane 5c",
    "renew_grant_vectors": "lane 5c",
    "observation_vectors": "Control: kind/outcome ingestion rules",
    "domain_separation": "Control + agent: request and observation bytes never cross",
}
METADATA = {"contract", "extends", "file", "note"}


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as session:
            yield session
    finally:
        engine.dispose()


def test_v2_vector_file_is_vendored_byte_identical_and_pinned() -> None:
    assert hashlib.sha256(V2_FILE.read_bytes()).hexdigest() == PINNED_V2_SHA256
    assert V2["file"] == "target_api_v2.json"
    assert V2["extends"]["file"] == "target_api_v1.json"


def test_every_v2_group_is_accounted_for() -> None:
    assert set(V2) == set(ROUTER_REPLAYED) | set(LATER_OR_OTHER_OWNER) | METADATA


def _rig(db_forwarded: list[Any], db: Session) -> Any:
    def fake_record(session: Session, command: Any) -> Any:
        db_forwarded.append(command)
        return SimpleNamespace(
            disposition="accepted",
            changed_state=False,
            attempt_id="a-1",
            receipt_id=None,
            verdict=None,
        )

    runtime = build_runtime(
        directory=StaticDirectory(
            record(
                public_key_b64u=KEY["public_b64u"],
                credential_id=KEY["key_id"],
                target_ref=TARGET,
            )
        ),
        response_seed=_RESPONSE_SEED,
        handlers=TargetApiHandlers(
            consumption=ConsumptionService(UnwiredBackend()),
            materials=MaterialsHandler(None),
            observations=ObservationHandler(ControlObservationSink(record=fake_record)),
        ),
        # the v2 file publishes the same test seeds as v1
        denied=frozenset(),
        session=db,
    )
    return client_for(runtime)


_COUNTER = iter(range(1, 10_000))


def _post(client: Any, body: bytes) -> Any:
    path = f"{BASE}/targets/{TARGET}/observations"
    return send(
        client,
        method="POST",
        path=path,
        body=body,
        headers=request_headers(
            KEY["seed_b64u"],
            method="POST",
            path=path,
            body=body,
            nonce=f"{next(_COUNTER) + 5000:032x}",
        ),
    )


def test_router_replays_agent_observation_ok_wires_to_control_unchanged(
    db: Session,
) -> None:
    for row in V2["agent_observation"]["ok"]:
        forwarded: list[Any] = []
        body = row["wire_utf8"].encode()
        assert observation_claims(body) == (KEY["key_id"], TARGET)
        response = _post(_rig(forwarded, db), body)
        assert response.status_code == 200, row["report_id"]
        (command,) = forwarded
        assert command.observation == body


def test_router_replays_agent_observation_refusals(db: Session) -> None:
    for row in V2["agent_observation"]["refused_verify"]:
        forwarded: list[Any] = []
        body = row["wire_utf8"].encode()
        response = _post(_rig(forwarded, db), body)
        # Signature verification is Control's: the sink forwards what claims to be
        # the caller's own, and refuses (403, audited) what claims to be another's.
        if observation_claims(body) == (KEY["key_id"], TARGET):
            assert response.status_code == 200, row["name"]
            assert forwarded[0].observation == body
        else:
            assert response.status_code == 403, row["name"]
            assert forwarded == []
    for row in V2["agent_observation"]["refused_parse"]:
        forwarded = []
        body = bytes.fromhex(row["body_hex"])
        response = _post(_rig(forwarded, db), body)
        # Either the router refuses the JSON itself (duplicate key, not JSON), or
        # Control gets the exact bytes and refuses them as malformed. Never
        # accepted by this layer.
        if forwarded:
            assert forwarded[0].observation == body, row["name"]
        else:
            assert response.status_code == 400, row["name"]


def test_an_ok_wire_claiming_another_credential_or_target_is_not_forwarded() -> None:
    row = V2["agent_observation"]["ok"][0]
    for old, new in (
        (f'"key_id":"{KEY["key_id"]}"', '"key_id":"cred-0002"'),
        (f'"target_ref":"{TARGET}"', '"target_ref":"dotmac-erp-v2/production/host-b"'),
    ):
        assert old in row["wire_utf8"]
        body = row["wire_utf8"].replace(old, new).encode()
        assert observation_claims(body) is not None
        assert observation_claims(body) != (KEY["key_id"], TARGET)


# ── resolve carries the plan's job and image (Foundation operator-job entry) ──


class _PlanBackend(UnwiredBackend):
    def __init__(self, operation: str, snapshot: Any) -> None:
        self._operation = operation
        self._snapshot = snapshot

    def resolve(self, db: Any, *, request: Any, store_now: Any) -> Resolution:
        return Resolution(
            dispatch_id="dispatch-0001",
            target_ref=TARGET,
            resolution_id="res-1",
            context={},
            operation=self._operation,
            plan_snapshot=self._snapshot,
        )


def _resolve(db: Session, operation: str, snapshot: Any) -> Any:
    runtime = build_runtime(
        directory=StaticDirectory(
            record(public_key_b64u=KEY["public_b64u"], credential_id=KEY["key_id"])
        ),
        response_seed=_RESPONSE_SEED,
        handlers=TargetApiHandlers(
            consumption=ConsumptionService(_PlanBackend(operation, snapshot)),
            materials=MaterialsHandler(None),
            observations=ObservationHandler(None),
        ),
        denied=frozenset(),
        session=db,
    )
    path = f"{BASE}/targets/{TARGET}/resolve"
    body = b'{"dispatch_id":"dispatch-0001"}'
    return send(
        client_for(runtime),
        method="POST",
        path=path,
        body=body,
        headers=request_headers(
            KEY["seed_b64u"],
            method="POST",
            path=path,
            body=body,
            nonce=f"{next(_COUNTER) + 9000:032x}",
        ),
    )


def test_resolve_replays_the_binding_vectors_with_control_plan_key_names(
    db: Session,
) -> None:
    job = V2["binding"]["job"]
    snapshot = job["snapshot"]
    binding = snapshot["deploy_binding"]
    body = _resolve(db, job["operation"], snapshot).json()
    assert body["operation"] == "run_job"
    # verbatim: the signed plan's own values under the plan's own key names
    assert body["dispatched_job"] == binding["dispatched_job"]
    assert body["plan_image"] == binding["images"][0]
    assert set(body["dispatched_job"]) >= {"argv", "materials", "name", "params"}
    assert body["plan_image"]["source"] == "present"

    serving = V2["binding"]["serving"]
    deploy = _resolve(db, serving["operation"], serving["snapshot"]).json()
    assert deploy["operation"] == "deploy"
    assert "dispatched_job" not in deploy and "plan_image" not in deploy


def test_resolve_refuses_the_dispatched_job_mismatch_vectors(db: Session) -> None:
    rows = [
        r for r in V2["binding"]["refused"] if r["code"] == "dispatched_job_mismatch"
    ]
    assert len(rows) == 2
    for row in rows:
        response = _resolve(db, row["operation"], row["snapshot"])
        assert response.status_code == 409, row["name"]
        assert response.json()["error"] == "dispatched_job_mismatch", row["name"]
