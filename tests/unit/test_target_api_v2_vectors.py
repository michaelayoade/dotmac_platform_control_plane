"""Control's `contract/target_api_v2.json` (a delta over v1), vendored next to v1.

Sha-pinned and never edited. The groups that exercise this assembly's SERVER are
replayed over HTTP through the real router (observations). The rest belong to
other owners or to later lanes and are listed with the reason, so a group added
by a later Control release cannot be skipped.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

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
PINNED_V2_SHA256 = "2ffcccdc2e74054ef6ff1496671c951aceaecc70e41de17b75545c4768d4c2a4"
V2: dict[str, Any] = json.loads(V2_FILE.read_bytes())
KEY = V2["agent_observation"]["key"]
_RESPONSE_SEED = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"

ROUTER_REPLAYED = {
    "agent_observation": "test_router_replays_agent_observation_*",
}
LATER_OR_OTHER_OWNER = {
    "attestation_pair": "consume backend, once #270 pins an a18 with the pair verifier",
    "binding": "agent + Control: job params render and serving",
    "constants": "lease constants and endpoints_added: lane 5c (lease API)",
    "lease_body_vectors": "lane 5c",
    "lease_scenarios": "lane 5c",
    "renew_grant_vectors": "lane 5c",
    "observation_vectors": "Control: kind/outcome ingestion rules",
    "domain_separation": "Control + agent: request and observation bytes never cross",
}
METADATA = {"contract", "extends", "file", "note"}


def test_v2_vector_file_is_vendored_byte_identical_and_pinned() -> None:
    assert hashlib.sha256(V2_FILE.read_bytes()).hexdigest() == PINNED_V2_SHA256
    assert V2["file"] == "target_api_v2.json"
    assert V2["extends"]["file"] == "target_api_v1.json"


def test_every_v2_group_is_accounted_for() -> None:
    assert set(V2) == set(ROUTER_REPLAYED) | set(LATER_OR_OTHER_OWNER) | METADATA


def _rig(db_forwarded: list[Any]) -> Any:
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
        session=_Db(),
    )
    return client_for(runtime)


class _Db:
    """The sink's mismatch path writes an audit row; replays of valid wires don't."""


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


def test_router_replays_agent_observation_ok_wires_to_control_unchanged() -> None:
    for row in V2["agent_observation"]["ok"]:
        forwarded: list[Any] = []
        body = row["wire_utf8"].encode()
        assert observation_claims(body) == (KEY["key_id"], TARGET)
        response = _post(_rig(forwarded), body)
        assert response.status_code == 200, row["report_id"]
        (command,) = forwarded
        assert command.observation == body


def test_router_replays_agent_observation_refusals() -> None:
    for row in V2["agent_observation"]["refused_verify"]:
        forwarded: list[Any] = []
        body = row["wire_utf8"].encode()
        # Signature verification is Control's: the sink only forwards.
        assert _post(_rig(forwarded), body).status_code == 200, row["name"]
        assert forwarded[0].observation == body
    for row in V2["agent_observation"]["refused_parse"]:
        forwarded = []
        body = bytes.fromhex(row["body_hex"])
        response = _post(_rig(forwarded), body)
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
