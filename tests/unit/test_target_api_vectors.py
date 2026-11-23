"""Control's frozen target-API vectors, replayed through CP's REAL router.

`contract/target_api_v1.json` (Control a18, sha256 pinned below) is the shared
contract: Control, the agent and this assembly all replay it. Review condition
C6 on Control #76: "CP 5b replays every vector through its real router". The
file is vendored byte-identical and never edited here; a `_v2` file is a Control
release followed by a CP pin change.

Groups that exercise the SERVER are driven over HTTP through `build_router`.
Groups that are pure functions of the contract are replayed against the mirror
(`target_api.contract`), which keeps the mirror honest until lane 5a pins a18 and
deletes it. Every group of the file must be accounted for in one of the two
tables below, so a group added by a later Control release cannot be skipped.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

import pytest
from target_api_support import (
    BASE,
    PINNED_VECTOR_SHA256,
    STORE_NOW,
    TARGET,
    VECTOR_FILE,
    MemoryNonces,
    RecordingHandlers,
    SeedSigner,
    StaticDirectory,
    b64u,
    build_runtime,
    client_for,
    record,
    request_headers,
    send,
    unb64u,
    vectors,
)

from vendor_cp.deployment.target_api import contract as c
from vendor_cp.deployment.target_api.auth import (
    KernelNonceLedger,
    TargetRequestAuthenticator,
    refusal_status,
)
from vendor_cp.deployment.target_api.response_signing import (
    Ed25519ResponseSigner,
    ResponseKeyUnavailable,
)
from vendor_cp.deployment.target_api.router import signed_response

V = vectors()
REQUEST_PUB = V["keys"]["request"]["public_b64u"]
REQUEST_SEED = V["keys"]["request"]["seed_b64u"]
RESPONSE_SEED = V["keys"]["response"]["seed_b64u"]
RESPONSE_PUB = V["keys"]["response"]["public_b64u"]

#: Groups driven over HTTP through the real router.
ROUTER_REPLAYED = {
    "request_vectors": "test_router_replays_request_vectors",
    "request_check": "test_router_replays_request_check_ok / _refused",
    "paths": "test_router_replays_paths_*",
    "json_bodies": "test_router_replays_json_bodies",
    "response_vectors": "test_router_signs_responses_exactly_as_the_vectors",
    "nonce_ledger": "test_router_refuses_a_nonce_replay / test_kernel_nonce_ledger_*",
    "denied_public_keys": "test_denied_public_keys_*",
    "keys": "used to sign by every test here",
    "materials": (
        "test_target_api_consumption.py::test_router_replays_materials_vectors"
        " and ::test_mirror_materials_vectors"
    ),
}
#: Pure functions of the contract, replayed against the mirror.
MIRROR_REPLAYED = {
    "constants": "test_mirror_constants_match_the_vectors",
    "encoding": "test_mirror_encoding_vectors",
    "stamp_vectors": "test_mirror_encoding_vectors",
    "response_check": "test_mirror_response_check_vectors (the client half)",
    "retry_idempotency": "test_retry_idempotency_table_matches",
}
#: Metadata of the file itself.
METADATA = {"contract", "file", "note"}
#: Behaviour that belongs to the deploy AGENT or to CONTROL, with no server
#: behaviour in this assembly: params rendering, secret shapes, OpenBao names.
NOT_CP_SERVER = {
    "render_vectors": "agent: canonical params.env rendering",
    "secret_name_vectors": "Control descriptor parse + agent duplicate",
    "secret_ref_vectors": "Control: derived secret_ref",
    "target_binding": "Control registration: OpenBao namespace-env",
    "value_vectors": "agent + Control: secret-shaped value refusal",
}


def test_vector_file_is_vendored_byte_identical_and_pinned() -> None:
    raw = VECTOR_FILE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == PINNED_VECTOR_SHA256
    assert json.loads(raw)["file"] == "target_api_v1.json"


def test_every_vector_group_is_accounted_for() -> None:
    accounted = (
        set(ROUTER_REPLAYED) | set(MIRROR_REPLAYED) | METADATA | set(NOT_CP_SERVER)
    )
    assert set(V) == accounted


# ── The mirror against the pure groups ──────────────────────────────────────


def test_mirror_constants_match_the_vectors() -> None:
    k = V["constants"]
    assert c.BASE_PATH == k["base_path"] == BASE
    assert c.REQUEST_PURPOSE == k["request_purpose"]
    assert c.RESPONSE_PURPOSE == k["response_purpose"]
    assert c.MAX_SKEW_SECONDS == k["max_skew_seconds"]
    assert list(c.BINDINGS_ENV_NAMES) == k["bindings_env_names"]
    assert list(c.DEPLOY_ENV_NAMES) == k["deploy_env_names"]
    assert {
        "credential_id": c.H_CREDENTIAL,
        "issued_at": c.H_ISSUED_AT,
        "nonce": c.H_NONCE,
        "response_signature": c.H_RESPONSE_SIGNATURE,
        "signature": c.H_SIGNATURE,
        "target_ref": c.H_TARGET,
    } == k["headers"]
    assert [{"method": v, "route": r, "caller": who} for v, r, who in c.ENDPOINTS] == [
        {"method": row["method"], "route": row["route"], "caller": row["caller"]}
        for row in V["paths"]["routes"]
    ]
    assert c.NONCE_LEDGER_SCOPE == V["nonce_ledger"]["scope"]
    assert c.NONCE_RETENTION == V["nonce_ledger"]["retention"]


def test_mirror_encoding_vectors() -> None:
    enc = V["encoding"]
    for row in enc["base64url"]["ok"]:
        raw = bytes.fromhex(row["hex"])
        assert c.b64u_encode(raw) == row["text"]
        assert c.b64u_decode(row["text"]) == raw
    for text in enc["base64url"]["refused"]:
        with pytest.raises(c.TargetApiError):
            c.b64u_decode(text)
    for nonce in enc["nonces"]["ok"]:
        assert c.check_nonce(nonce) == nonce
    for nonce in enc["nonces"]["refused"]:
        with pytest.raises(c.TargetApiError):
            c.check_nonce(nonce)
    for row in enc["skew"]:
        if row["ok"]:
            c.check_skew(row["issued_at"], row["store_now"])
        else:
            with pytest.raises(c.TargetApiError):
                c.check_skew(row["issued_at"], row["store_now"])
    for text in enc["stamps"]["ok"]:
        assert c.format_stamp(c.parse_stamp(text)) == text
    for text in enc["stamps"]["refused"]:
        with pytest.raises(c.TargetApiError):
            c.parse_stamp(text)
    for row in V["stamp_vectors"]:
        assert c.format_stamp(datetime.fromisoformat(row["input"])) == row["expected"]
    for status, code in enc["unsigned_status"].items():
        assert c.classify_unsigned_response(int(status)) == code


def test_mirror_response_check_vectors() -> None:
    for row in V["response_check"]["ok"]:
        got = c.check_response(
            method=row["method"],
            path=row["path"],
            request_nonce=row["request_nonce"],
            status=row["status"],
            body=row["body_utf8"].encode(),
            headers=row["headers"],
        )
        assert got.message.decode() == row["message_utf8"]
        assert got.signature == unb64u(row["signature_b64u"])
    for row in V["response_check"]["refused"]:
        i = row["inputs"]
        with pytest.raises(c.TargetApiError) as caught:
            c.check_response(
                method=i["method"],
                path=i["path"],
                request_nonce=i["request_nonce"],
                status=i["status"],
                body=i["body_utf8"].encode(),
                headers=_pairs(i),
            )
        assert caught.value.code == row["code"], row["name"]


def test_mirror_request_credential_id_vectors() -> None:
    group = V["request_check"]["credential_id"]
    for row in group["ok"]:
        assert c.request_credential_id(_pairs(row)) == row["credential_id"]
    for row in group["refused"]:
        with pytest.raises(c.TargetApiError) as caught:
            c.request_credential_id(_pairs(row))
        assert caught.value.code == row["code"], row["name"]


def test_retry_idempotency_table_matches() -> None:
    assert c.RETRY_IDEMPOTENCY == V["retry_idempotency"]


def _pairs(row: dict[str, Any]) -> list[tuple[str, str]]:
    """A vector's headers: `headers_pairs` when the case needs a REPEATED header."""
    if "headers_pairs" in row:
        return [(str(k), str(v)) for k, v in row["headers_pairs"]]
    return [(str(k), str(v)) for k, v in row["headers"].items()]


# ── The real router ─────────────────────────────────────────────────────────


def _router_for(
    *,
    target_ref: str = TARGET,
    credential_id: str = "cred-0001",
    store_now: str = STORE_NOW,
    nonces: MemoryNonces | None = None,
    handlers: RecordingHandlers | None = None,
) -> tuple[Any, RecordingHandlers, MemoryNonces]:
    handlers = handlers or RecordingHandlers()
    nonces = nonces or MemoryNonces()
    runtime = build_runtime(
        directory=StaticDirectory(
            record(
                public_key_b64u=REQUEST_PUB,
                credential_id=credential_id,
                target_ref=target_ref,
            )
        ),
        response_seed=RESPONSE_SEED,
        store_now=store_now,
        nonces=nonces,
        handlers=handlers,
        denied=frozenset(),
    )
    return client_for(runtime), handlers, nonces


def test_router_replays_request_vectors() -> None:
    for row in V["request_vectors"]:
        client, handlers, _ = _router_for(
            target_ref=row["target_ref"], credential_id=row["credential_id"]
        )
        body = row["body_utf8"].encode()
        response = send(
            client,
            method=row["method"],
            path=row["path"],
            headers=row["headers"],
            body=body,
        )
        assert response.status_code == 200, row["path"]
        (call, _payload), *rest = handlers.calls
        assert not rest
        assert call.coordinates.signed_message.decode() == row["message_utf8"]
        assert call.coordinates.signature_b64u == row["signature_b64u"]
        assert call.coordinates.nonce == row["nonce"]
        assert call.principal.target_ref == row["target_ref"]


def test_router_replays_request_check_ok() -> None:
    for row in V["request_check"]["ok"]:
        i = row["inputs"]
        client, handlers, nonces = _router_for(
            target_ref=i["credential_target_ref"],
            credential_id=i["looked_up_credential_id"],
            store_now=i["store_now"],
        )
        response = send(
            client,
            method=i["method"],
            path=i["raw_path"],
            headers=_pairs(i),
            body=i["body_utf8"].encode(),
            query=i["query_string"],
        )
        assert response.status_code == 200
        (call, _), *rest = handlers.calls
        assert not rest
        want = row["coordinates"]
        got = {
            "credential_id": call.coordinates.credential_id,
            "dispatch_id": call.coordinates.dispatch_id,
            "route": call.coordinates.route,
            "target_ref": call.coordinates.target_ref,
            "signed_message_utf8": call.coordinates.signed_message.decode(),
            "nonce_ledger_key": call.coordinates.nonce_ledger_key,
        }
        # some rows pin only a subset of the coordinates (the case-insensitive
        # header row pins the target); every pinned one must match
        assert want.items() <= got.items(), row
        assert nonces.spent == {call.coordinates.nonce_ledger_key}


def test_router_replays_request_check_refused() -> None:
    for row in V["request_check"]["refused"]:
        i = row["inputs"]
        client, handlers, nonces = _router_for(
            target_ref=i["credential_target_ref"],
            credential_id=i["looked_up_credential_id"],
            store_now=i["store_now"],
        )
        response = send(
            client,
            method=i["method"],
            path=i["raw_path"],
            headers=_pairs(i),
            body=i["body_utf8"].encode(),
            query=i["query_string"],
        )
        code = row["code"]
        # A request that NAMES a credential other than the one the directory
        # returned cannot reach `check_request` over HTTP: the record's own id
        # disagrees with the header's, and the server refuses at the lookup.
        expected = (
            "credential_refused" if code == "credential_lookup_mismatch" else code
        )
        assert response.json()["error"] == expected, row["name"]
        assert response.status_code == (
            401 if expected == "credential_refused" else refusal_status(code)
        ), row["name"]
        assert not handlers.calls, row["name"]
        assert not nonces.spent, row["name"]


def test_router_replays_paths_ok() -> None:
    verbs = {r["route"]: r["method"] for r in V["paths"]["routes"]}
    for index, row in enumerate(V["paths"]["ok"]):
        client, handlers, _ = _router_for(target_ref=row["target_ref"])
        route = row["route"]
        method = verbs["committed/<dispatch_id>" if route == "committed" else route]
        nonce = f"{index:032x}"
        headers = request_headers(
            REQUEST_SEED,
            method=method,
            path=row["path"],
            body=b"{}" if method == "POST" else b"",
            target_ref=row["target_ref"],
            nonce=nonce,
        )
        response = send(
            client,
            method=method,
            path=row["path"],
            headers=headers,
            body=b"{}" if method == "POST" else b"",
        )
        assert response.status_code == 200, row["path"]
        (call, _), *rest = handlers.calls
        assert not rest
        assert call.coordinates.target_ref == row["target_ref"]
        assert call.coordinates.dispatch_id == row.get("dispatch_id")


def test_router_replays_paths_refused() -> None:
    for index, row in enumerate(V["paths"]["refused"]):
        path, query = row["path"], ""
        if "?" in path:
            path, query = path.split("?", 1)
        client, handlers, nonces = _router_for()
        headers = request_headers(
            REQUEST_SEED, method="GET", path=path, nonce=f"{index + 100:032x}"
        )
        response = send(client, method="GET", path=path, headers=headers, query=query)
        assert response.status_code in (400, 401, 403, 404, 405), row["path"]
        assert not handlers.calls, row["path"]
        assert not nonces.spent, row["path"]


def test_router_replays_paths_wrong_verbs() -> None:
    for index, row in enumerate(V["paths"]["wrong_verbs"]):
        client, handlers, nonces = _router_for()
        path = f"{BASE}/targets/{TARGET}/{row['route']}"
        headers = request_headers(
            REQUEST_SEED,
            method=row["method"],
            path=path,
            nonce=f"{index + 200:032x}",
        )
        response = send(client, method=row["method"], path=path, headers=headers)
        assert response.status_code == 405
        assert response.json()["error"] == "wrong_verb"
        assert not handlers.calls
        assert not nonces.spent


def test_router_replays_json_bodies() -> None:
    path = f"{BASE}/targets/{TARGET}/observations"
    for index, row in enumerate(V["json_bodies"]["ok"]):
        client, handlers, _ = _router_for()
        body = row["body_utf8"].encode()
        response = send(
            client,
            method="POST",
            path=path,
            body=body,
            headers=request_headers(
                REQUEST_SEED,
                method="POST",
                path=path,
                body=body,
                nonce=f"{index + 300:032x}",
            ),
        )
        assert response.status_code == 200
        assert handlers.calls[0][1] == row["parsed"]
    for index, row in enumerate(V["json_bodies"]["refused"]):
        client, handlers, nonces = _router_for()
        body = bytes.fromhex(row["body_hex"])
        response = send(
            client,
            method="POST",
            path=path,
            body=body,
            headers=request_headers(
                REQUEST_SEED,
                method="POST",
                path=path,
                body=body,
                nonce=f"{index + 400:032x}",
            ),
        )
        assert response.status_code == 400
        assert response.json()["error"] == row["code"]
        # authenticated, so the nonce is spent; no handler ran
        assert not handlers.calls
        assert len(nonces.spent) == 1


def test_router_refuses_a_nonce_replay() -> None:
    row = V["request_vectors"][0]
    client, handlers, nonces = _router_for()
    first = send(
        client,
        method=row["method"],
        path=row["path"],
        headers=row["headers"],
    )
    second = send(
        client,
        method=row["method"],
        path=row["path"],
        headers=row["headers"],
    )
    assert first.status_code == 200
    assert second.status_code == 401
    assert second.json()["error"] == "nonce_replay"
    assert len(handlers.calls) == 1
    assert nonces.spent == {V["nonce_ledger"]["example_key"]}


def test_router_signs_responses_exactly_as_the_vectors() -> None:
    runtime = build_runtime(
        directory=StaticDirectory(None),
        response_seed=RESPONSE_SEED,
        denied=frozenset(),
    )
    for row in V["response_vectors"]:
        response = signed_response(
            runtime,
            content=row["body_utf8"].encode(),
            status=row["status"],
            method=row["method"],
            raw_path=row["path"],
            request_nonce=row["request_nonce"],
        )
        assert response.headers[c.H_RESPONSE_SIGNATURE] == row["signature_b64u"], row[
            "message_utf8"
        ]


def test_router_response_signature_binds_the_request() -> None:
    """Over HTTP, with the message written out by hand (independent of the mirror)."""
    row = V["request_vectors"][0]
    client, _, _ = _router_for()
    response = send(
        client, method=row["method"], path=row["path"], headers=row["headers"]
    )
    message = "\n".join(
        [
            "cp-target-response.v1",
            row["method"],
            row["path"],
            row["nonce"],
            str(response.status_code),
            hashlib.sha256(response.content).hexdigest(),
        ]
    ).encode()
    signer = SeedSigner(RESPONSE_SEED)
    assert response.headers["X-Dotmac-Response-Signature"] == b64u(signer.sign(message))
    assert json.loads(response.content)["store_now"] == STORE_NOW


def test_denied_public_keys_vectors() -> None:
    denied = V["denied_public_keys"]
    assert {k["public_b64u"] for k in denied["keys"]} == c.DENIED_PUBLIC_KEYS_B64U
    assert c.is_denied_public_key(REQUEST_PUB)
    assert c.is_denied_public_key(RESPONSE_PUB)
    assert not c.is_denied_public_key(denied["accepted_example"])
    # Enrolled with a denied key, the DEFAULT authenticator authenticates nobody,
    # even though the signature is genuine.
    row = V["request_vectors"][0]
    runtime = build_runtime(
        directory=StaticDirectory(record(public_key_b64u=REQUEST_PUB)),
        response_seed=RESPONSE_SEED,
        handlers=RecordingHandlers(),
    )
    client = client_for(runtime)
    response = send(
        client, method=row["method"], path=row["path"], headers=row["headers"]
    )
    assert response.status_code == 401
    assert response.json()["error"] == "credential_refused"


def test_denied_public_keys_cannot_be_the_response_key() -> None:
    for seed in (REQUEST_SEED, RESPONSE_SEED):
        with pytest.raises(ResponseKeyUnavailable):
            Ed25519ResponseSigner(unb64u(seed), key_id="k")
    fresh = Ed25519ResponseSigner(bytes(range(64, 96)), key_id="k")
    assert not c.is_denied_public_key(fresh.public_key_b64u)


def test_kernel_nonce_ledger_vectors() -> None:
    from dotmac_kernel.idempotency_models import PlatformIdempotencyRecord
    from dotmac_kernel.testing import create_test_engine, isolated_session
    from sqlalchemy import select

    ledger = V["nonce_ledger"]
    key = c.nonce_ledger_key("cred-0001", "000000000000000000000000a5a5a5a6")
    assert key == ledger["example_key"]
    engine = create_test_engine()
    try:
        with isolated_session(engine) as db:
            kernel = KernelNonceLedger()
            assert kernel.spend(db, key) is True
            assert kernel.spend(db, key) is False
            row = db.execute(
                select(PlatformIdempotencyRecord).where(
                    PlatformIdempotencyRecord.scope == ledger["scope"]
                )
            ).scalar_one()
            assert row.key == key
            assert row.expires_at is None  # permanent: `purge_expired` never reaps it
    finally:
        engine.dispose()


def test_authenticator_is_the_one_default_denied_set() -> None:
    from inspect import signature

    default = signature(TargetRequestAuthenticator).parameters["denied_public_keys"]
    assert default.default == c.DENIED_PUBLIC_KEYS_B64U
