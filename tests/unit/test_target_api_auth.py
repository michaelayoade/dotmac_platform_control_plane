"""DESIGN-rev3 section 2.6 request authentication, replay and response purpose.

Named tests for the section 2.9 rows `test_target_api_auth_negatives` and
`test_nonce_replay_refused`. The router is the real one; the ports are the
router's own seams. Keys here are generated, never the vector file's published
ones (the vector replay lives in `test_target_api_vectors.py`).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from target_api_support import (
    BASE,
    STORE_NOW,
    TARGET,
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
)

from vendor_cp.deployment.target_api import contract as c
from vendor_cp.deployment.target_api.auth import SlidingWindowRateLimiter
from vendor_cp.deployment.target_api.response_signing import (
    RESPONSE_KEY_FILE_ENV,
    RESPONSE_KEY_ID_ENV,
    ResponseKeyUnavailable,
    load_response_signer,
)
from vendor_cp.deployment.target_api.router import MAX_BODY_BYTES

_SEED = bytes(range(1, 33))
_SEED_B64U = b64u(_SEED)
_PUBLIC = b64u(
    Ed25519PrivateKey.from_private_bytes(_SEED)
    .public_key()
    .public_bytes(Encoding.Raw, PublicFormat.Raw)
)
_RESPONSE_SEED = b64u(bytes(range(100, 132)))
_PATH = f"{BASE}/targets/{TARGET}/materials"
_NONCE = "00000000000000000000000000000001"


def _rig(
    *,
    rec: Any = "default",
    nonces: MemoryNonces | None = None,
    limiter: SlidingWindowRateLimiter | None = None,
    store_now: str = STORE_NOW,
) -> tuple[Any, RecordingHandlers, MemoryNonces]:
    handlers = RecordingHandlers()
    nonces = nonces or MemoryNonces()
    directory = StaticDirectory(
        record(public_key_b64u=_PUBLIC) if rec == "default" else rec
    )
    runtime = build_runtime(
        directory=directory,
        response_seed=_RESPONSE_SEED,
        nonces=nonces,
        handlers=handlers,
        limiter=limiter,
        store_now=store_now,
    )
    return client_for(runtime), handlers, nonces


def _get(client: Any, *, nonce: str = _NONCE) -> Any:
    headers = request_headers(_SEED_B64U, method="GET", path=_PATH, nonce=nonce)
    return send(client, method="GET", path=_PATH, headers=headers)


def test_a_genuine_request_is_served_signed_and_spends_its_nonce() -> None:
    client, handlers, nonces = _rig()
    response = _get(client)
    assert response.status_code == 200
    assert len(handlers.calls) == 1
    call, payload = handlers.calls[0]
    assert payload is None
    assert call.principal.kind == "target"
    assert call.principal.target_ref == TARGET
    assert call.principal.principal_ref == "target-credential:cred-0001"
    assert nonces.spent == {f"cred-0001/{_NONCE}"}
    assert response.headers["Cache-Control"] == "no-store"


def test_target_api_auth_negatives() -> None:
    """Unsigned, unknown, revoked, cross-target, skewed, forged: every one refused,
    none reaching a handler, none spending a nonce."""
    other_key = b64u(
        Ed25519PrivateKey.from_private_bytes(bytes(range(7, 39)))
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    cases = {
        "unknown credential": (dict(rec=None), 401, "credential_refused"),
        "revoked or not yet active": (
            dict(rec=record(public_key_b64u=_PUBLIC, eligible=False)),
            401,
            "credential_refused",
        ),
        "wrong purpose": (
            dict(rec=record(public_key_b64u=_PUBLIC, purpose_ok=False)),
            401,
            "credential_refused",
        ),
        "forged: another key signed": (
            dict(rec=record(public_key_b64u=other_key)),
            401,
            "credential_refused",
        ),
        "cross-target: credential bound to another host": (
            dict(
                rec=record(
                    public_key_b64u=_PUBLIC,
                    target_ref="dotmac-erp-v2/production/host-b",
                )
            ),
            403,
            "target_mismatch_credential",
        ),
        "skewed past 60 s": (dict(store_now="2026-11-22T10:01:01Z"), 401, "skew"),
    }
    for name, (rig_args, status, code) in cases.items():
        client, handlers, nonces = _rig(**rig_args)
        response = _get(client)
        assert response.status_code == status, name
        assert response.json()["error"] == code, name
        assert not handlers.calls, name
        assert not nonces.spent, name

    # unsigned: the signature header is absent
    client, handlers, nonces = _rig()
    headers = [
        (k, v)
        for k, v in request_headers(_SEED_B64U, method="GET", path=_PATH, nonce=_NONCE)
        if k != c.H_SIGNATURE
    ]
    response = send(client, method="GET", path=_PATH, headers=headers)
    assert response.status_code == 401
    assert response.json()["error"] == "missing_header"
    assert not handlers.calls and not nonces.spent

    # a body that differs from the one signed
    client, handlers, nonces = _rig()
    headers = request_headers(
        _SEED_B64U,
        method="POST",
        path=f"{BASE}/targets/{TARGET}/observations",
        body=b"{}",
        nonce=_NONCE,
    )
    response = send(
        client,
        method="POST",
        path=f"{BASE}/targets/{TARGET}/observations",
        headers=headers,
        body=b'{"a":1}',
    )
    assert response.status_code == 401
    assert response.json()["error"] == "credential_refused"
    assert not handlers.calls and not nonces.spent


def test_nonce_replay_refused() -> None:
    client, handlers, nonces = _rig()
    headers = request_headers(_SEED_B64U, method="GET", path=_PATH, nonce=_NONCE)
    assert send(client, method="GET", path=_PATH, headers=headers).status_code == 200
    again = send(client, method="GET", path=_PATH, headers=headers)
    assert again.status_code == 401
    assert again.json()["error"] == "nonce_replay"
    assert len(handlers.calls) == 1
    # a retry carries a NEW nonce and is served: retry safety is the business
    # key's job, never the nonce's
    fresh = request_headers(
        _SEED_B64U, method="GET", path=_PATH, nonce="00000000000000000000000000000002"
    )
    assert send(client, method="GET", path=_PATH, headers=fresh).status_code == 200
    # the same nonce under ANOTHER credential is a different ledger key
    assert nonces.spent == {
        f"cred-0001/{_NONCE}",
        "cred-0001/00000000000000000000000000000002",
    }


def test_a_session_cookie_or_bearer_token_is_refused_not_ignored() -> None:
    for extra in ({"Authorization": "Bearer x"}, {"Cookie": "session=x"}):
        client, handlers, nonces = _rig()
        headers = request_headers(_SEED_B64U, method="GET", path=_PATH, nonce=_NONCE)
        response = send(
            client, method="GET", path=_PATH, headers=headers + list(extra.items())
        )
        assert response.status_code == 401
        assert response.json()["error"] == "ambient_credential"
        assert not handlers.calls and not nonces.spent


def test_body_over_the_cap_is_an_unsigned_413() -> None:
    client, handlers, _ = _rig()
    path = f"{BASE}/targets/{TARGET}/observations"
    body = b"x" * (MAX_BODY_BYTES + 1)
    headers = request_headers(
        _SEED_B64U, method="POST", path=path, body=body, nonce=_NONCE
    )
    response = send(client, method="POST", path=path, headers=headers, body=body)
    assert response.status_code == 413
    assert c.H_RESPONSE_SIGNATURE not in response.headers
    assert not handlers.calls
    assert c.classify_unsigned_response(413) == "cp_unreachable"


def test_the_rate_limit_is_per_authenticated_credential_and_unsigned() -> None:
    limiter = SlidingWindowRateLimiter(limit=2, window_seconds=60.0)
    client, handlers, nonces = _rig(limiter=limiter)
    # An unauthenticated caller naming this credential spends none of its budget.
    for n in (10, 11, 12):
        headers = request_headers(
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            method="GET",
            path=_PATH,
            nonce=f"{n:032x}",
        )
        forged = send(client, method="GET", path=_PATH, headers=headers)
        assert forged.status_code == 401
    for n in (1, 2):
        assert _get(client, nonce=f"{n:032x}").status_code == 200
    third = _get(client, nonce=f"{3:032x}")
    assert third.status_code == 429
    assert c.H_RESPONSE_SIGNATURE not in third.headers
    assert len(handlers.calls) == 2
    assert f"cred-0001/{3:032x}" not in nonces.spent
    assert c.classify_unsigned_response(429) == "cp_unreachable"


def test_every_response_names_cp_time_and_is_signed_under_the_response_purpose() -> (
    None
):
    client, _, _ = _rig()
    ok = _get(client)
    refused = _get(client)  # the same nonce again
    for response in (ok, refused):
        assert response.json()["store_now"] == STORE_NOW
        signature = response.headers[c.H_RESPONSE_SIGNATURE]
        message = c.response_message(
            method="GET",
            path=_PATH,
            request_nonce=_NONCE,
            status=response.status_code,
            body=response.content,
        )
        assert signature == b64u(SeedSigner(_RESPONSE_SEED).sign(message))
        # the purpose is the response purpose, not the request purpose
        assert message.startswith(c.RESPONSE_PURPOSE.encode())
    assert refused.status_code == 401


def test_the_response_key_is_configured_by_name_and_never_a_test_key(
    tmp_path: Path,
) -> None:
    key = tmp_path / "response.key"
    key.write_text(_RESPONSE_SEED)
    key.chmod(0o644)
    env = {RESPONSE_KEY_FILE_ENV: str(key), RESPONSE_KEY_ID_ENV: "cp-response-1"}
    with pytest.raises(ResponseKeyUnavailable):
        load_response_signer(env)  # group/world readable
    key.chmod(0o600)
    signer = load_response_signer(env)
    assert signer.key_id == "cp-response-1"
    assert not c.is_denied_public_key(signer.public_key_b64u)
    with pytest.raises(ResponseKeyUnavailable):
        load_response_signer({})
    link = tmp_path / "link.key"
    os.symlink(key, link)
    with pytest.raises(ResponseKeyUnavailable):
        load_response_signer({**env, RESPONSE_KEY_FILE_ENV: str(link)})
    key.write_text("AA")  # not 32 bytes
    key.chmod(0o600)
    with pytest.raises(ResponseKeyUnavailable):
        load_response_signer(env)
