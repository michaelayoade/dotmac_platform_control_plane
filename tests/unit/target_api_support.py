"""Shared harness for the target-API tests.

Everything here drives the REAL router (`build_router`) over HTTP with a
Starlette `TestClient`. The ports it fills in (credential directory, nonce
ledger, clock, handlers) are the router's declared seams, not substitutes for it.
The request signing below is written out by hand, independent of the contract
mirror, so a mistake in the mirror cannot make its own test pass.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from contextlib import nullcontext
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from vendor_cp.deployment.target_api.auth import (
    AuthenticatedCall,
    CredentialDirectory,
    CredentialRecord,
    NonceLedger,
    SlidingWindowRateLimiter,
    TargetRequestAuthenticator,
)
from vendor_cp.deployment.target_api.handlers import HandlerResult, TargetHandlers
from vendor_cp.deployment.target_api.router import TargetApiRuntime, build_router

VECTOR_FILE = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "target_api"
    / "target_api_v1.json"
)
#: Control a18's CHANGELOG value for `contract/target_api_v1.json`.
PINNED_VECTOR_SHA256 = (
    "2e02f2ca295ee531d819d8c09aa7887ed4801c6272e60dd8b2c151d21929a907"
)
BASE = "/platform/deploy/target/v1"
TARGET = "dotmac-erp-v2/production/host-a"
STORE_NOW = "2026-11-22T10:00:00Z"


def vectors() -> dict[str, Any]:
    loaded = json.loads(VECTOR_FILE.read_bytes())
    assert isinstance(loaded, dict)
    return loaded


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def stamp(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


class SeedSigner:
    """An Ed25519 signer from a seed, including the vector file's PUBLISHED seeds.

    The production signer refuses those (that is tested); the replay needs them
    to reproduce the vector signatures byte for byte.
    """

    def __init__(self, seed_b64u: str, *, key_id: str = "test-response-key") -> None:
        self._key = Ed25519PrivateKey.from_private_bytes(unb64u(seed_b64u))
        self._key_id = key_id

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def public_key_b64u(self) -> str:
        return b64u(self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))

    def sign(self, message: bytes) -> bytes:
        return bytes(self._key.sign(message))


def request_signature(
    seed_b64u: str,
    *,
    method: str,
    path: str,
    body: bytes,
    credential_id: str,
    target_ref: str,
    issued_at: str,
    nonce: str,
) -> str:
    """The request signature, from the wire definition written out by hand."""
    message = "\n".join(
        [
            "dotmac.target_request.v1",
            method,
            path,
            hashlib.sha256(body).hexdigest(),
            credential_id,
            target_ref,
            issued_at,
            nonce,
        ]
    ).encode("utf-8")
    key = Ed25519PrivateKey.from_private_bytes(unb64u(seed_b64u))
    return b64u(key.sign(message))


def request_headers(
    seed_b64u: str,
    *,
    method: str,
    path: str,
    body: bytes = b"",
    credential_id: str = "cred-0001",
    target_ref: str = TARGET,
    issued_at: str = STORE_NOW,
    nonce: str,
) -> list[tuple[str, str]]:
    return [
        ("X-Dotmac-Credential-Id", credential_id),
        ("X-Dotmac-Target-Ref", target_ref),
        ("X-Dotmac-Issued-At", issued_at),
        ("X-Dotmac-Nonce", nonce),
        (
            "X-Dotmac-Signature",
            request_signature(
                seed_b64u,
                method=method,
                path=path,
                body=body,
                credential_id=credential_id,
                target_ref=target_ref,
                issued_at=issued_at,
                nonce=nonce,
            ),
        ),
    ]


class StaticDirectory:
    """Answers every id with one record, as the id the record says it is."""

    def __init__(self, record: CredentialRecord | None) -> None:
        self.record = record
        self.lookups: list[str] = []

    def lookup(
        self, db: Session, credential_id: str, *, at: datetime
    ) -> CredentialRecord | None:
        self.lookups.append(credential_id)
        return self.record


class MemoryNonces:
    def __init__(self) -> None:
        self.spent: set[str] = set()

    def spend(self, db: Session, ledger_key: str) -> bool:
        if ledger_key in self.spent:
            return False
        self.spent.add(ledger_key)
        return True


class RecordingHandlers:
    def __init__(self, result: HandlerResult | None = None) -> None:
        self.calls: list[tuple[AuthenticatedCall, object]] = []
        self._result = result or HandlerResult(200, {"ok": True})

    def handle(
        self, call: AuthenticatedCall, db: Session, payload: object
    ) -> HandlerResult:
        self.calls.append((call, payload))
        return self._result


def record(
    *,
    public_key_b64u: str,
    credential_id: str = "cred-0001",
    target_ref: str = TARGET,
    eligible: bool = True,
    purpose_ok: bool = True,
) -> CredentialRecord:
    return CredentialRecord(
        credential_id=credential_id,
        target_ref=target_ref,
        public_key_b64u=public_key_b64u,
        eligible=eligible,
        purpose_ok=purpose_ok,
    )


def build_runtime(
    *,
    directory: CredentialDirectory,
    response_seed: str,
    store_now: str = STORE_NOW,
    nonces: NonceLedger | None = None,
    handlers: TargetHandlers | None = None,
    denied: frozenset[str] | None = None,
    limiter: SlidingWindowRateLimiter | None = None,
) -> TargetApiRuntime:
    """`denied=frozenset()` lets the replay admit the vector file's published
    request key; production composition (`install_runtime`) never passes it."""
    kwargs: dict[str, Any] = {}
    if denied is not None:
        kwargs["denied_public_keys"] = denied
    instant = stamp(store_now)
    return TargetApiRuntime(
        authenticator=TargetRequestAuthenticator(
            directory=directory,
            nonces=nonces or MemoryNonces(),
            clock=lambda db: instant,
            limiter=limiter or SlidingWindowRateLimiter(limit=10_000),
            **kwargs,
        ),
        signer=SeedSigner(response_seed),
        handlers=handlers or RecordingHandlers(),
        sessions=lambda: nullcontext(None),  # type: ignore[arg-type,return-value]
    )


def client_for(runtime: TargetApiRuntime) -> TestClient:
    app = FastAPI()
    app.include_router(build_router(lambda: runtime))
    return TestClient(app)


def send(
    client: TestClient,
    *,
    method: str,
    path: str,
    headers: Mapping[str, str] | list[tuple[str, str]],
    body: bytes = b"",
    query: str = "",
) -> Any:
    pairs = list(headers.items()) if isinstance(headers, Mapping) else list(headers)
    url = f"{path}?{query}" if query else path
    return client.request(method, url, content=body, headers=pairs)
