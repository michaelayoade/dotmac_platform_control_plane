"""The target API router: one authenticated, signed entrance.

ONE catch-all route under `/platform/deploy/target/v1`. Everything about the path
is decided by the contract (`parse_target_path`, called from `check_request`),
not by this framework's route table, so a percent-encoded separator, a trailing
slash or a query string reaches the same refusal as any other malformed path
instead of a redirect or a differently-routed handler. The route is composed once,
so "every target route carries the authentication" is one fact, not nine.

Order, per request: body cap (unsigned 413) -> authentication in a session this
function owns (`TargetRequestAuthenticator`) -> the handler in the SAME session
-> commit -> signed response. The commit happens BEFORE the response exists, so
a client can never hold a signed answer for a transaction that did not commit.

Every response, errors included, is signed under the response purpose bound to
the REQUEST's nonce and carries CP database time (`store_now`). The exceptions
are the unsigned transport faults the contract defines (413, 429) and a request
too malformed to name a nonce and a path.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Final

from fastapi import APIRouter, Request, Response
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from vendor_cp.deployment.target_api import contract as c
from vendor_cp.deployment.target_api.auth import (
    AuthenticatedCall,
    TargetApiRefusal,
    TargetRequestAuthenticator,
)
from vendor_cp.deployment.target_api.handlers import HandlerResult, TargetHandlers
from vendor_cp.deployment.target_api.response_signing import ResponseSigner

__all__ = ["MAX_BODY_BYTES", "TargetApiRuntime", "build_router", "signed_response"]

#: DESIGN-rev3 section 2.6: body cap 256 KiB.
MAX_BODY_BYTES: Final = 262_144

_METHODS: Final = ["GET", "POST", "PUT", "PATCH", "DELETE"]


@dataclass(frozen=True, slots=True)
class TargetApiRuntime:
    """Everything the router needs, fixed at startup. Nothing is request-selected."""

    authenticator: TargetRequestAuthenticator
    signer: ResponseSigner
    handlers: TargetHandlers
    #: One transaction: commit on success, rollback on error, close always
    #: (`dotmac_kernel.db.platform_session` in production).
    sessions: Callable[[], AbstractContextManager[Session]]


@dataclass(frozen=True, slots=True)
class _Outcome:
    status: int
    payload: dict[str, object]
    signed: bool


async def _read_body(request: Request) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None:
        if not declared.isdigit():
            raise TargetApiRefusal("bad_content_length", 400, signed=False)
        if int(declared) > MAX_BODY_BYTES:
            raise TargetApiRefusal("body_too_large", 413, signed=False)
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > MAX_BODY_BYTES:
            raise TargetApiRefusal("body_too_large", 413, signed=False)
        chunks.append(chunk)
    return b"".join(chunks)


def _raw_path(request: Request) -> str:
    """The path as the client sent it. ASGI decodes `%2F` in `path`, not here."""
    raw = request.scope.get("raw_path")
    if isinstance(raw, bytes):
        return raw.decode("latin-1")
    return str(request.scope["path"])


def _request_nonce(pairs: list[tuple[str, str]]) -> str | None:
    values = [v for k, v in pairs if k.lower() == c.H_NONCE.lower()]
    if len(values) != 1:
        return None
    try:
        return c.check_nonce(values[0])
    except c.TargetApiError:
        return None


def _dispatch(
    runtime: TargetApiRuntime,
    call: AuthenticatedCall,
    db: Session,
    method: str,
    body: bytes,
) -> HandlerResult:
    """Parse the JSON of a POST (refusing duplicate keys), then hand over.

    A refusal here is a RESULT, not an exception: the nonce is already spent in
    this session and the request has been fully authenticated, so it commits.
    """
    payload: object = None
    if method == "POST":
        try:
            payload = c.parse_json_body(body)
        except c.TargetApiError as exc:
            return HandlerResult(400, {"error": exc.code})
    return runtime.handlers.handle(call, db, payload)


def _serve(
    runtime: TargetApiRuntime,
    *,
    method: str,
    raw_path: str,
    query_string: str,
    pairs: list[tuple[str, str]],
    body: bytes,
) -> _Outcome:
    try:
        with runtime.sessions() as db:
            call = runtime.authenticator.authenticate(
                db,
                method=method,
                raw_path=raw_path,
                query_string=query_string,
                headers=pairs,
                body=body,
            )
            result = _dispatch(runtime, call, db, method, body)
        payload = dict(result.body)
        payload["store_now"] = call.store_now_stamp
        return _Outcome(result.status, payload, True)
    except TargetApiRefusal as refusal:
        payload = {"error": refusal.code}
        if refusal.store_now is not None:
            payload["store_now"] = refusal.store_now
        return _Outcome(refusal.status, payload, refusal.signed)


def signed_response(
    runtime: TargetApiRuntime,
    *,
    content: bytes,
    status: int,
    method: str,
    raw_path: str,
    request_nonce: str | None,
    sign: bool = True,
) -> Response:
    """The one place a response is built and signed.

    Signed over the response purpose, the verb, the path, the REQUEST's nonce,
    the status and the body hash. A request too malformed to name a nonce and a
    target path gets an unsigned answer, which a client treats as a failed
    signature (4xx) or a retryable fault (413, 429, 5xx).
    """
    headers = {"Cache-Control": "no-store"}
    if sign and request_nonce is not None:
        try:
            c.parse_target_path(raw_path)
            message = c.response_message(
                method=method,
                path=raw_path,
                request_nonce=request_nonce,
                status=status,
                body=content,
            )
        except c.TargetApiError:
            pass
        else:
            headers[c.H_RESPONSE_SIGNATURE] = c.b64u_encode(
                runtime.signer.sign(message)
            )
    return Response(
        content=content,
        status_code=status,
        media_type="application/json",
        headers=headers,
    )


def _response(
    runtime: TargetApiRuntime,
    outcome: _Outcome,
    *,
    method: str,
    raw_path: str,
    request_nonce: str | None,
) -> Response:
    content = json.dumps(outcome.payload, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return signed_response(
        runtime,
        content=content,
        status=outcome.status,
        method=method,
        raw_path=raw_path,
        request_nonce=request_nonce,
        sign=outcome.signed,
    )


def build_router(provider: Callable[[], TargetApiRuntime]) -> APIRouter:
    router = APIRouter(prefix=c.BASE_PATH, include_in_schema=False)

    @router.api_route("/{rest:path}", methods=_METHODS)
    async def target_api(request: Request) -> Response:
        runtime = provider()
        method = request.method.upper()
        raw_path = _raw_path(request)
        pairs = [(str(k), str(v)) for k, v in request.headers.items()]
        nonce = _request_nonce(pairs)
        try:
            body = await _read_body(request)
        except TargetApiRefusal as refusal:
            outcome = _Outcome(refusal.status, {"error": refusal.code}, False)
        else:
            outcome = await run_in_threadpool(
                _serve,
                runtime,
                method=method,
                raw_path=raw_path,
                query_string=request.scope.get("query_string", b"").decode("latin-1"),
                pairs=pairs,
                body=body,
            )
        return _response(
            runtime, outcome, method=method, raw_path=raw_path, request_nonce=nonce
        )

    return router
