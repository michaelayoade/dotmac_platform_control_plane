"""`ControlConsumptionClient`: the target-side client of the one target API.

It replaces the target's database reach. The target holds NO database credential,
no `pg_hba` entry and no route to the CP host: it signs each request with the
enrolled PoP key and talks HTTPS to the one target API (DESIGN-rev3 sections 2.6
and 3), pinning the CA at enrolment and a distinct CP response key.

Pure stdlib plus `cryptography`; it imports the contract, never SQLAlchemy or the
kernel, because it runs on the target.

Every response is judged by the contract's `check_response` BEFORE anything in it
is believed: exactly one canonical signature, a request-bound message, a valid
signature under the pinned response key. An unsigned 413/429/5xx is a retryable
transport fault; any other unsigned answer is a forged one. The host clock is
checked against the signed CP time on every response.

`refuse_database_environment` is the inverted tripwire: a target that carries any
database setting refuses to start, because a database path is exactly what this
client exists to remove.
"""

from __future__ import annotations

import json
import secrets
import ssl
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vendor_cp.deployment.target_api import contract as c

__all__ = [
    "DATABASE_ENV_NAMES",
    "AlreadyConsumedError",
    "ConsumptionClientError",
    "ControlConsumptionClient",
    "ControlRefusedError",
    "DatabaseReachRefused",
    "Transport",
    "TransportResponse",
    "UrllibTransport",
    "load_pop_seed",
    "refuse_database_environment",
]

#: Settings that name a database. Any of them, or any `PG*`, refuses.
DATABASE_ENV_NAMES: Final = (
    "DISPATCH_CONSUMPTION_DATABASE_URL",
    "DATABASE_URL",
    "PLATFORM_DATABASE_URL",
    "LANE3_LEASE_DATABASE_URL",
)
POP_KEY_CREDENTIAL: Final = "pop-key"
_CREDENTIALS_DIRECTORY: Final = "CREDENTIALS_DIRECTORY"


class DatabaseReachRefused(RuntimeError):
    """A target carries a database setting. Names only, never values."""


def refuse_database_environment(environ: Mapping[str, str]) -> None:
    present = sorted(
        name for name in environ if name in DATABASE_ENV_NAMES or name.startswith("PG")
    )
    if present:
        raise DatabaseReachRefused(
            "a target holds no database credential; remove: " + ", ".join(present)
        )


class ConsumptionClientError(Exception):
    """A closed client-side failure. `code` never carries a value."""

    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


class ControlRefusedError(ConsumptionClientError):
    """A SIGNED refusal from CP."""

    def __init__(self, status: int, code: str) -> None:
        super().__init__(code, retryable=status in (500, 503))
        self.status = status


class AlreadyConsumedError(ConsumptionClientError):
    """`409 already_consumed`: the dispatch committed; take `lookup_committed`."""

    def __init__(self, marker: object) -> None:
        super().__init__("already_consumed")
        self.marker = marker


@dataclass(frozen=True, slots=True)
class TransportResponse:
    status: int
    headers: Sequence[tuple[str, str]]
    body: bytes


class Transport(Protocol):
    def request(
        self,
        method: str,
        path: str,
        headers: Sequence[tuple[str, str]],
        body: bytes,
    ) -> TransportResponse: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class UrllibTransport:
    """HTTPS to the one CP origin, the CA pinned at enrolment, no redirects."""

    def __init__(self, base_url: str, *, ca_file: str, timeout: float = 30.0) -> None:
        if not base_url.startswith("https://") or base_url.endswith("/"):
            raise ValueError("the target API is reached over https, no trailing slash")
        context = ssl.create_default_context(cafile=ca_file)
        self._base = base_url
        self._timeout = timeout
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context), _NoRedirect
        )

    def request(
        self,
        method: str,
        path: str,
        headers: Sequence[tuple[str, str]],
        body: bytes,
    ) -> TransportResponse:
        # S310's premise is a URL of unknown provenance: the scheme is fixed to
        # https in `__init__` and the path is built by `contract.target_path`.
        req = urllib.request.Request(  # noqa: S310
            self._base + path,
            data=body if method == "POST" else None,
            method=method,
            headers=dict(headers),
        )
        try:
            with self._opener.open(req, timeout=self._timeout) as response:
                return TransportResponse(
                    response.status, list(response.headers.items()), response.read()
                )
        except urllib.error.HTTPError as error:
            return TransportResponse(
                error.code, list(error.headers.items()), error.read()
            )


def load_pop_seed(environ: Mapping[str, str]) -> bytes:
    """The PoP key's seed: `pop-key` in the systemd credentials directory."""
    directory = environ.get(_CREDENTIALS_DIRECTORY, "").strip()
    if not directory:
        raise ConsumptionClientError("pop_key_unavailable")
    path = Path(directory) / POP_KEY_CREDENTIAL
    try:
        if path.is_symlink():
            raise ConsumptionClientError("pop_key_unavailable")
        seed = c.b64u_decode(path.read_text(encoding="ascii").strip())
    except (OSError, UnicodeError, c.TargetApiError):
        raise ConsumptionClientError("pop_key_unavailable") from None
    if len(seed) != 32:
        raise ConsumptionClientError("pop_key_unavailable")
    return seed


class ControlConsumptionClient:
    def __init__(
        self,
        *,
        transport: Transport,
        target_ref: str,
        credential_id: str,
        pop_seed: bytes,
        response_public_key_b64u: str,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        nonce: Callable[[], str] = lambda: secrets.token_hex(16),
    ) -> None:
        if c.is_denied_public_key(response_public_key_b64u):
            raise ConsumptionClientError("response_key_denied")
        try:
            self._response_key = Ed25519PublicKey.from_public_bytes(
                c.b64u_decode(response_public_key_b64u)
            )
            self._pop_key = Ed25519PrivateKey.from_private_bytes(pop_seed)
        except (c.TargetApiError, ValueError):
            raise ConsumptionClientError("key_material_invalid") from None
        self._transport = transport
        self._target_ref = target_ref
        self._credential_id = credential_id
        self._clock = clock
        self._nonce = nonce

    # -- the endpoints the bindings call ------------------------------------

    def resolve(self, request: Mapping[str, object]) -> Mapping[str, Any]:
        return self._call("POST", "resolve", request)

    def consume(self, request: Mapping[str, object]) -> Mapping[str, Any]:
        """The committed marker. `AlreadyConsumedError` carries the existing one."""
        return self._call("POST", "consume", request)

    def lookup_committed(self, dispatch_id: str) -> Mapping[str, Any] | None:
        try:
            return self._call("GET", "committed", None, dispatch_id=dispatch_id)
        except ControlRefusedError as refusal:
            if refusal.status == 404 and refusal.code == "not_committed":
                return None
            raise

    # -- the one exchange ------------------------------------------------------

    def _call(
        self,
        method: str,
        route: str,
        payload: Mapping[str, object] | None,
        *,
        dispatch_id: str | None = None,
    ) -> Mapping[str, Any]:
        path = c.target_path(self._target_ref, route, dispatch_id=dispatch_id)
        body = (
            b""
            if payload is None
            else json.dumps(
                dict(payload), sort_keys=True, separators=(",", ":")
            ).encode()
        )
        nonce = c.check_nonce(self._nonce())
        issued_at = c.format_stamp(self._clock())
        message = c.request_message(
            method=method,
            path=path,
            body=body,
            credential_id=self._credential_id,
            target_ref=self._target_ref,
            issued_at=issued_at,
            nonce=nonce,
        )
        headers = c.request_headers(
            credential_id=self._credential_id,
            target_ref=self._target_ref,
            issued_at=issued_at,
            nonce=nonce,
            signature_b64u=c.b64u_encode(self._pop_key.sign(message)),
        )
        try:
            answer = self._transport.request(method, path, list(headers.items()), body)
        except OSError:
            raise ConsumptionClientError("cp_unreachable", retryable=True) from None
        return self._judge(method, path, nonce, answer)

    def _judge(
        self, method: str, path: str, nonce: str, answer: TransportResponse
    ) -> Mapping[str, Any]:
        try:
            check = c.check_response(
                method=method,
                path=path,
                request_nonce=nonce,
                status=answer.status,
                body=answer.body,
                headers=list(answer.headers),
            )
        except c.TargetApiError as exc:
            raise ConsumptionClientError(
                exc.code, retryable=exc.code == "cp_unreachable"
            ) from None
        try:
            self._response_key.verify(check.signature, check.message)
        except InvalidSignature:
            raise ConsumptionClientError("response_signature_invalid") from None
        try:
            document = c.parse_json_body(answer.body)
        except c.TargetApiError:
            raise ConsumptionClientError("response_malformed") from None
        if not isinstance(document, dict):
            raise ConsumptionClientError("response_malformed")
        try:
            c.check_skew(c.format_stamp(self._clock()), str(document.get("store_now")))
        except c.TargetApiError:
            # The host clock disagrees with SIGNED CP time: nothing is believed.
            raise ConsumptionClientError("clock_skew") from None
        error = document.get("error")
        if answer.status == 200:
            return document
        if answer.status == 409 and error == "already_consumed":
            raise AlreadyConsumedError(document.get("committed"))
        raise ControlRefusedError(answer.status, str(error))
