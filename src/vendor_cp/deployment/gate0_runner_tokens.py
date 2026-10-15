"""Finite actual-job OIDC acquisition; signature authentication stays at servers."""

from __future__ import annotations

import base64
import http.client
import os
import re
import ssl
import time
from dataclasses import dataclass, field
from multiprocessing.connection import Connection
from urllib.parse import quote, unquote_plus, urlsplit

from vendor_cp.deployment.gate0_framing import strict_object
from vendor_cp.deployment.gate0_role_custody import ProviderRefused, _spawn_request
from vendor_cp.deployment.gate0_runner_projection import (
    _HOST,
    RunnerProjectionCase,
    _decode_response,
    _ProjectionHTTPResponse,
)

AUDIENCE = "urn:dotmac:gate0:rehearsal-issuer"


def _query_keys(query: str) -> None:
    """Reject ambiguous decoding before any actual job credential is retained.

    Keep original bytes for transport; decoding exists only to restrict names.
    A second percent escape, semicolon separator or control can be interpreted
    differently by brokers, so those encodings fail rather than normalize.
    """
    if type(query) is not str or not query or len(query) > 8192:
        raise ProviderRefused()
    seen = set()
    for pair in query.split("&"):
        if not pair or pair.count("=") != 1:
            raise ProviderRefused()
        key, value = pair.split("=", 1)
        for encoded in (key, value):
            if re.search(r"%(?![0-9A-Fa-f]{2})", encoded):
                raise ProviderRefused()
            decoded = None
            try:
                decoded = unquote_plus(encoded, encoding="utf-8", errors="strict")
            except UnicodeError:
                pass
            if decoded is None:
                raise ProviderRefused()
            if any(ord(c) <= 32 or ord(c) >= 127 or c in "%;&=#" for c in decoded):
                raise ProviderRefused()
        name = unquote_plus(key, encoding="utf-8", errors="strict").casefold()
        if not name or name == "audience" or name in seen:
            raise ProviderRefused()
        seen.add(name)


@dataclass(frozen=True, slots=True)
class JobBrokerBinding:
    """Exact independently installed request coordinates, never a URL pattern."""

    origin: str
    path: str
    query: str
    qualification_digest: str

    def request_path(self, actual: str) -> tuple[str, str]:
        _query_keys(self.query)
        parsed = urlsplit(actual)
        origin = urlsplit(self.origin)
        if (
            origin.scheme != "https"
            or origin.netloc != origin.hostname
            or not origin.hostname
            or _HOST.fullmatch(origin.hostname) is None
            or origin.path
            or origin.query
            or origin.fragment
            or not self.path.startswith("/")
            or self.path.startswith("//")
            or any(c in self.path + self.query for c in "\r\n#")
            or not self.query
            or parsed.scheme != "https"
            or parsed.netloc != origin.netloc
            or parsed.path != self.path
            or parsed.query != self.query
            or parsed.fragment
            or actual != self.origin + self.path + "?" + self.query
            or re.fullmatch(r"sha256:[0-9a-f]{64}", self.qualification_digest) is None
        ):
            raise ProviderRefused()
        return origin.hostname, self.path + "?" + self.query + "&audience=" + quote(
            AUDIENCE, safe=""
        )


def _token_child(
    pipe: Connection, host: str, path: str, credential: str, timeout: float
) -> None:
    connection = None
    response = None
    raw = None
    failed = False
    try:
        paths = ssl.get_default_verify_paths()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(
            cafile=paths.openssl_cafile, capath=paths.openssl_capath
        )
        connection = http.client.HTTPSConnection(
            host, 443, timeout=timeout, context=context
        )
        connection.response_class = _ProjectionHTTPResponse
        connection.request(
            "GET",
            path,
            body=None,
            headers={
                "Authorization": "Bearer " + credential,
                "Accept": "application/json",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        if type(response) is not _ProjectionHTTPResponse:
            raise ProviderRefused()
        raw = _decode_response(response)
    except BaseException:
        failed = True
    finally:
        for resource in (response, connection):
            try:
                if resource is not None:
                    resource.close()
            except BaseException:
                failed = True
    try:
        if not failed and raw is not None:
            pipe.send_bytes(raw)
    except BaseException:  # noqa: S110 -- no source exception crosses IPC
        pass
    finally:
        try:
            pipe.close()
        except BaseException:  # noqa: S110 -- never emit transport diagnostics
            pass


@dataclass(slots=True, repr=False)
class InstalledJobTokens:
    _cases: tuple[RunnerProjectionCase, RunnerProjectionCase]
    _host: str
    _path: str
    _credential: str = field(repr=False)
    _counts: list[int] = field(default_factory=lambda: [0, 0], repr=False)
    _failed: bool = False

    @classmethod
    def from_installed(cls, installation: object) -> InstalledJobTokens:
        # No caller URL/token or credential callback. The loader owns installation
        # provenance; acquisition is deferred until its case's actual use.
        from vendor_cp.deployment.gate0_runner_installation import (
            InstalledRunnerCollection,
        )

        if type(installation) is not InstalledRunnerCollection:
            raise ProviderRefused()
        installation.require_actual_job()
        host, path = installation.broker.request_path(
            os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
        )
        credential = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
        if not 0 < len(credential) <= 32768 or any(
            ord(c) <= 32 or ord(c) >= 127 for c in credential
        ):
            raise ProviderRefused()
        return cls(
            (installation.cases[0].projection, installation.cases[1].projection),
            host,
            path,
            credential,
        )

    def next(self, case: RunnerProjectionCase) -> str:
        failed = False
        result = None
        try:
            if self._failed or not any(case is item for item in self._cases):
                raise ProviderRefused()
            index = 0 if case is self._cases[0] else 1
            if self._counts[index] >= (8, 23)[index]:
                raise ProviderRefused()
            self._counts[index] += 1  # Attempts, including failure, consume slots.
            case.require_open()
            deadline = min(case.deadline, time.monotonic() + 5.0)
            raw = _spawn_request(
                _token_child,
                (self._host, self._path, self._credential, deadline - time.monotonic()),
                deadline,
            )
            if not 0 < len(raw) <= 65536:
                raise ProviderRefused()
            document = strict_object(raw, 65536)
            if set(document) != {"value"}:
                raise ProviderRefused()
            token = document["value"]
            if (
                type(token) is not str
                or not 0 < len(token) <= 32768
                or re.fullmatch(
                    r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token
                )
                is None
            ):
                raise ProviderRefused()
            payload = token.split(".")[1]
            claims = strict_object(
                base64.b64decode(
                    payload + "=" * (-len(payload) % 4), altchars=b"-_", validate=True
                ),
                24576,
            )
            expected = case.window.document["github"]
            if any(claims.get(k) != v for k, v in expected.items()):
                raise ProviderRefused()
            # Payload checks only restrict output. They do not authenticate JWTs.
            if (
                any(type(claims.get(k)) is not int for k in ("iat", "nbf", "exp"))
                or not claims["iat"] <= claims["nbf"] <= time.time() < claims["exp"]
                or not 0 < claims["exp"] - claims["iat"] <= 300
            ):
                raise ProviderRefused()
            case.require_open()
            if time.monotonic() >= deadline:
                raise ProviderRefused()
            result = token
        except Exception:
            failed = True
        if failed or result is None:
            self._failed = True
            self._credential = ""
            raise ProviderRefused()
        return result
