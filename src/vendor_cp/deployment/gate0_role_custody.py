"""Role-local custody source. No installation bindings or custody ceremony.

A4 provisional private_key_b64url encoding needs CP owner confirmation.
All external HTTP work runs in a killable child; secrets use memory pipes only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import multiprocessing
import os
import select
import struct
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from multiprocessing.connection import Connection
from typing import TYPE_CHECKING, Literal, cast
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from vendor_cp.deployment.rehearsal_issuer_trust_state import (
    RehearsalIssuerTrustState,
    TrustEligibility,
)

if TYPE_CHECKING:
    from dotmac_deployment_control import (
        RehearsalIssuerAuthorizationSignature,
        RehearsalIssuerAuthorizationSignerIdentity,
    )

JSONRecord = dict[str, object]


class ProviderRefused(ValueError):
    def __init__(self) -> None:
        super().__init__("gate0_provider_refused")


def json_record(value: object) -> JSONRecord:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise ProviderRefused()
    return cast(JSONRecord, value)


def json_string(value: object) -> str:
    if type(value) is not str:
        raise ProviderRefused()
    return value


def json_integer(value: object) -> int:
    if type(value) is not int:
        raise ProviderRefused()
    return value


def strict_json(raw: bytes, maximum: int = 131072) -> JSONRecord:
    def pairs(items: list[tuple[str, object]]) -> JSONRecord:
        result: JSONRecord = {}
        for key, value in items:
            if key in result:
                raise ProviderRefused()
            result[key] = value
        return result

    def constant(_: str) -> object:
        raise ProviderRefused()

    failed = False
    result: JSONRecord | None = None
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= maximum:
            raise ProviderRefused()
        result = json_record(
            json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
        )
    except Exception:
        failed = True
    if failed or result is None:
        raise ProviderRefused()
    return result


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        raise ProviderRefused()


def _http_child(
    connection: Connection,
    url: str,
    method: str,
    token: str | None,
    body: bytes | None,
    timeout: float,
    maximum: int,
) -> None:
    """Child has no stdout diagnostics and never returns exception details."""
    try:
        headers = {"Content-Type": "application/json"}
        if token is not None:
            headers["X-Vault-Token"] = token
        # Constructor and fixed path owner enforce HTTPS before spawning.
        request = urllib.request.Request(  # noqa: S310
            url, data=body, headers=headers, method=method
        )
        # Ignore proxy environment; TLS uses system trust, hostname verification on.
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect()
        )
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(maximum + 1)
            if response.status != 200 or len(raw) > maximum:
                raise ProviderRefused()
        connection.send_bytes(raw)
    except Exception:
        try:
            connection.send_bytes(b"")
        except Exception:  # noqa: S110 -- closed IPC must never emit diagnostics
            pass
    finally:
        try:
            connection.close()
        except Exception:  # noqa: S110 -- teardown emits no source exception details
            pass


def _receive_message(
    connection: Connection, deadline: float, maximum: int = 131072
) -> bytes:
    """Read multiprocessing's small-message frame without blocking on a body.

    send_bytes uses a signed network-order 32-bit length below 2 GiB. Our
    child never sends the extended-length form; reject it and oversized frames.
    Readiness alone is never treated as complete header/payload availability.
    """
    descriptor = connection.fileno()
    os.set_blocking(descriptor, False)

    def exact(length: int) -> bytes:
        received = bytearray()
        while len(received) < length:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProviderRefused()
            ready, _, _ = select.select([descriptor], [], [], remaining)
            if not ready or time.monotonic() >= deadline:
                raise ProviderRefused()
            try:
                part = os.read(descriptor, length - len(received))
            except (BlockingIOError, InterruptedError):
                continue
            if not part:
                raise ProviderRefused()
            received.extend(part)
        if time.monotonic() >= deadline:
            raise ProviderRefused()
        return bytes(received)

    length = struct.unpack("!i", exact(4))[0]
    if not 0 < length <= maximum:
        raise ProviderRefused()
    return exact(length)


@dataclass(frozen=True, slots=True)
class BoundedJSONTransport:
    """Fixed HTTPS origin, no redirects/proxies; hard parent cancellation bound.

    A child is killed on timeout. No thread or callback can retain a late result.
    The caller's original monotonic deadline also bounds cache-independent work.
    """

    origin: str
    timeout: float = 5.0

    def __post_init__(self) -> None:
        parsed = urlsplit(self.origin)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
            or not math.isfinite(self.timeout)
            or not 0 < self.timeout <= 5
        ):
            raise ProviderRefused()

    def request(
        self,
        path: str,
        *,
        method: str,
        token: str | None,
        document: Mapping[str, object] | None,
        deadline: float,
    ) -> JSONRecord:
        if (
            not (
                path.startswith("/v1/")
                or (
                    path == "/.well-known/jwks"
                    and self.origin.rstrip("/")
                    == "https://token.actions.githubusercontent.com"
                )
            )
            or ".." in path
            or "?" in path
            or "#" in path
            or method not in ("GET", "POST")
            or not math.isfinite(deadline)
        ):
            raise ProviderRefused()
        io_deadline = min(deadline, time.monotonic() + self.timeout)
        remaining = io_deadline - time.monotonic()
        if remaining <= 0:
            raise ProviderRefused()
        body = (
            None if document is None else json.dumps(document, allow_nan=False).encode()
        )
        if body is not None and len(body) > 32768:
            raise ProviderRefused()
        parent, child = multiprocessing.get_context("spawn").Pipe(duplex=False)
        process = multiprocessing.get_context("spawn").Process(
            target=_http_child,
            args=(
                child,
                self.origin.rstrip("/") + path,
                method,
                token,
                body,
                remaining,
                131072,
            ),
            daemon=True,
        )
        failed = False
        raw = b""
        try:
            process.start()
            child.close()
            raw = _receive_message(parent, io_deadline)
        except Exception:
            failed = True
        finally:
            parent.close()
            child.close()
            if process.pid is not None:
                if process.is_alive():
                    process.kill()
                process.join(timeout=0.2)
                if process.is_alive():
                    failed = True
        if failed or time.monotonic() >= io_deadline:
            raise ProviderRefused()
        result = strict_json(raw)
        if time.monotonic() >= io_deadline:
            raise ProviderRefused()
        return result


@dataclass(frozen=True, slots=True)
class RolePaths:
    approle: str
    seed: str

    @classmethod
    def for_role(cls, role: str) -> RolePaths:
        if role not in ("issuer", "attester"):
            raise ProviderRefused()
        return cls(
            f"platform-cp-rehearsal-{role}",
            f"secret/data/dotmac/platform-cp/rehearsal-{role}/signing-key",
        )


def _fingerprint(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@dataclass(slots=True, repr=False)
class LocalRoleKey:
    role: Literal["issuer", "attester"]
    key_id: str
    public_key: bytes
    trust: RehearsalIssuerTrustState
    _private: Ed25519PrivateKey = field(repr=False)
    _deadline: float = field(repr=False)
    _expires: datetime = field(repr=False)
    _started: datetime = field(repr=False)
    _origin: float = field(repr=False)

    @property
    def purpose(self) -> str:
        return (
            "deployment_rehearsal_issuer"
            if self.role == "issuer"
            else "deployment_rehearsal_harness_evidence"
        )

    def _open(self) -> None:
        if (
            not self._origin <= time.monotonic() < self._deadline
            or not self._started <= datetime.now(UTC) < self._expires
            or self.trust.eligibility(
                key_id=self.key_id, public_key_fingerprint=_fingerprint(self.public_key)
            )
            != TrustEligibility.ELIGIBLE
        ):
            raise ProviderRefused()

    def attester_sign(self, message: bytes) -> bytes:
        if self.role != "attester":
            raise ProviderRefused()
        return self._sign(message)

    def _sign(self, message: bytes) -> bytes:
        self._open()
        if type(message) is not bytes or not 0 < len(message) <= 131072:
            raise ProviderRefused()
        signature = self._private.sign(message)
        self._open()
        return signature

    @property
    def rehearsal_issuer_identity(self) -> RehearsalIssuerAuthorizationSignerIdentity:
        from dotmac_deployment_control import (
            RehearsalIssuerAuthorizationSignerIdentity,
        )

        if self.role != "issuer":
            raise ProviderRefused()
        self._open()
        return RehearsalIssuerAuthorizationSignerIdentity(
            self.key_id, "ed25519", _fingerprint(self.public_key)
        )

    def sign_rehearsal_issuer_authorization(
        self, canonical_bytes: bytes
    ) -> RehearsalIssuerAuthorizationSignature:
        from dotmac_deployment_control import (
            RehearsalIssuerAuthorizationSignature,
        )

        if self.role != "issuer":
            raise ProviderRefused()
        return RehearsalIssuerAuthorizationSignature(
            self.key_id,
            "ed25519",
            self.purpose,
            _fingerprint(self.public_key),
            base64.b64encode(self._sign(canonical_bytes)).decode(),
        )


@dataclass(frozen=True, slots=True)
class PublicIssuerVerifier:
    key_id: str
    public_key: bytes
    trust: RehearsalIssuerTrustState
    deadline: float
    expires_at: datetime
    started_at: datetime
    monotonic_origin: float

    def verify_rehearsal_issuer_authorization(
        self,
        *,
        key_id: str,
        algorithm: str,
        purpose: str,
        public_key_fingerprint: str,
        canonical_bytes: bytes,
        signature: str,
    ) -> bool:
        try:
            if (
                not self.monotonic_origin <= time.monotonic() < self.deadline
                or not self.started_at <= datetime.now(UTC) < self.expires_at
                or key_id != self.key_id
                or algorithm != "ed25519"
                or purpose != "deployment_rehearsal_issuer"
                or public_key_fingerprint != _fingerprint(self.public_key)
                or self.trust.eligibility(
                    key_id=key_id, public_key_fingerprint=public_key_fingerprint
                )
                != TrustEligibility.ELIGIBLE
                or type(canonical_bytes) is not bytes
                or not 0 < len(canonical_bytes) <= 131072
            ):
                return False
            Ed25519PublicKey.from_public_bytes(self.public_key).verify(
                base64.b64decode(signature, validate=True), canonical_bytes
            )
            return (
                self.monotonic_origin <= time.monotonic() < self.deadline
                and self.started_at <= datetime.now(UTC) < self.expires_at
                and self.trust.eligibility(
                    key_id=key_id, public_key_fingerprint=public_key_fingerprint
                )
                == TrustEligibility.ELIGIBLE
            )
        except (InvalidSignature, ValueError, TypeError):
            return False


@dataclass(slots=True, repr=False)
class RoleMaterial:
    key: LocalRoleKey
    issuer_trust: RehearsalIssuerTrustState
    attester_trust: RehearsalIssuerTrustState

    @property
    def public_key(self) -> bytes:
        return self.key.public_key

    @property
    def issuer_signer(self) -> LocalRoleKey:
        if self.key.role != "issuer":
            raise ProviderRefused()
        return self.key

    @property
    def issuer_verifier(self) -> PublicIssuerVerifier:
        if self.key.role != "issuer":
            raise ProviderRefused()
        return PublicIssuerVerifier(
            self.key.key_id,
            self.key.public_key,
            self.issuer_trust,
            self.key._deadline,
            self.key._expires,
            self.key._started,
            self.key._origin,
        )

    @property
    def attester_sign(self) -> Callable[[bytes], bytes]:
        if self.key.role != "attester":
            raise ProviderRefused()
        return self.key.attester_sign


class RoleCustody:
    """One bootstrap per instance; exact paths, <=300s and <=32 token uses.

    seed_format is intentionally unset until the custody owner adopts the
    A4 provisional {key_id, private_key_b64url} wire encoding.
    No callback decoder is executed.
    Public refresh is explicit. Failure poisons the provider; no renewal/retry.
    """

    def __init__(
        self,
        *,
        role: Literal["issuer", "attester"],
        role_id: str,
        key_id: str,
        public_key: bytes,
        minimum_versions: dict[str, int],
        transport: BoundedJSONTransport | None = None,
        seed_format: Literal["a4-provisional-private-key-b64url"] | None = None,
        expires_at: datetime | None = None,
    ) -> None:
        self.paths = RolePaths.for_role(role)
        if (
            type(transport) is not BoundedJSONTransport
            or seed_format != "a4-provisional-private-key-b64url"
            or type(public_key) is not bytes
            or len(public_key) != 32
            or not role_id
            or not key_id
            or len(role_id) > 512
            or len(key_id) > 512
            or set(minimum_versions) != {"issuer", "attester"}
            or any(type(v) is not int or v < 1 for v in minimum_versions.values())
            or expires_at is None
            or expires_at.tzinfo is None
            or not 0 < (expires_at - datetime.now(UTC)).total_seconds() <= 300
        ):
            raise ProviderRefused()
        self.role, self.role_id, self.key_id = role, role_id, key_id
        self.public_key, self.transport = public_key, transport
        self.minimum_versions = dict(minimum_versions)
        self.expires_at = expires_at
        self.started_at = datetime.now(UTC)
        self.origin = time.monotonic()
        self.deadline = self.origin + (expires_at - self.started_at).total_seconds()
        self._started = False
        self._closed = False
        self._token: str | None = None
        self._uses = 0
        self._material: RoleMaterial | None = None

    def _request(
        self,
        path: str,
        *,
        token: str | None = None,
        document: Mapping[str, object] | None = None,
        method: str = "POST",
    ) -> JSONRecord:
        if (
            self._closed
            or not self.origin <= time.monotonic() < self.deadline
            or not self.started_at <= datetime.now(UTC) < self.expires_at
        ):
            raise ProviderRefused()
        if token == self._token and token is not None:
            self._uses += 1
            if self._uses > 32:
                raise ProviderRefused()
        return self.transport.request(
            path, method=method, token=token, document=document, deadline=self.deadline
        )

    def bootstrap(self, wrapping_token: str) -> RoleMaterial:
        if self._started or self._closed:
            raise ProviderRefused()
        self._started = True
        failed = False
        try:
            if (
                not isinstance(wrapping_token, str)
                or not 0 < len(wrapping_token) <= 8192
            ):
                raise ProviderRefused()
            wrap = json_record(
                self._request(
                    "/v1/sys/wrapping/lookup",
                    token=wrapping_token,
                    document={"token": wrapping_token},
                )["data"]
            )
            created = datetime.fromisoformat(
                json_string(wrap["creation_time"]).replace("Z", "+00:00")
            )
            ttl = json_integer(wrap["creation_ttl"])
            age = (datetime.now(UTC) - created).total_seconds()
            if (
                wrap["creation_path"]
                != f"auth/approle/role/{self.paths.approle}/secret-id"
                or type(ttl) is not int
                or not 0 < ttl <= 300
                or not 0 <= age < ttl
            ):
                raise ProviderRefused()
            secret = json_record(
                self._request(
                    "/v1/sys/wrapping/unwrap", token=wrapping_token, document={}
                )["data"]
            )
            if (
                type(secret.get("secret_id_num_uses")) is not int
                or secret.get("secret_id_num_uses") != 1
                or type(secret.get("secret_id_ttl")) is not int
                or not 0 < json_integer(secret["secret_id_ttl"]) <= 300
                or not isinstance(secret.get("secret_id"), str)
            ):
                raise ProviderRefused()
            auth = json_record(
                self._request(
                    "/v1/auth/approle/login",
                    document={
                        "role_id": self.role_id,
                        "secret_id": secret["secret_id"],
                    },
                )["auth"]
            )
            if (
                auth.get("renewable") is not False
                or type(auth.get("lease_duration")) is not int
                or not 0 < json_integer(auth["lease_duration"]) <= 300
                or not isinstance(auth.get("client_token"), str)
            ):
                raise ProviderRefused()
            self._token = json_string(auth["client_token"])
            self.deadline = min(
                self.deadline, time.monotonic() + json_integer(auth["lease_duration"])
            )
            lookup = json_record(
                self._request(
                    "/v1/auth/token/lookup-self", token=self._token, method="GET"
                )["data"]
            )
            if (
                lookup.get("renewable") is not False
                or type(lookup.get("num_uses")) is not int
                or not 0 < json_integer(lookup["num_uses"]) <= 32
                or type(lookup.get("ttl")) is not int
                or not 0 < json_integer(lookup["ttl"]) <= 300
            ):
                raise ProviderRefused()
            self._uses = 32 - json_integer(lookup["num_uses"])
            self.deadline = min(
                self.deadline, time.monotonic() + json_integer(lookup["ttl"])
            )
            seed = json_record(
                json_record(
                    self._request(
                        "/v1/" + self.paths.seed, token=self._token, method="GET"
                    )["data"]
                )["data"]
            )
            if (
                set(seed) != {"key_id", "private_key_b64url"}
                or seed["key_id"] != self.key_id
            ):
                raise ProviderRefused()
            encoded = json_string(seed["private_key_b64url"])
            raw = base64.b64decode(
                encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True
            )
            if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != encoded:
                raise ProviderRefused()
            private = Ed25519PrivateKey.from_private_bytes(raw)
            if (
                private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                != self.public_key
            ):
                raise ProviderRefused()
            states: dict[str, RehearsalIssuerTrustState] = {}
            for role in ("issuer", "attester"):
                record = self._trust_record(role)

                def read_record(record: JSONRecord = record) -> object:
                    return record

                states[role] = RehearsalIssuerTrustState.start(
                    minimum_version=self.minimum_versions[role],
                    read_record=read_record,
                )
            key = LocalRoleKey(
                self.role,
                self.key_id,
                self.public_key,
                states[self.role],
                private,
                self.deadline,
                self.expires_at,
                self.started_at,
                self.origin,
            )
            key._open()
            self._material = RoleMaterial(key, states["issuer"], states["attester"])
        except Exception:
            failed = True
        if failed or self._material is None:
            self.close()
            raise ProviderRefused()
        return self._material

    def _trust_record(self, role: str) -> JSONRecord:
        return json_record(
            json_record(
                self._request(
                    f"/v1/secret/data/dotmac/platform-cp/rehearsal-{role}/trust-state",
                    token=self._token,
                    method="GET",
                )["data"]
            )["data"]
        )

    def refresh(self) -> None:
        if self._material is None or self._closed:
            raise ProviderRefused()
        failed = False
        try:
            for role, state in (
                ("issuer", self._material.issuer_trust),
                ("attester", self._material.attester_trust),
            ):

                def read_record(role: str = role) -> object:
                    return self._trust_record(role)

                state.refresh(read_record=read_record)
        except Exception:
            failed = True
        if failed:
            self.close()
            raise ProviderRefused()

    def close(self) -> None:
        self._closed = True
        self._token = None
        if self._material is not None:
            for state in (self._material.issuer_trust, self._material.attester_trust):
                try:
                    state.refresh(read_record=lambda: None)
                except ValueError:
                    pass
            self._material = None
