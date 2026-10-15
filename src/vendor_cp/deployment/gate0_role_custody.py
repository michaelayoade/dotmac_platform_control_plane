"""Role-local custody source. No installation bindings or custody ceremony.

A4 provisional private_key_b64url encoding needs CP owner confirmation.
All external HTTP work runs in a killable child; secrets use memory pipes only.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import ipaddress
import json
import math
import multiprocessing
import os
import re
import select
import signal
import socket
import stat
import struct
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from multiprocessing.connection import Connection
from types import MappingProxyType
from typing import TYPE_CHECKING, BinaryIO, Literal, cast
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
    TrustStateSnapshot,
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


def _spawn_request(
    target: Callable[..., None],
    args: tuple[object, ...],
    deadline: float,
    *,
    process_group: bool = False,
) -> bytes:
    """Shared spawn/IPC bound, reserving teardown time inside the I/O deadline."""
    remaining = deadline - time.monotonic()
    receive_deadline = deadline - min(0.2, max(0.0, remaining) / 10)
    if time.monotonic() >= receive_deadline:
        raise ProviderRefused()
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(target=target, args=(child, *args), daemon=True)
    failed, raw = False, b""
    try:
        process.start()
        child.close()
        raw = _receive_message(parent, receive_deadline)
    except Exception:
        failed = True
    finally:
        parent.close()
        child.close()
        if process.pid is not None:
            try:
                if process_group:
                    try:
                        if os.getpgid(process.pid) == process.pid:
                            os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                if process.is_alive():
                    process.kill()
                process.join(timeout=min(0.2, max(0.0, deadline - time.monotonic())))
                if process.is_alive():
                    failed = True
            except Exception:
                failed = True
    if failed or time.monotonic() >= deadline:
        raise ProviderRefused()
    return raw


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
        raw = _spawn_request(
            _http_child,
            (self.origin.rstrip("/") + path, method, token, body, remaining, 131072),
            io_deadline,
        )
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


_PIN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_INTERFACE = re.compile(r"[A-Za-z0-9_.-]{1,15}\Z")
_WG_BINARY = "/usr/bin/wg"
_NETWORK_FILE = "/run/dotmac-gate0/network.json"


def _private_ipv4(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        address = ipaddress.IPv4Address(value)
        return str(address) == value and any(
            address in ipaddress.IPv4Network(network)
            for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        )
    except ValueError:
        return False


@dataclass(frozen=True, slots=True)
class WireGuardBaoEndpoint:
    """Closed public pins; a digest alone never authenticates the launch.

    Bootstrap must bind these pins to its measured local launch context.
    Root-measured namespace/firewall immutability and the capability-free native
    device bind remain installation obligations, never boolean inputs. The
    worker consumes that measurement and executes no privileged WG query.
    """

    role: Literal["issuer", "attester"]
    address: str
    port: int
    local_address: str
    interface: str
    interface_index: int
    namespace_device: int
    namespace_inode: int
    peer_fingerprint: str
    peer_allowed_ip: str
    wg_binary_digest: str
    network_config_digest: str
    launch_packet_digest: str
    timeout: float = 5.0

    def __post_init__(self) -> None:
        if (
            self.role not in ("issuer", "attester")
            or not _private_ipv4(self.address)
            or not _private_ipv4(self.local_address)
            or self.address == self.local_address
            or type(self.port) is not int
            or not 1 <= self.port <= 65535
            or type(self.interface) is not str
            or _INTERFACE.fullmatch(self.interface) is None
            or self.interface in (".", "..")
            or any(
                type(v) is not int or not 0 < v <= 18446744073709551615
                for v in (
                    self.interface_index,
                    self.namespace_device,
                    self.namespace_inode,
                )
            )
            or self.interface_index > 2147483647
            or self.peer_allowed_ip != self.address + "/32"
            or any(
                type(v) is not str or _PIN.fullmatch(v) is None
                for v in (
                    self.peer_fingerprint,
                    self.wg_binary_digest,
                    self.network_config_digest,
                    self.launch_packet_digest,
                )
            )
            or type(self.timeout) not in (int, float)
            or not math.isfinite(self.timeout)
            or not 0 < self.timeout <= 5
        ):
            raise ProviderRefused()


def _protected_digest(path: str, maximum: int, *, executable: bool = False) -> str:
    """Fixed source-owned paths only, with no-follow protected parent walk."""
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        root = os.fstat(descriptor)
        if root.st_uid != 0 or root.st_mode & 0o022:
            raise ProviderRefused()
        parts = path.strip("/").split("/")
        for part in parts[:-1]:
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
            )
            os.close(descriptor)
            descriptor = child
            metadata = os.fstat(descriptor)
            if metadata.st_uid != 0 or metadata.st_mode & 0o022:
                raise ProviderRefused()
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
        try:
            metadata = os.fstat(file_fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != 0
                or metadata.st_mode & 0o022
                or metadata.st_mode & 0o6000
                or not 0 < metadata.st_size <= maximum
                or executable
                and not metadata.st_mode & 0o111
            ):
                raise ProviderRefused()
            digest = hashlib.sha256()
            count = 0
            while True:
                data = os.read(file_fd, min(65536, maximum + 1 - count))
                if not data:
                    break
                count += len(data)
                if count > maximum:
                    raise ProviderRefused()
                digest.update(data)
            after = os.fstat(file_fd)
            if count != metadata.st_size or any(
                getattr(after, field) != getattr(metadata, field)
                for field in (
                    "st_dev",
                    "st_ino",
                    "st_mode",
                    "st_uid",
                    "st_size",
                    "st_mtime_ns",
                    "st_ctime_ns",
                )
            ):
                raise ProviderRefused()
            return "sha256:" + digest.hexdigest()
        finally:
            os.close(file_fd)
    finally:
        os.close(descriptor)


def _remaining(deadline: float) -> float:
    value = deadline - time.monotonic()
    if value <= 0:
        raise ProviderRefused()
    return value


def _namespace(endpoint: WireGuardBaoEndpoint) -> None:
    observed = os.stat("/proc/self/ns/net")
    if (observed.st_dev, observed.st_ino) != (
        endpoint.namespace_device,
        endpoint.namespace_inode,
    ) or socket.if_nametoindex(endpoint.interface) != endpoint.interface_index:
        raise ProviderRefused()


def _wireguard_facts(endpoint: WireGuardBaoEndpoint, deadline: float) -> None:
    _namespace(endpoint)
    if (
        _protected_digest(_WG_BINARY, 16777216, executable=True)
        != endpoint.wg_binary_digest
        or _protected_digest(_NETWORK_FILE, 32768) != endpoint.network_config_digest
    ):
        raise ProviderRefused()
    # The actual root launch owner measured the full public WG inventory before
    # irreversibly dropping network mutation privileges. Each request consumes
    # its protected original context; the worker never executes a privileged wg.
    from vendor_cp.deployment.gate0_launch import InstalledLaunchContext

    InstalledLaunchContext.from_installed().require_bao_endpoint(endpoint, deadline)
    _namespace(endpoint)


class _BoundedHTTPReader:
    """HTTPResponse decoder with a cumulative header/chunk/trailer line bound."""

    def __init__(self, stream: BinaryIO) -> None:
        self.stream = stream
        self.line_bytes = 0

    def readline(self, size: int = -1) -> bytes:
        remaining = 16384 - self.line_bytes
        line = self.stream.readline(
            min(size, remaining + 1) if size >= 0 else remaining + 1
        )
        self.line_bytes += len(line)
        if self.line_bytes > 16384:
            raise ProviderRefused()
        return line

    def read(self, size: int = -1) -> bytes:
        if not 0 <= size <= 131073:
            raise ProviderRefused()
        return self.stream.read(size)

    def flush(self) -> None:
        # HTTPResponse.close() calls IOBase.close(), which flushes its input
        # wrapper before closing it. This read-only stream has no write buffer.
        self.stream.flush()

    def close(self) -> None:
        self.stream.close()


class _BoundedHTTPSocket:
    def __init__(self, connected: socket.socket) -> None:
        self.connected = connected

    def makefile(self, mode: str) -> _BoundedHTTPReader:
        if mode != "rb":
            raise ProviderRefused()
        return _BoundedHTTPReader(cast(BinaryIO, self.connected.makefile("rb")))


def _bao_response(connected: socket.socket) -> bytes:
    response = http.client.HTTPResponse(
        cast(socket.socket, _BoundedHTTPSocket(connected))
    )
    try:
        response.begin()
        length = response.headers.get_all("Content-Length", [])
        transfer = response.headers.get_all("Transfer-Encoding", [])
        if (
            response.status != 200
            or response.headers.get("Content-Encoding", "identity") != "identity"
            or len(length) > 1
            or len(transfer) > 1
            or bool(length) == bool(transfer)
            or transfer
            and transfer != ["chunked"]
            or length
            and (
                re.fullmatch(r"[0-9]{1,6}", length[0]) is None
                or not 0 < int(length[0]) <= 131072
            )
        ):
            raise ProviderRefused()
        raw = response.read(131073)
        if not 0 < len(raw) <= 131072 or length and len(raw) != int(length[0]):
            raise ProviderRefused()
        return raw
    finally:
        response.close()


def _socket_readback(connected: socket.socket, endpoint: WireGuardBaoEndpoint) -> None:
    _namespace(endpoint)
    bound = connected.getsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, 16)
    if (
        bound.rstrip(b"\0") != endpoint.interface.encode("ascii")
        or connected.getsockname()[0] != endpoint.local_address
        or connected.getpeername() != (endpoint.address, endpoint.port)
    ):
        raise ProviderRefused()


def _wg_http_child(
    connection: Connection,
    endpoint: WireGuardBaoEndpoint,
    path: str,
    method: str,
    token: str | None,
    body: bytes | None,
    deadline: float,
) -> None:
    try:
        # The qualified supervisor must own the entire container/cgroup: this
        # transport/tool group must not survive abrupt death of its caller.
        # Linux launch qualification must permit this. No permission fallback.
        os.setsid()
        _wireguard_facts(endpoint, deadline)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connected:
            connected.settimeout(_remaining(deadline))
            connected.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE,
                endpoint.interface.encode("ascii") + b"\0",
            )
            connected.bind((endpoint.local_address, 0))
            if connected.getsockopt(
                socket.SOL_SOCKET, socket.SO_BINDTODEVICE, 16
            ).rstrip(b"\0") != endpoint.interface.encode("ascii"):
                raise ProviderRefused()
            _namespace(endpoint)
            connected.connect((endpoint.address, endpoint.port))
            _socket_readback(connected, endpoint)
            headers = (
                f"{method} {path} HTTP/1.1\r\n"
                f"Host: {endpoint.address}:{endpoint.port}\r\n"
                "Connection: close\r\nContent-Type: application/json\r\n"
                "Accept-Encoding: identity\r\n"
            )
            if token is not None:
                headers += "X-Vault-Token: " + token + "\r\n"
            headers += f"Content-Length: {len(body or b'')}\r\n\r\n"
            connected.settimeout(_remaining(deadline))
            connected.sendall(headers.encode("ascii") + (body or b""))
            raw = _bao_response(connected)
            _remaining(deadline)
        connection.send_bytes(raw)
    except Exception:
        try:
            connection.send_bytes(b"")
        except Exception:  # noqa: S110 -- child emits no diagnostics
            pass
    finally:
        connection.close()


@dataclass(frozen=True, slots=True)
class WireGuardBaoTransport:
    endpoint: WireGuardBaoEndpoint

    def __post_init__(self) -> None:
        if type(self.endpoint) is not WireGuardBaoEndpoint:
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
        paths = RolePaths.for_role(self.endpoint.role)
        allowed = {
            ("POST", "/v1/sys/wrapping/lookup"),
            ("POST", "/v1/sys/wrapping/unwrap"),
            ("POST", "/v1/auth/approle/login"),
            ("GET", "/v1/auth/token/lookup-self"),
            ("GET", "/v1/" + paths.seed),
            ("GET", "/v1/secret/data/dotmac/platform-cp/rehearsal-issuer/trust-state"),
            (
                "GET",
                "/v1/secret/data/dotmac/platform-cp/rehearsal-attester/trust-state",
            ),
        }
        if (
            type(method) is not str
            or type(path) is not str
            or (method, path) not in allowed
            or type(deadline) not in (int, float)
            or not math.isfinite(deadline)
            or token is not None
            and (
                type(token) is not str
                or not 0 < len(token) <= 8192
                or any(not 33 <= ord(c) <= 126 for c in token)
            )
            or method == "GET"
            and (token is None or document is not None)
            or path.endswith("/login")
            and (
                token is not None
                or document is None
                or set(document) != {"role_id", "secret_id"}
                or any(
                    type(v) is not str or not 0 < len(v) <= 8192
                    for v in document.values()
                )
            )
            or path.endswith("/lookup")
            and (token is None or document != {"token": token})
            or path.endswith("/unwrap")
            and (token is None or document != {})
        ):
            raise ProviderRefused()
        io_deadline = min(deadline, time.monotonic() + self.endpoint.timeout)
        _remaining(io_deadline)
        body = (
            None if document is None else json.dumps(document, allow_nan=False).encode()
        )
        if body is not None and len(body) > 32768:
            raise ProviderRefused()
        result = strict_json(
            _spawn_request(
                _wg_http_child,
                (self.endpoint, path, method, token, body, io_deadline),
                io_deadline,
                process_group=True,
            )
        )
        _remaining(io_deadline)
        return result


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


def _verify_public_issuer_signature(
    expected_key_id: str,
    public_key: bytes,
    snapshot: TrustStateSnapshot | None,
    *,
    key_id: str,
    algorithm: str,
    purpose: str,
    public_key_fingerprint: str,
    canonical_bytes: bytes,
    signature: str,
) -> bool:
    """Shared public signature/purpose/original-snapshot predicate; no clocks."""
    try:
        if (
            key_id != expected_key_id
            or algorithm != "ed25519"
            or purpose != "deployment_rehearsal_issuer"
            or public_key_fingerprint != _fingerprint(public_key)
            or snapshot is None
            or snapshot.eligibility(
                key_id=key_id, public_key_fingerprint=public_key_fingerprint
            )
            != TrustEligibility.ELIGIBLE
            or type(canonical_bytes) is not bytes
            or not 0 < len(canonical_bytes) <= 131072
        ):
            return False
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            base64.b64decode(signature, validate=True), canonical_bytes
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


@dataclass(frozen=True, slots=True)
class RetainedIssuerVerifier:
    """Signature facts against an original snapshot, never current eligibility.

    The caller independently authenticates original snapshot/floor provenance.
    This has no clock, custody, refresh, signing key, or admission capability.
    """

    key_id: str
    public_key: bytes
    trust: TrustStateSnapshot

    def __post_init__(self) -> None:
        if (
            type(self.key_id) is not str
            or not 0 < len(self.key_id) <= 512
            or type(self.public_key) is not bytes
            or len(self.public_key) != 32
            or type(self.trust) is not TrustStateSnapshot
            or type(self.trust.version) is not int
            or self.trust.version < 1
        ):
            raise ProviderRefused()
        # Detach even a manually constructed DTO's mutable backing map/set.
        object.__setattr__(
            self,
            "trust",
            TrustStateSnapshot(
                self.trust.version,
                MappingProxyType(dict(self.trust.trusted_key_ids)),
                frozenset(self.trust.revoked_key_ids),
            ),
        )

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
        return _verify_public_issuer_signature(
            self.key_id,
            self.public_key,
            self.trust,
            key_id=key_id,
            algorithm=algorithm,
            purpose=purpose,
            public_key_fingerprint=public_key_fingerprint,
            canonical_bytes=canonical_bytes,
            signature=signature,
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
                or self.trust.eligibility(
                    key_id=key_id, public_key_fingerprint=public_key_fingerprint
                )
                != TrustEligibility.ELIGIBLE
            ):
                return False
            if not _verify_public_issuer_signature(
                self.key_id,
                self.public_key,
                self.trust.snapshot,
                key_id=key_id,
                algorithm=algorithm,
                purpose=purpose,
                public_key_fingerprint=public_key_fingerprint,
                canonical_bytes=canonical_bytes,
                signature=signature,
            ):
                return False
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


class CustodyProfile(StrEnum):
    """Two fixed finite allocations; installation cannot invent numeric caps."""

    ISSUER_FINITE_V1 = "issuer-finite-v1"
    ATTESTER_FINITE_V1 = "attester-finite-v1"

    @property
    def role(self) -> Literal["issuer", "attester"]:
        return "issuer" if self is CustodyProfile.ISSUER_FINITE_V1 else "attester"

    @property
    def token_limit(self) -> int:
        return 20 if self is CustodyProfile.ISSUER_FINITE_V1 else 8

    @property
    def http_limit(self) -> int:
        return self.token_limit + 3


class RoleCustody:
    """One bootstrap per instance; exact paths, <=300s and <=32 token uses.

    seed_format is intentionally unset until the custody owner adopts the
    A4 provisional {key_id, private_key_b64url} wire encoding.
    No callback decoder is executed.
    Public refresh is explicit. Failure poisons the provider; no renewal/retry.
    Production uses a named finite profile and the original local deadline;
    the legacy library profile retains its 32-use ceiling.
    """

    def __init__(
        self,
        *,
        role: Literal["issuer", "attester"],
        role_id: str,
        key_id: str,
        public_key: bytes,
        minimum_versions: dict[str, int],
        transport: BoundedJSONTransport | WireGuardBaoTransport | None = None,
        seed_format: Literal["a4-provisional-private-key-b64url"] | None = None,
        expires_at: datetime | None = None,
        profile: CustodyProfile | None = None,
        launch_deadline: float | None = None,
    ) -> None:
        self.paths = RolePaths.for_role(role)
        if (
            type(transport) not in (BoundedJSONTransport, WireGuardBaoTransport)
            or type(transport) is WireGuardBaoTransport
            and transport.endpoint.role != role
            or profile is not None
            and (
                type(profile) is not CustodyProfile
                or profile.role != role
                or launch_deadline is None
            )
            or launch_deadline is not None
            and (
                type(launch_deadline) not in (int, float)
                or not math.isfinite(launch_deadline)
                or not 0 < launch_deadline - time.monotonic() <= 300
            )
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
        self.public_key = public_key
        self.transport = cast(BoundedJSONTransport | WireGuardBaoTransport, transport)
        self.minimum_versions = dict(minimum_versions)
        self.expires_at = expires_at
        self.started_at = datetime.now(UTC)
        self.origin = time.monotonic()
        self.deadline = self.origin + (expires_at - self.started_at).total_seconds()
        if launch_deadline is not None:
            self.deadline = min(self.deadline, launch_deadline)
        self.profile = profile
        self._started = False
        self._closed = False
        self._token: str | None = None
        self._uses = 0
        self._token_attempts = 0
        self._http_attempts = 0
        self._phases = 0
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
        is_service = token == self._token and token is not None
        if (
            is_service
            and (
                self._uses >= 32
                or self.profile is not None
                and self._token_attempts >= self.profile.token_limit
            )
            or self.profile is not None
            and self._http_attempts >= self.profile.http_limit
        ):
            raise ProviderRefused()
        # Count attempts before I/O; failed or ambiguous requests are never free.
        self._http_attempts += 1
        if is_service:
            self._token_attempts += 1
            self._uses += 1
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
            self._uses = max(self._uses, 32 - json_integer(lookup["num_uses"]))
            self._precheck_budget(token_uses=3, http_calls=3)
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

    def _precheck_budget(self, *, token_uses: int, http_calls: int) -> None:
        if (
            self._closed
            or not self.origin <= time.monotonic() < self.deadline
            or not self.started_at <= datetime.now(UTC) < self.expires_at
            or self._uses + token_uses > 32
            or self.profile is not None
            and (
                self._token_attempts + token_uses > self.profile.token_limit
                or self._http_attempts + http_calls > self.profile.http_limit
            )
        ):
            raise ProviderRefused()

    def precheck_phase(
        self, phase: Literal["submission", "challenge", "complete"]
    ) -> None:
        """Pure availability check; refresh reserves the phase exactly once."""
        if self._material is None or self.profile is None:
            raise ProviderRefused()
        if self.profile is CustodyProfile.ISSUER_FINITE_V1:
            valid = phase == "submission" and self._phases < 8
        else:
            valid = (self._phases, phase) in ((0, "challenge"), (1, "complete"))
        if not valid:
            raise ProviderRefused()
        self._precheck_budget(token_uses=2, http_calls=2)

    def refresh(
        self, *, phase: Literal["submission", "challenge", "complete"] | None = None
    ) -> None:
        if self._material is None or self._closed:
            raise ProviderRefused()
        failed = False
        try:
            if self.profile is not None:
                if phase is None:
                    raise ProviderRefused()
                self.precheck_phase(phase)
                self._phases += 1
            elif phase is not None:
                raise ProviderRefused()
            else:
                self._precheck_budget(token_uses=2, http_calls=2)
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
