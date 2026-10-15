"""Finite candidate GitHub GET owner. Facts never grant Gate 0 acceptance.

Installed provenance/native measurements are external prerequisites. JSON pins
bind those records but cannot establish that their measurements actually occurred.
"""

from __future__ import annotations

import base64
import hashlib
import io
import ipaddress
import json
import math
import multiprocessing
import os
import re
import select
import socket
import ssl
import stat
import struct
import time
import zipfile
import zlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from urllib.parse import quote, urlsplit

_INSTALLATION = "/run/dotmac-gate0-e/github-read.json"
_ROOT_BINDING = "/etc/dotmac-gate0-e/github-read-binding.json"
_CREDENTIAL = "/run/dotmac-gate0-e/github-read-token"
_CA = "/etc/ssl/certs/ca-certificates.crt"
_JSON_CAP = 1024 * 1024
_CIPHER_CAP = 17 * 1024 * 1024
_ZIP_CAP = _CIPHER_CAP + 256 * 1024
_SEAL = object()


class GitHubReadRefused(ValueError):
    def __init__(self) -> None:
        super().__init__("GITHUB_READ_REFUSED")


class AttestationTransportUnqualified(GitHubReadRefused):
    def __init__(self) -> None:
        ValueError.__init__(self, "ATTESTATION_TRANSPORT_UNQUALIFIED")


def _require(condition: bool) -> None:
    if not condition:
        raise GitHubReadRefused()


def _text(value: object, maximum: int = 512) -> str:
    _require(type(value) is str and 0 < len(value) <= maximum)
    _require(value.strip() == value and all(32 <= ord(c) < 127 for c in value))
    return value


def _id(value: object) -> int:
    _require(type(value) is int and value > 0)
    return value


def _hex(value: object, length: int = 64) -> str:
    _require(
        type(value) is str
        and re.fullmatch("[0-9a-f]{" + str(length) + "}", value) is not None
    )
    return value


def _obj(value: object) -> dict:
    _require(type(value) is dict)
    return value


def _closed(value: object, fields: str) -> dict:
    value = _obj(value)
    _require(set(value) == set(fields.split()))
    return value


def _array(value: object, maximum: int) -> list:
    _require(type(value) is list and len(value) <= maximum)
    return value


def _json(raw: bytes) -> object:
    _require(type(raw) is bytes and 0 < len(raw) <= _JSON_CAP)

    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result)
            result[key] = value
        return result

    def invalid(_):
        raise GitHubReadRefused()

    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)

        def bounded(item, depth=0):
            _require(depth <= 32)
            if type(item) is dict:
                _require(len(item) <= 2048)
                for key, child in item.items():
                    bounded(key, depth + 1)
                    bounded(child, depth + 1)
            elif type(item) is list:
                _require(len(item) <= 2048)
                for child in item:
                    bounded(child, depth + 1)
            elif type(item) is str:
                _require(len(item) <= 750000)

        bounded(value)
        return value
    except Exception:
        raise GitHubReadRefused() from None


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _instant(value: object) -> datetime:
    """Bounded aware RFC3339; accepted precision is preserved, never rounded.

    GitHub documents milliseconds and explicit offsets. Python's datetime holds
    microseconds, so this profile supports 1..6 fractional digits and refuses
    higher precision rather than silently truncating it. RFC3339 -00:00 denotes
    an unknown local offset and cannot establish the instant required here.
    """
    _require(type(value) is str and 20 <= len(value) <= 32)
    _require(
        re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
            r"[0-9]{2}:[0-9]{2}:[0-9]{2}"
            r"(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])",
            value,
        )
        is not None
        and not value.endswith("-00:00")
    )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        _require(parsed.tzinfo is not None and parsed.utcoffset() is not None)
        return parsed.astimezone(UTC)
    except (ValueError, OverflowError):
        raise GitHubReadRefused() from None


def _protected(
    path: str, maximum: int, leaf_uid: int = 0, private: bool = True
) -> bytes:
    """Walk every component without following symlinks, including ancestry."""
    _require(path.startswith("/") and ".." not in path.split("/"))
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        parts = path.strip("/").split("/")
        for index, part in enumerate(parts):
            new = os.open(
                part,
                os.O_RDONLY
                | os.O_NOFOLLOW
                | os.O_NONBLOCK
                | (os.O_DIRECTORY if index < len(parts) - 1 else 0),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = new
            info = os.fstat(descriptor)
            _require(
                info.st_uid == (leaf_uid if index == len(parts) - 1 else 0)
                and not info.st_mode & 0o022
            )
            if index == len(parts) - 1:
                _require(
                    stat.S_ISREG(info.st_mode)
                    and (not private or not info.st_mode & 0o077)
                    and 0 < info.st_size <= maximum
                )
                raw = os.read(descriptor, maximum + 1)
                _require(len(raw) == info.st_size and not os.read(descriptor, 1))
                return raw
        raise GitHubReadRefused()
    finally:
        os.close(descriptor)


class ProducerStage(StrEnum):
    PROTECTED_JOB_STARTED = "PROTECTED_JOB_STARTED"
    COLLECTION_SNAPSHOT = "COLLECTION_SNAPSHOT"
    PRODUCER_JOB_COMPLETE = "PRODUCER_JOB_COMPLETE"
    PRODUCER_RUN_COMPLETE = "PRODUCER_RUN_COMPLETE"


class EndpointCode(StrEnum):
    REPOSITORY = "repository"
    WORKFLOW = "workflow"
    SOURCE = "source"
    RUN = "run"
    ATTEMPT = "attempt"
    JOBS = "jobs"
    REVIEWS = "reviews"
    PENDING = "pending"
    ENVIRONMENT = "environment"
    BRANCHES = "branches"
    ARTIFACTS = "artifacts"
    ARTIFACT = "artifact"
    ZIP = "zip"
    RELEASE = "release"
    ASSETS = "assets"
    ASSET = "asset"
    ASSET_BYTES = "asset_bytes"
    TAG_REF = "tag_ref"
    TAG = "tag"


@dataclass(frozen=True, slots=True)
class RepositoryPin:
    owner: str
    name: str
    repository_id: int
    owner_id: int

    def __post_init__(self):
        for item in (self.owner, self.name):
            _require(
                type(item) is str
                and re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,99}", item) is not None
                and item not in (".", "..")
            )
        _id(self.repository_id)
        _id(self.owner_id)


@dataclass(frozen=True, slots=True)
class StepPin:
    number: int
    name: str
    required_stage: ProducerStage


@dataclass(frozen=True, slots=True)
class WorkflowPin:
    id: int
    path: str
    commit: str
    blob_sha: str
    sha256: str
    job_key: str
    job_name: str
    environment_id: int
    environment_name: str
    reviewer_id: int
    runner_group_id: int
    runner_id: int
    runner_name: str
    required_steps: tuple[StepPin, ...]
    action_source_pins: tuple[str, ...]
    source_policy_pin: tuple[str, str]


@dataclass(frozen=True, slots=True)
class RunPin:
    repository: RepositoryPin
    workflow: WorkflowPin
    run_id: int
    attempt: int
    head_sha: str
    branch: str
    event: str
    actor_id: int
    triggering_actor_id: int


@dataclass(frozen=True, slots=True)
class TransferPin:
    artifact_id: int
    name: str
    expected_artifact_names: tuple[str, ...]
    ciphertext_name: str = "gate0-evidence.pgp"
    projection_name: str = "gate0-evidence-public.json"


@dataclass(frozen=True, slots=True)
class ReleaseAssetPin:
    id: int
    name: str
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class ReleasePin:
    release_id: int
    tag: str
    commit: str
    assets: tuple[ReleaseAssetPin, ...]


@dataclass(frozen=True, slots=True)
class GitHubObservation:
    endpoint: EndpointCode
    page: int
    status: int
    response_sha256: str
    body: bytes = field(repr=False)
    observed_at_utc: str
    observed_monotonic: float


@dataclass(frozen=True, slots=True)
class StepFact:
    number: int
    name: str
    status: str
    conclusion: str | None
    started_at: str | None
    completed_at: str | None


@dataclass(frozen=True, slots=True)
class JobFact:
    id: int
    run_id: int
    head_sha: str
    name: str
    status: str
    conclusion: str | None
    started_at: str | None
    completed_at: str | None
    runner_id: int
    runner_name: str
    runner_group_id: int
    steps: tuple[StepFact, ...]


@dataclass(frozen=True, slots=True)
class ReviewFact:
    state: str
    reviewer_id: int
    environment_ids: tuple[int, ...]
    environment_names: tuple[str, ...]
    observation_sha256: str


@dataclass(frozen=True, slots=True)
class SourceFact:
    commit: str
    path: str
    blob_sha: str
    bytes_sha256: str
    raw_bytes: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class ProducerFacts:
    repository_id: int
    owner_id: int
    run_id: int
    attempt: int
    workflow_id: int
    head_sha: str
    workflow_source: SourceFact
    stage: ProducerStage
    status: str
    conclusion: str | None
    jobs: tuple[JobFact, ...]
    review: ReviewFact
    environment_id: int
    policy_observation_digests: tuple[str, ...]
    observations: tuple[GitHubObservation, ...] = field(repr=False)


@dataclass(frozen=True, slots=True)
class VerifiedProducerTransfer:
    producer: ProducerFacts
    artifact_id: int
    artifact_name: str
    archive_sha256: str
    archive_size: int
    ciphertext: bytes = field(repr=False)
    ciphertext_sha256: str
    projection: bytes = field(repr=False)
    projection_sha256: str
    observations: tuple[GitHubObservation, ...] = field(repr=False)


@dataclass(frozen=True, slots=True)
class ReleaseAssetFact:
    id: int
    name: str
    state: str
    content_type: str
    size: int
    sha256: str
    uploader_id: int
    raw_bytes: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class DownloadedReleaseFacts:
    repository_id: int
    release_id: int
    tag: str
    peeled_commit: str
    draft: bool
    immutable: bool
    assets: tuple[ReleaseAssetFact, ...]
    observations: tuple[GitHubObservation, ...] = field(repr=False)
    raw_tag_sha: str
    owner_id: int


@dataclass(frozen=True, slots=True)
class PublicationFacts:
    run: ProducerFacts
    display_title: str
    selected_summary_digest: str
    review_response_digest: str


class _Wire:
    def __init__(self, channel: ssl.SSLSocket, deadline: float):
        self.channel, self.deadline, self.buffer = channel, deadline, bytearray()

    def read(self, count: int) -> bytes:
        while len(self.buffer) < count:
            remaining = self.deadline - time.monotonic()
            _require(remaining > 0)
            self.channel.settimeout(remaining)
            chunk = self.channel.recv(min(65536, max(1, count - len(self.buffer))))
            _require(bool(chunk))
            self.buffer.extend(chunk)
        result = bytes(self.buffer[:count])
        del self.buffer[:count]
        return result

    def line(self) -> bytes:
        result = bytearray()
        while not result.endswith(b"\r\n"):
            _require(len(result) < 8192)
            result.extend(self.read(1))
        return bytes(result[:-2])

    def eof(self):
        _require(not self.buffer)
        remaining = self.deadline - time.monotonic()
        _require(remaining > 0)
        self.channel.settimeout(remaining)
        _require(self.channel.recv(1) == b"")


def _redirect(location: str, origins: tuple[str, ...]) -> tuple[str, str]:
    _require(
        len(location) <= 8192 and all(32 < ord(c) < 127 and c != "\\" for c in location)
    )
    parsed = urlsplit(location)
    _require(
        parsed.scheme == "https"
        and parsed.hostname in origins
        and parsed.port in (None, 443)
        and not parsed.username
        and not parsed.password
        and not parsed.fragment
    )
    _require(
        parsed.netloc == parsed.hostname or parsed.netloc == parsed.hostname + ":443"
    )
    _require(parsed.path.startswith("/") and not parsed.path.startswith("//"))
    return parsed.hostname, parsed.path + ("?" + parsed.query if parsed.query else "")


def _https(
    host: str,
    path: str,
    token: bytes | None,
    binary: bool,
    maximum: int,
    deadline: float,
):
    """Resolve once; connect the exact checked address; SNI is original host."""
    addresses = socket.getaddrinfo(
        host, 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
    )
    _require(0 < len(addresses) <= 32)
    for family, _kind, _protocol, _, address in addresses:
        ip = ipaddress.ip_address(address[0])
        _require(ip.is_global and not ip.is_multicast and not ip.is_unspecified)
        _require(family in (socket.AF_INET, socket.AF_INET6))
    family, kind, protocol, _, address = addresses[0]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile=_CA)
    raw = socket.socket(family, kind, protocol)
    try:
        remaining = deadline - time.monotonic()
        _require(remaining > 0)
        raw.settimeout(remaining)
        raw.connect(address)
        with context.wrap_socket(raw, server_hostname=host) as tls:
            wire = _Wire(tls, deadline)
            headers = [
                "GET " + path + " HTTP/1.1",
                "Host: " + host,
                "Connection: close",
                "Accept-Encoding: identity",
                "User-Agent: dotmac-gate0-e-read/1",
            ]
            if token is not None:
                _require(host == "api.github.com")
                headers.extend(
                    [
                        "Authorization: Bearer " + token.decode("ascii"),
                        "X-GitHub-Api-Version: 2026-03-10",
                        "Accept: "
                        + (
                            "application/octet-stream"
                            if binary
                            else "application/vnd.github+json"
                        ),
                    ]
                )
            elif binary:
                headers.append("Accept: application/octet-stream")
            tls.settimeout(max(0.001, deadline - time.monotonic()))
            tls.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
            status_line = wire.line()
            _require(
                re.fullmatch(rb"HTTP/1\.[01] [0-9]{3} [\x20-\x7e]*", status_line)
                is not None
            )
            status = int(status_line.split(b" ")[1])
            fields = {}
            consumed = len(status_line) + 2
            for _ in range(129):
                line = wire.line()
                consumed += len(line) + 2
                _require(consumed <= 65536)
                if not line:
                    break
                _require(len(fields) < 128 and b":" in line and not line[:1].isspace())
                key, value = line.split(b":", 1)
                _require(re.fullmatch(rb"[A-Za-z0-9!#$%&'*+.^_`|~-]+", key) is not None)
                key = key.decode("ascii").lower()
                _require(key not in fields)
                _require(all(32 <= c < 127 or c == 9 for c in value))
                fields[key] = value.decode("ascii").strip()
            else:
                raise GitHubReadRefused()
            _require(fields.get("content-encoding", "identity") == "identity")
            _require(status in (200, 302))
            if status == 200:
                content_type = fields.get("content-type", "").split(";", 1)[0]
                _require(
                    content_type
                    in (
                        (
                            "application/octet-stream",
                            "application/zip",
                            "application/x-zip-compressed",
                        )
                        if binary
                        else ("application/json",)
                    )
                )
            _require(("content-length" in fields) != ("transfer-encoding" in fields))
            body = bytearray()
            if "content-length" in fields:
                length = fields["content-length"]
                _require(
                    re.fullmatch(r"0|[1-9][0-9]{0,8}", length) is not None
                    and int(length) <= maximum
                )
                body.extend(wire.read(int(length)))
            else:
                _require(fields["transfer-encoding"] == "chunked")
                while True:
                    size = wire.line()
                    _require(re.fullmatch(rb"[0-9a-fA-F]{1,8}", size) is not None)
                    count = int(size, 16)
                    _require(len(body) + count <= maximum)
                    if not count:
                        _require(wire.line() == b"")
                        break
                    body.extend(wire.read(count))
                    _require(wire.read(2) == b"\r\n")
            wire.eof()
            return status, fields, bytes(body)
    finally:
        raw.close()


def _pagination(link: str | None, path: str, page: int) -> tuple[int, int]:
    if link is None:
        return 0, 0
    _require(page > 0 and len(link) <= 8192)
    found = {}
    base = path.rsplit("page=", 1)[0]
    for part in link.split(","):
        match = re.fullmatch(r'\s*<([^<>]+)>; rel="(next|last|first|prev)"\s*', part)
        _require(match is not None and match[2] not in found)
        coordinate = match[1]
        prefix = "https://api.github.com" + base
        _require(coordinate.startswith(prefix))
        number = coordinate[len(prefix) :]
        _require(re.fullmatch(r"[1-4]", number) is not None)
        found[match[2]] = int(number)
    _require(
        found.get("next", 0) in (0, page + 1)
        and found.get("prev", page - 1) == page - 1
        and found.get("first", 1) == 1
    )
    _require(found.get("last", page) >= page)
    return found.get("next", 0), found.get("last", 0)


def _http_child(
    channel: socket.socket,
    path: str,
    token: bytes,
    binary: bool,
    maximum: int,
    origins: tuple[str, ...],
    deadline: float,
    page: int,
):
    try:
        status, headers, body = _https(
            "api.github.com", path, token, binary, maximum, deadline
        )
        next_page, last_page = _pagination(headers.get("link"), path, page)
        if status == 302:
            _require(binary and "location" in headers)
            host, redirected_path = _redirect(headers["location"], origins)
            token = b""
            status, headers, body = _https(
                host, redirected_path, None, True, maximum, deadline
            )
            _require(
                status == 200 and "location" not in headers and "link" not in headers
            )
        else:
            _require("location" not in headers)
        channel.settimeout(max(0.001, deadline - time.monotonic()))
        channel.sendall(
            struct.pack("!IIII", status, next_page, last_page, len(body)) + body
        )
        channel.shutdown(socket.SHUT_WR)
    except BaseException:  # noqa: S110 -- never log private transport errors
        pass
    finally:
        channel.close()


def _spawn_get(
    path: str,
    token: bytes,
    binary: bool,
    maximum: int,
    origins: tuple[str, ...],
    phase_deadline: float,
    page: int,
):
    """One absolute deadline includes spawn, DNS, network, IPC, EOF and reap."""
    deadline = min(phase_deadline, time.monotonic() + (45 if binary else 10))
    work_deadline = deadline - 1.0
    _require(work_deadline > time.monotonic())
    parent, child = socket.socketpair()
    process = multiprocessing.get_context("spawn").Process(
        target=_http_child,
        args=(child, path, token, binary, maximum, origins, work_deadline, page),
        daemon=True,
    )
    result = None
    cleanup_ok = False
    try:
        process.start()
        child.close()
        parent.setblocking(False)

        def exact(count):
            output = bytearray()
            while len(output) < count:
                remaining = work_deadline - time.monotonic()
                _require(
                    remaining > 0
                    and bool(select.select([parent], [], [], remaining)[0])
                )
                chunk = parent.recv(min(65536, count - len(output)))
                _require(bool(chunk))
                output.extend(chunk)
            return bytes(output)

        status, next_page, last_page, size = struct.unpack("!IIII", exact(16))
        _require(status == 200 and size <= maximum)
        body = exact(size)
        remaining = work_deadline - time.monotonic()
        _require(
            remaining > 0
            and bool(select.select([parent], [], [], remaining)[0])
            and parent.recv(1) == b""
        )
        process.join(max(0, work_deadline - time.monotonic()))
        _require(process.exitcode == 0)
        result = status, next_page, last_page, body
    finally:
        parent.close()
        child.close()
        if process.pid is not None:
            if process.is_alive():
                process.kill()
            process.join(max(0, deadline - time.monotonic()))
            cleanup_ok = not process.is_alive() and time.monotonic() <= deadline
            if cleanup_ok:
                process.close()
        if not cleanup_ok:
            result = None
            raise GitHubReadRefused()
    _require(result is not None)
    return result


def _pin_document(pin: object) -> tuple[dict, bytes]:
    pin = _closed(pin, "path digest")
    path, digest = _text(pin["path"]), _hex(pin["digest"])
    _require(path.startswith("/etc/dotmac-gate0-e/") and path not in (_ROOT_BINDING,))
    raw = _protected(path, _JSON_CAP)
    value = _obj(_json(raw))
    _require(_digest(raw) == digest and _canonical(value) == raw)
    return value, raw


def _repository(value: object) -> RepositoryPin:
    value = _closed(value, "owner name repository_id owner_id")
    return RepositoryPin(**value)


def _run(value: object, repository: RepositoryPin) -> RunPin:
    value = _closed(
        value,
        "repository workflow run_id attempt head_sha branch event actor_id "
        "triggering_actor_id",
    )
    _require(_repository(value["repository"]) == repository)
    w = _closed(
        value["workflow"],
        "id path commit blob_sha sha256 job_key job_name environment_id "
        "environment_name reviewer_id runner_group_id runner_id "
        "runner_name required_steps action_source_pins source_policy_pin",
    )
    for name in ("id", "environment_id", "reviewer_id", "runner_group_id", "runner_id"):
        _id(w[name])
    for name in ("job_key", "job_name", "environment_name", "runner_name"):
        _text(w[name])
    _require(
        re.fullmatch(r"\.github/workflows/[A-Za-z0-9_-]+\.ya?ml", _text(w["path"]))
        is not None
    )
    _hex(w["commit"], 40)
    _hex(w["blob_sha"], 40)
    _hex(w["sha256"])
    steps = tuple(
        StepPin(_id(s["number"]), _text(s["name"]), ProducerStage(s["required_stage"]))
        for s in (
            _closed(s, "number name required_stage")
            for s in _array(w["required_steps"], 128)
        )
    )
    _require(
        sum(s.required_stage == ProducerStage.PROTECTED_JOB_STARTED for s in steps) <= 1
    )
    _require(
        bool(steps)
        and [s.number for s in steps] == sorted({s.number for s in steps})
        and len({s.name for s in steps}) == len(steps)
    )
    actions = tuple(_text(a) for a in _array(w["action_source_pins"], 128))
    _require(
        bool(actions)
        and all(
            re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}", a)
            for a in actions
        )
    )
    source_pin = _closed(w["source_policy_pin"], "path digest")
    source_tuple = (_text(source_pin["path"]), _hex(source_pin["digest"]))
    workflow = WorkflowPin(
        **(
            w
            | {
                "required_steps": steps,
                "action_source_pins": actions,
                "source_policy_pin": source_tuple,
            }
        )
    )
    _id(value["run_id"])
    _id(value["actor_id"])
    _id(value["triggering_actor_id"])
    _require(
        type(value["attempt"]) is int
        and value["attempt"] == 1
        and value["branch"] == "main"
        and value["event"] == "workflow_dispatch"
        and _hex(value["head_sha"], 40) == workflow.commit
    )
    return RunPin(**(value | {"repository": repository, "workflow": workflow}))


def _source_policy(run: RunPin) -> dict:
    w = run.workflow
    policy, _ = _pin_document(
        dict(zip(("path", "digest"), w.source_policy_pin, strict=True))
    )
    policy = _closed(
        policy,
        "schema workflow_sha256 workflow_blob_sha job_key job_name "
        "environment_id environment_name required_steps action_source_pins "
        "mandatory_jobs sole_artifact_step publication_title "
        "selected_summary_digest projection_sha256 ciphertext_sha256 "
        "branch_policies environment_rules policy_digest campaign_digest "
        "source_bundle_digest",
    )
    _require(policy["schema"] == "Gate0EGitHubSourcePolicy.v1")
    for key, expected in (
        ("workflow_sha256", w.sha256),
        ("workflow_blob_sha", w.blob_sha),
        ("job_key", w.job_key),
        ("job_name", w.job_name),
        ("environment_id", w.environment_id),
        ("environment_name", w.environment_name),
        ("action_source_pins", list(w.action_source_pins)),
    ):
        _require(type(policy[key]) is type(expected) and policy[key] == expected)
    _require(
        _canonical(policy["required_steps"])
        == _canonical(
            [
                {
                    "number": s.number,
                    "name": s.name,
                    "required_stage": s.required_stage.value,
                }
                for s in w.required_steps
            ]
        )
    )
    mandatory = _array(policy["mandatory_jobs"], 128)
    _require(
        bool(mandatory)
        and len(set(mandatory)) == len(mandatory)
        and w.job_name in mandatory
    )
    for name in mandatory:
        _text(name)
    _require(
        policy["sole_artifact_step"]
        in [
            s.number
            for s in w.required_steps
            if s.required_stage
            in (
                ProducerStage.PRODUCER_JOB_COMPLETE,
                ProducerStage.PRODUCER_RUN_COMPLETE,
            )
        ]
    )
    _array(policy["branch_policies"], 32)
    _array(policy["environment_rules"], 32)
    for name in ("projection_sha256", "ciphertext_sha256"):
        if policy[name] is not None:
            _hex(policy[name])
    if policy["selected_summary_digest"] is not None:
        _hex(policy["selected_summary_digest"])
    for name in ("policy_digest", "campaign_digest", "source_bundle_digest"):
        _prefixed_digest(policy[name])
    if policy["publication_title"] is not None:
        _text(policy["publication_title"])
        _hex(policy["selected_summary_digest"])
    return policy


class InstalledGate0GitHubReads:
    """Single-attempt methods; no caller-selected transport or credentials."""

    __slots__ = (
        "_installation",
        "_repository",
        "_producer",
        "_publication",
        "_transfer",
        "_release",
        "_origins",
        "_qualification",
        "_policies",
        "_used",
        "_failed",
        "_observations",
        "_deadline",
        "_metadata",
        "_exchanges",
        "_issued",
    )

    def __init__(self, seal: object, installation: dict, qualification: dict):
        _require(seal is _SEAL)
        self._installation = installation
        self._qualification = qualification
        self._repository = _repository(installation["repository"])
        self._producer = (
            _run(installation["producer"], self._repository)
            if installation["producer"] is not None
            else None
        )
        self._publication = (
            _run(installation["publication"], self._repository)
            if installation["publication"] is not None
            else None
        )
        self._policies = {
            run.run_id: _source_policy(run)
            for run in (self._producer, self._publication)
            if run is not None
        }
        self._transfer = installation["transfer"]
        self._release = installation["release"]
        self._origins = tuple(installation["download_origins"])
        self._used, self._failed = set(), False
        self._issued = []
        self._observations, self._deadline, self._metadata, self._exchanges = (
            [],
            0.0,
            0,
            0,
        )

    @classmethod
    def from_installed(cls) -> InstalledGate0GitHubReads:
        try:
            raw = _protected(_INSTALLATION, _JSON_CAP)
            installation = _closed(
                _json(raw),
                "schema policy_digest phase repository producer publication "
                "transfer release download_origins credential qualification",
            )
            _require(
                _canonical(installation) == raw
                and installation["schema"] == "Gate0EGitHubReadInstallation.v1"
            )
            _hex(installation["policy_digest"])
            binding_raw = _protected(_ROOT_BINDING, 65536)
            binding = _closed(
                _json(binding_raw),
                "schema installation_sha256 qualification_sha256 source_sha256 "
                "native_receipt_pin runtime_uid",
            )
            _require(
                _canonical(binding) == binding_raw
                and binding["schema"] == "Gate0EGitHubRootBinding.v1"
                and _hex(binding["installation_sha256"]) == _digest(raw)
            )
            _require(
                type(binding["runtime_uid"]) is int
                and binding["runtime_uid"] >= 0
                and os.getuid() == os.geteuid() == binding["runtime_uid"]
            )
            _require(
                _digest(_protected(os.path.abspath(__file__), _JSON_CAP, private=False))
                == _hex(binding["source_sha256"])
            )
            qualification, qual_raw = _pin_document(installation["qualification"])
            qualification = _closed(
                qualification,
                "schema installation_policy_digest native_receipt_pin api_version "
                "runtime_uid credential_uid permissions action_time "
                "source_policy_digests transfer_profile immutable_setting",
            )
            _require(
                qualification["schema"] == "Gate0EGitHubNativeQualification.v1"
                and _digest(qual_raw) == _hex(binding["qualification_sha256"])
                and qualification["installation_policy_digest"]
                == installation["policy_digest"]
                and qualification["api_version"] == "2026-03-10"
                and qualification["runtime_uid"] == binding["runtime_uid"]
            )
            _require(
                qualification["native_receipt_pin"] == binding["native_receipt_pin"]
            )
            # An external native-review record is required, never synthesized here.
            receipt, _ = _pin_document(binding["native_receipt_pin"])
            receipt = _closed(
                receipt,
                "schema qualification_measurements_digest runtime_identity_digest "
                "reviewer_record_digest",
            )
            _require(receipt["schema"] == "Gate0ENativeReviewReceipt.v1")
            for key in (
                "qualification_measurements_digest",
                "runtime_identity_digest",
                "reviewer_record_digest",
            ):
                _hex(receipt[key])
            _require(
                _canonical(qualification["permissions"])
                == _canonical(
                    {
                        "metadata": "read",
                        "actions": "read",
                        "contents": "read",
                        "repository_id": _repository(
                            installation["repository"]
                        ).repository_id,
                    }
                )
            )
            _require(installation["credential"] == _CREDENTIAL)
            _require(
                type(qualification["credential_uid"]) is int
                and qualification["credential_uid"] in (0, binding["runtime_uid"])
            )
            origins = _array(installation["download_origins"], 16)
            _require(bool(origins) and len(set(origins)) == len(origins))
            for host in origins:
                _require(
                    type(host) is str
                    and re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host)
                    is not None
                    and "." in host
                    and ".." not in host
                    and host != "api.github.com"
                )
                try:
                    ipaddress.ip_address(host)
                except ValueError:
                    continue
                raise GitHubReadRefused()
            phase = installation["phase"]
            _require(
                phase
                in (
                    "protected_job",
                    "producer",
                    "transfer",
                    "draft",
                    "published",
                    "publication",
                )
            )
            required = {
                "protected_job": (True, False, False, False),
                "producer": (True, False, False, False),
                "transfer": (True, False, True, False),
                "draft": (True, False, False, True),
                "published": (True, False, False, True),
                "publication": (False, True, False, False),
            }[phase]
            _require(
                tuple(
                    installation[key] is not None
                    for key in ("producer", "publication", "transfer", "release")
                )
                == required
            )
            result = cls(_SEAL, installation, qualification)
            expected_policies = sorted(
                run.workflow.source_policy_pin[1]
                for run in (result._producer, result._publication)
                if run is not None
            )
            _require(qualification["source_policy_digests"] == expected_policies)
            _require(
                all(
                    policy["policy_digest"] == "sha256:" + installation["policy_digest"]
                    for policy in result._policies.values()
                )
            )
            return result
        except Exception:
            raise GitHubReadRefused() from None

    def owns_facts(self, facts: object) -> bool:
        """Live identity check; DTO construction/JSON never authenticates facts."""
        return not self._failed and any(facts is item for item in self._issued)

    def _phase(self, name: str, seconds: int, operation, *, deadline=None):
        try:
            _require(
                not self._failed
                and name not in self._used
                and self._installation["phase"] == name
            )
            self._used.add(name)
            self._deadline = time.monotonic() + seconds
            if deadline is not None or name == "protected_job":
                _require(type(deadline) in (int, float) and math.isfinite(deadline))
                self._deadline = min(self._deadline, deadline)
            _require(time.monotonic() < self._deadline)
            self._observations, self._metadata, self._exchanges = [], 0, 0
            result = operation()
            _require(time.monotonic() < self._deadline)
            self._issued.append(result)
            return result
        except Exception:
            self._failed = True
            self._observations.clear()
            self._issued.clear()
            raise GitHubReadRefused() from None

    def _path(
        self,
        code: EndpointCode,
        run: RunPin | None,
        identifier: int | str | None,
        page: int,
    ):
        root = "/repos/" + self._repository.owner + "/" + self._repository.name
        w = run.workflow if run else None
        paths = {EndpointCode.REPOSITORY: ""}
        if run:
            r = "/actions/runs/" + str(run.run_id)
            paths.update(
                {
                    EndpointCode.RUN: r,
                    EndpointCode.ATTEMPT: r + "/attempts/1",
                    EndpointCode.JOBS: r + "/attempts/1/jobs",
                    EndpointCode.REVIEWS: r + "/approvals",
                    EndpointCode.PENDING: r + "/pending_deployments",
                    EndpointCode.ARTIFACTS: r + "/artifacts",
                    EndpointCode.WORKFLOW: "/actions/workflows/" + str(w.id),
                    EndpointCode.SOURCE: "/contents/" + w.path + "?ref=" + w.commit,
                    EndpointCode.ENVIRONMENT: "/environments/"
                    + quote(w.environment_name, safe=""),
                    EndpointCode.BRANCHES: "/environments/"
                    + quote(w.environment_name, safe="")
                    + "/deployment-branch-policies",
                }
            )
        if code in (
            EndpointCode.ARTIFACT,
            EndpointCode.ZIP,
            EndpointCode.RELEASE,
            EndpointCode.ASSETS,
            EndpointCode.ASSET,
            EndpointCode.ASSET_BYTES,
        ):
            number = str(_id(identifier))
            paths.update(
                {
                    EndpointCode.ARTIFACT: "/actions/artifacts/" + number,
                    EndpointCode.ZIP: "/actions/artifacts/" + number + "/zip",
                    EndpointCode.RELEASE: "/releases/" + number,
                    EndpointCode.ASSETS: "/releases/" + number + "/assets",
                    EndpointCode.ASSET: "/releases/assets/" + number,
                    EndpointCode.ASSET_BYTES: "/releases/assets/" + number,
                }
            )
        if code == EndpointCode.TAG_REF:
            paths[code] = "/git/ref/tags/" + quote(_text(identifier), safe="")
        if code == EndpointCode.TAG:
            paths[code] = "/git/tags/" + _hex(identifier, 40)
        _require(code in paths)
        suffix = paths[code]
        if page:
            _require(
                code
                in (
                    EndpointCode.JOBS,
                    EndpointCode.ARTIFACTS,
                    EndpointCode.ASSETS,
                    EndpointCode.BRANCHES,
                )
                and 1 <= page <= 4
            )
            suffix += "?per_page=100&page=" + str(page)
        return root + suffix

    def _get(
        self,
        code: EndpointCode,
        run: RunPin | None = None,
        identifier: int | str | None = None,
        page: int = 0,
        maximum: int = _JSON_CAP,
    ):
        binary = code in (EndpointCode.ZIP, EndpointCode.ASSET_BYTES)
        _require(self._exchanges < 48 and time.monotonic() < self._deadline)
        # A download may make one additional CDN exchange.
        self._exchanges += 2 if binary else 1
        _require(self._exchanges <= 48)
        token = _protected(_CREDENTIAL, 16384, self._qualification["credential_uid"])
        _require(all(32 < byte < 127 for byte in token))
        status, next_page, last_page, raw = _spawn_get(
            self._path(code, run, identifier, page),
            token,
            binary,
            maximum,
            self._origins,
            self._deadline,
            page,
        )
        token = b""
        if not binary:
            self._metadata += len(raw)
            _require(self._metadata <= 16 * _JSON_CAP)
        observation = GitHubObservation(
            code,
            page,
            status,
            _digest(raw),
            raw,
            datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            time.monotonic(),
        )
        self._observations.append(observation)
        return (raw if binary else _json(raw)), next_page, last_page

    def _read(self, code, run=None, identifier=None):
        value, next_page, last_page = self._get(code, run, identifier)
        _require(next_page == last_page == 0)
        return value

    def _pages(self, code, field_name, maximum, run=None, identifier=None):
        result, total = [], None
        for page in range(1, 5):
            value, next_page, last_page = self._get(code, run, identifier, page)
            if field_name:
                value = _obj(value)
                count = value["total_count"]
                _require(
                    type(count) is int
                    and 0 <= count <= maximum
                    and (total is None or total == count)
                )
                total = count
                items = _array(value[field_name], 100)
            else:
                items = _array(value, 100)
            result.extend(items)
            _require(
                len(result) <= maximum
                and len({_id(_obj(item)["id"]) for item in result}) == len(result)
            )
            if not next_page:
                _require(
                    last_page in (0, page)
                    and (total is None or len(result) == total)
                    and len(items) < 100
                )
                return result
            _require(
                next_page == page + 1 and last_page >= next_page and len(items) == 100
            )
        raise GitHubReadRefused()

    def _run_anchor(self, value: object, run: RunPin) -> dict:
        value = _obj(value)
        w = run.workflow
        for key, expected in (
            ("id", run.run_id),
            ("run_attempt", 1),
            ("workflow_id", w.id),
            ("head_sha", run.head_sha),
            ("head_branch", run.branch),
            ("event", run.event),
            ("path", w.path),
        ):
            _require(type(value[key]) is type(expected) and value[key] == expected)
        for key, expected in (
            ("repository", self._repository.repository_id),
            ("head_repository", self._repository.repository_id),
            ("actor", run.actor_id),
            ("triggering_actor", run.triggering_actor_id),
        ):
            _require(_id(_obj(value[key])["id"]) == expected)
        repo = _obj(value["repository"])
        _require(_id(_obj(repo["owner"])["id"]) == self._repository.owner_id)
        _require(
            value["status"] in ("queued", "in_progress", "completed")
            and value["conclusion"]
            in (
                None,
                "success",
                "failure",
                "cancelled",
                "skipped",
                "neutral",
                "timed_out",
                "action_required",
                "stale",
                "startup_failure",
            )
        )
        selected = {
            key: value[key]
            for key in (
                "id",
                "run_attempt",
                "workflow_id",
                "head_sha",
                "head_branch",
                "event",
                "path",
                "status",
                "conclusion",
                "display_title",
            )
        }
        _text(selected["display_title"])
        return selected

    def _producer_facts(self, run: RunPin, stage: ProducerStage) -> ProducerFacts:
        _require(type(stage) is ProducerStage)
        w = run.workflow
        policy = self._policies[run.run_id]
        repository = _obj(self._read(EndpointCode.REPOSITORY))
        _require(
            _id(repository["id"]) == self._repository.repository_id
            and _id(_obj(repository["owner"])["id"]) == self._repository.owner_id
            and repository["full_name"]
            == self._repository.owner + "/" + self._repository.name
        )
        anchor = self._run_anchor(self._read(EndpointCode.RUN, run), run)
        _require(self._run_anchor(self._read(EndpointCode.ATTEMPT, run), run) == anchor)
        workflow = _obj(self._read(EndpointCode.WORKFLOW, run))
        _require(_id(workflow["id"]) == w.id and workflow["path"] == w.path)
        contents = _obj(self._read(EndpointCode.SOURCE, run))
        _require(
            contents["type"] == "file"
            and contents["path"] == w.path
            and contents["sha"] == w.blob_sha
            and contents["encoding"] == "base64"
        )
        _require(type(contents["size"]) is int and 0 < contents["size"] <= 512 * 1024)
        encoded = contents["content"]
        _require(
            type(encoded) is str
            and re.fullmatch(r"[A-Za-z0-9+/=\n]+", encoded) is not None
        )
        raw = base64.b64decode(encoded.replace("\n", ""), validate=True)
        _require(
            len(raw) == contents["size"]
            and _digest(raw) == w.sha256
            and hashlib.sha1(
                b"blob " + str(len(raw)).encode() + b"\0" + raw, usedforsecurity=False
            ).hexdigest()
            == w.blob_sha
        )
        source = SourceFact(w.commit, w.path, w.blob_sha, w.sha256, raw)
        roster = self._pages(EndpointCode.JOBS, "jobs", 128, run)
        _require(
            {item["name"] for item in roster} == set(policy["mandatory_jobs"])
            and len(roster) == len(policy["mandatory_jobs"])
        )
        jobs = []
        for item in roster:
            item = _obj(item)
            _require(
                _id(item["run_id"]) == run.run_id and item["head_sha"] == run.head_sha
            )
            # The exact attempt-jobs endpoint authenticates attempt selection.
            # The documented job DTO has no run_attempt field. If GitHub supplies
            # one additionally, it may corroborate but never contradict the pin.
            if "run_attempt" in item:
                _require(_id(item["run_attempt"]) == 1)
            _text(item["name"])
            _require(
                item["status"] in ("queued", "in_progress", "completed")
                and item["conclusion"]
                in (
                    None,
                    "success",
                    "failure",
                    "cancelled",
                    "skipped",
                    "neutral",
                    "timed_out",
                    "action_required",
                    "stale",
                )
            )
            steps = []
            for step in _array(item["steps"], 128):
                step = _obj(step)
                _id(step["number"])
                _text(step["name"])
                _require(
                    step["status"] in ("queued", "in_progress", "completed")
                    and step["conclusion"]
                    in (
                        None,
                        "success",
                        "failure",
                        "cancelled",
                        "skipped",
                        "neutral",
                        "timed_out",
                        "action_required",
                    )
                )
                for timestamp in ("started_at", "completed_at"):
                    if step[timestamp] is not None:
                        _instant(step[timestamp])
                if step["completed_at"] is not None:
                    _require(
                        step["started_at"] is not None
                        and _instant(step["started_at"])
                        <= _instant(step["completed_at"])
                    )
                steps.append(
                    StepFact(
                        **{
                            key: step[key]
                            for key in (
                                "number",
                                "name",
                                "status",
                                "conclusion",
                                "started_at",
                                "completed_at",
                            )
                        }
                    )
                )
            _require(
                [s.number for s in steps] == sorted({s.number for s in steps})
                and len({s.name for s in steps}) == len(steps)
            )
            for timestamp in ("started_at", "completed_at"):
                if item[timestamp] is not None:
                    _instant(item[timestamp])
            if item["completed_at"] is not None:
                _require(
                    item["started_at"] is not None
                    and _instant(item["started_at"]) <= _instant(item["completed_at"])
                )
            jobs.append(
                JobFact(
                    _id(item["id"]),
                    run.run_id,
                    run.head_sha,
                    item["name"],
                    item["status"],
                    item["conclusion"],
                    item["started_at"],
                    item["completed_at"],
                    _id(item["runner_id"]),
                    _text(item["runner_name"]),
                    _id(item["runner_group_id"]),
                    tuple(steps),
                )
            )
        selected = [job for job in jobs if job.name == w.job_name]
        _require(len(selected) == 1)
        job = selected[0]
        _require(
            (job.runner_id, job.runner_name, job.runner_group_id)
            == (w.runner_id, w.runner_name, w.runner_group_id)
            and job.started_at is not None
        )
        _require(
            tuple((s.number, s.name) for s in job.steps)
            == tuple((s.number, s.name) for s in w.required_steps)
        )
        ranks = {s: n for n, s in enumerate(ProducerStage)}
        courier_number = None
        if stage == ProducerStage.PROTECTED_JOB_STARTED:
            couriers = [
                s
                for s in w.required_steps
                if s.required_stage == ProducerStage.PROTECTED_JOB_STARTED
            ]
            _require(len(couriers) == 1)
            courier_number = couriers[0].number
        for fact, pin in zip(job.steps, w.required_steps, strict=True):
            if courier_number == pin.number:
                _require(
                    fact.status == "in_progress"
                    and fact.conclusion is None
                    and fact.started_at is not None
                    and fact.completed_at is None
                    and _instant(job.started_at) <= _instant(fact.started_at)
                )
            elif ranks[pin.required_stage] <= ranks[stage] or (
                courier_number is not None and pin.number < courier_number
            ):
                _require(
                    fact.status == "completed"
                    and fact.conclusion == "success"
                    and fact.started_at is not None
                    and fact.completed_at is not None
                )
                _require(_instant(job.started_at) <= _instant(fact.started_at))
                if job.completed_at is not None:
                    _require(_instant(fact.completed_at) <= _instant(job.completed_at))
        if stage == ProducerStage.PROTECTED_JOB_STARTED:
            _require(
                job.status == "in_progress"
                and job.conclusion is None
                and job.completed_at is None
                and anchor["status"] == "in_progress"
                and anchor["conclusion"] is None
            )
        if stage not in (
            ProducerStage.PROTECTED_JOB_STARTED,
            ProducerStage.COLLECTION_SNAPSHOT,
        ):
            _require(
                job.status == "completed"
                and job.conclusion == "success"
                and job.completed_at is not None
            )
        if stage == ProducerStage.PRODUCER_RUN_COMPLETE:
            _require(
                anchor["status"] == "completed" and anchor["conclusion"] == "success"
            )
            _require(
                all(
                    j.status == "completed"
                    and j.conclusion == "success"
                    and j.completed_at is not None
                    and all(
                        s.status == "completed"
                        and s.conclusion == "success"
                        and s.completed_at is not None
                        for s in j.steps
                    )
                    for j in jobs
                )
            )
        reviews = _array(self._read(EndpointCode.REVIEWS, run), 32)
        reviews_digest = self._observations[-1].response_sha256
        relevant = []
        for review in reviews:
            review = _obj(review)
            environments = _array(review["environments"], 32)
            ids = tuple(_id(_obj(env)["id"]) for env in environments)
            names = tuple(_text(_obj(env)["name"]) for env in environments)
            _require(len(set(ids)) == len(ids))
            if w.environment_id in ids or w.environment_name in names:
                _require(
                    ids == (w.environment_id,)
                    and names == (w.environment_name,)
                    and review["state"] == "approved"
                    and _id(_obj(review["user"])["id"]) == w.reviewer_id
                )
                relevant.append(
                    ReviewFact("approved", w.reviewer_id, ids, names, reviews_digest)
                )
        _require(len(relevant) == 1)
        pending = _array(self._read(EndpointCode.PENDING, run), 32)
        _require(
            all(
                _id(_obj(_obj(item)["environment"])["id"]) != w.environment_id
                and _obj(_obj(item)["environment"])["name"] != w.environment_name
                for item in pending
            )
        )
        environment = _obj(self._read(EndpointCode.ENVIRONMENT, run))
        _require(
            _id(environment["id"]) == w.environment_id
            and environment["name"] == w.environment_name
        )
        rules = _array(environment["protection_rules"], 32)
        _require(rules == policy["environment_rules"])
        branches = self._pages(EndpointCode.BRANCHES, "branch_policies", 32, run)
        branch_facts = sorted(
            (
                {"name": _text(_obj(b)["name"]), "type": _text(_obj(b)["type"])}
                for b in branches
            ),
            key=lambda b: (b["name"], b["type"]),
        )
        _require(
            branch_facts == policy["branch_policies"]
            and all(b["type"] == "branch" for b in branch_facts)
        )
        # Current REST policy is never substituted for action-time qualification.
        action = _closed(
            _obj(self._qualification["action_time"])[str(run.run_id)],
            "run_id head_sha runner_id runner_group_id job_name environment_id "
            "qualified_at protection_rules_sha256 branch_policies_sha256 "
            "source_policy_digest native_record_digest",
        )
        for key, expected in (
            ("run_id", run.run_id),
            ("head_sha", run.head_sha),
            ("runner_id", w.runner_id),
            ("runner_group_id", w.runner_group_id),
            ("job_name", w.job_name),
            ("environment_id", w.environment_id),
            ("source_policy_digest", w.source_policy_pin[1]),
            ("protection_rules_sha256", _digest(_canonical(rules))),
            ("branch_policies_sha256", _digest(_canonical(branch_facts))),
        ):
            _require(type(action[key]) is type(expected) and action[key] == expected)
        _hex(action["native_record_digest"])
        _require(_instant(action["qualified_at"]) <= _instant(job.started_at))
        _require(self._run_anchor(self._read(EndpointCode.RUN, run), run) == anchor)
        return ProducerFacts(
            self._repository.repository_id,
            self._repository.owner_id,
            run.run_id,
            1,
            w.id,
            run.head_sha,
            source,
            stage,
            anchor["status"],
            anchor["conclusion"],
            tuple(jobs),
            relevant[0],
            w.environment_id,
            (w.source_policy_pin[1], _digest(_canonical(action))),
            tuple(self._observations),
        )

    def producer_snapshot(self, stage: ProducerStage) -> ProducerFacts:
        def observe():
            _require(stage != ProducerStage.PROTECTED_JOB_STARTED)
            return self._producer_facts(self._producer, stage)

        return self._phase("producer", 90, observe)

    def protected_job_snapshot(self, *, deadline: float) -> ProducerFacts:
        """Observe the assigned protected job before collection, without future success.

        Original provisioning authority caps this one-use read phase. These facts
        authenticate GitHub observations, not local PID or cgroup ownership.
        """
        return self._phase(
            "protected_job",
            90,
            lambda: self._producer_facts(
                self._producer, ProducerStage.PROTECTED_JOB_STARTED
            ),
            deadline=deadline,
        )

    def publication_snapshot(self) -> PublicationFacts:
        def observe():
            run = self._publication
            facts = self._producer_facts(run, ProducerStage.COLLECTION_SNAPSHOT)
            policy = self._policies[run.run_id]
            anchor = self._run_anchor(self._read(EndpointCode.RUN, run), run)
            _require(
                policy["publication_title"] is not None
                and anchor["display_title"] == policy["publication_title"]
            )
            return PublicationFacts(
                facts,
                anchor["display_title"],
                policy["selected_summary_digest"],
                facts.review.observation_sha256,
            )

        return self._phase("publication", 90, observe)

    def _artifact(
        self, run: RunPin, transfer: TransferPin, producer: ProducerFacts
    ) -> dict:
        item = _obj(self._read(EndpointCode.ARTIFACT, identifier=transfer.artifact_id))
        _require(
            _id(item["id"]) == transfer.artifact_id
            and item["name"] == transfer.name
            and item["expired"] is False
        )
        _require(
            type(item["size_in_bytes"]) is int and 0 < item["size_in_bytes"] <= _ZIP_CAP
        )
        _require(type(item["digest"]) is str and item["digest"].startswith("sha256:"))
        _hex(item["digest"][7:])
        source = _obj(item["workflow_run"])
        for key, expected in (
            ("id", run.run_id),
            ("repository_id", self._repository.repository_id),
            ("head_repository_id", self._repository.repository_id),
            ("head_sha", run.head_sha),
            ("head_branch", run.branch),
        ):
            _require(type(source[key]) is type(expected) and source[key] == expected)
        job = next(j for j in producer.jobs if j.name == run.workflow.job_name)
        upload_number = self._policies[run.run_id]["sole_artifact_step"]
        step = next(s for s in job.steps if s.number == upload_number)
        _require(
            step.status == "completed"
            and step.conclusion == "success"
            and step.started_at is not None
            and step.completed_at is not None
        )
        _require(
            _instant(step.started_at)
            <= _instant(item["created_at"])
            <= _instant(item["updated_at"])
            <= _instant(step.completed_at)
        )
        _require(_instant(item["expires_at"]) > datetime.now(UTC))
        return {
            key: item[key]
            for key in (
                "id",
                "name",
                "size_in_bytes",
                "expired",
                "digest",
                "workflow_run",
                "created_at",
                "updated_at",
                "expires_at",
            )
        }

    def encrypted_transfer(self) -> VerifiedProducerTransfer:
        def observe():
            value = _closed(
                self._transfer,
                "artifact_id name expected_artifact_names ciphertext_name "
                "projection_name",
            )
            names = tuple(
                _text(n) for n in _array(value["expected_artifact_names"], 32)
            )
            _require(
                bool(names)
                and len(set(names)) == len(names)
                and value["name"] in names
                and value["ciphertext_name"] == "gate0-evidence.pgp"
                and value["projection_name"] == "gate0-evidence-public.json"
            )
            pin = TransferPin(_id(value["artifact_id"]), _text(value["name"]), names)
            producer = self._producer_facts(
                self._producer, ProducerStage.PRODUCER_JOB_COMPLETE
            )
            roster = self._pages(
                EndpointCode.ARTIFACTS, "artifacts", 32, self._producer
            )
            _require(
                len(roster) == len(names)
                and {item["name"] for item in roster} == set(names)
                and any(
                    _id(item["id"]) == pin.artifact_id and item["name"] == pin.name
                    for item in roster
                )
            )
            before = self._artifact(self._producer, pin, producer)
            raw, next_page, last_page = self._get(
                EndpointCode.ZIP, identifier=pin.artifact_id, maximum=_ZIP_CAP
            )
            _require(
                next_page == last_page == 0
                and len(raw) == before["size_in_bytes"]
                and _digest(raw) == before["digest"][7:]
            )
            _require(
                self._qualification["transfer_profile"]
                == "flat-two-stored-or-deflate-no-extra.v1"
            )
            ciphertext, projection = _unzip(raw)
            policy = self._policies[self._producer.run_id]
            for data, key in (
                (ciphertext, "ciphertext_sha256"),
                (projection, "projection_sha256"),
            ):
                _require(policy[key] is None or _digest(data) == policy[key])
            _projection(projection, ciphertext, producer, policy)
            _require(self._artifact(self._producer, pin, producer) == before)
            self._run_anchor(
                self._read(EndpointCode.RUN, self._producer), self._producer
            )
            return VerifiedProducerTransfer(
                producer,
                pin.artifact_id,
                pin.name,
                _digest(raw),
                len(raw),
                ciphertext,
                _digest(ciphertext),
                projection,
                _digest(projection),
                tuple(self._observations),
            )

        return self._phase("transfer", 180, observe)

    def _release_pin(self, published: bool) -> ReleasePin:
        value = _closed(self._release, "release_id tag commit assets")
        _require(
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}", _text(value["tag"]))
            is not None
            and ".." not in value["tag"]
            and "//" not in value["tag"]
        )
        assets = []
        expected_names = (
            (
                "gate0-evidence.pgp",
                "gate0-evidence-public.json",
                "gate0-readiness-receipt.json",
            )
            if published
            else ("gate0-evidence.pgp", "gate0-evidence-public.json")
        )
        for asset in _array(value["assets"], 3):
            asset = _closed(asset, "id name size sha256")
            _require(
                type(asset["size"]) is int
                and 0 < asset["size"] <= _asset_cap(asset["name"])
            )
            assets.append(
                ReleaseAssetPin(
                    _id(asset["id"]),
                    asset["name"],
                    asset["size"],
                    _hex(asset["sha256"]),
                )
            )
        _require(
            tuple(a.name for a in assets) == expected_names
            and len({a.id for a in assets}) == len(assets)
        )
        return ReleasePin(
            _id(value["release_id"]),
            value["tag"],
            _hex(value["commit"], 40),
            tuple(assets),
        )

    def _release_anchor(self, value: object, pin: ReleasePin, published: bool):
        value = _obj(value)
        _require(
            _id(value["id"]) == pin.release_id
            and value["tag_name"] == pin.tag
            and type(value["draft"]) is bool
            and value["draft"] is (not published)
            and type(value["immutable"]) is bool
        )
        _instant(value["created_at"])
        if value["published_at"] is not None:
            _require(
                _instant(value["created_at"])
                <= _instant(value["published_at"])
                <= datetime.now(UTC)
            )
        if published:
            _require(value["immutable"] is True and value["published_at"] is not None)
        return {
            key: value[key]
            for key in (
                "id",
                "tag_name",
                "draft",
                "immutable",
                "created_at",
                "published_at",
            )
        }

    def _asset_metadata(self, value: object, pin: ReleaseAssetPin):
        value = _obj(value)
        _require(
            _id(value["id"]) == pin.id
            and value["name"] == pin.name
            and value["state"] == "uploaded"
            and type(value["size"]) is int
            and value["size"] == pin.size
            and value["digest"] == "sha256:" + pin.sha256
        )
        _id(_obj(value["uploader"])["id"])
        _text(value["content_type"])
        _require(
            _instant(value["created_at"])
            <= _instant(value["updated_at"])
            <= datetime.now(UTC)
        )
        return {
            key: value[key]
            for key in (
                "id",
                "name",
                "state",
                "size",
                "digest",
                "content_type",
                "uploader",
                "created_at",
                "updated_at",
            )
        }

    def _tag_binding(self, pin: ReleasePin) -> tuple[str, str]:
        ref = _obj(self._read(EndpointCode.TAG_REF, identifier=pin.tag))
        _require(ref["ref"] == "refs/tags/" + pin.tag)
        target = _obj(ref["object"])
        raw_tag_sha = _hex(target["sha"], 40)
        visited = set()
        for depth in range(5):
            sha = _hex(target["sha"], 40)
            _require(sha not in visited)
            visited.add(sha)
            if target["type"] == "commit":
                _require(sha == pin.commit)
                return raw_tag_sha, sha
            _require(target["type"] == "tag" and depth < 4)
            tag = _obj(self._read(EndpointCode.TAG, identifier=sha))
            _require(_hex(tag["sha"], 40) == sha)
            target = _obj(tag["object"])
        raise GitHubReadRefused()

    def _tag_commit(self, pin: ReleasePin) -> str:
        return self._tag_binding(pin)[1]

    def _release_facts(self, published: bool) -> DownloadedReleaseFacts:
        pin = self._release_pin(published)
        producer = self._producer_facts(
            self._producer, ProducerStage.PRODUCER_RUN_COMPLETE
        )
        _require(pin.commit == producer.head_sha)
        repository = _obj(self._read(EndpointCode.REPOSITORY))
        _require(
            _id(repository["id"]) == self._repository.repository_id
            and _id(_obj(repository["owner"])["id"]) == self._repository.owner_id
            and repository["full_name"]
            == self._repository.owner + "/" + self._repository.name
        )
        if published:
            setting = _closed(
                self._qualification["immutable_setting"],
                "repository_id state response_sha256 native_record_digest observed_at",
            )
            _require(
                _id(setting["repository_id"]) == self._repository.repository_id
                and setting["state"] == "enabled"
            )
            _hex(setting["response_sha256"])
            _hex(setting["native_record_digest"])
            _require(_instant(setting["observed_at"]) <= datetime.now(UTC))
        before = self._release_anchor(
            self._read(EndpointCode.RELEASE, identifier=pin.release_id), pin, published
        )
        inventory = self._pages(
            EndpointCode.ASSETS, None, 32, identifier=pin.release_id
        )
        _require(
            {item["id"] for item in inventory} == {a.id for a in pin.assets}
            and len(inventory) == len(pin.assets)
        )
        initial = {}
        facts = []
        for asset in pin.assets:
            listed = next(item for item in inventory if item["id"] == asset.id)
            metadata = self._asset_metadata(
                self._read(EndpointCode.ASSET, identifier=asset.id), asset
            )
            _require(self._asset_metadata(listed, asset) == metadata)
            initial[asset.id] = metadata
            raw, next_page, last_page = self._get(
                EndpointCode.ASSET_BYTES,
                identifier=asset.id,
                maximum=_asset_cap(asset.name),
            )
            _require(
                next_page == last_page == 0
                and len(raw) == asset.size
                and _digest(raw) == asset.sha256
            )
            if asset.name.endswith(".json"):
                _obj(_json(raw))
            _require(
                self._asset_metadata(
                    self._read(EndpointCode.ASSET, identifier=asset.id), asset
                )
                == metadata
            )
            facts.append(
                ReleaseAssetFact(
                    asset.id,
                    asset.name,
                    "uploaded",
                    metadata["content_type"],
                    asset.size,
                    asset.sha256,
                    metadata["uploader"]["id"],
                    raw,
                )
            )
        _projection(
            next(a.raw_bytes for a in facts if a.name == "gate0-evidence-public.json"),
            next(a.raw_bytes for a in facts if a.name == "gate0-evidence.pgp"),
            producer,
            self._policies[self._producer.run_id],
        )
        tag_binding = self._tag_binding(pin)
        after_inventory = self._pages(
            EndpointCode.ASSETS, None, 32, identifier=pin.release_id
        )
        _require(
            {item["id"] for item in after_inventory} == set(initial)
            and len(after_inventory) == len(initial)
        )
        for asset in pin.assets:
            _require(
                self._asset_metadata(
                    next(item for item in after_inventory if item["id"] == asset.id),
                    asset,
                )
                == initial[asset.id]
            )
        _require(
            self._release_anchor(
                self._read(EndpointCode.RELEASE, identifier=pin.release_id),
                pin,
                published,
            )
            == before
            and self._tag_binding(pin) == tag_binding
        )
        return DownloadedReleaseFacts(
            self._repository.repository_id,
            pin.release_id,
            pin.tag,
            tag_binding[1],
            not published,
            before["immutable"],
            tuple(facts),
            tuple(self._observations),
            tag_binding[0],
            self._repository.owner_id,
        )

    def draft_snapshot(self) -> DownloadedReleaseFacts:
        return self._phase("draft", 180, lambda: self._release_facts(False))

    def published_snapshot(self) -> DownloadedReleaseFacts:
        return self._phase("published", 180, lambda: self._release_facts(True))


def _asset_cap(name: str) -> int:
    caps = {
        "gate0-evidence.pgp": _CIPHER_CAP,
        "gate0-evidence-public.json": 65536,
        "gate0-readiness-receipt.json": 131072,
    }
    _require(name in caps)
    return caps[name]


def _unzip(raw: bytes) -> tuple[bytes, bytes]:
    """Strict, qualified profile; no extraction, ZIP64 or descriptors."""
    _require(22 <= len(raw) <= _ZIP_CAP and raw[-22:-18] == b"PK\x05\x06")
    _, disk, central_disk, count_disk, count, central_size, central_offset, comment = (
        struct.unpack("<4s4H2IH", raw[-22:])
    )
    _require(
        disk == central_disk == comment == 0
        and count_disk == count == 2
        and central_offset + central_size == len(raw) - 22
    )
    output = {}
    end = 0
    expanded = 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        _require(not archive.comment and len(archive.infolist()) == 2)
        for info in archive.infolist():
            _require(
                info.filename in ("gate0-evidence.pgp", "gate0-evidence-public.json")
                and info.filename not in output
                and info.orig_filename == info.filename
            )
            _require(
                info.header_offset == end
                and info.flag_bits == 0
                and info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                and not info.extra
                and not info.comment
                and not info.is_dir()
                and info.volume == 0
                and info.extract_version <= 20
            )
            mode = info.external_attr >> 16
            _require(mode == 0 or stat.S_IFMT(mode) in (0, stat.S_IFREG))
            _require(
                not (info.external_attr & 0x10)
                and 0 < info.file_size <= _asset_cap(info.filename)
                and 0 < info.compress_size <= _ZIP_CAP
            )
            _require(info.header_offset + 30 <= central_offset)
            (
                signature,
                version,
                flags,
                method,
                _,
                _,
                crc,
                compressed,
                size,
                name_size,
                extra_size,
            ) = struct.unpack(
                "<4s5H3I2H", raw[info.header_offset : info.header_offset + 30]
            )
            _require(
                signature == b"PK\x03\x04"
                and version <= 20
                and flags == 0
                and method == info.compress_type
                and crc == info.CRC
                and compressed == info.compress_size
                and size == info.file_size
                and extra_size == 0
            )
            start = info.header_offset + 30
            _require(raw[start : start + name_size] == info.filename.encode("ascii"))
            end = start + name_size + compressed
            _require(end <= central_offset)
            member = bytearray()
            decoder = (
                zlib.decompressobj(-15)
                if info.compress_type == zipfile.ZIP_DEFLATED
                else None
            )
            for offset in range(start + name_size, end, 65536):
                block = raw[offset : min(end, offset + 65536)]
                if decoder is not None:
                    block = decoder.decompress(block, info.file_size - len(member) + 1)
                    _require(not decoder.unconsumed_tail and not decoder.unused_data)
                member.extend(block)
                expanded += len(block)
                _require(
                    len(member) <= info.file_size and expanded <= _CIPHER_CAP + 65536
                )
            if decoder is not None:
                _require(decoder.eof and not decoder.unused_data)
            else:
                _require(compressed == size)
            _require(len(member) == info.file_size and zlib.crc32(member) == info.CRC)
            output[info.filename] = bytes(member)
        _require(
            end == central_offset
            and set(output) == {"gate0-evidence.pgp", "gate0-evidence-public.json"}
        )
    _obj(_json(output["gate0-evidence-public.json"]))
    return output["gate0-evidence.pgp"], output["gate0-evidence-public.json"]


class InstalledGhReleaseVerifier:
    """Deliberately unavailable: no qualified official-tool transport yet."""

    @classmethod
    def from_installed(cls):
        raise AttestationTransportUnqualified()


def _prefixed_digest(value: object) -> str:
    _require(type(value) is str and value.startswith("sha256:"))
    _hex(value[7:])
    return value


def _projection(
    raw: bytes, ciphertext: bytes, producer: ProducerFacts, policy: dict
) -> dict:
    _require(0 < len(raw) <= 65536)
    value = _closed(
        _json(raw),
        "schema policy_digest campaign_digest source_bundle_digest "
        "collection_digest plaintext_archive_digest inner_manifest_digest "
        "ciphertext_digest ciphertext_bytes producer result",
    )
    _require(
        value["schema"] == "Gate0EncryptedEvidenceProjection.v1"
        and value["result"] == "encrypted_evidence"
    )
    for key in (
        "policy_digest",
        "campaign_digest",
        "source_bundle_digest",
        "collection_digest",
        "plaintext_archive_digest",
        "inner_manifest_digest",
        "ciphertext_digest",
    ):
        _prefixed_digest(value[key])
    for key in ("policy_digest", "campaign_digest", "source_bundle_digest"):
        _require(value[key] == policy[key])
    _require(
        type(value["ciphertext_bytes"]) is int
        and value["ciphertext_bytes"] == len(ciphertext)
        and 0 < len(ciphertext) <= _CIPHER_CAP
        and value["ciphertext_digest"] == "sha256:" + _digest(ciphertext)
    )
    coordinates = _closed(
        value["producer"],
        "repository_id owner_id workflow_id run_id attempt job_id source_revision",
    )
    selected = next(job for job in producer.jobs if job.name == policy["job_name"])
    expected = {
        "repository_id": producer.repository_id,
        "owner_id": producer.owner_id,
        "workflow_id": producer.workflow_id,
        "run_id": producer.run_id,
        "attempt": 1,
        "job_id": selected.id,
        "source_revision": producer.head_sha,
    }
    for key, expected_value in expected.items():
        _require(
            type(coordinates[key]) is type(expected_value)
            and coordinates[key] == expected_value
        )
    # collection/plaintext/inner-manifest hashes remain retained producer claims.
    return value
