"""Closed root-output handoff, with no installed provenance fallback.

Codecs validate shape and joins, never authenticate a root. The concrete owner
below retains actual child pipes/EOF/wait. Installed construction requires
the measured holder/A9 sshd/process binding;
there is no caller-supplied command, UID, authenticated flag, or transport factory.
"""

from __future__ import annotations

import base64
import hashlib
import math
import os
import re
import select
import socket
import stat
import struct
import subprocess
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TypedDict, cast

from vendor_cp.deployment.gate0_framing import canonical, strict_object
from vendor_cp.deployment.gate0_role_custody import ProviderRefused


class FilePin(TypedDict):
    path: str
    digest: str


class Endpoint(TypedDict):
    host: str
    port: int
    user: str
    host_key_alias: str


class ActivationBinding(TypedDict):
    executable_digest: str
    instance_id: str
    qualification_digest: str
    image_digest: str
    source_revision: str


class RootEndpoint(Endpoint):
    binding: dict[str, str]
    activation: ActivationBinding


class SocketMetadata(TypedDict):
    path: str
    uid: int
    device: int
    inode: int
    mode: int


class AgentBinding(SocketMetadata):
    parents: list[SocketMetadata]


class HolderCase(TypedDict):
    kind: str
    IDP3: RootEndpoint
    NS3: RootEndpoint


class ReceiverCase(TypedDict):
    IDP3: dict[str, str]
    NS3: dict[str, str]


class PeerBinding(TypedDict):
    uid: int
    pid: int
    start: str


class HolderInstallation(TypedDict):
    schema: str
    campaign_digest: str
    ssh_binary: FilePin
    holder_uid: int
    home: str
    public_identity: FilePin
    public_key_fingerprint: str
    ssh_add_binary: FilePin
    agent: AgentBinding
    agent_qualification: FilePin
    known_hosts: FilePin
    downstream: Endpoint
    cases: list[HolderCase]


class ReceiverInstallation(TypedDict):
    schema: str
    campaign_digest: str
    receiver_uid: int
    collector: PeerBinding
    sshd_binary: FilePin
    sshd_config: FilePin
    receiver_binary: FilePin
    authorized_keys: FilePin
    qualification: FilePin
    holder_public_key: str
    holder_source: str
    cases: list[ReceiverCase]


def _holder_host(case: HolderCase, host: str) -> RootEndpoint:
    return case["IDP3"] if host == "IDP3" else case["NS3"]


def _receiver_host(case: ReceiverCase, host: str) -> dict[str, str]:
    return case["IDP3"] if host == "IDP3" else case["NS3"]


_MAX_ROOT = 196608
_MAX_ENVELOPE = 270336
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PHASES = {
    "issuer": ("issuer_listening",),
    "attester": ("management_listening", "attester_listening_after_capture"),
}
_CLEANUP_COMMON = (
    "schema host_role case_kind launch_packet_digest local_packet_digest window_digest "
    "machine_id_digest network_measurement_digest supervisor_pid supervisor_start "
    "started_at "
    "expires_at phase_completed_at terminals daemon_observations boundaries "
    "removed expected_removed "
    "cleanup_completed_at outcome reason delivery_status "
)
_BINDING_FIELDS = (
    "host_role case_kind launch_packet_digest local_packet_digest window_digest "
    "machine_id_digest network_measurement_digest not_before expires_at"
).split()


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _hash(value: object) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ProviderRefused()
    return value


def _object(raw: bytes, fields: str, maximum: int = _MAX_ENVELOPE) -> dict[str, object]:
    doc = strict_object(raw, maximum)
    if canonical(doc) != raw or set(doc) != set(fields.split()):
        raise ProviderRefused()
    return doc


@dataclass(frozen=True, slots=True)
class RootHostBinding:
    """Inert expected root coordinates; construction confers no provenance."""

    document: bytes = field(repr=False)

    def __post_init__(self) -> None:
        doc = _object(self.document, " ".join(_BINDING_FIELDS), 8192)
        if (
            type(doc["host_role"]) is not str
            or type(doc["case_kind"]) is not str
            or doc["host_role"] not in _PHASES
            or doc["case_kind"]
            not in (
                "consume_replay",
                "withdrawal_later_use",
            )
        ):
            raise ProviderRefused()
        for key in _BINDING_FIELDS:
            if key.endswith("digest"):
                _hash(doc[key])
            elif type(doc[key]) is not str or not 0 < len(cast(str, doc[key])) <= 512:
                raise ProviderRefused()

    @property
    def terms(self) -> dict[str, str]:
        return cast(dict[str, str], strict_object(self.document, 8192))


class RootFrameSequence:
    """Per-host closed roster: IDP3 phase/final, NS3 two phases/final.

    Retains exact bytes. A frame's parsed claims are still untrusted until its
    authenticated owned channel is joined by the collector.
    """

    def __init__(self, binding: RootHostBinding) -> None:
        if type(binding) is not RootHostBinding:
            raise ProviderRefused()
        self.binding = binding
        self.records: list[bytes] = []
        self.final: bytes | None = None
        self._process_binding: tuple[object, ...] | None = None

    def accept(self, raw: bytes) -> str:
        doc = strict_object(raw, _MAX_ROOT)
        terms = self.binding.terms
        phases = _PHASES[terms["host_role"]]
        index = len(self.records)
        if (
            canonical(doc) != raw
            or self.final is not None
            or any(doc.get(k) != v for k, v in terms.items() if k != "not_before")
        ):
            raise ProviderRefused()
        if index < len(phases):
            from vendor_cp.deployment.gate0_launch_phase import decode_phase

            doc = dict(decode_phase(raw))
            if (
                doc["phase"] != phases[index]
                or doc["not_before"] != terms["not_before"]
            ):
                raise ProviderRefused()
            kind = phases[index]
        else:
            if (
                index != len(phases)
                or doc.get("schema") != "Gate0LaunchCleanup.v1"
                or set(doc)
                != set(
                    (
                        _CLEANUP_COMMON
                        + (
                            "capture_delivery"
                            if terms["host_role"] == "issuer"
                            else "management_capture"
                        )
                    ).split()
                )
                or doc.get("delivery_status") != "unconfirmed"
                or doc.get("outcome") not in ("complete", "incomplete")
            ):
                raise ProviderRefused()
            kind = "final"
        process_binding = tuple(
            doc.get(k) for k in ("supervisor_pid", "supervisor_start", "started_at")
        )
        pid = process_binding[0]
        if (
            type(pid) is not int
            or pid <= 0
            or any(type(v) is not str or not v for v in process_binding[1:])
        ):
            raise ProviderRefused()
        if (
            self._process_binding is not None
            and self._process_binding != process_binding
        ):
            raise ProviderRefused()
        self._process_binding = process_binding
        if kind == "final":
            self.final = raw
        self.records.append(raw)
        return kind

    def final_bytes(self) -> bytes:
        if self.final is None:
            raise ProviderRefused()
        return self.final

    def require_complete(self) -> None:
        if self.final is None:
            raise ProviderRefused()
        final = strict_object(self.final)
        if final["outcome"] != "complete" or final["reason"] != "completed_mechanics":
            raise ProviderRefused()


def encode_root_event(campaign: str, host: str, raw: bytes) -> bytes:
    """Preserve original root bytes; this envelope makes no authenticity claim."""
    _hash(campaign)
    if host not in ("IDP3", "NS3"):
        raise ProviderRefused()
    strict_object(raw, _MAX_ROOT)
    return canonical(
        {
            "schema": "Gate0RootHandoff.v1",
            "campaign_digest": campaign,
            "host": host,
            "root_b64": base64.b64encode(raw).decode("ascii"),
        }
    )


def decode_root_event(raw: bytes, campaign: str) -> tuple[str, bytes]:
    doc = _object(raw, "schema campaign_digest host root_b64")
    _hash(campaign)
    if (
        doc["schema"] != "Gate0RootHandoff.v1"
        or doc["campaign_digest"] != campaign
        or doc["host"] not in ("IDP3", "NS3")
        or type(doc["root_b64"]) is not str
    ):
        raise ProviderRefused()
    try:
        root = base64.b64decode(doc["root_b64"], validate=True)
    except ValueError:
        raise ProviderRefused() from None
    if base64.b64encode(root).decode("ascii") != doc["root_b64"]:
        raise ProviderRefused()
    strict_object(root, _MAX_ROOT)
    return doc["host"], root


def encode_case_a_complete(
    campaign: str, join: bytes, finals: tuple[bytes, bytes]
) -> bytes:
    """Collector calls only after its verified A join on its protected IPC."""
    _hash(campaign)
    strict_object(join, _MAX_ROOT)
    if type(finals) is not tuple or len(finals) != 2:
        raise ProviderRefused()
    return canonical(
        {
            "schema": "Gate0CaseAComplete.v1",
            "campaign_digest": campaign,
            "join_digest": _digest(join),
            "root_final_digests": [_digest(raw) for raw in finals],
        }
    )


def decode_case_a_complete(
    raw: bytes, campaign: str, finals: tuple[bytes, bytes]
) -> str:
    doc = _object(raw, "schema campaign_digest join_digest root_final_digests", 4096)
    if (
        doc["schema"] != "Gate0CaseAComplete.v1"
        or doc["campaign_digest"] != _hash(campaign)
        or doc["root_final_digests"] != [_digest(raw) for raw in finals]
    ):
        raise ProviderRefused()
    return _hash(doc["join_digest"])


class _OwnedIO:
    """Dedicated actual process pipes or peer-checked socket, original deadline."""

    def __init__(self, read_fd: int, write_fd: int, deadline: float) -> None:
        if not math.isfinite(deadline) or deadline <= time.monotonic():
            raise ProviderRefused()
        self.read_fd, self.write_fd, self.deadline = read_fd, write_fd, deadline
        self.received = self.sent = 0
        os.set_blocking(read_fd, False)
        os.set_blocking(write_fd, False)

    def _wait(self, fd: int, write: bool) -> None:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ProviderRefused()
        r, w, _ = select.select(
            [] if write else [fd], [fd] if write else [], [], remaining
        )
        if not (w if write else r) or time.monotonic() >= self.deadline:
            raise ProviderRefused()

    def _read(self, size: int, *, eof: bool = False) -> bytes | None:
        result = bytearray()
        while len(result) < size:
            self._wait(self.read_fd, False)
            try:
                chunk = os.read(self.read_fd, size - len(result))
            except BlockingIOError:
                continue
            if not chunk:
                if eof and not result:
                    return None
                raise ProviderRefused()
            result.extend(chunk)
        if time.monotonic() >= self.deadline:
            raise ProviderRefused()
        return bytes(result)

    def receive(self, *, eof: bool = False) -> bytes | None:
        header = self._read(4, eof=eof)
        if header is None:
            return None
        size = struct.unpack("!I", header)[0]
        if not 0 < size <= _MAX_ENVELOPE or self.received >= 16:
            raise ProviderRefused()
        self.received += 1
        raw = self._read(size)
        if raw is None:
            raise ProviderRefused()
        strict_object(raw, _MAX_ENVELOPE)
        return raw

    def send(self, raw: bytes) -> None:
        strict_object(raw, _MAX_ENVELOPE)
        if self.sent >= 16:
            raise ProviderRefused()
        self.sent += 1
        pending = memoryview(struct.pack("!I", len(raw)) + raw)
        while pending:
            self._wait(self.write_fd, True)
            try:
                count = os.write(self.write_fd, pending[:512])
            except BlockingIOError:
                continue
            if count <= 0:
                raise ProviderRefused()
            pending = pending[count:]


class _OwnedLaunch:
    """One Popen owned by the fixed holder; not constructible from an exit DTO."""

    def __init__(
        self,
        process: subprocess.Popen[bytes],
        sequence: RootFrameSequence,
        deadline: float,
    ) -> None:
        if process.stdout is None:
            raise ProviderRefused()
        self.process, self.sequence = process, sequence
        self._original_end = deadline
        self.io = _OwnedIO(process.stdout.fileno(), process.stdout.fileno(), deadline)
        self.eof = False
        self.returncode: int | None = None

    def next_root(self) -> tuple[str, bytes] | None:
        if self.eof:
            raise ProviderRefused()
        if len(self.sequence.records) >= len(
            _PHASES[self.sequence.binding.terms["host_role"]]
        ):
            self.io.deadline = self._original_end + 2
        raw = self.io.receive(eof=True)
        if raw is None:
            self.eof = True
            remaining = self.io.deadline - time.monotonic()
            if remaining <= 0:
                raise ProviderRefused()
            try:
                self.returncode = self.process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                raise ProviderRefused() from None
            if time.monotonic() >= self.io.deadline:
                raise ProviderRefused()
            return None
        return self.sequence.accept(raw), raw

    def require_complete(self) -> None:
        self.sequence.require_complete()
        if not self.eof or self.returncode != 0:
            raise ProviderRefused()

    def close(self) -> None:
        _teardown([self.process], time.monotonic() + 2)


def _teardown(processes: list[subprocess.Popen[bytes]], deadline: float) -> None:
    """Attempt every kill, reap and stream close under one fixed cleanup end."""
    failure: BaseException | None = None
    for process in processes:
        try:
            if process.poll() is None:
                process.kill()
        except BaseException as error:
            if failure is None:
                failure = error
    for process in processes:
        try:
            process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except BaseException as error:
            if failure is None:
                failure = error
        finally:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except BaseException as error:
                        if failure is None:
                            failure = error
    if failure is not None:
        raise ProviderRefused() from failure


def _require_peer(channel: socket.socket, uid: int, pid: int, start: str) -> None:
    """Kernel credentials plus fixed protected PID/start; never JSON identity."""
    if channel.family != socket.AF_UNIX or not hasattr(socket, "SO_PEERCRED"):
        raise ProviderRefused()
    actual_pid, actual_uid, _ = struct.unpack(
        "3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    )
    if (actual_pid, actual_uid) != (pid, uid) or uid <= 0:
        raise ProviderRefused()
    # Field 22 follows the final ')' in /proc stat; comm can contain spaces/').
    with open(f"/proc/{actual_pid}/stat", "rb") as stream:
        raw = stream.read(8193)
    if len(raw) > 8192 or raw.rsplit(b")", 1)[-1].split()[19].decode("ascii") != start:
        raise ProviderRefused()


def _protected_bytes(
    path: Path, uid: int, maximum: int = 65536, *, private: bool = False
) -> bytes:
    """No symlink components; final regular file owned by installed authority."""
    if not path.is_absolute() or ".." in path.parts:
        raise ProviderRefused()
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for index, name in enumerate(path.parts[1:]):
            last = index == len(path.parts) - 2
            child = os.open(
                name,
                os.O_RDONLY
                | os.O_NOFOLLOW
                | os.O_NONBLOCK
                | os.O_CLOEXEC
                | (0 if last else os.O_DIRECTORY),
                dir_fd=fd,
            )
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            # Mac holder's home components may belong to that holder; A9 root
            # descriptors require root-owned ancestry all the way from '/'.
            if (
                info.st_uid not in ({0, uid} if not last else {uid})
                or info.st_mode & 0o022
            ):
                raise ProviderRefused()
            if last and (
                not stat.S_ISREG(info.st_mode) or (private and info.st_mode & 0o077)
            ):
                raise ProviderRefused()
        raw = os.read(fd, maximum + 1)
        if not 0 < len(raw) <= maximum or os.read(fd, 1):
            raise ProviderRefused()
        return raw
    finally:
        os.close(fd)


def _pinned_file(doc: FilePin, uid: int, *, private: bool = False) -> str:
    if (
        type(doc) is not dict
        or set(doc) != {"path", "digest"}
        or type(doc["path"]) is not str
    ):
        raise ProviderRefused()
    raw = _protected_bytes(Path(doc["path"]), uid, 32 * 1024 * 1024, private=private)
    if _digest(raw) != _hash(doc["digest"]):
        raise ProviderRefused()
    return doc["path"]


def _process(pid: int) -> tuple[int, int, str]:
    if type(pid) is not int or pid <= 0:
        raise ProviderRefused()
    root = Path(f"/proc/{pid}")
    raw = (root / "stat").read_bytes()
    status = (root / "status").read_bytes()
    if len(raw) > 8192 or len(status) > 65536:
        raise ProviderRefused()
    fields = raw.rsplit(b")", 1)[-1].split()
    uid_lines = [line for line in status.splitlines() if line.startswith(b"Uid:")]
    if len(uid_lines) != 1:
        raise ProviderRefused()
    uids = uid_lines[0].split()[1:]
    if len(uids) != 4 or len(set(uids)) != 1:
        raise ProviderRefused()
    return int(fields[1]), int(uids[0]), fields[19].decode("ascii")


def _peer_binding(value: object) -> tuple[int, int, str]:
    if type(value) is not dict or set(value) != {"uid", "pid", "start"}:
        raise ProviderRefused()
    if (
        type(value["uid"]) is not int
        or value["uid"] <= 0
        or type(value["start"]) is not str
    ):
        raise ProviderRefused()
    _, uid, start = _process(value["pid"])
    if (uid, start) != (value["uid"], value["start"]):
        raise ProviderRefused()
    return uid, value["pid"], start


def _deadline(instant: str, wall: datetime, mono: float) -> float:
    at = datetime.fromisoformat(instant.replace("Z", "+00:00"))
    offset = at.utcoffset()
    if at.tzinfo is None or offset is None or offset.total_seconds() != 0:
        raise ProviderRefused()
    return mono + (at - wall).total_seconds()


def _terminal(campaign: str, host: str, launch: _OwnedLaunch) -> bytes:
    if (
        not launch.eof
        or type(launch.returncode) is not int
        or launch.sequence.final is None
    ):
        raise ProviderRefused()
    return canonical(
        {
            "schema": "Gate0RootHandoffTerminal.v1",
            "campaign_digest": campaign,
            "host": host,
            "root_final_digest": _digest(launch.sequence.final),
            "stdout_eof": True,
            "management_returncode": launch.returncode,
        }
    )


def decode_terminal(raw: bytes, campaign: str, host: str, final: bytes) -> int:
    doc = _object(
        raw,
        "schema campaign_digest host root_final_digest stdout_eof "
        "management_returncode",
        4096,
    )
    status = doc["management_returncode"]
    if (
        doc["schema"] != "Gate0RootHandoffTerminal.v1"
        or doc["campaign_digest"] != _hash(campaign)
        or doc["host"] != host
        or doc["root_final_digest"] != _digest(final)
        or doc["stdout_eof"] is not True
        or type(status) is not int
        or not -255 <= status <= 255
    ):
        raise ProviderRefused()
    return status


def _validate_cases(cases: object, *, holder: bool) -> None:
    if type(cases) is not list or len(cases) != 2:
        raise ProviderRefused()
    hashes: dict[str, set[str]] = {
        "launch_packet_digest": set(),
        "window_digest": set(),
    }
    local_hashes: set[str] = set()
    instances: set[str] = set()
    for kind, case in zip(
        ("consume_replay", "withdrawal_later_use"), cases, strict=True
    ):
        expected = {"IDP3", "NS3"} | ({"kind"} if holder else set())
        if type(case) is not dict or set(case) != expected:
            raise ProviderRefused()
        terms = []
        for host in ("IDP3", "NS3"):
            if holder:
                activation = cast(ActivationBinding, case[host]["activation"])
                _activation(activation)
                if activation["instance_id"] in instances:
                    raise ProviderRefused()
                instances.add(activation["instance_id"])
            doc = case[host]["binding"] if holder else case[host]
            bound = RootHostBinding(canonical(doc)).terms
            if bound["case_kind"] != kind or bound["host_role"] != (
                "issuer" if host == "IDP3" else "attester"
            ):
                raise ProviderRefused()
            wall, mono = datetime.now(UTC), time.monotonic()
            start = _deadline(bound["not_before"], wall, mono)
            end = _deadline(bound["expires_at"], wall, mono)
            if not 0 < end - start <= 300 or end <= mono or start - mono > 600:
                raise ProviderRefused()
            if bound["local_packet_digest"] in local_hashes:
                raise ProviderRefused()
            local_hashes.add(bound["local_packet_digest"])
            terms.append(bound)
        for key in (
            "launch_packet_digest",
            "window_digest",
            "not_before",
            "expires_at",
        ):
            if terms[0][key] != terms[1][key]:
                raise ProviderRefused()
        for key, seen in hashes.items():
            if terms[0][key] in seen:
                raise ProviderRefused()
            seen.add(terms[0][key])


def _qualified_receiver(doc: ReceiverInstallation) -> None:
    raw = _protected_bytes(Path(doc["qualification"]["path"]), 0)
    receipt = _object(
        raw,
        "schema receiver_uid sshd_binary_digest sshd_config_digest "
        "receiver_binary_digest authorized_keys_digest holder_public_key "
        "holder_source source_revision native_receipt_digest",
    )
    if receipt["schema"] != "Gate0HandoffSshdQualification.v1":
        raise ProviderRefused()
    mapping = cast(dict[str, object], doc)
    for key in ("receiver_uid", "holder_public_key", "holder_source"):
        if receipt[key] != mapping[key]:
            raise ProviderRefused()
    for key in ("sshd_binary", "sshd_config", "receiver_binary", "authorized_keys"):
        if receipt[key + "_digest"] != cast(FilePin, mapping[key])["digest"]:
            raise ProviderRefused()
    _hash(receipt["native_receipt_digest"])
    if (
        type(receipt["source_revision"]) is not str
        or re.fullmatch(r"[0-9a-f]{40}", receipt["source_revision"]) is None
    ):
        raise ProviderRefused()


def activation_command(campaign: str, case_kind: str, host_role: str) -> str:
    _hash(campaign)
    cases = {
        "consume_replay": "consume-replay",
        "withdrawal_later_use": "withdrawal-later-use",
    }
    if case_kind not in cases or host_role not in ("issuer", "attester"):
        raise ProviderRefused()
    return (
        "/usr/local/libexec/dotmac-gate0/"
        + campaign[7:]
        + "/"
        + cases[case_kind]
        + "-"
        + host_role
    )


def _activation(value: ActivationBinding) -> None:
    if type(value) is not dict or set(value) != {
        "executable_digest",
        "instance_id",
        "qualification_digest",
        "image_digest",
        "source_revision",
    }:
        raise ProviderRefused()
    for digest in (
        value["executable_digest"],
        value["qualification_digest"],
        value["image_digest"],
    ):
        _hash(digest)
    if (
        not isinstance(value["instance_id"], str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value["instance_id"])
        is None
    ):
        raise ProviderRefused()
    if (
        not isinstance(value["source_revision"], str)
        or re.fullmatch(r"[0-9a-f]{40}", value["source_revision"]) is None
    ):
        raise ProviderRefused()


def _agent_socket(agent: AgentBinding, uid: int) -> None:
    if type(agent) is not dict or set(agent) != {
        "path",
        "uid",
        "device",
        "inode",
        "mode",
        "parents",
    }:
        raise ProviderRefused()
    path = Path(agent["path"])
    if (
        not path.is_absolute()
        or path.resolve(strict=True) != path
        or agent["uid"] != uid
    ):
        raise ProviderRefused()
    parents = list(reversed(path.parents))
    if len(agent["parents"]) != len(parents):
        raise ProviderRefused()
    for expected, parent in zip(agent["parents"], parents, strict=True):
        info = parent.stat(follow_symlinks=False)
        if type(expected) is not dict or set(expected) != {
            "path",
            "uid",
            "device",
            "inode",
            "mode",
        }:
            raise ProviderRefused()
        if expected != {
            "path": str(parent),
            "uid": info.st_uid,
            "device": info.st_dev,
            "inode": info.st_ino,
            "mode": stat.S_IMODE(info.st_mode),
        } or not stat.S_ISDIR(info.st_mode):
            raise ProviderRefused()
        sticky_temp = (
            str(parent) == "/private/tmp"
            and info.st_uid == 0
            and stat.S_IMODE(info.st_mode) == 0o1777
        )
        if info.st_uid not in (0, uid) or (info.st_mode & 0o022 and not sticky_temp):
            raise ProviderRefused()
    parent_info = path.parent.stat(follow_symlinks=False)
    info = path.stat(follow_symlinks=False)
    if (
        parent_info.st_uid != uid
        or stat.S_IMODE(parent_info.st_mode) != 0o700
        or not stat.S_ISSOCK(info.st_mode)
    ):
        raise ProviderRefused()
    if (info.st_uid, info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode)) != (
        uid,
        agent["device"],
        agent["inode"],
        agent["mode"],
    ) or agent["mode"] not in (0o600, 0o660, 0o666):
        raise ProviderRefused()


def _qualified_agent(doc: HolderInstallation) -> None:
    receipt = _object(
        _protected_bytes(
            Path(doc["agent_qualification"]["path"]), doc["holder_uid"], private=True
        ),
        "schema holder_uid public_key_fingerprint ssh_binary_digest "
        "ssh_add_binary_digest native_receipt_digest custody_owner_ref",
    )
    if (
        receipt["schema"] != "Gate0HolderAgentQualification.v1"
        or receipt["holder_uid"] != doc["holder_uid"]
        or receipt["public_key_fingerprint"] != doc["public_key_fingerprint"]
        or receipt["ssh_binary_digest"] != doc["ssh_binary"]["digest"]
        or receipt["ssh_add_binary_digest"] != doc["ssh_add_binary"]["digest"]
    ):
        raise ProviderRefused()
    _hash(receipt["native_receipt_digest"])
    if (
        type(receipt["custody_owner_ref"]) is not str
        or not 0 < len(receipt["custody_owner_ref"]) <= 512
    ):
        raise ProviderRefused()


def _bounded_output(process: subprocess.Popen[bytes], deadline: float) -> bytes:
    if process.stdout is None:
        raise ProviderRefused()
    fd = process.stdout.fileno()
    os.set_blocking(fd, False)
    output = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise ProviderRefused()
        try:
            chunk = os.read(fd, min(4096, 65537 - len(output)))
        except BlockingIOError:
            continue
        if not chunk:
            break
        output.extend(chunk)
        if len(output) > 65536:
            raise ProviderRefused()
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ProviderRefused()
    try:
        status = process.wait(timeout=remaining)
    except subprocess.TimeoutExpired:
        raise ProviderRefused() from None
    if status != 0 or time.monotonic() >= deadline:
        raise ProviderRefused()
    process.stdout.close()
    return bytes(output)


_SEAL = object()


class FixedLaunchHolder:
    """Fixed non-root Mac holder: one handoff, four privileged remote launches.

    Source installation is inert until fixed private configuration/pins exist.
    The holder forwards actual root bytes, never reads a root evidence file.
    """

    def __init__(
        self,
        seal: object,
        doc: HolderInstallation,
        ssh: str,
        wall: datetime,
        mono: float,
    ) -> None:
        if seal is not _SEAL:
            raise ProviderRefused()
        self._doc, self._ssh, self._wall, self._mono = doc, ssh, wall, mono
        self._used = False
        self._processes: list[subprocess.Popen[bytes]] = []
        self._launches: list[_OwnedLaunch] = []

    @classmethod
    def from_installed(cls) -> FixedLaunchHolder:
        if os.geteuid() <= 0 or os.getuid() != os.geteuid():
            raise ProviderRefused()
        # Actual non-root holder home, never HOME or a caller-selected path.
        import pwd

        home = Path(pwd.getpwuid(os.geteuid()).pw_dir).resolve(strict=True)
        raw = _protected_bytes(
            home / ".config/dotmac-gate0/handoff.json", os.geteuid(), private=True
        )
        doc = cast(
            HolderInstallation,
            _object(
                raw,
                "schema campaign_digest ssh_binary holder_uid home public_identity "
                "public_key_fingerprint ssh_add_binary agent agent_qualification "
                "known_hosts downstream cases",
            ),
        )
        if doc["schema"] != "Gate0HolderInstallation.v1":
            raise ProviderRefused()
        _hash(doc["campaign_digest"])
        ssh = _pinned_file(doc["ssh_binary"], 0)
        if doc["holder_uid"] != os.geteuid() or doc["home"] != str(home):
            raise ProviderRefused()
        for directory in (home / ".config", home / ".config/dotmac-gate0"):
            info = directory.stat(follow_symlinks=False)
            if (
                info.st_uid != os.geteuid()
                or not stat.S_ISDIR(info.st_mode)
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                raise ProviderRefused()
        _pinned_file(doc["public_identity"], os.geteuid())
        public = _protected_bytes(
            Path(doc["public_identity"]["path"]), os.geteuid(), 1024
        )
        selected = parse_holder_auth_info(b"publickey " + public)
        wire = base64.b64decode(selected.split(b" ")[1], validate=True)
        fingerprint = "SHA256:" + base64.b64encode(
            hashlib.sha256(wire).digest()
        ).decode("ascii").rstrip("=")
        if doc["public_key_fingerprint"] != fingerprint:
            raise ProviderRefused()
        _pinned_file(doc["ssh_add_binary"], 0)
        _pinned_file(doc["agent_qualification"], os.geteuid(), private=True)
        _qualified_agent(doc)
        _agent_socket(doc["agent"], os.geteuid())
        _pinned_file(doc["known_hosts"], os.geteuid())
        _endpoint(doc["downstream"], receiver=True)
        cases = doc["cases"]
        if type(cases) is not list or len(cases) != 2:
            raise ProviderRefused()
        for kind, case in zip(
            ("consume_replay", "withdrawal_later_use"), cases, strict=True
        ):
            if (
                type(case) is not dict
                or set(case) != {"kind", "IDP3", "NS3"}
                or case["kind"] != kind
            ):
                raise ProviderRefused()
            for host in ("IDP3", "NS3"):
                endpoint = _holder_host(case, host)
                _endpoint(endpoint, receiver=False)
                _activation(endpoint["activation"])
                binding = RootHostBinding(canonical(endpoint["binding"]))
                if binding.terms["case_kind"] != kind or binding.terms["host_role"] != (
                    "issuer" if host == "IDP3" else "attester"
                ):
                    raise ProviderRefused()
        _validate_cases(cases, holder=True)
        return cls(_SEAL, doc, ssh, datetime.now(UTC), time.monotonic())

    def _spawn(
        self, endpoint: Endpoint, *, downstream: bool
    ) -> subprocess.Popen[bytes]:
        deadline = _deadline(
            self._doc["cases"][0]["IDP3"]["binding"]["expires_at"]
            if downstream
            else cast(RootEndpoint, endpoint)["binding"]["expires_at"],
            self._wall,
            self._mono,
        )
        self._check_agent(deadline)
        command = [
            self._ssh,
            "-F",
            "/dev/null",
            "-T",
            "-oBatchMode=yes",
            "-oStrictHostKeyChecking=yes",
            "-oIdentitiesOnly=yes",
            "-oIdentityAgent=" + self._doc["agent"]["path"],
            "-oCertificateFile=none",
            "-oAddKeysToAgent=no",
            "-oUseKeychain=no",
            "-oPasswordAuthentication=no",
            "-oKbdInteractiveAuthentication=no",
            "-oProxyCommand=none",
            "-oProxyJump=none",
            "-oControlMaster=no",
            "-oControlPath=none",
            "-oClearAllForwardings=yes",
            "-oForwardAgent=no",
            "-oForwardX11=no",
            "-oPermitLocalCommand=no",
            "-oRequestTTY=no",
            "-oConnectionAttempts=1",
            "-oConnectTimeout=5",
            "-oServerAliveInterval=0",
            "-oEscapeChar=none",
            "-oUserKnownHostsFile=" + self._doc["known_hosts"]["path"],
            "-oGlobalKnownHostsFile=/dev/null",
            "-oHostKeyAlias=" + endpoint["host_key_alias"],
            "-i",
            self._doc["public_identity"]["path"],
            "-p",
            str(endpoint["port"]),
            endpoint["user"] + "@" + endpoint["host"],
        ]
        if not downstream:
            terms = cast(RootEndpoint, endpoint)["binding"]
            command.append(
                activation_command(
                    self._doc["campaign_digest"], terms["case_kind"], terms["host_role"]
                )
            )
        _agent_socket(self._doc["agent"], self._doc["holder_uid"])
        process: subprocess.Popen[bytes] = subprocess.Popen(  # noqa: S603 -- fixed protected pinned invocation
            command,
            stdin=subprocess.PIPE if downstream else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={
                "PATH": "/usr/bin:/bin",
                "LANG": "C",
                "SSH_AUTH_SOCK": self._doc["agent"]["path"],
            },
            close_fds=True,
            start_new_session=True,
        )
        self._processes.append(process)
        return process

    def _check_agent(self, original_end: float) -> None:
        end = min(original_end, time.monotonic() + 2)
        doc = self._doc
        _agent_socket(doc["agent"], doc["holder_uid"])
        public = _protected_bytes(
            Path(doc["public_identity"]["path"]), doc["holder_uid"], 1024
        )
        if _digest(public) != doc["public_identity"]["digest"]:
            raise ProviderRefused()
        key = parse_holder_auth_info(b"publickey " + public)
        for args in (("-L",), ("-T", doc["public_identity"]["path"])):
            if time.monotonic() >= end:
                raise ProviderRefused()
            process: subprocess.Popen[bytes] = subprocess.Popen(  # noqa: S603 -- fixed pinned agent usability command
                [doc["ssh_add_binary"]["path"], *args],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env={
                    "PATH": "/usr/bin:/bin",
                    "LANG": "C",
                    "SSH_AUTH_SOCK": doc["agent"]["path"],
                },
                close_fds=True,
                start_new_session=True,
            )
            self._processes.append(process)
            output = _bounded_output(process, end)
            if args == ("-L",):
                selected = [
                    b" ".join(line.split(b" ", 2)[:2]) for line in output.splitlines()
                ]
                if selected.count(key) != 1:
                    raise ProviderRefused()
            elif output:
                raise ProviderRefused()
            _agent_socket(doc["agent"], doc["holder_uid"])

    def _launch(self, endpoint: RootEndpoint) -> _OwnedLaunch:
        binding = RootHostBinding(canonical(endpoint["binding"]))
        end = _deadline(binding.terms["expires_at"], self._wall, self._mono)
        start = _deadline(binding.terms["not_before"], self._wall, self._mono)
        remaining_start = start - time.monotonic()
        if remaining_start > 0:
            if remaining_start > 600:
                raise ProviderRefused()
            select.select([], [], [], remaining_start)
        if not start <= time.monotonic() < end or not 0 < end - start <= 300:
            raise ProviderRefused()
        owner = _OwnedLaunch(
            self._spawn(endpoint, downstream=False), RootFrameSequence(binding), end
        )
        self._launches.append(owner)
        return owner

    def run(self) -> None:
        if self._used:
            raise ProviderRefused()
        self._used = True
        doc = self._doc
        b_end = _deadline(
            doc["cases"][1]["IDP3"]["binding"]["expires_at"], self._wall, self._mono
        )
        failure: BaseException | None = None
        try:
            if time.monotonic() >= b_end:
                raise ProviderRefused()
            downstream = self._spawn(doc["downstream"], downstream=True)
            if downstream.stdin is None or downstream.stdout is None:
                raise ProviderRefused()
            relay = _OwnedIO(
                downstream.stdout.fileno(),
                downstream.stdin.fileno(),
                _deadline(
                    doc["cases"][0]["IDP3"]["binding"]["expires_at"],
                    self._wall,
                    self._mono,
                ),
            )
            for index, case in enumerate(doc["cases"]):
                case_end = _deadline(
                    case["IDP3"]["binding"]["expires_at"], self._wall, self._mono
                )
                relay.deadline = case_end
                ns = self._launch(case["NS3"])
                first = ns.next_root()
                if first is None or first[0] != "management_listening":
                    raise ProviderRefused()
                relay.send(encode_root_event(doc["campaign_digest"], "NS3", first[1]))
                idp = self._launch(case["IDP3"])
                active = {ns.io.read_fd: ("NS3", ns), idp.io.read_fd: ("IDP3", idp)}
                while active:
                    end = min(
                        launch._original_end
                        + (
                            2
                            if len(launch.sequence.records)
                            >= len(_PHASES[launch.sequence.binding.terms["host_role"]])
                            else 0
                        )
                        for _, launch in active.values()
                    )
                    remaining = end - time.monotonic()
                    if remaining <= 0:
                        raise ProviderRefused()
                    ready, _, _ = select.select(list(active), [], [], remaining)
                    if not ready:
                        raise ProviderRefused()
                    for fd in ready:
                        host, launch = active[fd]
                        item = launch.next_root()
                        if item is None:
                            relay.deadline = case_end + 2
                            relay.send(_terminal(doc["campaign_digest"], host, launch))
                            del active[fd]
                        else:
                            if item[0] != "final" and time.monotonic() >= case_end:
                                raise ProviderRefused()
                            relay.deadline = case_end + (2 if item[0] == "final" else 0)
                            relay.send(
                                encode_root_event(doc["campaign_digest"], host, item[1])
                            )
                idp.require_complete()
                ns.require_complete()
                if index == 0:
                    # Independent own A final/EOF/management waits above are
                    # mandatory even if a malicious/lost downstream ACK exists.
                    relay.deadline = case_end
                    ack = relay.receive()
                    if ack is None:
                        raise ProviderRefused()
                    decode_case_a_complete(
                        ack,
                        doc["campaign_digest"],
                        (idp.sequence.final_bytes(), ns.sequence.final_bytes()),
                    )
            downstream.stdin.close()
            if relay.receive(eof=True) is not None:
                raise ProviderRefused()
            _finish_downstream(downstream, relay.deadline)
        except BaseException as error:
            failure = error
        finally:
            try:
                self.close()
            except BaseException as error:
                if failure is None:
                    failure = error
        if failure is not None:
            raise failure

    def close(self) -> None:
        _teardown(self._processes, time.monotonic() + 2)


def _finish_downstream(process: subprocess.Popen[bytes], deadline: float) -> None:
    """Actual downstream wait must finish strictly inside its unchanged deadline."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ProviderRefused()
    try:
        status = process.wait(timeout=remaining)
    except subprocess.TimeoutExpired:
        raise ProviderRefused() from None
    if time.monotonic() >= deadline or status != 0:
        raise ProviderRefused()


def _endpoint(value: object, *, receiver: bool) -> None:
    fields = {"host", "port", "user", "host_key_alias"} | (
        set() if receiver else {"binding", "activation"}
    )
    if type(value) is not dict or set(value) != fields:
        raise ProviderRefused()
    for key in ("host", "user", "host_key_alias"):
        if (
            type(value[key]) is not str
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}", value[key]) is None
        ):
            raise ProviderRefused()
    if type(value["port"]) is not int or not 1 <= value["port"] <= 65535:
        raise ProviderRefused()
    if value["user"] == "root" and receiver:
        raise ProviderRefused()


def parse_holder_auth_info(raw: bytes) -> bytes:
    """OpenSSH ExposeAuthInfo single plain Ed25519 method, no certificate.

    Like SshdSessionReader this relies on the qualified dedicated UID/sshd
    startup boundary. It does not protect against compromise of that UID.
    """
    if (
        type(raw) is not bytes
        or len(raw) > 1024
        or raw.count(b"\n") != 1
        or not raw.endswith(b"\n")
    ):
        raise ProviderRefused()
    parts = raw[:-1].split(b" ")
    if len(parts) != 3 or parts[:2] != [b"publickey", b"ssh-ed25519"]:
        raise ProviderRefused()
    try:
        wire = base64.b64decode(parts[2], validate=True)
    except ValueError:
        raise ProviderRefused() from None
    if (
        len(wire) != 51
        or wire[:19] != b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"
        or base64.b64encode(wire) != parts[2]
    ):
        raise ProviderRefused()
    return b" ".join(parts[1:])


def _read_holder_auth(uid: int) -> bytes:
    if (
        os.geteuid() != uid
        or os.environ.get("SSH_ORIGINAL_COMMAND")
        or os.environ.get("SSH_TTY")
    ):
        raise ProviderRefused()
    path = os.environ.get("SSH_USER_AUTH", "")
    if re.fullmatch(r"/tmp/sshauth\.[A-Za-z0-9]{15}", path) is None:  # noqa: S108 -- pinned OpenSSH ExposeAuthInfo convention
        raise ProviderRefused()
    directory = os.open(
        "/tmp",  # noqa: S108 -- qualified sshd authinfo mount
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )  # noqa: S108 -- qualified daemon mount
    fd = -1
    try:
        fd = os.open(
            path.rsplit("/", 1)[1],
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory,
        )
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != uid
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or not 0 < before.st_size <= 1024
        ):
            raise ProviderRefused()
        raw = os.read(fd, 1025)
        after = os.fstat(fd)
        fields = (
            "st_dev",
            "st_ino",
            "st_uid",
            "st_mode",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if len(raw) != before.st_size or any(
            getattr(before, k) != getattr(after, k) for k in fields
        ):
            raise ProviderRefused()
        return parse_holder_auth_info(raw)
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(directory)


class InstalledHandoffReceiver:
    """Finite forced command under the existing qualified sshd trust boundary.

    Root-protected installation pins code/config/authorized key and the actual
    collector process. Plain authinfo is accepted only at this trusted startup;
    same-UID compromise is role compromise, as for the existing NS3 adapter.
    """

    def __init__(
        self,
        seal: object,
        doc: ReceiverInstallation,
        peer: tuple[int, int, str],
        wall: datetime,
        mono: float,
    ) -> None:
        if seal is not _SEAL:
            raise ProviderRefused()
        self._doc, self._peer, self._wall, self._mono = doc, peer, wall, mono
        self._used = False

    @classmethod
    def from_installed(cls) -> InstalledHandoffReceiver:
        raw = _protected_bytes(Path("/run/dotmac-gate0-handoff/installation.json"), 0)
        doc = cast(
            ReceiverInstallation,
            _object(
                raw,
                "schema campaign_digest receiver_uid collector sshd_binary sshd_config "
                "receiver_binary authorized_keys qualification holder_public_key "
                "holder_source "
                "cases",
            ),
        )
        if (
            doc["schema"] != "Gate0ReceiverInstallation.v1"
            or type(doc["receiver_uid"]) is not int
            or not 0 < doc["receiver_uid"] == os.geteuid()
        ):
            raise ProviderRefused()
        _hash(doc["campaign_digest"])
        for key in (
            "sshd_binary",
            "sshd_config",
            "receiver_binary",
            "authorized_keys",
            "qualification",
        ):
            _pinned_file(cast(FilePin, cast(dict[str, object], doc)[key]), 0)
        _qualified_receiver(doc)
        peer = _peer_binding(doc["collector"])
        if peer[0] == doc["receiver_uid"]:
            raise ProviderRefused()
        expected_key = doc["holder_public_key"]
        if type(expected_key) is not str or _read_holder_auth(
            doc["receiver_uid"]
        ) != expected_key.encode("ascii"):
            raise ProviderRefused()
        # Actual sshd-supplied connection source, not a claimed transport DTO.
        connection = os.environ.get("SSH_CONNECTION", "").split()
        if len(connection) != 4 or connection[0] != doc["holder_source"]:
            raise ProviderRefused()
        # Pinned daemon source/readback and qualification receipt define startup
        # protection, as in the existing SshdSessionReader. No unprivileged
        # root-/proc access or invented per-session root broker is required.
        cases = doc["cases"]
        if type(cases) is not list or len(cases) != 2:
            raise ProviderRefused()
        for kind, case in zip(
            ("consume_replay", "withdrawal_later_use"), cases, strict=True
        ):
            if type(case) is not dict or set(case) != {"IDP3", "NS3"}:
                raise ProviderRefused()
            for host in ("IDP3", "NS3"):
                terms = RootHostBinding(canonical(_receiver_host(case, host))).terms
                if terms["case_kind"] != kind or terms["host_role"] != (
                    "issuer" if host == "IDP3" else "attester"
                ):
                    raise ProviderRefused()
        _validate_cases(cases, holder=False)
        return cls(_SEAL, doc, peer, datetime.now(UTC), time.monotonic())

    def run(self) -> None:
        if self._used:
            raise ProviderRefused()
        self._used = True
        doc = self._doc
        # Single use persists on failure. Never unlink/rearm this marker.
        marker = Path("/run/dotmac-gate0-handoff/receiver/claimed")
        directory = os.open(
            marker.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        try:
            info = os.fstat(directory)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ProviderRefused()
            fd = os.open(
                marker.name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=directory,
            )
            os.close(fd)
        finally:
            os.close(directory)
        end = (
            _deadline(doc["cases"][1]["IDP3"]["expires_at"], self._wall, self._mono) + 2
        )
        first_end = _deadline(
            doc["cases"][0]["IDP3"]["expires_at"], self._wall, self._mono
        )
        upstream = _OwnedIO(0, 1, first_end)
        local = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            remaining = first_end - time.monotonic()
            if remaining <= 0:
                raise ProviderRefused()
            local.settimeout(min(2.0, remaining))
            local.connect("/run/dotmac-gate0-handoff/collector.sock")
            _require_peer(local, *self._peer)
            collector = _OwnedIO(local.fileno(), local.fileno(), first_end)
            for index, case in enumerate(doc["cases"]):
                case_end = _deadline(case["IDP3"]["expires_at"], self._wall, self._mono)
                case_start = _deadline(
                    case["IDP3"]["not_before"], self._wall, self._mono
                )
                if time.monotonic() < case_start:
                    select.select([], [], [], case_start - time.monotonic())
                upstream.deadline = collector.deadline = case_end
                sequences = {
                    host: RootFrameSequence(
                        RootHostBinding(canonical(_receiver_host(case, host)))
                    )
                    for host in ("IDP3", "NS3")
                }
                terminals: set[str] = set()
                phase_order = [
                    ("NS3", "management_listening"),
                    ("IDP3", "issuer_listening"),
                    ("NS3", "attester_listening_after_capture"),
                ]
                phase_index = 0
                while len(terminals) < 2:
                    upstream.deadline = case_end + (2 if phase_index == 3 else 0)
                    raw = upstream.receive()
                    if raw is None:
                        raise ProviderRefused()
                    kind = "terminal"
                    parsed = strict_object(raw, _MAX_ENVELOPE)
                    if parsed.get("schema") == "Gate0RootHandoff.v1":
                        host, root = decode_root_event(raw, doc["campaign_digest"])
                        if host in terminals:
                            raise ProviderRefused()
                        kind = sequences[host].accept(root)
                        if kind != "final":
                            if (
                                phase_index >= len(phase_order)
                                or (host, kind) != phase_order[phase_index]
                                or time.monotonic() >= case_end
                            ):
                                raise ProviderRefused()
                            phase_index += 1
                        elif phase_index != len(phase_order):
                            raise ProviderRefused()
                    else:
                        candidate = parsed.get("host")
                        if type(candidate) is not str:
                            raise ProviderRefused()
                        host = candidate
                        if (
                            host not in sequences
                            or host in terminals
                            or sequences[host].final is None
                        ):
                            raise ProviderRefused()
                        if (
                            decode_terminal(
                                raw,
                                doc["campaign_digest"],
                                host,
                                sequences[host].final_bytes(),
                            )
                            != 0
                        ):
                            raise ProviderRefused()
                        sequences[host].require_complete()
                        terminals.add(host)
                    collector.deadline = case_end + (
                        2
                        if phase_index == 3
                        and kind == "final"
                        or parsed.get("schema") == "Gate0RootHandoffTerminal.v1"
                        else 0
                    )
                    collector.send(raw)
                if index == 0:
                    upstream.deadline = collector.deadline = case_end
                    ack = collector.receive()
                    if ack is None:
                        raise ProviderRefused()
                    decode_case_a_complete(
                        ack,
                        doc["campaign_digest"],
                        (
                            sequences["IDP3"].final_bytes(),
                            sequences["NS3"].final_bytes(),
                        ),
                    )
                    upstream.send(ack)
            upstream.deadline = end
            if upstream.receive(eof=True) is not None:
                raise ProviderRefused()
            local.shutdown(socket.SHUT_WR)
        finally:
            local.close()
