"""Finite Linux launch mechanics, never a provider or authority factory.

Installation is deliberately absent from the wheel. Protected files are an
existing root installation's inputs, not self-authenticating JSON credentials.
Only this root supervisor publishes captures or enables one planned connection.
"""

from __future__ import annotations

import base64
import ctypes
import errno
import hashlib
import ipaddress
import math
import os
import pwd
import re
import select
import socket
import stat
import struct
import subprocess
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import IO, TYPE_CHECKING, Literal, NotRequired, TypedDict

if TYPE_CHECKING:
    from vendor_cp.deployment.gate0_services import IssuerProcessResult
from uuid import UUID

from vendor_cp.deployment.gate0_capture import CaptureCoordinates, decode_capture
from vendor_cp.deployment.gate0_framing import canonical, strict_object
from vendor_cp.deployment.gate0_role_custody import (
    ProviderRefused,
    WireGuardBaoEndpoint,
)

ROOT = Path("/run/dotmac-gate0")
CGROUP_ROOT = Path("/sys/fs/cgroup/dotmac-gate0")
CaseKind = Literal["consume_replay", "withdrawal_later_use"]
AttesterSlot = Literal["issue", "consume"]
SLOTS = ("issue", "consume")
Role = Literal["issuer", "attester", "management", "capture_sender"]
_SEAL = object()


# Fixed architect-reviewed capability profiles. These are not caller inputs.
_CONTINUING_CAPS = 0x400E3  # CHOWN, DAC_OVERRIDE, KILL, SETGID, SETUID, SYS_CHROOT
_PREFLIGHT_CAPS = 0x411E3  # continuing + SETPCAP + NET_ADMIN
_SECUREBITS = 234


class _CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]
    version: int
    pid: int


class _CapData(ctypes.Structure):
    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    ]
    effective: int
    permitted: int
    inheritable: int


def _capget() -> tuple[int, int, int]:
    libc = ctypes.CDLL(None, use_errno=True)
    get = libc.capget
    get.argtypes = [ctypes.POINTER(_CapHeader), ctypes.POINTER(_CapData)]
    get.restype = ctypes.c_int
    header, data = _CapHeader(0x20080522, 0), (_CapData * 2)()
    if int(get(ctypes.byref(header), data)) != 0 or header.version != 0x20080522:
        raise ProviderRefused()
    return (
        data[0].effective | (data[1].effective << 32),
        data[0].permitted | (data[1].permitted << 32),
        data[0].inheritable | (data[1].inheritable << 32),
    )


def _capset(effective: int, permitted: int, inheritable: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    put = libc.capset
    put.argtypes = [ctypes.POINTER(_CapHeader), ctypes.POINTER(_CapData)]
    put.restype = ctypes.c_int
    header, data = _CapHeader(0x20080522, 0), (_CapData * 2)()
    for index in range(2):
        data[index].effective = (effective >> (index * 32)) & 0xFFFFFFFF
        data[index].permitted = (permitted >> (index * 32)) & 0xFFFFFFFF
        data[index].inheritable = (inheritable >> (index * 32)) & 0xFFFFFFFF
    if int(put(ctypes.byref(header), data)) != 0:
        raise ProviderRefused()


def _prctl_raw(option: int, argument: int = 0, third: int = 0) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    call = libc.prctl
    call.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    call.restype = ctypes.c_int
    ctypes.set_errno(0)
    return int(call(option, argument, third, 0, 0))


def _prctl(option: int, argument: int = 0, third: int = 0) -> int:
    result = _prctl_raw(option, argument, third)
    if result < 0:
        raise ProviderRefused()
    return result


def _cap_last_cap() -> int:
    raw = _read(Path("/proc/sys/kernel/cap_last_cap"), 16)
    if re.fullmatch(rb"[0-9]{1,2}\n?", raw) is None:
        raise ProviderRefused()
    last = int(raw)
    if not 18 <= last <= 63:
        raise ProviderRefused()
    for capability in range(last + 1):
        if _prctl(23, capability) not in (0, 1):
            raise ProviderRefused()
    if _prctl_raw(23, last + 1) != -1 or ctypes.get_errno() != errno.EINVAL:
        raise ProviderRefused()
    return last


def _ambient_set(last: int) -> int:
    result = 0
    for capability in range(last + 1):
        present = _prctl(47, 1, capability)
        if present not in (0, 1):
            raise ProviderRefused()
        result |= present << capability
    return result


def _bounding_set(last: int) -> int:
    result = 0
    for capability in range(last + 1):
        present = _prctl(23, capability)
        if present not in (0, 1):
            raise ProviderRefused()
        result |= present << capability
    return result


def _require_capability_profile(mask: int) -> None:
    last = _cap_last_cap()
    if not 18 <= last <= 63 or (
        _capget() != (mask, mask, 0)
        or _bounding_set(last) != mask
        or _ambient_set(last) != 0
        or _prctl(27) != _SECUREBITS
        or _prctl(39) != 1
    ):
        raise ProviderRefused()


def _require_initial_process() -> None:
    pid = os.getpid()
    if (
        os.geteuid() != 0
        or os.listdir("/proc/self/task") != [str(pid)]
        or _read(Path(f"/proc/{pid}/task/{pid}/children"), 4096).strip()
    ):
        raise ProviderRefused()


def _prepare_network_privileges() -> None:
    _require_initial_process()
    last = _cap_last_cap()
    if not 18 <= last <= 63:
        raise ProviderRefused()
    _, permitted, _ = _capget()
    if (
        permitted & _PREFLIGHT_CAPS != _PREFLIGHT_CAPS
        or _bounding_set(last) & _PREFLIGHT_CAPS != _PREFLIGHT_CAPS
        or _prctl(27) not in (0, _SECUREBITS)
    ):
        raise ProviderRefused()
    _prctl(47, 4)  # PR_CAP_AMBIENT_CLEAR_ALL
    _prctl(28, _SECUREBITS)
    if _prctl(27) != _SECUREBITS:
        raise ProviderRefused()
    _capset(_PREFLIGHT_CAPS, _PREFLIGHT_CAPS, 0)
    for capability in range(last + 1):
        if not _PREFLIGHT_CAPS & (1 << capability):
            _prctl(24, capability)
    _prctl(38, 1)  # irreversible no_new_privs, inherited across exec
    _require_capability_profile(_PREFLIGHT_CAPS)


def _seal_network_privileges() -> None:
    _require_capability_profile(_PREFLIGHT_CAPS)
    last = _cap_last_cap()
    _capset(_CONTINUING_CAPS | (1 << 8), _CONTINUING_CAPS | (1 << 8), 0)
    for capability in range(last + 1):
        if capability != 8 and not _CONTINUING_CAPS & (1 << capability):
            _prctl(24, capability)
    _prctl(24, 8)  # SETPCAP last
    _prctl(47, 4)
    _capset(_CONTINUING_CAPS, _CONTINUING_CAPS, 0)
    _require_capability_profile(_CONTINUING_CAPS)


def _proc_capabilities(pid: int) -> tuple[int, int, int, int, int, int]:
    # Kernel proc entries belong to their process UID, not the root file
    # installer. Fixed native PID path, bounded read, no caller-selected file.
    descriptor = os.open(
        f"/proc/{pid}/status", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        raw = _bytes(descriptor, 65536).decode("ascii")
    finally:
        os.close(descriptor)
    names = ("CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd", "NoNewPrivs")
    found: dict[str, int] = {}
    for line in raw.splitlines():
        key, separator, value = line.partition(":")
        if key in names:
            text = value.strip()
            if (
                key in found
                or not separator
                or re.fullmatch(
                    r"[0-9a-f]{16}" if key != "NoNewPrivs" else r"[01]", text
                )
                is None
            ):
                raise ProviderRefused()
            found[key] = int(text, 16 if key != "NoNewPrivs" else 10)
    if set(found) != set(names):
        raise ProviderRefused()
    return (
        found["CapEff"],
        found["CapPrm"],
        found["CapInh"],
        found["CapAmb"],
        found["CapBnd"],
        found["NoNewPrivs"],
    )


def _require_worker_privileges(uid: int, supervisor_pid: int) -> None:
    account = pwd.getpwuid(uid)
    descriptor = os.open(
        "/proc/self/status", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        status = _bytes(descriptor, 65536).decode("ascii")
    finally:
        os.close(descriptor)
    uid_rows = [
        line.split()[1:] for line in status.splitlines() if line.startswith("Uid:")
    ]
    if (
        uid <= 0
        or os.getresuid() != (uid, uid, uid)
        or uid_rows != [[str(uid)] * 4]
        or os.getresgid() != (account.pw_gid,) * 3
        or not set(os.getgroups()) <= {account.pw_gid}
        or _proc_capabilities(os.getpid()) != (0, 0, 0, 0, _CONTINUING_CAPS, 1)
        or _proc_capabilities(supervisor_pid)
        != (_CONTINUING_CAPS, _CONTINUING_CAPS, 0, 0, _CONTINUING_CAPS, 1)
        or _capget() != (0, 0, 0)
        or _ambient_set(_cap_last_cap()) != 0
        or _prctl(27) != _SECUREBITS
        or _prctl(39) != 1
    ):
        raise ProviderRefused()


class LaunchState(StrEnum):
    AWAITING_CAPTURE = "AWAITING_CAPTURE"
    READY = "READY"
    SLOT_ACTIVE = "SLOT_ACTIVE"
    READY_FOR_NEXT = "READY_FOR_NEXT"
    TERMINAL = "TERMINAL"


DaemonTermination = Literal[
    "exited", "signaled", "wait_timeout", "forced_cleanup", "wait_failed"
]


class DaemonObservation(TypedDict):
    schema: str
    boundary: str
    pid: int
    process_start: str
    daemon_returncode: int | None
    termination: DaemonTermination
    completed_at: str
    completed_elapsed_seconds: float
    phase_deadline_elapsed_seconds: float


class CleanupReason(StrEnum):
    COMPLETED = "completed_mechanics"
    EXECUTION_INCOMPLETE = "execution_incomplete"
    BOUNDARY_FAILED = "boundary_cleanup_failed"
    PROCESS_REAP_FAILED = "process_reap_failed"
    DESCRIPTOR_CLOSE_FAILED = "descriptor_close_failed"
    EPHEMERAL_FAILED = "ephemeral_cleanup_failed"
    CLEANUP_MISSING = "cleanup_missing"
    EXPORT_FAILED = "export_failed"


class LaunchIncomplete(RuntimeError):
    """Execution started; refusal does not prove an authority mutation absent."""

    def __init__(self) -> None:
        super().__init__("gate0_launch_incomplete")


def _protected(path: Path, *, directory: bool = False, uid: int = 0) -> int:
    """Walk every component without symlinks; retain the final owned descriptor."""
    if not path.is_absolute() or ".." in path.parts:
        raise ProviderRefused()
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for index, name in enumerate(path.parts[1:]):
            last = index == len(path.parts) - 2
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
            if not last or directory:
                flags |= os.O_DIRECTORY
            child = os.open(name, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            expected_uid = uid if last else 0
            if info.st_uid != expected_uid or info.st_mode & 0o022:
                raise ProviderRefused()
            if last and not directory and not stat.S_ISREG(info.st_mode):
                raise ProviderRefused()
        return fd
    except BaseException:
        os.close(fd)
        raise


def _bytes(fd: int, maximum: int) -> bytes:
    result = bytearray()
    while len(result) <= maximum:
        part = os.read(fd, min(4096, maximum + 1 - len(result)))
        if not part:
            return bytes(result)
        result.extend(part)
    raise ProviderRefused()


def _read(path: Path, maximum: int = 65536) -> bytes:
    fd = _protected(path)
    try:
        return _bytes(fd, maximum)
    finally:
        os.close(fd)


def _write(fd: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            raise ProviderRefused()
        view = view[count:]


def _instant(value: object) -> datetime:
    if type(value) is not str:
        raise ProviderRefused()
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    offset = result.utcoffset()
    if result.tzinfo is None or offset is None or offset.total_seconds() != 0:
        raise ProviderRefused()
    return result


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _process_identity(pid: int) -> str:
    # stat's command may contain spaces and parentheses; field 22 is starttime.
    raw = Path(f"/proc/{pid}/stat").read_text()
    return raw[raw.rfind(")") + 2 :].split()[19]


@dataclass(frozen=True, slots=True)
class LaunchClocks:
    started_at: datetime
    monotonic_origin: float
    deadline: float
    expires_at: datetime

    @classmethod
    def start(cls, absolute_end: datetime) -> LaunchClocks:
        wall, mono = datetime.now(UTC), time.monotonic()
        if absolute_end.tzinfo is None:
            raise ProviderRefused()
        remaining = (absolute_end - wall).total_seconds()
        if not 0 < remaining <= 300:
            raise ProviderRefused()
        return cls(wall, mono, mono + remaining, absolute_end)

    def require_open(self) -> None:
        wall, mono = datetime.now(UTC), time.monotonic()
        if (
            not all(math.isfinite(v) for v in (self.monotonic_origin, self.deadline))
            or mono < self.monotonic_origin
            or mono >= self.deadline
            or wall < self.started_at
            or wall >= self.expires_at
        ):
            raise ProviderRefused()


@dataclass(frozen=True, slots=True)
class CaptureInstallReadback:
    launch_packet_digest: str
    capture: CaptureCoordinates
    effective_end: datetime

    def document(self) -> dict[str, object]:
        return {
            "schema": "Gate0CaptureInstalled.v1",
            "launch_packet_digest": self.launch_packet_digest,
            "capture": _coordinate_document(self.capture),
            "effective_end": self.effective_end.isoformat().replace("+00:00", "Z"),
        }


def _coordinate_document(value: CaptureCoordinates) -> dict[str, object]:
    return {
        "capture_digest": value.capture_digest,
        "window_digest": value.window_digest,
        "plan_id": str(value.plan_id),
        "plan_digest": value.plan_digest,
        "target_id": str(value.target_id),
        "approval_request_id": str(value.approval_request_id),
    }


def _record(value: object, fields: set[str]) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ProviderRefused()
    result: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ProviderRefused()
        result[key] = item
    if set(result) != fields:
        raise ProviderRefused()
    return result


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 1048576:
        raise ProviderRefused()
    return value


def _integer(value: object, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ProviderRefused()
    return value


def _number(value: object) -> float:
    if not isinstance(value, int | float) or isinstance(value, bool):
        raise ProviderRefused()
    result = float(value)
    if not math.isfinite(result):
        raise ProviderRefused()
    return result


def _sha(value: object) -> str:
    result = _text(value)
    if re.fullmatch(r"sha256:[0-9a-f]{64}", result) is None:
        raise ProviderRefused()
    return result


def _fingerprint(value: object) -> str:
    result = _text(value)
    if re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", result) is None:
        raise ProviderRefused()
    raw = base64.b64decode(result[7:] + "=", validate=True)
    if (
        len(raw) != 32
        or base64.b64encode(raw).decode("ascii").rstrip("=") != result[7:]
    ):
        raise ProviderRefused()
    return result


def _role(value: object) -> Role:
    if value == "issuer":
        return "issuer"
    if value == "attester":
        return "attester"
    if value == "management":
        return "management"
    if value == "capture_sender":
        return "capture_sender"
    raise ProviderRefused()


class CaptureSelection(TypedDict):
    window_digest: str
    plan_id: str
    plan_digest: str
    target_id: str
    approval_request_id: str


def _selection(value: object) -> CaptureSelection:
    item = _record(
        value,
        {"window_digest", "plan_id", "plan_digest", "target_id", "approval_request_id"},
    )
    result: CaptureSelection = {
        "window_digest": _sha(item["window_digest"]),
        "plan_id": _text(item["plan_id"]),
        "plan_digest": _sha(item["plan_digest"]),
        "target_id": _text(item["target_id"]),
        "approval_request_id": _text(item["approval_request_id"]),
    }
    for name in ("plan_id", "target_id", "approval_request_id"):
        raw = _text(item[name])
        if str(UUID(raw)) != raw:
            raise ProviderRefused()
    return result


def _case_kind(value: object) -> CaseKind:
    if value == "consume_replay":
        return "consume_replay"
    if value == "withdrawal_later_use":
        return "withdrawal_later_use"
    raise ProviderRefused()


class RoleTerms(TypedDict):
    key_id: str
    public_key_b64: str
    source_revision: str
    image_digest: str
    profile_digest: str


def _role_terms(value: object) -> RoleTerms:
    item = _record(
        value,
        {
            "key_id",
            "public_key_b64",
            "source_revision",
            "image_digest",
            "profile_digest",
        },
    )
    result: RoleTerms = {
        "key_id": _text(item["key_id"]),
        "public_key_b64": _text(item["public_key_b64"]),
        "source_revision": _text(item["source_revision"]),
        "image_digest": _sha(item["image_digest"]),
        "profile_digest": _sha(item["profile_digest"]),
    }
    raw = base64.b64decode(result["public_key_b64"], validate=True)
    if (
        len(result["key_id"]) > 512
        or len(raw) != 32
        or base64.b64encode(raw).decode("ascii") != result["public_key_b64"]
        or re.fullmatch(r"[0-9a-f]{40}", result["source_revision"]) is None
    ):
        raise ProviderRefused()
    return result


class RunDocument(TypedDict):
    schema: str
    run_id: str
    run_attempt: str
    case_kind: CaseKind
    not_before: str
    expires_at: str
    capture: CaptureSelection
    roles: dict[str, RoleTerms]
    controller_ca_fingerprint: str
    management_key_fingerprint: str


def _run_document(raw: bytes) -> RunDocument:
    item = _record(
        strict_object(raw),
        {
            "schema",
            "run_id",
            "run_attempt",
            "case_kind",
            "not_before",
            "expires_at",
            "capture",
            "roles",
            "controller_ca_fingerprint",
            "management_key_fingerprint",
        },
    )
    roles = _record(item["roles"], {"issuer", "attester"})
    result: RunDocument = {
        "schema": _text(item["schema"]),
        "run_id": _text(item["run_id"]),
        "run_attempt": _text(item["run_attempt"]),
        "case_kind": _case_kind(item["case_kind"]),
        "not_before": _text(item["not_before"]),
        "expires_at": _text(item["expires_at"]),
        "capture": _selection(item["capture"]),
        "roles": {
            "issuer": _role_terms(roles["issuer"]),
            "attester": _role_terms(roles["attester"]),
        },
        "controller_ca_fingerprint": _fingerprint(item["controller_ca_fingerprint"]),
        "management_key_fingerprint": _fingerprint(item["management_key_fingerprint"]),
    }
    if (
        canonical(result) != raw
        or result["schema"] != "Gate0RunIdentity.v1"
        or re.fullmatch(r"[1-9][0-9]{0,127}", result["run_id"]) is None
        or re.fullmatch(r"[1-9][0-9]{0,127}", result["run_attempt"]) is None
    ):
        raise ProviderRefused()
    start, end = _instant(result["not_before"]), _instant(result["expires_at"])
    if (
        not start <= datetime.now(UTC) < end
        or not 0 < (end - start).total_seconds() <= 300
    ):
        raise ProviderRefused()
    return result


class WireGuardPeer(TypedDict):
    public_key: str
    allowed_ips: list[str]


def _wg_key(value: object) -> str:
    text = _text(value)
    try:
        raw = base64.b64decode(text, validate=True)
    except ValueError:
        raise ProviderRefused() from None
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != text:
        raise ProviderRefused()
    return text


def _peer_inventory(value: object) -> list[WireGuardPeer]:
    if not isinstance(value, list) or not 0 < len(value) <= 32:
        raise ProviderRefused()
    result: list[WireGuardPeer] = []
    keys: set[str] = set()
    addresses: set[str] = set()
    for unparsed in value:
        item = _record(unparsed, {"public_key", "allowed_ips"})
        key = _wg_key(item["public_key"])
        entries = item["allowed_ips"]
        if key in keys or not isinstance(entries, list) or not 0 < len(entries) <= 32:
            raise ProviderRefused()
        keys.add(key)
        allowed: list[str] = []
        for entry in entries:
            text = _text(entry)
            if not text.endswith("/32"):
                raise ProviderRefused()
            try:
                address = _private_ipv4(text[:-3])
            except ValueError:
                raise ProviderRefused() from None
            if address + "/32" != text or address in addresses:
                raise ProviderRefused()
            addresses.add(address)
            allowed.append(text)
        result.append({"public_key": key, "allowed_ips": sorted(allowed)})
    return sorted(result, key=lambda peer: peer["public_key"])


def _observed_peer_inventory(
    peers_raw: bytes, allowed_raw: bytes
) -> list[WireGuardPeer]:
    try:
        peers = [_wg_key(line) for line in peers_raw.decode("ascii").splitlines()]
        entries: list[WireGuardPeer] = []
        for line in allowed_raw.decode("ascii").splitlines():
            fields = line.split("\t")
            if len(fields) != 2:
                raise ProviderRefused()
            entries.append(
                {"public_key": _wg_key(fields[0]), "allowed_ips": fields[1].split()}
            )
        inventory = _peer_inventory(entries)
        if len(peers) != len(set(peers)) or sorted(peers) != [
            peer["public_key"] for peer in inventory
        ]:
            raise ProviderRefused()
        return inventory
    except (ValueError, UnicodeError):
        raise ProviderRefused() from None


class Network(TypedDict):
    interface: str
    index: int
    namespace_device: int
    namespace_inode: int
    bao_address: str
    local_address: str
    peer_public_key: str
    peer_allowed_ip: str
    route_document: str
    nft_ruleset_digest: str
    peers: list[WireGuardPeer]


def _private_ipv4(value: object) -> str:
    result = _text(value)
    address = ipaddress.IPv4Address(result)
    if str(address) != result or not any(
        address in ipaddress.IPv4Network(subnet)
        for subnet in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    ):
        raise ProviderRefused()
    return result


def _network(value: object) -> Network:
    item = _record(
        value,
        {
            "interface",
            "index",
            "namespace_device",
            "namespace_inode",
            "bao_address",
            "local_address",
            "peer_public_key",
            "peer_allowed_ip",
            "peers",
            "route_document",
            "nft_ruleset_digest",
        },
    )
    result: Network = {
        "interface": _text(item["interface"]),
        "index": _integer(item["index"], minimum=1),
        "namespace_device": _integer(item["namespace_device"], minimum=1),
        "namespace_inode": _integer(item["namespace_inode"], minimum=1),
        "bao_address": _private_ipv4(item["bao_address"]),
        "local_address": _private_ipv4(item["local_address"]),
        "peer_public_key": _wg_key(item["peer_public_key"]),
        "peer_allowed_ip": _text(item["peer_allowed_ip"]),
        "peers": _peer_inventory(item["peers"]),
        "route_document": _text(item["route_document"]),
        "nft_ruleset_digest": _sha(item["nft_ruleset_digest"]),
    }
    interface = result["interface"]
    key = base64.b64decode(result["peer_public_key"], validate=True)
    if (
        len(interface) > 15
        or not interface.replace("-", "").replace("_", "").isalnum()
        or len(key) != 32
        or base64.b64encode(key).decode("ascii") != result["peer_public_key"]
        or result["peer_allowed_ip"] != result["bao_address"] + "/32"
    ):
        raise ProviderRefused()
    if {
        "public_key": result["peer_public_key"],
        "allowed_ips": [result["peer_allowed_ip"]],
    } not in result["peers"] or any(
        result["local_address"] + "/32" in peer["allowed_ips"]
        for peer in result["peers"]
    ):
        raise ProviderRefused()
    return result


class SshEndpoint(TypedDict):
    local_address: str
    local_port: int
    remote_address: str


def _ssh_endpoint(value: object) -> SshEndpoint:
    item = _record(value, {"local_address", "local_port", "remote_address"})
    port = _integer(item["local_port"], minimum=1)
    if not 1024 <= port <= 65535:
        raise ProviderRefused()
    return {
        "local_address": _private_ipv4(item["local_address"]),
        "local_port": port,
        "remote_address": _private_ipv4(item["remote_address"]),
    }


class ManagementIdentity(TypedDict):
    holder_uid: int
    device: int
    inode: int
    public_key_fingerprint: str


def _management_identity(value: object) -> ManagementIdentity:
    item = _record(value, {"holder_uid", "device", "inode", "public_key_fingerprint"})
    return {
        "holder_uid": _integer(item["holder_uid"], minimum=1),
        "device": _integer(item["device"], minimum=1),
        "inode": _integer(item["inode"], minimum=1),
        "public_key_fingerprint": _fingerprint(item["public_key_fingerprint"]),
    }


class LocalPacket(TypedDict):
    schema: str
    host_role: Literal["issuer", "attester"]
    run_end: str
    network: Network
    binary_digests: dict[str, str]
    capture: CaptureSelection
    installation_digests: dict[str, str]
    ssh_endpoints: dict[str, SshEndpoint]
    sshd_digest: str
    shared_run_digest: str
    machine_id_digest: str
    issuer_uid: NotRequired[int]
    capture_sender_uid: NotRequired[int]
    management_identity: NotRequired[ManagementIdentity]
    cli_digest: NotRequired[str]
    issuer_sshd_config_digest: NotRequired[str]
    attester_uid: NotRequired[int]
    management_uid: NotRequired[int]
    sshd_config_digest: NotRequired[str]
    management_sshd_config_digest: NotRequired[str]


def _hashes(value: object, fields: set[str]) -> dict[str, str]:
    return {key: _sha(item) for key, item in _record(value, fields).items()}


def _local_packet(raw: bytes) -> LocalPacket:
    unparsed = strict_object(raw)
    role = _role(unparsed.get("host_role"))
    common = {
        "schema",
        "host_role",
        "run_end",
        "network",
        "binary_digests",
        "capture",
        "installation_digests",
        "ssh_endpoints",
        "sshd_digest",
        "shared_run_digest",
        "machine_id_digest",
    }
    if role == "issuer":
        extra = {
            "issuer_uid",
            "capture_sender_uid",
            "management_identity",
            "cli_digest",
            "issuer_sshd_config_digest",
        }
        endpoint_names, install_names = {"issuer"}, {"issuer", "capture_sender"}
    elif role == "attester":
        extra = {
            "attester_uid",
            "management_uid",
            "sshd_config_digest",
            "management_sshd_config_digest",
        }
        endpoint_names, install_names = (
            {"management", "attester"},
            {*SLOTS, "management"},
        )
    else:
        raise ProviderRefused()
    item = _record(unparsed, common | extra)
    endpoints = _record(item["ssh_endpoints"], endpoint_names)
    result: LocalPacket = {
        "schema": _text(item["schema"]),
        "host_role": role,
        "run_end": _text(item["run_end"]),
        "network": _network(item["network"]),
        "binary_digests": _hashes(
            item["binary_digests"], {"/usr/bin/wg", "/usr/sbin/ip", "/usr/sbin/nft"}
        ),
        "capture": _selection(item["capture"]),
        "installation_digests": _hashes(item["installation_digests"], install_names),
        "ssh_endpoints": {
            key: _ssh_endpoint(value) for key, value in endpoints.items()
        },
        "sshd_digest": _sha(item["sshd_digest"]),
        "shared_run_digest": _sha(item["shared_run_digest"]),
        "machine_id_digest": _sha(item["machine_id_digest"]),
    }
    if result["schema"] != "Gate0FiniteLaunch.v1":
        raise ProviderRefused()
    _instant(result["run_end"])
    for endpoint in result["ssh_endpoints"].values():
        if (
            endpoint["local_address"] != result["network"]["local_address"]
            or sum(
                endpoint["remote_address"] + "/32" in peer["allowed_ips"]
                for peer in result["network"]["peers"]
            )
            != 1
        ):
            raise ProviderRefused()
    if role == "issuer":
        result["issuer_uid"] = _integer(item["issuer_uid"], minimum=1)
        result["capture_sender_uid"] = _integer(item["capture_sender_uid"], minimum=1)
        result["management_identity"] = _management_identity(
            item["management_identity"]
        )
        result["cli_digest"] = _sha(item["cli_digest"])
        result["issuer_sshd_config_digest"] = _sha(item["issuer_sshd_config_digest"])
        if result["issuer_uid"] == result["capture_sender_uid"]:
            raise ProviderRefused()
    else:
        result["attester_uid"] = _integer(item["attester_uid"], minimum=1)
        result["management_uid"] = _integer(item["management_uid"], minimum=1)
        result["sshd_config_digest"] = _sha(item["sshd_config_digest"])
        result["management_sshd_config_digest"] = _sha(
            item["management_sshd_config_digest"]
        )
    return result


def _load_local_packet() -> LocalPacket:
    return _local_packet(_read(ROOT / "packet.json"))


class ContextRecord(TypedDict):
    network_measurement_digest: str
    packet_digest: str
    local_packet_digest: str
    machine_id_digest: str
    role: Role
    started_at: str
    monotonic_origin: float
    deadline: float
    expires_at: str
    worker_uid: int
    slot_id: str | None
    supervisor_pid: int
    supervisor_start: str
    boundary: str


def _context_record(raw: bytes) -> ContextRecord:
    item = _record(
        strict_object(raw),
        {
            "network_measurement_digest",
            "packet_digest",
            "local_packet_digest",
            "machine_id_digest",
            "role",
            "started_at",
            "monotonic_origin",
            "deadline",
            "expires_at",
            "worker_uid",
            "slot_id",
            "supervisor_pid",
            "supervisor_start",
            "boundary",
        },
    )
    role = _role(item["role"])
    slot = None if item["slot_id"] is None else _text(item["slot_id"])
    if (role == "attester" and slot not in SLOTS) or (
        role != "attester" and slot is not None
    ):
        raise ProviderRefused()
    result: ContextRecord = {
        "network_measurement_digest": _sha(item["network_measurement_digest"]),
        "packet_digest": _sha(item["packet_digest"]),
        "local_packet_digest": _sha(item["local_packet_digest"]),
        "machine_id_digest": _sha(item["machine_id_digest"]),
        "role": role,
        "started_at": _text(item["started_at"]),
        "monotonic_origin": _number(item["monotonic_origin"]),
        "deadline": _number(item["deadline"]),
        "expires_at": _text(item["expires_at"]),
        "worker_uid": _integer(item["worker_uid"], minimum=1),
        "slot_id": slot,
        "supervisor_pid": _integer(item["supervisor_pid"], minimum=1),
        "supervisor_start": _text(item["supervisor_start"]),
        "boundary": _text(item["boundary"]),
    }
    if result["boundary"] != "/dotmac-gate0/" + (slot if slot is not None else role):
        raise ProviderRefused()
    _instant(result["started_at"])
    _instant(result["expires_at"])
    return result


class IssuerPeer(TypedDict):
    issuer_uid: int
    issuer_pid: int
    issuer_start: str


class ExportRecord(IssuerPeer):
    descriptor: int
    device: int
    inode: int


def _export_record(raw: bytes) -> ExportRecord:
    item = _record(
        strict_object(raw),
        {"descriptor", "device", "inode", "issuer_uid", "issuer_pid", "issuer_start"},
    )
    return {
        "descriptor": _integer(item["descriptor"], minimum=3),
        "device": _integer(item["device"], minimum=1),
        "inode": _integer(item["inode"], minimum=1),
        "issuer_uid": _integer(item["issuer_uid"], minimum=1),
        "issuer_pid": _integer(item["issuer_pid"], minimum=1),
        "issuer_start": _text(item["issuer_start"]),
    }


class NetworkMeasurement(TypedDict):
    packet_digest: str
    local_packet_digest: str
    machine_id_digest: str
    namespace_device: int
    namespace_inode: int
    interface: str
    index: int
    bao_address: str
    local_address: str
    peer_public_key: str
    peer_allowed_ip: str
    peers: list[WireGuardPeer]
    route_digest: str
    nft_ruleset_digest: str
    started_at: str
    monotonic_origin: float
    deadline: float
    expires_at: str
    supervisor_pid: int
    supervisor_start: str


def _network_measurement(raw: bytes) -> NetworkMeasurement:
    item = _record(strict_object(raw), set(NetworkMeasurement.__annotations__))
    result: NetworkMeasurement = {
        "packet_digest": _sha(item["packet_digest"]),
        "local_packet_digest": _sha(item["local_packet_digest"]),
        "machine_id_digest": _sha(item["machine_id_digest"]),
        "namespace_device": _integer(item["namespace_device"], minimum=1),
        "namespace_inode": _integer(item["namespace_inode"], minimum=1),
        "interface": _text(item["interface"]),
        "index": _integer(item["index"], minimum=1),
        "bao_address": _private_ipv4(item["bao_address"]),
        "local_address": _private_ipv4(item["local_address"]),
        "peer_public_key": _wg_key(item["peer_public_key"]),
        "peer_allowed_ip": _text(item["peer_allowed_ip"]),
        "peers": _peer_inventory(item["peers"]),
        "route_digest": _sha(item["route_digest"]),
        "nft_ruleset_digest": _sha(item["nft_ruleset_digest"]),
        "started_at": _text(item["started_at"]),
        "monotonic_origin": _number(item["monotonic_origin"]),
        "deadline": _number(item["deadline"]),
        "expires_at": _text(item["expires_at"]),
        "supervisor_pid": _integer(item["supervisor_pid"], minimum=1),
        "supervisor_start": _text(item["supervisor_start"]),
    }
    _instant(result["started_at"])
    _instant(result["expires_at"])
    return result


def _peer(channel: socket.socket) -> tuple[int, int, int]:
    values = struct.unpack(
        "3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    )
    return _integer(values[0], minimum=1), _integer(values[1]), _integer(values[2])


def _socket_endpoint(value: object) -> tuple[str, int]:
    if not isinstance(value, tuple) or len(value) != 2:
        raise ProviderRefused()
    address, port = _private_ipv4(value[0]), _integer(value[1], minimum=1)
    if port > 65535:
        raise ProviderRefused()
    return address, port


@dataclass(frozen=True, slots=True)
class CaptureEntry:
    coordinates: CaptureCoordinates
    encoded: bytes


def _capture_entry(value: object) -> CaptureEntry:
    item = _record(value, {"coordinates", "capture_b64"})
    coordinates = _capture_coordinates(item["coordinates"])
    text = _text(item["capture_b64"])
    encoded = base64.b64decode(text, validate=True)
    if base64.b64encode(encoded).decode("ascii") != text:
        raise ProviderRefused()
    decode_capture(encoded, expected=coordinates)
    return CaptureEntry(coordinates, encoded)


def _capture_request(raw: bytes, packet_digest: str) -> CaptureEntry:
    item = _record(
        strict_object(raw, 196608), {"schema", "launch_packet_digest", "capture"}
    )
    if (
        item["schema"] != "Gate0CaptureInstall.v1"
        or _sha(item["launch_packet_digest"]) != packet_digest
    ):
        raise ProviderRefused()
    return _capture_entry(item["capture"])


def _selection_matches(
    selection: CaptureSelection, coordinates: CaptureCoordinates
) -> bool:
    return dict(selection) == {
        key: value
        for key, value in _coordinate_document(coordinates).items()
        if key != "capture_digest"
    }


def _capture_readback(raw: bytes) -> CaptureInstallReadback:
    item = _record(
        strict_object(raw),
        {"schema", "launch_packet_digest", "capture", "effective_end"},
    )
    if item["schema"] != "Gate0CaptureInstalled.v1":
        raise ProviderRefused()
    return CaptureInstallReadback(
        _sha(item["launch_packet_digest"]),
        _capture_coordinates(item["capture"]),
        _instant(item["effective_end"]),
    )


def _capture_coordinates(value: object) -> CaptureCoordinates:
    item = _record(
        value,
        {
            "capture_digest",
            "window_digest",
            "plan_id",
            "plan_digest",
            "target_id",
            "approval_request_id",
        },
    )
    result = CaptureCoordinates(
        _sha(item["capture_digest"]),
        _sha(item["window_digest"]),
        UUID(_text(item["plan_id"])),
        _sha(item["plan_digest"]),
        UUID(_text(item["target_id"])),
        UUID(_text(item["approval_request_id"])),
    )
    if _coordinate_document(result) != item:
        raise ProviderRefused()
    return result


@dataclass(frozen=True, slots=True)
class RunIdentity:
    """Canonical shared public terms; protected delivery supplies provenance."""

    canonical_bytes: bytes

    @classmethod
    def from_installed(cls) -> RunIdentity:
        raw = _read(ROOT / "run-packet.json")
        _run_document(raw)
        return cls(raw)

    @property
    def digest(self) -> str:
        return _digest(self.canonical_bytes)


@dataclass(frozen=True, slots=True)
class BoundaryCleanupEvidence:
    boundary: str
    cgroup_device: int
    cgroup_inode: int
    kill_issued: bool
    populated: int
    guardian_pid: int
    guardian_start: str
    guardian_wait_status: int

    def document(self) -> dict[str, object]:
        from dataclasses import asdict

        return asdict(self)


class SlotExecutionBoundary:
    """A root-owned cgroup v2 leaf; worker has no migration/delegation rights.

    Linux cgroup.kill covers setsid and double-fork descendants. No process-group
    operation is used as evidence of quiescence. A failed kill/readback is fatal.
    """

    def __init__(self, slot_id: str) -> None:
        if os.geteuid() != 0 or slot_id not in (
            *SLOTS,
            "issuer",
            "management",
            "capture_sender",
            "preflight",
        ):
            raise ProviderRefused()
        mounts = [
            line.split()
            for line in Path("/proc/self/mountinfo").read_text().splitlines()
        ]
        covering = [
            entry
            for entry in mounts
            if str(CGROUP_ROOT).startswith(entry[4].rstrip("/") + "/")
        ]
        mount = max(covering, key=lambda entry: len(entry[4])) if covering else []
        if not mount or mount[mount.index("-") + 1] != "cgroup2":
            raise ProviderRefused()
        parent = _protected(CGROUP_ROOT, directory=True)
        try:
            os.mkdir(slot_id, mode=0o700, dir_fd=parent)
        finally:
            os.close(parent)
        self.path = CGROUP_ROOT / slot_id
        self._fd = _protected(self.path, directory=True)
        if not (self.path / "cgroup.kill").is_file():
            raise ProviderRefused()
        metadata = os.fstat(self._fd)
        self._identity = (metadata.st_dev, metadata.st_ino)
        self._owner_pid = os.getpid()
        self._evidence: BoundaryCleanupEvidence | None = None
        self._closed = False
        self._cleanup_complete = False
        self._watchdog_pid: int | None = None
        self._watchdog_write: int | None = None

    def start_watchdog(self, deadline: float) -> None:
        """Independent root child kills on original deadline OR parent pipe EOF.

        The watchdog stays outside the cgroup. Parent crash therefore cannot
        leave its workers alive awaiting a Python handler or service restart.
        """
        if self._watchdog_pid is not None or not 0 < deadline - time.monotonic() <= 300:
            raise ProviderRefused()
        reader, writer = os.pipe2(os.O_CLOEXEC)
        pid = os.fork()
        if pid == 0:
            os.close(writer)
            try:
                null = os.open("/dev/null", os.O_RDWR | os.O_CLOEXEC)
                for standard in (0, 1, 2):
                    os.dup2(null, standard)
                if null > 2:
                    os.close(null)
                # A second guardian must not keep another boundary's parent
                # pipe alive after coordinator crash. Keep only this watch FD
                # and this cgroup FD; no inherited transport/key descriptors.
                for name in os.listdir("/proc/self/fd"):
                    descriptor = int(name)
                    if descriptor not in (0, 1, 2, reader, self._fd):
                        try:
                            os.close(descriptor)
                        except OSError as error:
                            if error.errno != errno.EBADF:
                                raise
                select.select([reader], [], [], max(0, deadline - time.monotonic()))
                self.terminate_and_confirm_empty()
            except BaseException:
                os._exit(1)
            finally:
                os.close(reader)
            os._exit(0)
        os.close(reader)
        self._watchdog_pid, self._watchdog_write = pid, writer
        self._watchdog_start = _process_identity(pid)

    def require_watchdog(self) -> None:
        if (
            self._watchdog_pid is None
            or os.waitpid(self._watchdog_pid, os.WNOHANG)[0] != 0
        ):
            raise ProviderRefused()

    def enter_child(self) -> None:
        if self._closed:
            raise ProviderRefused()
        fd = os.open("cgroup.procs", os.O_WRONLY | os.O_CLOEXEC, dir_fd=self._fd)
        try:
            _write(fd, str(os.getpid()).encode("ascii"))
        finally:
            os.close(fd)

    def terminate_and_confirm_empty(self) -> BoundaryCleanupEvidence | None:
        if self._cleanup_complete:
            return (
                self._evidence
            )  # only this root owner can re-enter a retired boundary
        if self._closed:
            raise ProviderRefused()
        # Retire on the first attempt, but never turn an unknown/failed cleanup
        # into successful idempotence. Completion also requires guardian reap.
        self._closed = True
        fd = os.open("cgroup.kill", os.O_WRONLY | os.O_CLOEXEC, dir_fd=self._fd)
        try:
            _write(fd, b"1")
        finally:
            os.close(fd)
        # Teardown has a bounded tail; no late result is accepted during it.
        tail = time.monotonic() + 2
        while time.monotonic() < tail:
            fd = os.open("cgroup.events", os.O_RDONLY | os.O_CLOEXEC, dir_fd=self._fd)
            try:
                events = _bytes(fd, 4096).splitlines()
            finally:
                os.close(fd)
            if b"populated 0" in events:
                os.close(self._fd)
                if self._watchdog_write is not None:
                    os.close(self._watchdog_write)
                    self._watchdog_write = None
                    # Guardian has only bounded public cgroup I/O after EOF.
                    guardian_end = time.monotonic() + 2
                    guardian = self._watchdog_pid
                    if guardian is None:
                        raise ProviderRefused()
                    while time.monotonic() < guardian_end:
                        child, status = os.waitpid(guardian, os.WNOHANG)
                        if child:
                            if status != 0:
                                raise ProviderRefused()
                            self._evidence = BoundaryCleanupEvidence(
                                self.path.name,
                                *self._identity,
                                True,
                                0,
                                guardian,
                                self._watchdog_start,
                                status,
                            )
                            self._cleanup_complete = True
                            return self._evidence
                        time.sleep(0.01)
                    raise ProviderRefused()
                if os.getpid() == self._owner_pid:
                    raise ProviderRefused()
                self._cleanup_complete = True
                return None
            time.sleep(0.01)
        raise ProviderRefused()


@dataclass(frozen=True, slots=True, init=False)
class InstalledLaunchContext:
    """Facts loaded from the fixed root installation and actual local process.

    A context cannot be minted by a request or ordinary constructor. Its root
    metadata is only trusted within the adopted dedicated protected launch.
    """

    packet_digest: str
    role: Role
    started_at: datetime
    monotonic_origin: float
    deadline: float
    expires_at: datetime
    worker_uid: int
    slot_id: str | None
    _supervisor_pid: int
    _supervisor_start: str
    _boundary: str
    local_packet_digest: str
    machine_id_digest: str
    network_measurement_digest: str

    def __init__(self, *, _seal: object | None = None, **values: object) -> None:
        if _seal is not _SEAL:
            raise ProviderRefused()
        for name, value in values.items():
            object.__setattr__(self, name, value)

    @classmethod
    def from_installed(cls) -> InstalledLaunchContext:
        if os.name != "posix" or not Path("/proc/self/cgroup").exists():
            raise ProviderRefused()
        record = _context_record(_read(ROOT / "context.json"))
        uid, slot = record["worker_uid"], record["slot_id"]
        if uid != os.geteuid():
            raise ProviderRefused()
        packet = _read(ROOT / "packet.json")
        local = _local_packet(packet)
        run = RunIdentity.from_installed()
        terms = _run_document(run.canonical_bytes)
        if (
            local["capture"] != terms["capture"]
            or local["run_end"] != terms["expires_at"]
            or _digest(packet) != record["local_packet_digest"]
            or run.digest != record["packet_digest"]
            or local["shared_run_digest"] != run.digest
            or _digest(_read(Path("/etc/machine-id"), 4096))
            != record["machine_id_digest"]
            or local["machine_id_digest"] != record["machine_id_digest"]
        ):
            raise ProviderRefused()
        result = cls(
            _seal=_SEAL,
            packet_digest=record["packet_digest"],
            role=record["role"],
            started_at=_instant(record["started_at"]),
            monotonic_origin=float(record["monotonic_origin"]),
            deadline=float(record["deadline"]),
            expires_at=_instant(record["expires_at"]),
            worker_uid=uid,
            slot_id=slot,
            _supervisor_pid=record["supervisor_pid"],
            _supervisor_start=record["supervisor_start"],
            _boundary=record["boundary"],
            local_packet_digest=record["local_packet_digest"],
            machine_id_digest=record["machine_id_digest"],
            network_measurement_digest=record["network_measurement_digest"],
        )
        result.require_open()
        return result

    def require_open(self) -> None:
        LaunchClocks(
            self.started_at, self.monotonic_origin, self.deadline, self.expires_at
        ).require_open()
        pid = self._supervisor_pid
        _require_worker_privileges(self.worker_uid, pid)
        if (
            os.geteuid() != self.worker_uid
            or Path(f"/proc/{pid}").stat().st_uid != 0
            or _process_identity(pid) != self._supervisor_start
            or Path("/proc/self/cgroup").read_text().strip() != "0::" + self._boundary
        ):
            raise ProviderRefused()

    def require_installation(
        self, role: Role, packet_digest: str, absolute_end: datetime
    ) -> None:
        self.require_open()
        if (
            role != self.role
            or packet_digest != self.packet_digest
            or absolute_end > self.expires_at
        ):
            raise ProviderRefused()
        if absolute_end <= datetime.now(UTC):
            raise ProviderRefused()
        local = _read(ROOT / "packet.json")
        if (
            _digest(local) != self.local_packet_digest
            or RunIdentity.from_installed().digest != self.packet_digest
            or _digest(_read(Path("/etc/machine-id"), 4096)) != self.machine_id_digest
        ):
            raise ProviderRefused()
        self._require_network_measurement(_local_packet(local))

    def _require_network_measurement(self, packet: LocalPacket) -> NetworkMeasurement:
        raw = _read(ROOT / "network-measurement.json")
        if _digest(raw) != self.network_measurement_digest:
            raise ProviderRefused()
        measurement = _network_measurement(raw)
        namespace = Path("/proc/self/ns/net").stat()
        network = packet["network"]
        start, end = (
            _instant(measurement["started_at"]),
            _instant(measurement["expires_at"]),
        )
        if (
            measurement["packet_digest"] != self.packet_digest
            or measurement["local_packet_digest"] != self.local_packet_digest
            or measurement["machine_id_digest"] != self.machine_id_digest
            or measurement["namespace_device"] != namespace.st_dev
            or measurement["namespace_inode"] != namespace.st_ino
            or measurement["started_at"] != self.started_at.isoformat()
            or measurement["expires_at"] != self.expires_at.isoformat()
            or measurement["monotonic_origin"] != self.monotonic_origin
            or not 0 < (end - start).total_seconds() <= 300
            or measurement["deadline"]
            != self.monotonic_origin + (end - start).total_seconds()
            or not self.monotonic_origin < self.deadline <= measurement["deadline"]
            or measurement["supervisor_pid"] != self._supervisor_pid
            or measurement["supervisor_start"] != self._supervisor_start
            or measurement["namespace_device"] != network["namespace_device"]
            or measurement["namespace_inode"] != network["namespace_inode"]
            or measurement["interface"] != network["interface"]
            or measurement["index"] != network["index"]
            or measurement["bao_address"] != network["bao_address"]
            or measurement["local_address"] != network["local_address"]
            or measurement["peer_public_key"] != network["peer_public_key"]
            or measurement["peer_allowed_ip"] != network["peer_allowed_ip"]
            or measurement["peers"] != network["peers"]
            or socket.if_nametoindex(network["interface"]) != network["index"]
            or measurement["route_digest"]
            != _digest(network["route_document"].encode("ascii"))
            or measurement["nft_ruleset_digest"] != network["nft_ruleset_digest"]
        ):
            raise ProviderRefused()
        return measurement

    def require_bao_endpoint(
        self, endpoint: WireGuardBaoEndpoint, deadline: float
    ) -> None:
        """Launch measurement + enforced immutability, not fresh WG netlink I/O."""
        self.require_installation(self.role, self.packet_digest, self.expires_at)
        if type(endpoint) is not WireGuardBaoEndpoint:
            raise ProviderRefused()
        endpoint.__post_init__()
        packet = _load_local_packet()
        measured = self._require_network_measurement(packet)
        peer = base64.b64decode(measured["peer_public_key"], validate=True)
        if (
            endpoint.role != self.role
            or endpoint.launch_packet_digest != self.packet_digest
            or endpoint.interface != measured["interface"]
            or endpoint.interface_index != measured["index"]
            or endpoint.namespace_device != measured["namespace_device"]
            or endpoint.namespace_inode != measured["namespace_inode"]
            or endpoint.address != measured["bao_address"]
            or endpoint.local_address != measured["local_address"]
            or endpoint.peer_allowed_ip != measured["peer_allowed_ip"]
            or endpoint.peer_fingerprint != _digest(peer)
            or endpoint.wg_binary_digest != packet["binary_digests"]["/usr/bin/wg"]
            or type(deadline) not in (int, float)
            or not math.isfinite(deadline)
            or not time.monotonic() < deadline <= self.deadline
        ):
            raise ProviderRefused()

    def open_wrapping_token(self) -> int:
        self.require_installation(self.role, self.packet_digest, self.expires_at)
        if self.role not in ("issuer", "attester"):
            raise ProviderRefused()
        claim = claim_slot_once(self)
        # sshd closes inherited descriptors: the fixed forced worker opens this.
        return open_slot_wrapper(claim)

    def require_run_role_terms(
        self,
        *,
        role: Literal["issuer", "attester"],
        source_revision: str,
        image_digest: str,
        own_key_id: str,
        own_public_key: bytes,
        peer_key_id: str,
        peer_public_key: bytes,
    ) -> None:
        self.require_installation(role, self.packet_digest, self.expires_at)
        if self.role != role:
            raise ProviderRefused()
        document = _run_document(RunIdentity.from_installed().canonical_bytes)
        terms = document["roles"][role]
        peer = document["roles"]["attester" if role == "issuer" else "issuer"]
        profile = _read(Path("/app/application_foundation_profile.json"))
        if (
            source_revision != terms["source_revision"]
            or image_digest != terms["image_digest"]
            or own_key_id != terms["key_id"]
            or type(own_public_key) is not bytes
            or base64.b64encode(own_public_key).decode("ascii")
            != terms["public_key_b64"]
            or peer_key_id != peer["key_id"]
            or type(peer_public_key) is not bytes
            or base64.b64encode(peer_public_key).decode("ascii")
            != peer["public_key_b64"]
            or _digest(profile) != terms["profile_digest"]
            or strict_object(profile).get("source_revision") != source_revision
        ):
            raise ProviderRefused()

    def open_installation(self) -> int:
        self.require_open()
        name = self.slot_id if self.role == "attester" else self.role
        if name is None:
            raise ProviderRefused()
        fd = _protected(ROOT / "installation" / (str(name) + ".json"))
        try:
            raw = _bytes(fd, 262144)
            packet = _load_local_packet()
            if _digest(raw) != packet["installation_digests"][name]:
                raise ProviderRefused()
            os.lseek(fd, 0, os.SEEK_SET)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def open_management_identity(self, *, expected_fingerprint: str) -> int:
        """Only the existing designated sender holder can open its RO key mount.

        The key is never decoded or copied here. A public-half fingerprint is
        an equality check; custody provenance comes from the protected existing
        mount, holder identity and reviewed packet, never a JSON boolean.
        """
        if self.role != "capture_sender":
            raise ProviderRefused()
        self.require_installation(self.role, self.packet_digest, self.expires_at)
        packet = _load_local_packet()
        expected = packet["management_identity"]
        if (
            expected["holder_uid"] != self.worker_uid
            or self.worker_uid != packet["capture_sender_uid"]
            or self.worker_uid == packet["issuer_uid"]
            or expected_fingerprint != expected["public_key_fingerprint"]
        ):
            raise ProviderRefused()
        source = ROOT / "management" / "identity"
        mounts = [
            line.split()
            for line in Path("/proc/self/mountinfo").read_text().splitlines()
        ]
        covering = [
            entry
            for entry in mounts
            if str(source) == entry[4]
            or str(source).startswith(entry[4].rstrip("/") + "/")
        ]
        mount = max(covering, key=lambda entry: len(entry[4])) if covering else []
        if not mount or "ro" not in mount[5].split(","):
            raise ProviderRefused()
        fd = _protected(source, uid=self.worker_uid)
        try:
            info = os.fstat(fd)
            if (
                info.st_mode & 0o077
                or info.st_nlink != 1
                or info.st_dev != expected["device"]
                or info.st_ino != expected["inode"]
            ):
                raise ProviderRefused()
            from vendor_cp.deployment.gate0_management_delivery import (
                ssh_public_key_fingerprint,
            )

            if (
                ssh_public_key_fingerprint(
                    _read(ROOT / "management" / "identity.pub", 4096), "ssh-ed25519"
                )
                != expected["public_key_fingerprint"]
            ):
                raise ProviderRefused()
            return fd
        except BaseException:
            os.close(fd)
            raise

    def open_capture_export(self) -> int:
        """One inherited root-parent stream, never a caller-selected capture file."""
        if self.role != "capture_sender":
            raise ProviderRefused()
        self.require_installation(self.role, self.packet_digest, self.expires_at)
        record = _export_record(_read(ROOT / "sender-export.json"))
        parent = _protected(ROOT / "sender-claims", directory=True, uid=self.worker_uid)
        try:
            marker = os.open(
                "capture_sender",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o400,
                dir_fd=parent,
            )
            os.close(marker)
        finally:
            os.close(parent)
        fd = os.dup(record["descriptor"])
        channel = socket.socket(fileno=fd)
        try:
            info = os.fstat(fd)
            pid, uid, _ = _peer(channel)
            if (
                channel.family != socket.AF_UNIX
                or channel.type & 0xF != socket.SOCK_STREAM
                or (info.st_dev, info.st_ino) != (record["device"], record["inode"])
                or uid != 0
                or pid != self._supervisor_pid
            ):
                raise ProviderRefused()
            packet = _load_local_packet()
            if record["issuer_uid"] != packet["issuer_uid"]:
                raise ProviderRefused()
            os.close(record["descriptor"])
            return channel.detach()
        except BaseException:
            channel.close()
            raise

    def open_issuer_capture_export(self) -> socket.socket:
        """Issuer's one public export socket; no management key access."""
        if self.role != "issuer":
            raise ProviderRefused()
        self.require_installation(self.role, self.packet_digest, self.expires_at)
        channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            channel.settimeout(min(10, self.deadline - time.monotonic()))
            channel.connect(str(ROOT / "issuer-export.sock"))
            pid, uid, _ = _peer(channel)
            if uid != 0 or pid != self._supervisor_pid:
                raise ProviderRefused()
            return channel
        except BaseException:
            channel.close()
            raise

    @property
    def required_phase(self) -> Literal["issue", "consume"]:
        if self.role != "attester" or self.slot_id not in SLOTS:
            raise ProviderRefused()
        return "issue" if self.slot_id == "issue" else "consume"

    def require_capture_selection(self, selection: dict[str, object]) -> None:
        self.require_open()
        local = _load_local_packet()
        run = RunIdentity.from_installed()
        terms = _run_document(run.canonical_bytes)
        if (
            run.digest != self.packet_digest
            or local["shared_run_digest"] != self.packet_digest
            or _selection(selection) != local["capture"]
            or local["capture"] != terms["capture"]
            or _instant(local["run_end"]) != self.expires_at
            or _instant(terms["expires_at"]) != self.expires_at
        ):
            raise ProviderRefused()

    def require_capture_slot(self, expected: CaptureCoordinates, phase: str) -> None:
        self.require_open()
        if self.role != "attester" or self.slot_id not in SLOTS:
            raise ProviderRefused()
        if phase != self.slot_id:
            raise ProviderRefused()
        packet = _load_local_packet()
        configured = packet["capture"]
        if not _selection_matches(configured, expected):
            raise ProviderRefused()

    def finish_slot(self, outcome: Literal["success", "refused"]) -> None:
        self.require_open()
        if (
            self.role != "attester"
            or self.slot_id not in SLOTS
            or outcome not in ("success", "refused")
        ):
            raise ProviderRefused()
        parent = _protected(
            ROOT / "status" / self.slot_id, directory=True, uid=self.worker_uid
        )
        try:
            fd = os.open(
                "terminal.json",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o400,
                dir_fd=parent,
            )
            try:
                _write(
                    fd,
                    canonical(
                        {
                            "schema": "Gate0SlotTerminal.v1",
                            "launch_packet_digest": self.packet_digest,
                            "slot": self.slot_id,
                            "outcome": outcome,
                        }
                    ),
                )
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            os.close(parent)

    @property
    def case_kind(self) -> CaseKind:
        return _run_document(RunIdentity.from_installed().canonical_bytes)["case_kind"]

    def finish_issuer(self, result: IssuerProcessResult) -> None:
        """Fixed wrapper calls only after successful custody and descriptor close."""
        from vendor_cp.deployment.gate0_collection import IssuerOutcome, OutcomeKind
        from vendor_cp.deployment.gate0_services import IssuerProcessResult

        self.require_open()
        if self.role != "issuer" or type(result) is not IssuerProcessResult:
            raise ProviderRefused()
        terms = _run_document(RunIdentity.from_installed().canonical_bytes)
        if result.exit_code != 3 or not 1 <= len(result.outcomes) <= 8:
            raise ProviderRefused()
        for ordinal, outcome in enumerate(result.outcomes, 1):
            if type(outcome) is not IssuerOutcome or outcome.ordinal != ordinal:
                raise ProviderRefused()
            IssuerOutcome.parse(outcome.document())
            if outcome.window_digest != terms["capture"]["window_digest"]:
                raise ProviderRefused()
            if (
                ordinal < len(result.outcomes)
                and outcome.kind is OutcomeKind.OWNER_REFUSED
            ):
                raise ProviderRefused()
        final = result.outcomes[-1]
        if final.kind is not OutcomeKind.OWNER_REFUSED or final.operation != "consume":
            raise ProviderRefused()
        terminal = {
            "schema": "Gate0IssuerTerminal.v1",
            "launch_packet_digest": self.packet_digest,
            "local_packet_digest": self.local_packet_digest,
            "case_kind": terms["case_kind"],
            "window_digest": terms["capture"]["window_digest"],
            "worker_declared_exit_code": 3,
            "transcript_digest": result.transcript_digest,
            "terminal_outcome": final.document(),
        }
        raw = canonical(terminal)
        if len(raw) > 65536:
            raise ProviderRefused()
        parent = _protected(
            ROOT / "status" / "issuer", directory=True, uid=self.worker_uid
        )
        try:
            fd = os.open(
                "terminal.json",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o400,
                dir_fd=parent,
            )
            try:
                _write(fd, raw)
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            os.close(parent)

    def open_management_channel(self) -> socket.socket:
        self.require_open()
        if self.role != "management":
            raise ProviderRefused()
        channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            channel.settimeout(min(10, self.deadline - time.monotonic()))
            channel.connect(str(ROOT / "management.sock"))
            _, uid, _ = _peer(channel)
            if uid != 0:
                raise ProviderRefused()
            return channel
        except BaseException:
            channel.close()
            raise

    def open_authenticated_capture(self, expected: CaptureCoordinates) -> int:
        self.require_open()
        if self.role != "attester" or self.slot_id not in SLOTS:
            raise ProviderRefused()
        if expected != self.capture_coordinates():
            raise ProviderRefused()
        name = "capture.json"
        fd = _protected(ROOT / "captures" / name)
        try:
            raw = _bytes(fd, 65536)
            decode_capture(raw, expected=expected)
            os.lseek(fd, 0, os.SEEK_SET)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def capture_coordinates(self) -> CaptureCoordinates:
        self.require_open()
        if self.role != "attester" or self.slot_id not in SLOTS:
            raise ProviderRefused()
        readback = _capture_readback(_read(ROOT / "captures" / "readback.json"))
        if (
            readback.launch_packet_digest != self.packet_digest
            or readback.effective_end != self.expires_at
        ):
            raise ProviderRefused()
        selected = readback.capture
        self.require_capture_slot(selected, self.required_phase)
        return selected

    def open_auth_info_directory(self) -> int:
        self.require_open()
        if self.role != "attester":
            raise ProviderRefused()
        return _protected(ROOT / "auth-info", directory=True)


@dataclass(frozen=True, slots=True, init=False)
class SessionClaim:
    context: InstalledLaunchContext
    pid: int

    def __init__(
        self, context: InstalledLaunchContext, *, _seal: object | None = None
    ) -> None:
        if _seal is not _SEAL:
            raise ProviderRefused()
        object.__setattr__(self, "context", context)
        object.__setattr__(self, "pid", os.getpid())


def claim_slot_once(context: InstalledLaunchContext) -> SessionClaim:
    if type(context) is not InstalledLaunchContext:
        raise ProviderRefused()
    context.require_installation(
        context.role, context.packet_digest, context.expires_at
    )
    name = context.slot_id if context.role == "attester" else context.role
    # Only claims/ is worker writable, never captures/, secrets/ or the mount.
    parent = _protected(ROOT / "claims", directory=True, uid=context.worker_uid)
    try:
        fd = os.open(
            str(name),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o400,
            dir_fd=parent,
        )
        os.close(fd)
    finally:
        os.close(parent)
    return SessionClaim(context, _seal=_SEAL)


def open_slot_wrapper(claim: SessionClaim) -> int:
    if type(claim) is not SessionClaim or claim.pid != os.getpid():
        raise ProviderRefused()
    context = claim.context
    context.require_installation(
        context.role, context.packet_digest, context.expires_at
    )
    name = context.slot_id if context.role == "attester" else context.role
    parent = _protected(ROOT / "claims", directory=True, uid=context.worker_uid)
    try:
        fd = os.open(
            str(name), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent
        )
        os.close(fd)
    finally:
        os.close(parent)
    # Root owns the fixed wrapper inode; only selected worker gets read access.
    return _protected(ROOT / "secrets" / str(name) / "wrapping-token")


def _no_replace(source: Path, destination: Path) -> None:
    # Linux renameat2 RENAME_NOREPLACE; no check-then-rename fallback.
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(source), -100, os.fsencode(destination), 1) != 0:
        raise ProviderRefused()


class FiniteGate0Supervisor:
    """One installed root launch, two attester slots, no recovery/retry loop."""

    @classmethod
    def from_installed(cls) -> FiniteGate0Supervisor:
        """The sole installed launcher entrypoint accepts no caller selections."""
        packet = _load_local_packet()
        role = packet["host_role"]
        uid = packet["issuer_uid"] if role == "issuer" else packet["attester_uid"]
        run = RunIdentity.from_installed()
        terms = _run_document(run.canonical_bytes)
        if (
            packet["shared_run_digest"] != run.digest
            or packet["run_end"] != terms["expires_at"]
            or packet["capture"] != terms["capture"]
            or packet["machine_id_digest"]
            != _digest(_read(Path("/etc/machine-id"), 4096))
        ):
            raise ProviderRefused()
        if (
            role == "issuer"
            and packet["management_identity"]["public_key_fingerprint"]
            != terms["management_key_fingerprint"]
        ):
            raise ProviderRefused()
        return cls(
            run_end=_instant(packet["run_end"]),
            packet_digest=run.digest,
            worker_uid=uid,
        )

    def run(self) -> None:
        """Fixed IDP3 issuer+sender or NS3 management+two attester sessions."""
        packet = _load_local_packet()
        role = packet["host_role"]
        listeners: list[socket.socket] = []
        failure: BaseException | None = None
        try:
            if role == "issuer":
                listener = self._listen_wg("issuer")
                listeners.append(listener)
                connection = self._accept_wg(listener, "issuer")
                listener.close()
                self.run_issuer_connection(connection)
                self._mechanics_complete = True
            elif role == "attester":
                management = self._listen_wg("management")
                listeners.append(management)
                connection = self._accept_wg(management, "management")
                management.close()
                self.run_management_connection(connection)
                listener = self._listen_wg("attester")
                listeners.append(listener)
                for _ in SLOTS:
                    connection = self._accept_wg(listener, "attester")
                    self.run_attester_connection(connection)
                self._mechanics_complete = True
            else:
                raise ProviderRefused()
        except Exception as error:
            self._remember_failure(CleanupReason.EXECUTION_INCOMPLETE)
            failure = error
            if self._activated:
                raise LaunchIncomplete() from error
            raise
        except BaseException as cancellation:
            self._remember_failure(CleanupReason.EXECUTION_INCOMPLETE)
            failure = cancellation
            raise
        finally:
            cleanup_failure: BaseException | None = None
            for listener in listeners:
                try:
                    listener.close()
                except BaseException as error:
                    self._remember_failure(CleanupReason.DESCRIPTOR_CLOSE_FAILED)
                    if cleanup_failure is None:
                        cleanup_failure = error
            try:
                self.close()
            except BaseException as error:
                if not getattr(self, "_cleanup_failed", False):
                    self._remember_failure(CleanupReason.EPHEMERAL_FAILED)
                if cleanup_failure is None:
                    cleanup_failure = error
            if cleanup_failure is not None and failure is None:
                if not isinstance(cleanup_failure, Exception):
                    raise cleanup_failure
                if self._activated:
                    raise LaunchIncomplete() from cleanup_failure
                raise cleanup_failure

    def _listen_wg(self, role: Role) -> socket.socket:
        self.clocks.require_open()
        packet = _load_local_packet()
        endpoint = packet["ssh_endpoints"][role]
        interface = packet["network"]["interface"]
        if (
            endpoint["local_address"] != packet["network"]["local_address"]
            or not 1 <= endpoint["local_port"] <= 65535
        ):
            raise ProviderRefused()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE,
                interface.encode("ascii") + b"\0",
            )
            listener.bind((endpoint["local_address"], endpoint["local_port"]))
            if (
                listener.getsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, 16)
                .rstrip(b"\0")
                .decode("ascii")
                != interface
            ):
                raise ProviderRefused()
            listener.settimeout(self.clocks.deadline - time.monotonic())
            listener.listen(1)
            return listener
        except BaseException:
            listener.close()
            raise

    def _accept_wg(self, listener: socket.socket, role: Role) -> socket.socket:
        self.clocks.require_open()
        listener.settimeout(self.clocks.deadline - time.monotonic())
        connection, _ = listener.accept()
        try:
            self._require_ssh_connection(connection, role)
            self.clocks.require_open()
            return connection
        except BaseException:
            connection.close()
            raise

    def __init__(
        self, *, run_end: datetime, packet_digest: str, worker_uid: int
    ) -> None:
        self.clocks = LaunchClocks.start(run_end)  # before any bootstrap or I/O
        if os.geteuid() != 0 or worker_uid <= 0:
            raise ProviderRefused()
        fd = _protected(ROOT, directory=True)
        os.close(fd)
        for legacy in ("a_issue", "a_consume", "b_issue", "b_consume"):
            for parent in ("installation", "secrets", "claims", "status"):
                candidate = (
                    ROOT
                    / parent
                    / (legacy + ".json" if parent == "installation" else legacy)
                )
                if candidate.exists() or candidate.is_symlink():
                    raise ProviderRefused()
        mount = [
            line.split()
            for line in Path("/proc/self/mountinfo").read_text().splitlines()
            if line.split()[4] == str(ROOT)
        ]
        if len(mount) != 1 or mount[0][mount[0].index("-") + 1] != "tmpfs":
            raise ProviderRefused()
        local = _read(ROOT / "packet.json")
        if (
            RunIdentity.from_installed().digest != packet_digest
            or _local_packet(local)["shared_run_digest"] != packet_digest
        ):
            raise ProviderRefused()
        marker = os.open(
            ROOT / "supervisor-once",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o400,
        )
        os.close(marker)
        self._run_terms = _run_document(RunIdentity.from_installed().canonical_bytes)
        self._local_terms = _local_packet(local)
        self.packet_digest, self.worker_uid = packet_digest, worker_uid
        self.local_packet_digest = _digest(local)
        self.machine_id_digest = _digest(_read(Path("/etc/machine-id"), 4096))
        if _local_packet(local)["machine_id_digest"] != self.machine_id_digest:
            raise ProviderRefused()
        self._boundaries: dict[str, SlotExecutionBoundary] = {}
        self._terminals: dict[str, dict[str, object]] = {}
        self._daemon_observations: dict[str, DaemonObservation] = {}
        self._daemon_live: dict[int, tuple[str, int, str, float]] = {}
        self._management_capture: dict[str, object] | None = None
        self._capture_delivery: dict[str, object] | None = None
        self._phase_completed: dict[str, str] = {}
        self._cleanup_complete = False
        self._mechanics_complete = False
        self._failure_reason: CleanupReason | None = None
        self._cleanup_failed = False
        self._cleanup_failure_reason: CleanupReason | None = None
        self._cleanup_completed_at: str | None = None
        self._removed: list[str] = []
        _prepare_network_privileges()
        self._measure_network()
        self.state = LaunchState.AWAITING_CAPTURE
        self._index = 0
        self._boundary: SlotExecutionBoundary | None = None
        self._sender_boundary: SlotExecutionBoundary | None = None
        self._management_listener: socket.socket | None = None
        self._active_deadline: float | None = None
        self._activated = False

    def _remember_failure(self, reason: CleanupReason) -> None:
        if reason in (
            CleanupReason.BOUNDARY_FAILED,
            CleanupReason.PROCESS_REAP_FAILED,
            CleanupReason.DESCRIPTOR_CLOSE_FAILED,
            CleanupReason.EPHEMERAL_FAILED,
        ):
            self._cleanup_failed = True
            if getattr(self, "_cleanup_failure_reason", None) is None:
                self._cleanup_failure_reason = reason
        if getattr(self, "_failure_reason", None) is None:
            self._failure_reason = reason

    def _pin_daemon(
        self, boundary: str, process: subprocess.Popen[bytes], deadline: float
    ) -> None:
        if boundary not in (*SLOTS, "issuer", "management"):
            raise ProviderRefused()
        self._daemon_live[id(process)] = (
            boundary,
            process.pid,
            _process_identity(process.pid),
            deadline,
        )

    def _record_daemon(
        self,
        process: subprocess.Popen[bytes],
        termination: DaemonTermination,
    ) -> None:
        boundary, pid, started, deadline = self._daemon_live[id(process)]
        mono = time.monotonic()
        code = process.returncode
        if code is not None and (type(code) is not int or not -255 <= code <= 255):
            code = None
            termination = "wait_failed"
        self._daemon_observations[boundary] = {
            "schema": "Gate0DaemonObservation.v1",
            "boundary": boundary,
            "pid": pid,
            "process_start": started,
            "daemon_returncode": code,
            "termination": termination,
            "completed_at": datetime.now(UTC).isoformat(),
            "completed_elapsed_seconds": mono - self.clocks.monotonic_origin,
            "phase_deadline_elapsed_seconds": deadline - self.clocks.monotonic_origin,
        }

    def _wait_daemon(self, process: subprocess.Popen[bytes], deadline: float) -> None:
        try:
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            self._record_daemon(process, "wait_timeout")
            raise
        except BaseException:
            self._record_daemon(process, "wait_failed")
            raise
        code = process.returncode
        if type(code) is not int or not 0 <= code <= 255:
            self._record_daemon(
                process, "signaled" if type(code) is int and code < 0 else "wait_failed"
            )
            raise LaunchIncomplete()
        self._record_daemon(process, "exited")
        self._require_phase_open(deadline)

    @staticmethod
    def _capture_completion(readback: CaptureInstallReadback) -> dict[str, object]:
        document = readback.document()
        return {"readback": document, "readback_digest": _digest(canonical(document))}

    def _retire_resources(
        self,
        boundary: SlotExecutionBoundary,
        process: subprocess.Popen[bytes] | None,
        descriptors: tuple[IO[bytes] | socket.socket | None, ...] = (),
        *,
        primary_failure: BaseException | None = None,
    ) -> None:
        """Keep the first failure while attempting every bounded local teardown."""
        failure: BaseException | None = None
        if process is not None and id(process) in getattr(self, "_daemon_live", {}):
            name = self._daemon_live[id(process)][0]
            if name not in self._daemon_observations:
                self._record_daemon(process, "forced_cleanup")
        try:
            boundary.terminate_and_confirm_empty()
        except BaseException as error:
            self._remember_failure(CleanupReason.BOUNDARY_FAILED)
            failure = error
        if process is not None:
            try:
                process.wait(timeout=2)
            except BaseException as error:
                self._remember_failure(CleanupReason.PROCESS_REAP_FAILED)
                if failure is None:
                    failure = error
                # Kill/reap the direct child even when cgroup cleanup is unknown.
                # This does not substitute for complete descendant quiescence.
                try:
                    process.kill()
                except BaseException:
                    self._remember_failure(CleanupReason.PROCESS_REAP_FAILED)
                # A failed kill does not prove the child is alive or reaped.
                try:
                    process.wait(timeout=2)
                except BaseException:
                    self._remember_failure(CleanupReason.PROCESS_REAP_FAILED)
        for descriptor in descriptors:
            if descriptor is not None:
                try:
                    descriptor.close()
                except BaseException as error:
                    self._remember_failure(CleanupReason.DESCRIPTOR_CLOSE_FAILED)
                    if failure is None:
                        failure = error
        if process is not None and id(process) in getattr(self, "_daemon_live", {}):
            name = self._daemon_live[id(process)][0]
            observation = self._daemon_observations.get(name)
            if observation is not None and observation["termination"] != "exited":
                self._record_daemon(process, observation["termination"])
        if failure is not None:
            if primary_failure is not None:
                raise primary_failure from failure
            raise failure

    def _measure_network(self) -> None:
        boundary = SlotExecutionBoundary("preflight")
        self._boundaries["preflight"] = boundary
        primary_failure: BaseException | None = None
        try:
            boundary.start_watchdog(self.clocks.deadline)
            measurement = self._measure_network_scoped(boundary)
        except BaseException as error:
            self._remember_failure(CleanupReason.EXECUTION_INCOMPLETE)
            primary_failure = error
            raise
        finally:
            # Parent capdrop cannot revoke a child's capabilities. Empty/reaped
            # includes every privileged helper and the independent guardian.
            self._retire_resources(boundary, None, primary_failure=primary_failure)
        self.clocks.require_open()
        _seal_network_privileges()
        self.clocks.require_open()
        self._publish_network_measurement(measurement)

    def _measure_network_scoped(self, boundary: SlotExecutionBoundary) -> bytes:
        """Compare actual PUBLIC kernel facts, never dump WG secret material.

        All expected facts and binary pins must be in the protected operational
        packet. Exact nft ruleset equality is additional to the fixed WG socket;
        the installation owner must review that ruleset's non-WG egress drop.
        """
        packet = _load_local_packet()
        network = packet["network"]
        interface = network["interface"]
        namespace = Path("/proc/self/ns/net").stat()
        if (
            namespace.st_dev != network["namespace_device"]
            or namespace.st_ino != network["namespace_inode"]
            or socket.if_nametoindex(interface) != network["index"]
        ):
            raise ProviderRefused()

        def public_query(binary: str, arguments: list[str]) -> bytes:
            self.clocks.require_open()
            if (
                _digest(_read(Path(binary), 16777216))
                != packet["binary_digests"][binary]
            ):
                raise ProviderRefused()
            deadline = min(self.clocks.deadline, time.monotonic() + 2)
            boundary.require_watchdog()
            process = subprocess.Popen(  # noqa: S603 -- fixed pinned public-only vectors
                [binary, *arguments],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/sbin:/usr/bin"},
                close_fds=True,
                preexec_fn=boundary.enter_child,
            )
            try:
                if process.stdout is None:
                    raise ProviderRefused()
                fd = process.stdout.fileno()
                os.set_blocking(fd, False)
                output = bytearray()
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
                        raise ProviderRefused()
                    part = os.read(fd, min(4096, 1048577 - len(output)))
                    if not part:
                        break
                    if len(output) + len(part) > 1048576:
                        raise ProviderRefused()
                    output.extend(part)
                process.wait(timeout=max(0.001, deadline - time.monotonic()))
                if process.returncode != 0 or time.monotonic() >= deadline:
                    raise ProviderRefused()
                return bytes(output)
            except BaseException as error:
                self._remember_failure(CleanupReason.EXECUTION_INCOMPLETE)
                self._retire_resources(
                    boundary, process, (process.stdout,), primary_failure=error
                )
                raise
            finally:
                if process.stdout is not None:
                    process.stdout.close()

        inventory = _observed_peer_inventory(
            public_query("/usr/bin/wg", ["show", interface, "peers"]),
            public_query("/usr/bin/wg", ["show", interface, "allowed-ips"]),
        )
        if inventory != network["peers"]:
            raise ProviderRefused()
        route = public_query(
            "/usr/sbin/ip",
            [
                "-j",
                "route",
                "get",
                network["bao_address"],
                "from",
                network["local_address"],
                "oif",
                interface,
            ],
        )
        if route != network["route_document"].encode("ascii"):
            raise ProviderRefused()
        rules = public_query("/usr/sbin/nft", ["-j", "list", "ruleset"])
        if _digest(rules) != network["nft_ruleset_digest"]:
            raise ProviderRefused()
        self.clocks.require_open()
        measurement = canonical(
            {
                "packet_digest": self.packet_digest,
                "local_packet_digest": self.local_packet_digest,
                "machine_id_digest": self.machine_id_digest,
                "namespace_device": namespace.st_dev,
                "namespace_inode": namespace.st_ino,
                "interface": interface,
                "index": network["index"],
                "peer_public_key": network["peer_public_key"],
                "peer_allowed_ip": network["peer_allowed_ip"],
                "bao_address": network["bao_address"],
                "local_address": network["local_address"],
                "peers": inventory,
                "started_at": self.clocks.started_at.isoformat(),
                "monotonic_origin": self.clocks.monotonic_origin,
                "deadline": self.clocks.deadline,
                "expires_at": self.clocks.expires_at.isoformat(),
                "supervisor_pid": os.getpid(),
                "supervisor_start": _process_identity(os.getpid()),
                "route_digest": _digest(route),
                "nft_ruleset_digest": _digest(rules),
            }
        )
        return measurement

    def _publish_network_measurement(self, measurement: bytes) -> None:
        _require_capability_profile(_CONTINUING_CAPS)
        _network_measurement(measurement)
        self.network_measurement_digest = _digest(measurement)
        fd = os.open(
            ROOT / "network-measurement.json",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o444,
        )
        try:
            _write(fd, measurement)
            os.fsync(fd)
        finally:
            os.close(fd)

    def _bind_management_listener(self) -> socket.socket:
        packet = _load_local_packet()
        management_uid = packet["management_uid"]
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            deadline = self._active_deadline or min(
                self.clocks.deadline, time.monotonic() + 10
            )
            listener.settimeout(deadline - time.monotonic())
            listener.bind(str(ROOT / "management.sock"))
            os.chmod(ROOT / "management.sock", 0o600)
            os.chown(ROOT / "management.sock", management_uid, -1)
            listener.listen(1)
            return listener
        except BaseException:
            listener.close()
            raise

    def serve_capture_once(
        self, expected: CaptureCoordinates | None = None
    ) -> CaptureInstallReadback:
        """One fixed local completion channel; no commands/paths are accepted."""
        if self.state != LaunchState.AWAITING_CAPTURE:
            raise ProviderRefused()
        if self._active_deadline is None:
            self._active_deadline = min(self.clocks.deadline, time.monotonic() + 10)
        packet = _load_local_packet()
        management_uid = packet["management_uid"]
        listener = self._management_listener or self._bind_management_listener()
        self._management_listener = None
        connection = None
        try:
            connection, _ = listener.accept()
            listener.close()  # never a second receiver/attempt
            pid, uid, _ = _peer(connection)
            if (
                uid != management_uid
                or Path(f"/proc/{pid}/cgroup").read_text().strip()
                != "0::/dotmac-gate0/management"
            ):
                raise ProviderRefused()
            result = self.commit_capture(connection.fileno(), expected)
            encoded = canonical(result.document())
            self._require_phase_open(self._active_deadline)
            connection.settimeout(self._active_deadline - time.monotonic())
            connection.sendall(struct.pack("!I", len(encoded)) + encoded)
            connection.shutdown(socket.SHUT_WR)
            self._require_phase_open(self._active_deadline)
            return result
        except BaseException:
            self.state = LaunchState.TERMINAL
            raise
        finally:
            listener.close()
            if connection is not None:
                connection.close()

    def commit_capture(
        self,
        stage_fd: int,
        expected: CaptureCoordinates | None = None,
    ) -> CaptureInstallReadback:
        """Root parent consumes its dedicated staging pipe through verified EOF.

        The receiver passes only public framed bytes, never an active inode,
        destination, observed_eof flag or permission to replace prior material.
        """
        if self.state != LaunchState.AWAITING_CAPTURE:
            raise ProviderRefused()
        try:
            self.clocks.require_open()
            packet = _load_local_packet()
            if expected is None:
                # Full coordinates may arrive with owner bytes over the same
                # authenticated management channel. A pipe/runner FD cannot
                # select this derivation path: require actual native peer facts.
                peer = socket.socket(fileno=os.dup(stage_fd))
                try:
                    pid, uid, _ = _peer(peer)
                    if (
                        uid != packet["management_uid"]
                        or Path(f"/proc/{pid}/cgroup").read_text().strip()
                        != "0::/dotmac-gate0/management"
                    ):
                        raise ProviderRefused()
                finally:
                    peer.close()
            deadline = self._active_deadline or min(
                self.clocks.deadline, time.monotonic() + 10
            )
            os.set_blocking(stage_fd, False)
            raw = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                if (
                    remaining <= 0
                    or not select.select([stage_fd], [], [], remaining)[0]
                ):
                    raise ProviderRefused()
                part = os.read(stage_fd, 196613 - len(raw))
                if not part:
                    break
                raw.extend(part)
                if len(raw) > 196612:
                    raise ProviderRefused()
            if len(raw) < 5 or struct.unpack("!I", raw[:4])[0] != len(raw) - 4:
                raise ProviderRefused()
            entry = _capture_request(bytes(raw[4:]), self.packet_digest)
            if expected is None:
                expected = entry.coordinates
            if entry.coordinates != expected or not _selection_matches(
                packet["capture"], expected
            ):
                raise ProviderRefused()
            encoded = entry.encoded
            capture = decode_capture(encoded, expected=expected)
            window = capture.binding.window.document
            terms = _run_document(RunIdentity.from_installed().canonical_bytes)
            if (
                window["controller"]["ca_fingerprint"]
                != terms["controller_ca_fingerprint"]
                or window["case_kind"] != terms["case_kind"]
                or window["github"]["run_id"] != terms["run_id"]
                or window["github"]["run_attempt"] != terms["run_attempt"]
                or self.clocks.expires_at > _instant(window["expires_at"])
            ):
                raise ProviderRefused()
            temporary = ROOT / "capture-commit"
            os.mkdir(temporary, mode=0o700)
            fd = os.open(
                temporary / "capture.json",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o400,
            )
            try:
                _write(fd, encoded)
                os.fchown(fd, 0, pwd.getpwuid(self.worker_uid).pw_gid)
                os.fchmod(fd, 0o440)
                os.fsync(fd)
            finally:
                os.close(fd)
            result = CaptureInstallReadback(
                self.packet_digest, expected, self.clocks.expires_at
            )
            readback_fd = os.open(
                temporary / "readback.json",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o400,
            )
            try:
                _write(readback_fd, canonical(result.document()))
                os.fchown(readback_fd, 0, pwd.getpwuid(self.worker_uid).pw_gid)
                os.fchmod(readback_fd, 0o440)
                os.fsync(readback_fd)
            finally:
                os.close(readback_fd)
            os.chown(temporary, 0, pwd.getpwuid(self.worker_uid).pw_gid)
            os.chmod(temporary, 0o550)  # noqa: S103 -- fixed worker group read/traverse
            directory_fd = _protected(temporary, directory=True)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            self.clocks.require_open()
            self._require_phase_open(deadline)
            _no_replace(temporary, ROOT / "captures")
            decode_capture(_read(ROOT / "captures" / "capture.json"), expected=expected)
            self.clocks.require_open()
            self._require_phase_open(deadline)
            self.state = LaunchState.READY
            if _read(ROOT / "captures" / "readback.json") != canonical(
                result.document()
            ):
                raise ProviderRefused()
            return result
        except BaseException:
            self.state = LaunchState.TERMINAL
            raise

    def run_attester_connection(self, connection: socket.socket) -> None:
        """One accepted TCP stream → pinned sshd -i → one irreversible claim.

        The fixed sshd config has the installed ForceCommand, worker identity,
        no PTY/environment/forwarding/RC/subsystem and exact certificate CA.
        Parent never accepts a second TCP connection for an active slot.
        """
        if (
            self.state not in (LaunchState.READY, LaunchState.READY_FOR_NEXT)
            or self._index >= len(SLOTS)
            or self._boundary is not None
        ):
            raise ProviderRefused()
        self.clocks.require_open()
        self._require_ssh_connection(connection, "attester")
        slot = SLOTS[self._index]
        slot_deadline = min(self.clocks.deadline, time.monotonic() + 30)
        boundary = SlotExecutionBoundary(slot)
        self._boundaries[slot] = boundary
        boundary.start_watchdog(slot_deadline)
        self._boundary = boundary
        self.state = LaunchState.SLOT_ACTIVE
        process = None
        primary_failure: BaseException | None = None
        try:
            # Binary/config pins are protected installation measurements.
            packet = _load_local_packet()
            binary = Path("/usr/sbin/sshd")
            config = ROOT / "sshd_config"
            if (
                _digest(_read(binary, 16777216)) != packet["sshd_digest"]
                or _digest(_read(config)) != packet["sshd_config_digest"]
            ):
                raise ProviderRefused()
            self._publish_context(slot, deadline=slot_deadline)
            boundary.require_watchdog()
            # preexec executes only one cgroup write before exec; no threads are
            # started by this root finite parent. All descendants inherit it.
            process = subprocess.Popen(  # noqa: S603 -- fixed pinned daemon vector
                [str(binary), "-i", "-e", "-f", str(config)],
                stdin=connection.fileno(),
                stdout=connection.fileno(),
                stderr=subprocess.DEVNULL,
                close_fds=True,
                env={"PATH": "/usr/sbin:/usr/bin"},
                preexec_fn=boundary.enter_child,
            )
            self._activated = True
            self._pin_daemon(slot, process, slot_deadline)
            connection.close()

            # This root process stays OUTSIDE the worker cgroup. Its timed wait
            # is the original-deadline process boundary even for native DB hangs.
            self._wait_daemon(process, slot_deadline)
            self._require_phase_open(slot_deadline)
            self.clocks.require_open()
            self._require_phase_open(slot_deadline)
            self._phase_completed[slot] = datetime.now(UTC).isoformat()
            self._retire_resources(boundary, None)
            self._require_terminal_success(slot)
            self._boundary = None
            self._index += 1
            self.state = (
                LaunchState.TERMINAL
                if self._index == len(SLOTS)
                else LaunchState.READY_FOR_NEXT
            )
        except BaseException as error:
            self._remember_failure(CleanupReason.EXECUTION_INCOMPLETE)
            primary_failure = error
            self.state = LaunchState.TERMINAL
            raise
        finally:
            self._retire_resources(
                boundary, process, (connection,), primary_failure=primary_failure
            )
            self._boundary = None

    def run_issuer_connection(self, connection: socket.socket) -> None:
        """The fixed issuer sshd worker is bounded before its native DB connect."""
        if self.state != LaunchState.AWAITING_CAPTURE or self._boundary is not None:
            raise ProviderRefused()
        self.clocks.require_open()
        self._require_ssh_connection(connection, "issuer")
        boundary = SlotExecutionBoundary("issuer")
        self._boundaries["issuer"] = boundary
        boundary.start_watchdog(self.clocks.deadline)
        self._boundary = boundary
        process = None
        primary_failure: BaseException | None = None
        export_listener = None
        export_connection = None
        try:
            packet = _load_local_packet()
            binary, config = Path("/usr/sbin/sshd"), ROOT / "issuer_sshd_config"
            if (
                _digest(_read(binary, 16777216)) != packet["sshd_digest"]
                or _digest(_read(config)) != packet["issuer_sshd_config_digest"]
            ):
                raise ProviderRefused()
            self._publish_context("issuer", "issuer")
            boundary.require_watchdog()
            export_listener = self._bind_issuer_export()
            process = subprocess.Popen(  # noqa: S603 -- fixed pinned issuer daemon
                [str(binary), "-i", "-e", "-f", str(config)],
                stdin=connection.fileno(),
                stdout=connection.fileno(),
                stderr=subprocess.DEVNULL,
                close_fds=True,
                env={"PATH": "/usr/sbin:/usr/bin"},
                preexec_fn=boundary.enter_child,
            )
            self._activated = True
            self._pin_daemon("issuer", process, self.clocks.deadline)
            connection.close()
            public_export, source_peer, export_connection, export_deadline = (
                self._receive_issuer_export(export_listener)
            )
            export_listener.close()
            response = self._run_capture_sender(
                public_export, source_peer, export_deadline
            )
            self._require_phase_open(export_deadline)
            export_connection.settimeout(export_deadline - time.monotonic())
            export_connection.sendall(response)
            export_connection.shutdown(socket.SHUT_WR)
            self._require_phase_open(export_deadline)
            export_connection.close()
            self._wait_daemon(process, self.clocks.deadline)
            self.clocks.require_open()
            self._phase_completed["issuer"] = datetime.now(UTC).isoformat()

        except BaseException as error:
            self._remember_failure(CleanupReason.EXECUTION_INCOMPLETE)
            primary_failure = error
            raise
        finally:
            self.state = LaunchState.TERMINAL
            self._retire_resources(
                boundary,
                process,
                (connection, export_listener, export_connection),
                primary_failure=primary_failure,
            )
            self._boundary = None
        self._require_terminal_success("issuer")

    def _bind_issuer_export(self) -> socket.socket:
        packet = _load_local_packet()
        if packet["issuer_uid"] != self.worker_uid:
            raise ProviderRefused()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.settimeout(self.clocks.deadline - time.monotonic())
            listener.bind(str(ROOT / "issuer-export.sock"))
            os.chmod(ROOT / "issuer-export.sock", 0o600)
            os.chown(ROOT / "issuer-export.sock", self.worker_uid, -1)
            listener.listen(1)
            return listener
        except BaseException:
            listener.close()
            raise

    def _receive_issuer_export(
        self, listener: socket.socket
    ) -> tuple[bytes, IssuerPeer, socket.socket, float]:
        """Native issuer peer → one bounded EOF-terminated owner export."""
        accepted, _ = listener.accept()
        connection: socket.socket | None = accepted
        listener.close()
        try:
            if connection is None:
                raise ProviderRefused()
            pid, uid, _ = _peer(connection)
            packet = _load_local_packet()
            if (
                uid != packet["issuer_uid"]
                or Path(f"/proc/{pid}/cgroup").read_text().strip()
                != "0::/dotmac-gate0/issuer"
            ):
                raise ProviderRefused()
            source: IssuerPeer = {
                "issuer_uid": uid,
                "issuer_pid": pid,
                "issuer_start": _process_identity(pid),
            }
            deadline = min(self.clocks.deadline, time.monotonic() + 10)
            connection.setblocking(False)
            raw = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                if (
                    remaining <= 0
                    or not select.select([connection], [], [], remaining)[0]
                ):
                    raise ProviderRefused()
                part = connection.recv(min(4096, 196613 - len(raw)))
                if not part:
                    break
                if len(raw) + len(part) > 196612:
                    raise ProviderRefused()
                raw.extend(part)
            self._require_phase_open(deadline)
            if len(raw) < 5 or struct.unpack("!I", raw[:4])[0] != len(raw) - 4:
                raise ProviderRefused()
            entry = _capture_request(bytes(raw[4:]), self.packet_digest)
            if not _selection_matches(packet["capture"], entry.coordinates):
                raise ProviderRefused()
            captured = decode_capture(entry.encoded, expected=entry.coordinates)
            window = captured.binding.window.document
            terms = _run_document(RunIdentity.from_installed().canonical_bytes)
            if (
                window["controller"]["ca_fingerprint"]
                != terms["controller_ca_fingerprint"]
                or window["case_kind"] != terms["case_kind"]
                or window["github"]["run_id"] != terms["run_id"]
                or window["github"]["run_attempt"] != terms["run_attempt"]
                or self.clocks.expires_at > _instant(window["expires_at"])
            ):
                raise ProviderRefused()
            self._require_phase_open(deadline)
            owned = connection
            connection = None
            return bytes(raw), source, owned, deadline
        finally:
            if connection is not None:
                connection.close()

    def _run_capture_sender(
        self, public_export: bytes, source_peer: IssuerPeer, deadline: float
    ) -> bytes:
        """Fixed sender child: public parent stream, existing RO identity mount."""
        self._require_phase_open(deadline)
        boundary = SlotExecutionBoundary("capture_sender")
        self._boundaries["capture_sender"] = boundary
        boundary.start_watchdog(deadline)
        self._sender_boundary = boundary
        parent, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        process = None
        primary_failure: BaseException | None = None
        try:
            packet = _load_local_packet()
            uid = packet["capture_sender_uid"]
            if uid == self.worker_uid:
                raise ProviderRefused()
            account = pwd.getpwuid(uid)
            executable = Path("/opt/venv/bin/dotmac-platform")
            if _digest(_read(executable, 16777216)) != packet["cli_digest"]:
                raise ProviderRefused()
            info = os.fstat(sender.fileno())
            record = canonical(
                {
                    "descriptor": sender.fileno(),
                    "device": info.st_dev,
                    "inode": info.st_ino,
                    **source_peer,
                }
            )
            fd = os.open(
                ROOT / "sender-export.json",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o444,
            )
            try:
                _write(fd, record)
                os.fsync(fd)
            finally:
                os.close(fd)
            self._publish_context("capture_sender", "capture_sender", deadline=deadline)
            boundary.require_watchdog()

            def enter_sender() -> None:
                boundary.enter_child()
                os.setgroups([])
                os.setgid(account.pw_gid)
                os.setuid(uid)

            process = subprocess.Popen(  # noqa: S603 -- fixed measured sender CLI
                [str(executable), "gate0", "capture-send"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                pass_fds=(sender.fileno(),),
                env={"PATH": "/opt/venv/bin:/usr/sbin:/usr/bin"},
                preexec_fn=enter_sender,
            )
            self._activated = True
            sender.close()
            parent.settimeout(max(0.001, deadline - time.monotonic()))
            parent.sendall(public_export)
            parent.shutdown(socket.SHUT_WR)
            parent.setblocking(False)
            response = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([parent], [], [], remaining)[0]:
                    raise ProviderRefused()
                part = parent.recv(min(4096, 65541 - len(response)))
                if not part:
                    break
                if len(response) + len(part) > 65540:
                    raise ProviderRefused()
                response.extend(part)
            if (
                len(response) < 5
                or struct.unpack("!I", response[:4])[0] != len(response) - 4
            ):
                raise ProviderRefused()
            export = _capture_request(public_export[4:], self.packet_digest)
            expected = CaptureInstallReadback(
                self.packet_digest,
                export.coordinates,
                self.clocks.expires_at,
            )
            if _capture_readback(bytes(response[4:])) != expected:
                raise ProviderRefused()
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
            if process.returncode != 0:
                raise ProviderRefused()
            self._require_phase_open(deadline)
            self._capture_delivery = self._capture_completion(expected)
            self._phase_completed["capture_sender"] = datetime.now(UTC).isoformat()
            self._retire_resources(boundary, None)
            self._sender_boundary = None
            return bytes(response)
        except BaseException as error:
            self._remember_failure(CleanupReason.EXECUTION_INCOMPLETE)
            primary_failure = error
            raise
        finally:
            self._retire_resources(
                boundary, process, (parent, sender), primary_failure=primary_failure
            )
            self._sender_boundary = None

    def run_management_connection(
        self,
        connection: socket.socket,
        expected: CaptureCoordinates | None = None,
    ) -> CaptureInstallReadback:
        """One management sshd stream and one bounded root publication channel."""
        if self.state != LaunchState.AWAITING_CAPTURE or self._boundary is not None:
            raise ProviderRefused()
        self._require_ssh_connection(connection, "management")
        management_deadline = min(self.clocks.deadline, time.monotonic() + 10)
        self._active_deadline = management_deadline
        packet = _load_local_packet()
        boundary = SlotExecutionBoundary("management")
        self._boundaries["management"] = boundary
        boundary.start_watchdog(management_deadline)
        self._boundary = boundary
        process = None
        primary_failure: BaseException | None = None
        try:
            binary, config = Path("/usr/sbin/sshd"), ROOT / "management_sshd_config"
            if (
                _digest(_read(binary, 16777216)) != packet["sshd_digest"]
                or _digest(_read(config)) != packet["management_sshd_config_digest"]
            ):
                raise ProviderRefused()
            self._publish_context(
                "management", "management", deadline=management_deadline
            )
            boundary.require_watchdog()
            self._management_listener = self._bind_management_listener()
            process = subprocess.Popen(  # noqa: S603 -- fixed pinned management daemon
                [str(binary), "-i", "-e", "-f", str(config)],
                stdin=connection.fileno(),
                stdout=connection.fileno(),
                stderr=subprocess.DEVNULL,
                close_fds=True,
                env={"PATH": "/usr/sbin:/usr/bin"},
                preexec_fn=boundary.enter_child,
            )
            self._activated = True
            self._pin_daemon("management", process, management_deadline)
            connection.close()
            result = self.serve_capture_once(expected)
            self._management_capture = self._capture_completion(result)
            self._wait_daemon(process, management_deadline)
            self._require_phase_open(management_deadline)
            self._phase_completed["management"] = datetime.now(UTC).isoformat()
            self._retire_resources(boundary, None)
            self._boundary = None
            return result
        except BaseException as error:
            self._remember_failure(CleanupReason.EXECUTION_INCOMPLETE)
            primary_failure = error
            self.state = LaunchState.TERMINAL
            raise
        finally:
            listener = self._management_listener
            self._management_listener = None
            self._retire_resources(
                boundary,
                process,
                (connection, listener),
                primary_failure=primary_failure,
            )
            self._boundary = None

    def _require_ssh_connection(self, connection: socket.socket, role: Role) -> None:
        """The accepted stream itself must match the protected WG ingress tuple."""
        self.clocks.require_open()
        packet = _load_local_packet()
        endpoint = packet["ssh_endpoints"][role]
        if (
            connection.family != socket.AF_INET
            or connection.type & 0xF != socket.SOCK_STREAM
        ):
            raise ProviderRefused()
        local, remote = (
            _socket_endpoint(connection.getsockname()),
            _socket_endpoint(connection.getpeername()),
        )
        interface = (
            connection.getsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, 16)
            .rstrip(b"\0")
            .decode("ascii")
        )
        if (
            interface != packet["network"]["interface"]
            or local != (endpoint["local_address"], endpoint["local_port"])
            or remote[0] != endpoint["remote_address"]
        ):
            raise ProviderRefused()
        if endpoint["local_address"] != packet["network"]["local_address"]:
            raise ProviderRefused()
        if str(ipaddress.IPv4Address(remote[0])) != remote[0]:
            raise ProviderRefused()

    def _require_terminal_success(self, slot: str) -> None:
        if slot not in (*SLOTS, "issuer"):
            raise ProviderRefused()
        parent = _protected(ROOT / "status" / slot, directory=True, uid=self.worker_uid)
        try:
            fd = os.open(
                "terminal.json",
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent,
            )
            try:
                info = os.fstat(fd)
                if (
                    info.st_uid != self.worker_uid
                    or info.st_mode & 0o222
                    or not stat.S_ISREG(info.st_mode)
                ):
                    raise ProviderRefused()
                raw = _bytes(fd, 65536)
                terminal = strict_object(raw, 65536)
                if slot == "issuer":
                    from vendor_cp.deployment.gate0_collection import (
                        IssuerOutcome,
                        OutcomeKind,
                    )

                    fields = {
                        "schema",
                        "launch_packet_digest",
                        "local_packet_digest",
                        "case_kind",
                        "window_digest",
                        "worker_declared_exit_code",
                        "transcript_digest",
                        "terminal_outcome",
                    }
                    terminal = _record(terminal, fields)
                    terms = self._run_terms
                    final = IssuerOutcome.parse(terminal["terminal_outcome"])
                    if (
                        terminal["schema"] != "Gate0IssuerTerminal.v1"
                        or terminal["local_packet_digest"] != self.local_packet_digest
                        or terminal["case_kind"] != terms["case_kind"]
                        or terminal["window_digest"]
                        != terms["capture"]["window_digest"]
                        or type(terminal["worker_declared_exit_code"]) is not int
                        or terminal["worker_declared_exit_code"] != 3
                        or final.kind is not OutcomeKind.OWNER_REFUSED
                        or final.operation != "consume"
                        or final.window_digest != terminal["window_digest"]
                    ):
                        raise ProviderRefused()
                    _sha(terminal["transcript_digest"])
                else:
                    terminal = _record(
                        terminal, {"schema", "launch_packet_digest", "slot", "outcome"}
                    )
                    if (
                        terminal["schema"] != "Gate0SlotTerminal.v1"
                        or terminal["slot"] != slot
                        or terminal["outcome"] != "success"
                    ):
                        raise ProviderRefused()
                if (
                    terminal["launch_packet_digest"] != self.packet_digest
                    or canonical(terminal) != raw
                ):
                    raise ProviderRefused()
                self._terminals[slot] = {
                    "worker_terminal_digest": _digest(raw),
                    "worker_terminal": terminal,
                }
            finally:
                os.close(fd)
        finally:
            os.close(parent)

    def _require_phase_open(self, deadline: float) -> None:
        self.clocks.require_open()
        if time.monotonic() >= deadline:
            raise ProviderRefused()

    def _publish_context(
        self, slot: str, role: Role = "attester", *, deadline: float | None = None
    ) -> None:
        # Fixed private mount is switched by the root installation between slots;
        # wrapper provisioning is never triggered here. Existing context refuses
        # replacement except this supervisor-owned transition after empty proof.
        packet = _load_local_packet()
        role_uid = (
            packet["capture_sender_uid"]
            if role == "capture_sender"
            else packet["management_uid"]
            if role == "management"
            else self.worker_uid
        )
        group = pwd.getpwuid(role_uid).pw_gid
        if role != "management":
            claims = ROOT / ("sender-claims" if role == "capture_sender" else "claims")
            if not claims.exists():
                os.mkdir(claims, mode=0o700)
                os.chown(claims, role_uid, group)
            claims_fd = _protected(claims, directory=True, uid=role_uid)
            os.close(claims_fd)
        if role in ("attester", "issuer"):
            status = ROOT / "status"
            if not status.exists():
                os.mkdir(status, mode=0o711)  # noqa: S103 -- fixed worker traverses only
            status_fd = _protected(status, directory=True)
            try:
                os.mkdir(slot, mode=0o700, dir_fd=status_fd)
                os.chown(slot, role_uid, group, dir_fd=status_fd)
            finally:
                os.close(status_fd)
        names = (
            ("issuer",)
            if role == "issuer"
            else ()
            if role == "capture_sender"
            else SLOTS
        )
        for name in names:
            source = ROOT / "secrets" / name / "wrapping-token"
            fd = _protected(source)
            try:
                os.fchown(fd, 0, group)
                os.fchmod(fd, 0o440 if name == slot and role != "management" else 0)
            finally:
                os.close(fd)
        record = {
            "packet_digest": self.packet_digest,
            "local_packet_digest": self.local_packet_digest,
            "machine_id_digest": self.machine_id_digest,
            "role": role,
            "started_at": self.clocks.started_at.isoformat(),
            "monotonic_origin": self.clocks.monotonic_origin,
            "deadline": self.clocks.deadline if deadline is None else deadline,
            "expires_at": self.clocks.expires_at.isoformat(),
            "worker_uid": role_uid,
            "slot_id": slot if role == "attester" else None,
            "supervisor_pid": os.getpid(),
            "supervisor_start": _process_identity(os.getpid()),
            "boundary": "/dotmac-gate0/" + slot,
            "network_measurement_digest": self.network_measurement_digest,
        }
        path = ROOT / "context.next"
        fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o444,
        )
        try:
            _write(fd, canonical(record))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(path, ROOT / "context.json")

    @staticmethod
    def _transient_paths() -> tuple[str, ...]:
        return (
            "context.json",
            "context.next",
            "sender-export.json",
            "issuer-export.sock",
            "management.sock",
            "captures/capture.json",
            "captures/readback.json",
            "capture-commit/capture.json",
            "capture-commit/readback.json",
            *("secrets/" + name + "/wrapping-token" for name in (*SLOTS, "issuer")),
            "captures",
            "capture-commit",
        )

    def close(self) -> None:
        # Successful repeated closes retain the actual first completion instant.
        # A failed close is never reclassified as complete on another invocation.
        if getattr(self, "_cleanup_complete", False):
            return
        self.state = LaunchState.TERMINAL
        self._cleanup_complete = False
        failure: BaseException | None = None
        for boundary in self._boundaries.values():
            try:
                self._retire_resources(boundary, None)
            except BaseException as error:
                if failure is None:
                    failure = error
        listener = self._management_listener
        self._management_listener = None
        if listener is not None:
            try:
                listener.close()
            except BaseException as error:
                self._remember_failure(CleanupReason.DESCRIPTOR_CLOSE_FAILED)
                if failure is None:
                    failure = error
        # Fixed paths only; terminal evidence, claims and once marker are retained.
        for relative in self._transient_paths():
            source = ROOT / relative
            try:
                try:
                    metadata = source.lstat()
                except FileNotFoundError:
                    if relative not in self._removed:
                        self._removed.append(relative)
                    continue
                if relative in ("issuer-export.sock", "management.sock"):
                    expected_uid = (
                        self._local_terms["issuer_uid"]
                        if relative == "issuer-export.sock"
                        else self._local_terms["management_uid"]
                    )
                    parent = _protected(ROOT, directory=True)
                    try:
                        if (
                            not stat.S_ISSOCK(metadata.st_mode)
                            or metadata.st_uid != expected_uid
                        ):
                            raise ProviderRefused()
                        os.unlink(relative, dir_fd=parent)
                    finally:
                        os.close(parent)
                elif relative in ("captures", "capture-commit"):
                    descriptor = _protected(source, directory=True)
                    os.close(descriptor)
                    source.rmdir()
                else:
                    descriptor = _protected(source)
                    try:
                        if relative.startswith("secrets/"):
                            os.fchmod(descriptor, 0)
                    finally:
                        os.close(descriptor)
                    source.unlink()
                if source.exists() or source.is_symlink():
                    raise ProviderRefused()
                if relative not in self._removed:
                    self._removed.append(relative)
            except BaseException as error:
                self._remember_failure(CleanupReason.EPHEMERAL_FAILED)
                if failure is None:
                    failure = error
        if failure is not None:
            raise failure
        if getattr(self, "_cleanup_failed", False):
            raise LaunchIncomplete()
        self._cleanup_complete = True
        self._cleanup_completed_at = datetime.now(UTC).isoformat()

    def cleanup_document(self) -> dict[str, object]:
        """Root mechanics evidence; protected collector still owes SSH status join."""
        packet = self._local_terms
        terms = self._run_terms
        role = packet["host_role"]
        expected = (
            {"preflight", "issuer", "capture_sender"}
            if role == "issuer"
            else {"preflight", "management", *SLOTS}
        )
        terminals = {"issuer"} if role == "issuer" else set(SLOTS)
        daemon_keys = {"issuer"} if role == "issuer" else {"management", *SLOTS}
        capture_completion = (
            self._capture_delivery if role == "issuer" else self._management_capture
        )
        complete = (
            self._cleanup_complete
            and self._mechanics_complete
            and set(self._boundaries) == expected
            and set(self._terminals) == terminals
            and set(self._daemon_observations) == daemon_keys
            and all(
                observation["termination"] == "exited"
                and type(observation["daemon_returncode"]) is int
                and 0 <= observation["daemon_returncode"] <= 255
                and 0
                <= observation["completed_elapsed_seconds"]
                < observation["phase_deadline_elapsed_seconds"]
                for observation in self._daemon_observations.values()
            )
            and capture_completion is not None
            and all(
                boundary._evidence is not None for boundary in self._boundaries.values()
            )
            and self._failure_reason is None
        )
        reason = (
            CleanupReason.COMPLETED
            if complete
            else (
                self._failure_reason
                or (
                    CleanupReason.CLEANUP_MISSING
                    if not self._cleanup_complete
                    else CleanupReason.EXECUTION_INCOMPLETE
                )
            )
        )
        completed_boundaries: list[dict[str, object]] = []
        for name in sorted(self._boundaries):
            evidence = self._boundaries[name]._evidence
            if evidence is not None:
                completed_boundaries.append(evidence.document())
        return {
            "schema": "Gate0LaunchCleanup.v1",
            "host_role": role,
            "case_kind": terms["case_kind"],
            "launch_packet_digest": self.packet_digest,
            "local_packet_digest": self.local_packet_digest,
            "window_digest": terms["capture"]["window_digest"],
            "machine_id_digest": self.machine_id_digest,
            "network_measurement_digest": self.network_measurement_digest,
            "supervisor_pid": os.getpid(),
            "supervisor_start": _process_identity(os.getpid()),
            "started_at": self.clocks.started_at.isoformat(),
            "expires_at": self.clocks.expires_at.isoformat(),
            "phase_completed_at": dict(self._phase_completed),
            "terminals": dict(self._terminals),
            "daemon_observations": dict(self._daemon_observations),
            "capture_delivery"
            if role == "issuer"
            else "management_capture": capture_completion,
            "boundaries": completed_boundaries,
            "removed": list(self._removed),
            "expected_removed": list(self._transient_paths()),
            "cleanup_completed_at": self._cleanup_completed_at,
            "outcome": "complete" if complete else "incomplete",
            "reason": reason.value,
            "delivery_status": "unconfirmed",
        }

    @property
    def mechanics_outcome(self) -> Literal["complete", "incomplete"]:
        return (
            "complete"
            if self.cleanup_document()["outcome"] == "complete"
            else "incomplete"
        )

    def export_cleanup(self) -> None:
        try:
            self._export_cleanup()
        except BaseException:
            self._remember_failure(CleanupReason.EXPORT_FAILED)
            raise

    def _export_cleanup(self) -> None:
        """Emit one private artifact and bounded stdout frame after final close."""
        raw = canonical(self.cleanup_document())
        if len(raw) > 196608:
            raise LaunchIncomplete()
        status = ROOT / "status"
        if not status.exists():
            os.mkdir(status, mode=0o711)  # noqa: S103 -- fixed worker traversal
        fd = _protected(status, directory=True)
        try:
            result = os.open(
                "launch-cleanup.json",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o400,
                dir_fd=fd,
            )
            try:
                _write(result, raw)
                os.fsync(result)
            finally:
                os.close(result)
        finally:
            os.close(fd)
        frame = memoryview(struct.pack("!I", len(raw)) + raw)
        was_blocking = os.get_blocking(1)
        os.set_blocking(1, False)
        try:
            end = time.monotonic() + 2
            while frame:
                remaining = end - time.monotonic()
                if remaining <= 0 or not select.select([], [1], [], remaining)[1]:
                    raise LaunchIncomplete()
                try:
                    count = os.write(1, frame)
                except BlockingIOError:
                    continue
                if count <= 0:
                    raise LaunchIncomplete()
                frame = frame[count:]
        finally:
            os.set_blocking(1, was_blocking)
