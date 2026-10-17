"""Fixed A9 lifecycle source candidate; local file facts never accept Gate 0.

Root-installed selections/native records are external trust inputs. Concrete owned
processes and inode handles, not unsigned observations, establish local ownership.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import select
import signal
import socket
import stat
import struct
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    SSHCertificate,
    SSHCertificateType,
    load_ssh_private_key,
    load_ssh_public_identity,
)

from vendor_cp.deployment.gate0_attester import (
    ssh_public_fingerprint,
    verify_controller_certificate,
)
from vendor_cp.deployment.gate0_framing import canonical, strict_object
from vendor_cp.deployment.gate0_launch import parse_run_document
from vendor_cp.deployment.gate0_runner_bootstrap import (
    CollectorRetirementFact,
    NativeSystemManager,
)
from vendor_cp.deployment.gate0_runner_handoff import measure_handoff_process
from vendor_cp.deployment.gate0_runtime import AdmittedOperation
from vendor_cp.deployment.gate0_window import FrozenIssuerWindow, WindowDocument

if TYPE_CHECKING:
    from vendor_cp.deployment.gate0_e_github import (
        InstalledGate0GitHubReads,
        ProducerFacts,
    )

JSONRecord = dict[str, Any]


_ROOT = Path("/run/dotmac-gate0-collector")
_INSTALLATION = _ROOT / "lifecycle-installation.json"
_KEYS = _ROOT / "keys"
_LIFECYCLE = _ROOT / "lifecycle"
_COURIER = _ROOT / "courier"
_SOCKET = _COURIER / "oidc.sock"
_KEYGEN = Path("/usr/bin/ssh-keygen")
_COLLECTION = _ROOT / "installation.json"
_SEAL = object()
_MARKER = b"Gate0A9LifecycleMarker.v1\n"
_PRELAUNCH = _LIFECYCLE / "prelaunch.json"
_METADATA_READY = b"Gate0A9MetadataReady.v1\n"
_SECRET_READY = b"Gate0A9SecretReady.v1\n"


class LifecycleRefused(ValueError):
    def __init__(self) -> None:
        super().__init__("gate0_a9_lifecycle_refused")


def _require(value: bool) -> None:
    if not value:
        raise LifecycleRefused()


def _before(deadline: float) -> None:
    _require(
        type(deadline) in (float, int)
        and math.isfinite(deadline)
        and time.monotonic() < deadline
    )


def _socket_before(channel: socket.socket, deadline: float) -> None:
    _before(deadline)
    channel.settimeout(max(0.001, deadline - time.monotonic()))


def _hash(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _digest(value: object) -> str:
    _require(
        type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None
    )
    return cast(str, value)


def _positive(value: object) -> int:
    _require(type(value) is int and value > 0)
    return cast(int, value)


def _closed(value: object, fields: str) -> JSONRecord:
    _require(type(value) is dict and set(value) == set(fields.split()))
    return cast(JSONRecord, value)


def _utc(value: object) -> datetime:
    _require(
        type(value) is str
        and 20 <= len(value) <= 32
        and re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|\+00:00)",
            value,
        )
        is not None
    )
    return datetime.fromisoformat(cast(str, value).replace("Z", "+00:00"))


def _directory(
    path: Path, *, uid: int = 0, gid: int | None = None, mode: int | None = None
) -> int:
    """Private helper; every production call passes a code-fixed path."""
    _require(path.is_absolute() and ".." not in path.parts)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    device = os.fstat(fd).st_dev
    try:
        for index, part in enumerate(path.parts[1:]):
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
            metadata = os.fstat(fd)
            last = index == len(path.parts) - 2
            _require(
                stat.S_ISDIR(metadata.st_mode)
                and metadata.st_uid == (uid if last else 0)
                and not metadata.st_mode & 0o022
            )
            # /run may be a dedicated tmpfs; descendants must stay on its device.
            if part == "run":
                device = metadata.st_dev
            _require(metadata.st_dev == device)
            if last and gid is not None:
                _require(metadata.st_gid == gid)
            if last and mode is not None:
                _require(stat.S_IMODE(metadata.st_mode) == mode)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _stable(metadata: os.stat_result) -> tuple[int, ...]:
    return tuple(
        getattr(metadata, name)
        for name in (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_uid",
            "st_gid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
    )


def _read_fd(
    fd: int, maximum: int, *, uid: int | None = None, mode: int | None = None
) -> bytes:
    before = os.fstat(fd)
    _require(
        stat.S_ISREG(before.st_mode)
        and before.st_nlink == 1
        and 0 < before.st_size <= maximum
    )
    if uid is not None:
        _require(before.st_uid == uid)
    if mode is not None:
        _require(stat.S_IMODE(before.st_mode) == mode)
    raw = os.pread(fd, maximum + 1, 0)
    _require(len(raw) == before.st_size and not os.pread(fd, 1, len(raw)))
    _require(_stable(os.fstat(fd)) == _stable(before))
    return raw


def _protected(path: Path, maximum: int = 65536, *, mode: int | None = None) -> bytes:
    parent = _directory(path.parent)
    try:
        fd = os.open(
            path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent
        )
        try:
            raw = _read_fd(fd, maximum, uid=0, mode=mode)
            _require(not os.fstat(fd).st_mode & 0o022)
            return raw
        finally:
            os.close(fd)
    finally:
        os.close(parent)


_PRELAUNCH_FIELDS = (
    "schema lifecycle_binding_digest campaign_digest collection_template "
    "bootstrap_template broker_policy collection_native_qualification "
    "bootstrap_native_qualification"
)


def _prelaunch_selection_digest(document: JSONRecord) -> str:
    # Explicit domain; qualification pins are checked separately in full prelaunch.
    return _hash(
        canonical(
            dict(
                schema="Gate0A9PrelaunchStaticSelection.v1",
                selection={
                    k: v
                    for k, v in document.items()
                    if k
                    not in (
                        "collection_native_qualification",
                        "bootstrap_native_qualification",
                    )
                },
            )
        )
    )


def _prelaunch(lifecycle: JSONRecord) -> tuple[bytes, JSONRecord, dict[str, bytes]]:
    raw = _protected(_PRELAUNCH, mode=0o600)
    document = _closed(strict_object(raw), _PRELAUNCH_FIELDS)
    _require(
        canonical(document) == raw
        and document["schema"] == "Gate0A9PrelaunchSelection.v1"
    )
    for name in ("lifecycle_binding_digest", "campaign_digest"):
        _require(document[name] == lifecycle[name])
    inputs = {}
    for name in (
        "collection_template",
        "bootstrap_template",
        "broker_policy",
        "collection_native_qualification",
        "bootstrap_native_qualification",
    ):
        pin = _closed(document[name], "path digest")
        path = Path(pin["path"])
        _require(path == _ROOT / (name.replace("_", "-") + ".json"))
        content = _protected(path)
        _require(_hash(content) == _digest(pin["digest"]))
        parsed = strict_object(content)
        _require(canonical(parsed) == content)
        inputs[name] = content
    return raw, document, inputs


def _marker(path: Path) -> None:
    _require(_protected(path, len(_MARKER), mode=0o600) == _MARKER)


def _proc(path: Path, maximum: int = 65536) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        raw = os.read(fd, maximum + 1)
        _require(len(raw) <= maximum and not os.read(fd, 1))
        return raw
    finally:
        os.close(fd)


def _uid_processes(uid: int, deadline: float) -> set[int]:
    found: set[int] = set()
    entries = os.listdir("/proc")
    _require(len(entries) <= 8192)
    for name in entries:
        _before(deadline)
        if not name.isdecimal():
            continue
        try:
            raw = _proc(Path("/proc") / name / "status")
        except FileNotFoundError:
            continue
        rows = [
            line.split()[1:] for line in raw.splitlines() if line.startswith(b"Uid:")
        ]
        _require(len(rows) == 1 and len(rows[0]) == 4)
        if uid in {int(v) for v in rows[0]}:
            found.add(int(name))
    return found


def _checked_certificate(
    raw: bytes,
    public: Ed25519PublicKey,
    operation: AdmittedOperation,
    start: datetime,
    end: datetime,
    ca_bytes: bytes,
) -> SSHCertificate:
    """Pure predicate reused only after the owner has read its fixed inodes."""
    _require(type(raw) is bytes and 0 < len(raw) <= 65536)
    identity = load_ssh_public_identity(raw)
    _require(isinstance(identity, SSHCertificate))
    certificate = cast(SSHCertificate, identity)
    _require(
        isinstance(certificate, SSHCertificate) and certificate.public_bytes() == raw
    )
    _require(isinstance(public, Ed25519PublicKey))
    _require(
        certificate.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
        == public.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
    )
    verify_controller_certificate(raw, operation, start, ca_public_key=ca_bytes)
    _require(
        certificate.type == SSHCertificateType.USER
        and certificate.valid_before >= end.timestamp()
    )
    return certificate


class FileSlot(StrEnum):
    A_KEY = "a_key"
    A_PUBLIC = "a_public"
    A_CERTIFICATE = "a_certificate"
    B_KEY = "b_key"
    B_PUBLIC = "b_public"
    B_CERTIFICATE = "b_certificate"
    A_STAGE_KEY = "a_stage_key"
    A_STAGE_PUBLIC = "a_stage_public"
    B_STAGE_KEY = "b_stage_key"
    B_STAGE_PUBLIC = "b_stage_public"
    JIT_SOURCE = "jit_source"
    OIDC_SOURCE = "oidc_source"
    COURIER_SELECTION = "courier_selection"
    COURIER_SOCKET = "courier_socket"


_ROSTER = {
    FileSlot.A_KEY: (_KEYS, "a.key"),
    FileSlot.A_PUBLIC: (_KEYS, "a.pub"),
    FileSlot.A_CERTIFICATE: (_KEYS, "a-cert.pub"),
    FileSlot.B_KEY: (_KEYS, "b.key"),
    FileSlot.B_PUBLIC: (_KEYS, "b.pub"),
    FileSlot.B_CERTIFICATE: (_KEYS, "b-cert.pub"),
    FileSlot.A_STAGE_KEY: (_KEYS / ".stage-a", "controller"),
    FileSlot.A_STAGE_PUBLIC: (_KEYS / ".stage-a", "controller.pub"),
    FileSlot.B_STAGE_KEY: (_KEYS / ".stage-b", "controller"),
    FileSlot.B_STAGE_PUBLIC: (_KEYS / ".stage-b", "controller.pub"),
    FileSlot.JIT_SOURCE: (_ROOT, "jit-config"),
    FileSlot.OIDC_SOURCE: (_ROOT, "oidc-request-token"),
    FileSlot.COURIER_SELECTION: (_COURIER, "installation.json"),
    FileSlot.COURIER_SOCKET: (_COURIER, "oidc.sock"),
}


@dataclass(slots=True, repr=False)
class OwnedLifecycleFile:
    slot: FileSlot
    parent_fd: int
    file_fd: int
    parent_dev: int
    parent_ino: int
    dev: int
    ino: int
    uid: int
    gid: int
    mode: int
    nlink: int
    size: int
    mtime_ns: int
    ctime_ns: int
    integrity: str | None = field(repr=False)

    def record(self) -> dict[str, object]:
        return {
            key: getattr(self, key)
            for key in (
                "slot",
                "parent_dev",
                "parent_ino",
                "dev",
                "ino",
                "uid",
                "gid",
                "mode",
                "nlink",
                "size",
                "mtime_ns",
                "ctime_ns",
                "integrity",
            )
        }


@dataclass(frozen=True, slots=True)
class PublicKeySelection:
    case_kind: str
    public_key: bytes
    controller_fingerprint: str


@dataclass(frozen=True, slots=True)
class _OriginalBounds:
    boot_id: str
    wall: datetime
    elapsed: float
    provisioning: datetime
    finalization: datetime

    @classmethod
    def parse(cls, value: object) -> _OriginalBounds:
        value = _closed(
            value, "boot_id wall monotonic provisioning_ends_at finalization_ends_at"
        )
        boot = (
            _proc(Path("/proc/sys/kernel/random/boot_id"), 64).decode("ascii").strip()
        )
        _require(
            value["boot_id"] == boot
            and re.fullmatch(r"[0-9a-f-]{36}", boot) is not None
        )
        _require(
            type(value["monotonic"]) in (int, float)
            and math.isfinite(value["monotonic"])
            and 0 <= value["monotonic"] <= time.monotonic()
        )
        result = cls(
            boot,
            _utc(value["wall"]),
            value["monotonic"],
            _utc(value["provisioning_ends_at"]),
            _utc(value["finalization_ends_at"]),
        )
        _require(result.wall < result.provisioning <= result.finalization)
        _before(result.finalization_end)
        return result

    @property
    def provisioning_end(self) -> float:
        return float(self.elapsed + (self.provisioning - self.wall).total_seconds())

    @property
    def finalization_end(self) -> float:
        return float(self.elapsed + (self.finalization - self.wall).total_seconds())


class _Journal:
    """Create-only root event records. No secret token bytes or token hashes."""

    def __init__(
        self, directory: int, binding: str, campaign: str, bounds: _OriginalBounds
    ) -> None:
        self.fd, self.binding, self.campaign, self.bounds = (
            directory,
            binding,
            campaign,
            bounds,
        )
        self.number = 0
        self.previous: str | None = None

    def event(self, kind: str, facts: dict[str, object], deadline: float) -> None:
        _before(deadline)
        _require(self.number < 128)
        raw = canonical(
            {
                "schema": "Gate0A9OwnershipJournalEvent.v1",
                "sequence": self.number,
                "previous_digest": self.previous,
                "lifecycle_binding_digest": self.binding,
                "campaign_digest": self.campaign,
                "boot_id": self.bounds.boot_id,
                "original_provisioning_microseconds": math.floor(
                    self.bounds.provisioning_end * 1000000
                ),
                "original_finalization_microseconds": math.floor(
                    self.bounds.finalization_end * 1000000
                ),
                "kind": kind,
                "facts": facts,
            }
        )
        _require(len(raw) <= 65536)
        fd = os.open(
            f"event-{self.number:03d}.json",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=self.fd,
        )
        try:
            offset = 0
            while offset < len(raw):
                _before(deadline)
                count = os.write(fd, raw[offset:])
                _require(count > 0)
                offset += count
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(self.fd)
        commit = os.open(
            f"committed-{self.number:03d}",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=self.fd,
        )
        try:
            _before(deadline)
            _require(os.write(commit, _MARKER) == len(_MARKER))
            os.fsync(commit)
        finally:
            os.close(commit)
        os.fsync(self.fd)
        self.number += 1
        self.previous = _hash(raw)
        _before(deadline)


class InstalledA9Lifecycle:
    """Fixed root-owned phases. Constructors cannot accept caller ownership DTOs."""

    def __init__(
        self, seal: object, document: JSONRecord, bounds: _OriginalBounds
    ) -> None:
        _require(seal is _SEAL)
        self._doc, self._bounds = document, bounds
        self._owned: dict[FileSlot, OwnedLifecycleFile] = {}
        self._retired: dict[FileSlot, dict[str, object]] = {}
        self._journal: _Journal | None = None
        self._manager: NativeSystemManager | None = None
        self._jit: NativeJitInvocation | None = None
        self._listener: socket.socket | None = None
        self._keys: tuple[PublicKeySelection, PublicKeySelection] | None = None
        self._failed = False
        self._close_started = self._close_failed = False
        self._journal_unavailable = False
        self._stages: dict[str, tuple[int, int]] = {}
        self._unknown_intents: set[str] = set()
        self._jit_record: JSONRecord | None = None
        self._jit_start_intent = False
        self._jit_invocation: str | None = None

    @classmethod
    def from_installed(cls) -> InstalledA9Lifecycle:
        try:
            _require(os.getuid() == os.geteuid() == 0)
            raw = _protected(_INSTALLATION, mode=0o600)
            doc = _closed(
                strict_object(raw),
                "schema lifecycle_binding_digest campaign_digest allocation_id "
                "repository_id run_id attempt collector_uid collector_gid "
                "courier_uid courier_gid original_bounds keygen_digest "
                "source_files ca_digest cleanup_reserve_microseconds launcher",
            )
            _require(
                canonical(doc) == raw
                and doc["schema"] == "Gate0A9LifecycleInstallation.v1"
            )
            for key in (
                "lifecycle_binding_digest",
                "campaign_digest",
                "keygen_digest",
                "ca_digest",
            ):
                _digest(doc[key])
            for key in (
                "repository_id",
                "run_id",
                "attempt",
                "collector_uid",
                "collector_gid",
                "courier_uid",
                "courier_gid",
                "cleanup_reserve_microseconds",
            ):
                _positive(doc[key])
            _require(
                doc["attempt"] == 1
                and doc["collector_uid"] != doc["courier_uid"]
                and doc["collector_gid"] != doc["courier_gid"]
            )
            _require(
                type(doc["allocation_id"]) is str
                and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", doc["allocation_id"])
                is not None
            )
            sources = _closed(
                doc["source_files"],
                "gate0_runner_lifecycle gate0_runner_lifecycle_courier",
            )
            for name in sources:
                _require(
                    _hash(
                        _protected(Path(__file__).parent / (name + ".py"), 1024 * 1024)
                    )
                    == _digest(sources[name])
                )
            _require(
                _hash(_protected(_KEYGEN, 32 * 1024 * 1024)) == doc["keygen_digest"]
            )
            qualification = strict_object(
                _protected(_ROOT / "lifecycle-qualification.json", mode=0o600)
            )
            _closed(qualification, "schema installation_digest native_receipt_digest")
            _require(
                qualification["schema"] == "Gate0A9LifecycleQualification.v1"
                and qualification["installation_digest"] == _hash(raw)
            )
            _require(
                _hash(_protected(_ROOT / "lifecycle-native.json", mode=0o600))
                == _digest(qualification["native_receipt_digest"])
            )
            NativeJitInvocation._selection(doc["launcher"])
            bounds = _OriginalBounds.parse(doc["original_bounds"])
            return cls(_SEAL, doc, bounds)
        except Exception:
            raise LifecycleRefused() from None

    def _ensure_directories(self) -> None:
        root = _directory(_ROOT)
        try:
            _require((os.fstat(root).st_mode & 0o001) != 0)
            for name, mode, gid in (
                ("keys", 0o750, self._doc["collector_gid"]),
                ("lifecycle", 0o700, 0),
                ("courier", 0o710, self._doc["courier_gid"]),
            ):
                try:
                    os.mkdir(name, mode, dir_fd=root)
                    fd = os.open(
                        name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root
                    )
                    try:
                        os.fchown(fd, 0, gid)
                        os.fchmod(fd, mode)
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    os.fsync(root)
                except FileExistsError:
                    pass
                fd = _directory(_ROOT / name, gid=gid, mode=mode)
                os.close(fd)
        finally:
            os.close(root)

    def _open_journal(self, *, fresh: bool) -> None:
        _require(not getattr(self, "_close_started", False))
        self._ensure_directories()
        parent = _directory(_LIFECYCLE, mode=0o700)
        claim = -1
        try:
            if fresh:
                claim = os.open(
                    "claimed",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=parent,
                )
                raw = canonical(
                    {
                        "schema": "Gate0A9LifecycleClaim.v1",
                        "lifecycle_binding_digest": self._doc[
                            "lifecycle_binding_digest"
                        ],
                        "campaign_digest": self._doc["campaign_digest"],
                        "boot_id": self._bounds.boot_id,
                    }
                )
                _require(os.write(claim, raw) == len(raw))
                os.fsync(claim)
                os.fsync(parent)
            else:
                raw = _protected(_LIFECYCLE / "claimed", mode=0o600)
                expected = {
                    "schema": "Gate0A9LifecycleClaim.v1",
                    "lifecycle_binding_digest": self._doc["lifecycle_binding_digest"],
                    "campaign_digest": self._doc["campaign_digest"],
                    "boot_id": self._bounds.boot_id,
                }
                _require(raw == canonical(expected))
            self._journal = _Journal(
                parent,
                self._doc["lifecycle_binding_digest"],
                self._doc["campaign_digest"],
                self._bounds,
            )
            parent = -1
            if not fresh:
                self._recover()
        finally:
            if claim >= 0:
                os.close(claim)
            if parent >= 0:
                os.close(parent)

    def _event(self, kind: str, facts: dict[str, object], deadline: float) -> None:
        _require(self._journal is not None and not self._journal_unavailable)
        try:
            cast(_Journal, self._journal).event(kind, facts, deadline)
        except Exception:
            self._journal_unavailable = True
            self._fail()
            raise

    def _cleanup_event(
        self, kind: str, facts: dict[str, object], deadline: float
    ) -> None:
        """Append uncertainty forbids success, never safe original-inode cleanup."""
        try:
            self._event(kind, facts, deadline)
        except Exception:
            self._journal_unavailable = True
            self._fail()

    def _fail(self) -> None:
        """Sticky factual failure; never consumes an event sequence or clears itself."""
        self._failed = True
        if self._journal is None:
            return
        self._persist_failure_marker()

    def _persist_failure_marker(self) -> None:
        """Fixed original-bounded marker; never uses a journal descriptor.

        Close may use this only after detaching a journal it already owned.
        """
        fd, parent = -1, -1
        try:
            _before(self._bounds.finalization_end)
            parent = _directory(_LIFECYCLE, mode=0o700)
            fd = os.open(
                "failed",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent,
            )
            _before(self._bounds.finalization_end)
            _require(os.write(fd, _MARKER) == len(_MARKER))
            os.fsync(fd)
            os.fsync(parent)
            _before(self._bounds.finalization_end)
        except FileExistsError:
            pass
        except Exception:
            # Failure to persist cannot authorize success in this owner.
            self._unknown_intents.add("failure_persistence")
        finally:
            for descriptor in (fd, parent):
                if descriptor >= 0:
                    try:
                        os.close(descriptor)
                    except BaseException:
                        self._unknown_intents.add("failure_persistence")

    def _phase(self, name: str, deadline: float) -> None:
        _require(not getattr(self, "_close_started", False))
        _before(deadline)
        _require(not self._failed or name == "retire")
        if self._journal is None:
            self._open_journal(fresh=name == "keys")
        _require(not self._failed or name == "retire")
        fd = -1
        try:
            try:
                fd = os.open(
                    "phase-" + name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=cast(_Journal, self._journal).fd,
                )
            except FileExistsError:
                _require(name == "retire")
                _marker(_LIFECYCLE / "phase-retire")
                return  # cleanup continuation only; never rearm an operation
            _require(os.write(fd, _MARKER) == len(_MARKER))
            os.fsync(fd)
            os.fsync(cast(_Journal, self._journal).fd)
            if name == "retire":
                self._cleanup_event("phase", {"name": name}, deadline)
            else:
                self._event("phase", {"name": name}, deadline)
        except Exception:
            self._fail()
            if name != "retire":
                raise
        finally:
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    self._fail()
                    if name != "retire":
                        raise

    def _capture(
        self, slot: FileSlot, *, allow_empty: bool = False
    ) -> OwnedLifecycleFile:
        _require(not getattr(self, "_close_started", False))
        parent_path, name = _ROSTER[slot]
        parent = _directory(parent_path)
        fd = -1
        try:
            fd = os.open(
                name,
                (
                    os.O_PATH
                    if slot == FileSlot.COURIER_SOCKET
                    else os.O_RDONLY | os.O_NONBLOCK
                )
                | os.O_NOFOLLOW,
                dir_fd=parent,
            )
            before = os.fstat(fd)
            socket_slot = slot == FileSlot.COURIER_SOCKET
            _require(
                (
                    stat.S_ISSOCK(before.st_mode)
                    if socket_slot
                    else stat.S_ISREG(before.st_mode)
                )
                and before.st_nlink in (1, 2)
                and 0 <= before.st_size <= 65536
            )
            if not socket_slot:
                raw = os.pread(fd, 65537, 0)
                _require(len(raw) == before.st_size and (allow_empty or bool(raw)))
                _require(
                    not os.pread(fd, 1, len(raw))
                    and _stable(os.fstat(fd)) == _stable(before)
                )
            else:
                raw = b""
            parent_stat = os.fstat(parent)
            owned = OwnedLifecycleFile(
                slot,
                parent,
                fd,
                parent_stat.st_dev,
                parent_stat.st_ino,
                before.st_dev,
                before.st_ino,
                before.st_uid,
                before.st_gid,
                stat.S_IMODE(before.st_mode),
                before.st_nlink,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
                None
                if slot in (FileSlot.OIDC_SOURCE, FileSlot.JIT_SOURCE)
                else _hash(raw),
            )
            previous = self._owned.get(slot)
            if previous is not None:
                _require((previous.dev, previous.ino) == (owned.dev, owned.ino))
            self._owned[slot] = owned
            parent, fd = -1, -1
            self._event("owned", owned.record(), self._bounds.finalization_end)
            if previous is not None:
                os.close(previous.file_fd)
                os.close(previous.parent_fd)
            return owned
        finally:
            for descriptor in (fd, parent):
                if descriptor >= 0:
                    try:
                        os.close(descriptor)
                    except OSError:
                        self._fail()

    def _refresh_aliases(self, dev: int, ino: int, *, cleanup: bool = False) -> None:
        for owned in self._owned.values():
            if (owned.dev, owned.ino) != (dev, ino):
                continue
            current = os.fstat(owned.file_fd)
            _require(
                (
                    current.st_dev,
                    current.st_ino,
                    current.st_uid,
                    current.st_gid,
                    stat.S_IMODE(current.st_mode),
                    current.st_size,
                )
                == (owned.dev, owned.ino, owned.uid, owned.gid, owned.mode, owned.size)
            )
            if owned.integrity is not None:
                _require(_hash(os.pread(owned.file_fd, 65537, 0)) == owned.integrity)
            owned.nlink, owned.ctime_ns = current.st_nlink, current.st_ctime_ns
            if cleanup:
                self._cleanup_event(
                    "owned", owned.record(), self._bounds.finalization_end
                )
            else:
                self._event("owned", owned.record(), self._bounds.finalization_end)

    def _recover(self) -> None:
        _require(self._journal is not None)
        try:
            _marker(_LIFECYCLE / "failed")
        except FileNotFoundError:
            pass
        except Exception:
            self._unknown_intents.add("failure_marker_invalid")
            self._fail()
        else:
            self._failed = True
        latest: dict[FileSlot, JSONRecord] = {}
        retired: dict[FileSlot, dict[str, object]] = {}
        pending: set[str] = set()
        for number in range(128):
            snapshot = (
                dict(latest),
                dict(retired),
                set(pending),
                dict(self._stages),
                self._jit_start_intent,
                self._jit_invocation,
                self._jit_record,
            )
            try:
                raw = _protected(_LIFECYCLE / f"event-{number:03d}.json", mode=0o600)
            except FileNotFoundError:
                # Fixed 128-position census: a missing event cannot hide a
                # later event/commit or an orphan commit at this position.
                for tail in range(number, 128):
                    _before(self._bounds.finalization_end)
                    names = (
                        (f"committed-{tail:03d}",)
                        if tail == number
                        else (f"event-{tail:03d}.json", f"committed-{tail:03d}")
                    )
                    for name in names:
                        try:
                            os.stat(
                                name,
                                dir_fd=cast(_Journal, self._journal).fd,
                                follow_symlinks=False,
                            )
                        except FileNotFoundError:
                            continue
                        except OSError:
                            self._journal_unavailable = True
                            self._fail()
                            continue
                        self._journal_unavailable = True
                        self._fail()
                break
            except Exception:
                self._journal_unavailable = True
                self._fail()
                break
            try:
                _marker(_LIFECYCLE / f"committed-{number:03d}")
                value = _closed(
                    strict_object(raw),
                    "schema sequence previous_digest lifecycle_binding_digest "
                    "campaign_digest boot_id original_provisioning_microseconds "
                    "original_finalization_microseconds kind facts",
                )
                _require(
                    canonical(value) == raw
                    and value["schema"] == "Gate0A9OwnershipJournalEvent.v1"
                    and type(value["sequence"]) is int
                    and value["sequence"] == number
                    and value["previous_digest"]
                    == cast(_Journal, self._journal).previous
                )
                for field_name, expected in (
                    ("lifecycle_binding_digest", self._doc["lifecycle_binding_digest"]),
                    ("campaign_digest", self._doc["campaign_digest"]),
                    ("boot_id", self._bounds.boot_id),
                    (
                        "original_provisioning_microseconds",
                        math.floor(self._bounds.provisioning_end * 1000000),
                    ),
                    (
                        "original_finalization_microseconds",
                        math.floor(self._bounds.finalization_end * 1000000),
                    ),
                ):
                    _require(
                        type(value[field_name]) is type(expected)
                        and value[field_name] == expected
                    )
                if value["kind"] == "owned":
                    record = _closed(
                        value["facts"],
                        "slot parent_dev parent_ino dev ino uid gid mode nlink size "
                        "mtime_ns ctime_ns integrity",
                    )
                    slot = FileSlot(record["slot"])
                    _require(
                        (slot in (FileSlot.OIDC_SOURCE, FileSlot.JIT_SOURCE))
                        == (record["integrity"] is None)
                    )
                    latest[slot] = record
                    pending.discard("slot:" + slot.value)
                elif value["kind"] == "deletion-intent":
                    record = _closed(
                        value["facts"], "slot device inode read_before_unlink"
                    )
                    slot = FileSlot(record["slot"])
                    _require(
                        type(record["read_before_unlink"]) is bool
                        and slot in latest
                        and (record["device"], record["inode"])
                        == (latest[slot]["dev"], latest[slot]["ino"])
                    )
                    pending.add("delete:" + slot.value)
                    if record["read_before_unlink"] is not True:
                        self._fail()
                elif value["kind"] == "retired":
                    record = _closed(
                        value["facts"],
                        "slot device inode read_before_unlink "
                        "unlinked absent_after_unlink",
                    )
                    for predicate in (
                        "read_before_unlink",
                        "unlinked",
                        "absent_after_unlink",
                    ):
                        _require(type(record[predicate]) is bool)
                        if record[predicate] is not True:
                            self._fail()
                    slot = FileSlot(record["slot"])
                    _require(
                        slot in latest
                        and (record["device"], record["inode"])
                        == (latest[slot]["dev"], latest[slot]["ino"])
                    )
                    retired[slot] = record
                    pending.discard("delete:" + slot.value)
                elif value["kind"] == "stage":
                    record = _closed(value["facts"], "case device inode")
                    _require(record["case"] in ("a", "b"))
                    self._stages[record["case"]] = (record["device"], record["inode"])
                    pending.discard("stage:" + record["case"])
                elif value["kind"] == "intent":
                    record = value["facts"]
                    if "slot" in record:
                        pending.add("slot:" + FileSlot(record["slot"]).value)
                    elif "stage" in record:
                        _require(record["stage"] in ("a", "b"))
                        pending.add("stage:" + record["stage"])
                    else:
                        raise LifecycleRefused()
                elif value["kind"] == "jit-start-intent":
                    record = _closed(value["facts"], "unit")
                    _require(record["unit"] == _JIT_UNIT and not self._jit_start_intent)
                    self._jit_start_intent = True
                elif value["kind"] == "jit-invocation":
                    record = _closed(value["facts"], "invocation")
                    invocation = record["invocation"]
                    _require(
                        self._jit_start_intent
                        and type(invocation) is str
                        and re.fullmatch(r"[0-9a-f]{32}", invocation) is not None
                        and self._jit_invocation is None
                    )
                    self._jit_invocation = cast(str, invocation)
                elif value["kind"] == "jit":
                    self._jit_record = _closed(
                        value["facts"],
                        "pid start invocation cgroup events_device events_inode",
                    )
                    _require(
                        self._jit_invocation is not None
                        and self._jit_record["invocation"] == self._jit_invocation
                    )
                elif value["kind"] not in (
                    "phase",
                    "intent",
                    "stage",
                    "generator",
                    "certificates",
                    "credential",
                    "collector",
                    "jit",
                ):
                    raise LifecycleRefused()
                (
                    cast(_Journal, self._journal).number,
                    cast(_Journal, self._journal).previous,
                ) = number + 1, _hash(raw)
            except Exception:
                (
                    latest,
                    retired,
                    pending,
                    self._stages,
                    self._jit_start_intent,
                    self._jit_invocation,
                    self._jit_record,
                ) = snapshot
                self._journal_unavailable = True
                self._fail()
                break  # preserve the damaged tail; trust no subsequent event
        self._unknown_intents |= pending
        if pending:
            self._fail()
        if self._jit_start_intent and self._jit_record is None:
            # Even an identified failed start is never readiness/success.
            self._fail()
        if cast(_Journal, self._journal).number >= 128:
            self._journal_unavailable = True
            self._fail()
        for slot, record in latest.items():
            if slot in retired:
                self._retired[slot] = retired[slot]
                continue
            parent_path, name = _ROSTER[slot]
            parent, fd = -1, -1
            try:
                parent = _directory(parent_path)
                info = os.fstat(parent)
                _require(
                    (info.st_dev, info.st_ino)
                    == (record["parent_dev"], record["parent_ino"])
                )
                fd = os.open(
                    name,
                    (
                        os.O_PATH
                        if slot == FileSlot.COURIER_SOCKET
                        else os.O_RDONLY | os.O_NONBLOCK
                    )
                    | os.O_NOFOLLOW,
                    dir_fd=parent,
                )
                actual = os.fstat(fd)
                _require(
                    (actual.st_dev, actual.st_ino) == (record["dev"], record["ino"])
                )
                if slot != FileSlot.COURIER_SOCKET:
                    _require(stat.S_ISREG(actual.st_mode))
                    raw = os.pread(fd, 65537, 0)
                    _require(len(raw) == actual.st_size <= 65536)
                    # A changed original may be safely unlinked, but its saved
                    # integrity mismatch can never become a success observation.
                self._owned[slot] = OwnedLifecycleFile(
                    slot,
                    parent,
                    fd,
                    **{key: record[key] for key in record if key != "slot"},
                )
                parent, fd = -1, -1
            except Exception:
                self._fail()
                self._unknown_intents.add("recovery:" + slot.value)
            finally:
                for descriptor in (parent, fd):
                    if descriptor >= 0:
                        try:
                            os.close(descriptor)
                        except OSError:
                            self._fail()

    def _capture_partial_stage_files(self) -> None:
        deadline = self._bounds.finalization_end
        _require(not _uid_processes(self._doc["collector_uid"], deadline))
        keys = _directory(_KEYS)
        try:
            for letter, identity in self._stages.items():
                try:
                    fd = os.open(
                        ".stage-" + letter,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=keys,
                    )
                    try:
                        actual = os.fstat(fd)
                        _require((actual.st_dev, actual.st_ino) == identity)
                        _require(
                            actual.st_uid in (0, self._doc["collector_uid"])
                            and stat.S_IMODE(actual.st_mode) == 0o700
                        )
                        names = os.listdir(fd)
                        _require(
                            set(names) <= {"controller", "controller.pub"}
                            and len(names) <= 2
                        )
                        os.fchown(fd, 0, 0)
                        os.fchmod(fd, 0o700)
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    slots = (
                        (FileSlot.A_STAGE_KEY, FileSlot.A_STAGE_PUBLIC)
                        if letter == "a"
                        else (FileSlot.B_STAGE_KEY, FileSlot.B_STAGE_PUBLIC)
                    )
                    for slot, name in zip(
                        slots, ("controller", "controller.pub"), strict=True
                    ):
                        if (
                            name in names
                            and slot not in self._owned
                            and slot not in self._retired
                        ):
                            try:
                                self._capture(slot, allow_empty=True)
                            except Exception:
                                self._fail()
                                self._unknown_intents.add(
                                    "stage_slot_recovery:" + slot.value
                                )
                except Exception:
                    self._fail()
                    self._unknown_intents.add("stage_recovery:" + letter)
        finally:
            os.close(keys)

    def _create_file(
        self, slot: FileSlot, raw: bytes, uid: int, gid: int, mode: int
    ) -> OwnedLifecycleFile:
        deadline = self._bounds.provisioning_end
        _before(deadline)
        _require(type(raw) is bytes and 0 < len(raw) <= 65536)
        parent_path, name = _ROSTER[slot]
        parent = _directory(parent_path)
        fd = -1
        try:
            p = os.fstat(parent)
            self._event(
                "intent",
                {"slot": slot, "parent_dev": p.st_dev, "parent_ino": p.st_ino},
                deadline,
            )
            fd = os.open(
                name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent,
            )
            os.fchown(fd, uid, gid)
            os.fchmod(fd, mode)
            os.fsync(fd)
            self._capture(slot, allow_empty=True)
            pending = memoryview(raw)
            while pending:
                _before(deadline)
                count = os.write(fd, pending)
                _require(count > 0)
                pending = pending[count:]
            os.fsync(fd)
            _require(_read_fd(fd, 65536, uid=uid, mode=mode) == raw)
            os.fsync(parent)
        finally:
            if fd >= 0:
                os.close(fd)
            os.close(parent)
        return self._capture(slot)

    def _generate_case(self, letter: str) -> PublicKeySelection:
        deadline = self._bounds.provisioning_end
        reserve = self._doc["cleanup_reserve_microseconds"] / 1000000
        work_end = deadline - reserve
        _before(work_end)
        _require(not _uid_processes(self._doc["collector_uid"], work_end))
        stage_path = _KEYS / (".stage-" + letter)
        keys = _directory(_KEYS, gid=self._doc["collector_gid"], mode=0o750)
        stage = -1
        process: subprocess.Popen[bytes] | None = None
        _require(
            hasattr(os, "waitid")
            and hasattr(os, "WNOWAIT")
            and hasattr(os, "pidfd_open")
            and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL
        )
        leader_fd = -1
        leader_start: str | None = None
        outputs = [bytearray(), bytearray()]
        reaped = False
        try:
            self._event("intent", {"stage": letter}, work_end)
            os.mkdir(".stage-" + letter, 0o700, dir_fd=keys)
            stage = os.open(
                ".stage-" + letter,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=keys,
            )
            os.fchown(stage, self._doc["collector_uid"], self._doc["collector_gid"])
            os.fchmod(stage, 0o700)
            metadata = os.fstat(stage)
            self._stages[letter] = (metadata.st_dev, metadata.st_ino)
            self._event(
                "stage",
                {"case": letter, "device": metadata.st_dev, "inode": metadata.st_ino},
                work_end,
            )
            _require(os.listdir(stage) == [])
            process = subprocess.Popen(  # noqa: S603 -- fixed pinned executable/vector
                (
                    str(_KEYGEN),
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-C",
                    "",
                    "-f",
                    str(stage_path / "controller"),
                ),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd="/",
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/"},
                user=self._doc["collector_uid"],
                group=self._doc["collector_gid"],
                extra_groups=(),
                umask=0o077,
                close_fds=True,
                start_new_session=True,
            )
            leader_fd = os.pidfd_open(process.pid, 0)
            parent_pid, leader_uid, leader_start = measure_handoff_process(process.pid)
            _require(
                parent_pid == os.getpid() and leader_uid == self._doc["collector_uid"]
            )
            _require(process.stdout is not None and process.stderr is not None)
            streams = {
                cast(BinaryIO, process.stdout).fileno(): 0,
                cast(BinaryIO, process.stderr).fileno(): 1,
            }
            for fd in streams:
                os.set_blocking(fd, False)
            while streams:
                _before(work_end)
                ready = select.select(
                    list(streams), [], [], work_end - time.monotonic()
                )[0]
                _require(bool(ready))
                for fd in ready:
                    chunk = os.read(fd, 4096)
                    if not chunk:
                        del streams[fd]
                    else:
                        outputs[streams[fd]].extend(chunk)
                        _require(len(outputs[streams[fd]]) <= 16384)
            while True:
                _before(work_end)
                status = os.waitid(
                    os.P_PID, process.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG
                )
                if status is not None:
                    _require(
                        status.si_pid == process.pid
                        and status.si_code == os.CLD_EXITED
                        and status.si_status == 0
                    )
                    break
                select.select(
                    [], [], [], min(0.01, max(0, work_end - time.monotonic()))
                )
            # WNOWAIT keeps this exact leader/PGID allocated through cleanup.
            _require(
                _uid_processes(self._doc["collector_uid"], work_end) <= {process.pid}
            )
            reaped = True
        finally:
            if process is not None:
                failed = False
                try:
                    _before(deadline)
                    # No poll()/wait() has reaped the owned session leader.
                    # Its retained PID prevents PGID reuse, including exited
                    # leaders whose descendants still hold output pipes.
                    if leader_start is not None:
                        _require(
                            measure_handoff_process(process.pid)
                            == (os.getpid(), self._doc["collector_uid"], leader_start)
                        )
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                except BaseException:
                    failed = True
                    # A retained pidfd can signal only this child if group
                    # cleanup fails. It grants no arbitrary process authority.
                    if leader_fd >= 0:
                        try:
                            _before(deadline)
                            signal.pidfd_send_signal(leader_fd, signal.SIGKILL)
                        except Exception:
                            failed = True
                try:
                    process.wait(timeout=max(0, deadline - time.monotonic()))
                    while _uid_processes(self._doc["collector_uid"], deadline):
                        _before(deadline)
                        select.select(
                            [], [], [], min(0.01, max(0, deadline - time.monotonic()))
                        )
                except BaseException:
                    failed = True
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        try:
                            stream.close()
                        except OSError:
                            failed = True
                if failed:
                    self._fail()
            if leader_fd >= 0:
                os.close(leader_fd)
            outputs.clear()
            try:
                if stage >= 0:
                    try:
                        if not _uid_processes(self._doc["collector_uid"], deadline):
                            os.fchown(stage, 0, 0)
                            os.fchmod(stage, 0o700)
                            os.fsync(stage)
                        else:
                            self._fail()
                    except Exception:
                        self._fail()
                    finally:
                        os.close(stage)
            finally:
                os.close(keys)
        _require(reaped and not self._failed)
        self._event(
            "generator",
            {"case": letter, "exit_code": 0, "dedicated_uid_empty": True},
            deadline,
        )
        stage = _directory(stage_path, mode=0o700)
        try:
            _require(set(os.listdir(stage)) == {"controller", "controller.pub"})
            for name, private in (("controller", True), ("controller.pub", False)):
                fd = os.open(
                    name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=stage
                )
                try:
                    _read_fd(fd, 65536, uid=self._doc["collector_uid"])
                    os.fchown(
                        fd,
                        self._doc["collector_uid"] if private else 0,
                        self._doc["collector_gid"],
                    )
                    os.fchmod(fd, 0o600 if private else 0o640)
                    os.fsync(fd)
                finally:
                    os.close(fd)
        finally:
            os.close(stage)
        slots = (
            (
                FileSlot.A_STAGE_KEY,
                FileSlot.A_STAGE_PUBLIC,
                FileSlot.A_KEY,
                FileSlot.A_PUBLIC,
            )
            if letter == "a"
            else (
                FileSlot.B_STAGE_KEY,
                FileSlot.B_STAGE_PUBLIC,
                FileSlot.B_KEY,
                FileSlot.B_PUBLIC,
            )
        )
        private_record, public_record = self._capture(slots[0]), self._capture(slots[1])
        private_bytes = _read_fd(private_record.file_fd, 65536)
        public_bytes = _read_fd(public_record.file_fd, 65536)
        try:
            private_key = load_ssh_private_key(private_bytes, password=None)
            public = load_ssh_public_identity(public_bytes.rstrip(b"\n"))
            _require(
                isinstance(private_key, Ed25519PrivateKey)
                and isinstance(public, Ed25519PublicKey)
            )
            private_key = cast(Ed25519PrivateKey, private_key)
            public = cast(Ed25519PublicKey, public)
            encoded = public.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
            _require(
                public_bytes in (encoded + b"\n", encoded + b" \n")
                and private_key.public_key().public_bytes(
                    Encoding.OpenSSH, PublicFormat.OpenSSH
                )
                == encoded
            )
        finally:
            private_bytes = b""
        for source, destination in ((slots[0], slots[2]), (slots[1], slots[3])):
            owned = self._owned[source]
            parent = _directory(_KEYS, mode=0o750)
            try:
                self._event(
                    "intent", {"slot": destination, "source_slot": source}, deadline
                )
                os.link(
                    _ROSTER[source][1],
                    _ROSTER[destination][1],
                    src_dir_fd=owned.parent_fd,
                    dst_dir_fd=parent,
                    follow_symlinks=False,
                )
                os.fsync(parent)
            finally:
                os.close(parent)
            promoted = self._capture(destination)
            _require((promoted.dev, promoted.ino) == (owned.dev, owned.ino))
            self._refresh_aliases(owned.dev, owned.ino)
        self._unlink_owned(slots[0], deadline)
        self._unlink_owned(slots[1], deadline)
        return PublicKeySelection(
            "consume_replay" if letter == "a" else "withdrawal_later_use",
            encoded,
            ssh_public_fingerprint(public),
        )

    def create_controller_keys(self) -> tuple[PublicKeySelection, PublicKeySelection]:
        try:
            self._phase("keys", self._bounds.provisioning_end)
            a, b = self._generate_case("a"), self._generate_case("b")
            _require(
                a.public_key != b.public_key
                and a.controller_fingerprint != b.controller_fingerprint
            )
            self._keys = (a, b)
            return self._keys
        except Exception:
            self._fail()
            raise LifecycleRefused() from None

    def _collection_cases(
        self,
    ) -> list[tuple[JSONRecord, WindowDocument, AdmittedOperation]]:
        _, _, inputs = _prelaunch(self._doc)
        document = strict_object(inputs["collection_template"])
        _require(
            document["schema"] == "Gate0RunnerCollectionTemplate.v1"
            and document["campaign_digest"] == self._doc["campaign_digest"]
            and type(document["collector_uid"]) is int
            and document["collector_uid"] == self._doc["collector_uid"]
        )
        cases = document["cases"]
        _require(type(cases) is list and len(cases) == 2)
        cases = cast(list[JSONRecord], cases)
        result: list[tuple[JSONRecord, WindowDocument, AdmittedOperation]] = []
        for index, case in enumerate(cases):
            _require(type(case) is dict)
            pins = []
            for field_name in ("shared_packet", "frozen_window"):
                pin = _closed(case[field_name], "path digest")
                # These are public installer-owned references, never deletion targets.
                path = Path(pin["path"])
                _require(
                    path.is_absolute()
                    and str(path).startswith(str(_ROOT) + "/")
                    and ".." not in path.parts
                )
                content = _protected(path)
                _require(_hash(content) == _digest(pin["digest"]))
                pins.append(content)
            shared, frozen = pins
            packet, window = (
                parse_run_document(shared),
                FrozenIssuerWindow.parse(frozen),
            )
            w, c = window.document, window.document["controller"]
            _require(
                w["case_kind"]
                == ("consume_replay" if index == 0 else "withdrawal_later_use")
                and packet["case_kind"] == w["case_kind"]
                and packet["capture"]["window_digest"] == window.digest
                and packet["controller_ca_fingerprint"] == c["ca_fingerprint"]
                and packet["run_id"] == w["github"]["run_id"]
                and packet["run_attempt"] == w["github"]["run_attempt"]
                and packet["not_before"] == w["not_before"]
                and packet["expires_at"] == w["expires_at"]
            )
            _require(
                w["github"]["repository_id"] == str(self._doc["repository_id"])
                and w["github"]["run_id"] == str(self._doc["run_id"])
                and w["github"]["run_attempt"] == "1"
            )
            operation = AdmittedOperation(
                w["github"]["repository_id"],
                w["github"]["run_id"],
                "1",
                w["window_id"],
                "issue",
                None,
                None,
                c["lease_id"],
                c["fingerprint"],
                w["target"]["ref"],
                packet["capture"]["plan_id"],
                packet["capture"]["plan_digest"],
                w["purpose"],
                w["target"]["operation"],
                w["plan_inputs"]["execution_plan_digest"],
                c["certificate_digest"],
                c["ca_fingerprint"],
            )
            result.append((case, w, operation))
        a, b = result
        _require(
            a[1]["github"] == b[1]["github"]
            and _utc(a[1]["expires_at"]) <= _utc(b[1]["not_before"])
        )
        for key in ("lease_id", "fingerprint", "certificate_digest"):
            _require(a[1]["controller"][key] != b[1]["controller"][key])
        _require(
            a[1]["window_id"] != b[1]["window_id"]
            and a[2].plan_id != b[2].plan_id
            and a[0]["command_id"] != b[0]["command_id"]
        )
        return result

    def install_controller_certificates(self) -> None:
        try:
            self._phase("certificates", self._bounds.provisioning_end)
            ca_bytes = _protected(_LIFECYCLE / "ca.pub")
            _require(_hash(ca_bytes) == self._doc["ca_digest"])
            ca = load_ssh_public_identity(ca_bytes)
            _require(
                isinstance(ca, Ed25519PublicKey)
                and ca.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH) == ca_bytes
            )
            _require(
                not _uid_processes(
                    self._doc["collector_uid"], self._bounds.provisioning_end
                )
            )
            cases = self._collection_cases()
            for index, (case, window, operation) in enumerate(cases):
                letter = "a" if index == 0 else "b"
                cert_slot = (
                    FileSlot.A_CERTIFICATE if index == 0 else FileSlot.B_CERTIFICATE
                )
                key_slot = FileSlot.A_KEY if index == 0 else FileSlot.B_KEY
                public_slot = FileSlot.A_PUBLIC if index == 0 else FileSlot.B_PUBLIC
                _require(key_slot in self._owned and public_slot in self._owned)
                private_bytes = _read_fd(
                    self._owned[key_slot].file_fd,
                    65536,
                    uid=self._doc["collector_uid"],
                    mode=0o600,
                )
                _require(_hash(private_bytes) == self._owned[key_slot].integrity)
                private_key = load_ssh_private_key(private_bytes, password=None)
                _require(isinstance(private_key, Ed25519PrivateKey))
                private_key = cast(Ed25519PrivateKey, private_key)
                private_bytes = b""
                raw = _protected(_LIFECYCLE / ("cert-" + letter + ".pub"))
                public = load_ssh_public_identity(
                    _read_fd(self._owned[public_slot].file_fd, 65536).rstrip(b"\n")
                )
                _require(isinstance(public, Ed25519PublicKey))
                public = cast(Ed25519PublicKey, public)
                _require(
                    private_key.public_key().public_bytes(
                        Encoding.OpenSSH, PublicFormat.OpenSSH
                    )
                    == public.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
                )
                del private_key
                _checked_certificate(
                    raw,
                    public,
                    operation,
                    _utc(window["not_before"]),
                    _utc(window["expires_at"]),
                    ca_bytes,
                )
                cert_pin = _closed(case["certificate"], "path digest")
                private_pin = _closed(case["private_key"], "path digest")
                _require(
                    cert_pin
                    == {
                        "path": str(_ROSTER[cert_slot][0] / _ROSTER[cert_slot][1]),
                        "digest": _hash(raw),
                    }
                )
                _require(
                    private_pin
                    == {
                        "path": str(_ROSTER[key_slot][0] / _ROSTER[key_slot][1]),
                        "digest": _digest(self._owned[key_slot].integrity),
                    }
                )
                self._create_file(cert_slot, raw, 0, self._doc["collector_gid"], 0o640)
            self._event(
                "certificates",
                {
                    "collection_template_digest": _hash(
                        _prelaunch(self._doc)[2]["collection_template"]
                    )
                },
                self._bounds.provisioning_end,
            )
        except Exception:
            self._fail()
            raise LifecycleRefused() from None

    def _install_original_jit_config(self, encoded: bytes) -> None:
        """Trusted root delivery seam; fixed create-only target, no pathname adoption.

        Coordinator's separately qualified installer receives these actual bytes
        privately from the off-host JIT provisioner. Bytes alone prove no job.
        """
        try:
            _require(os.getuid() == os.geteuid() == 0)
            self._phase("jit-config", self._bounds.provisioning_end)
            _require(
                type(encoded) is bytes
                and 0 < len(encoded) <= 65536
                and re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", encoded) is not None
            )
            import base64

            _require(
                base64.b64encode(base64.b64decode(encoded, validate=True)) == encoded
            )
            self._create_file(FileSlot.JIT_SOURCE, encoded, 0, 0, 0o600)
        except Exception:
            self._fail()
            raise LifecycleRefused() from None

    def _unlink_owned(self, slot: FileSlot, deadline: float) -> dict[str, object]:
        _before(deadline)
        owned = self._owned[slot]
        parent_path, name = _ROSTER[slot]
        _require(parent_path.is_absolute())
        parent = os.fstat(owned.parent_fd)
        _require(
            (parent.st_dev, parent.st_ino, parent.st_uid)
            == (owned.parent_dev, owned.parent_ino, 0)
            and not parent.st_mode & 0o022
        )
        current = os.stat(name, dir_fd=owned.parent_fd, follow_symlinks=False)
        held = os.fstat(owned.file_fd)
        # A replacement is NEVER removed; metadata anomalies cannot make success.
        _require(
            (current.st_dev, current.st_ino)
            == (owned.dev, owned.ino)
            == (held.st_dev, held.st_ino)
        )
        aliases = sum(
            (v.dev, v.ino) == (owned.dev, owned.ino) for v in self._owned.values()
        )
        valid = (
            _stable(current) == _stable(held)
            and current.st_nlink == aliases
            and (
                current.st_uid,
                current.st_gid,
                stat.S_IMODE(current.st_mode),
                current.st_size,
                current.st_mtime_ns,
                current.st_ctime_ns,
            )
            == (
                owned.uid,
                owned.gid,
                owned.mode,
                owned.size,
                owned.mtime_ns,
                owned.ctime_ns,
            )
        )
        if slot == FileSlot.COURIER_SOCKET:
            valid = valid and stat.S_ISSOCK(current.st_mode)
        else:
            _require(stat.S_ISREG(current.st_mode) and current.st_size <= 65536)
            raw = os.pread(owned.file_fd, 65537, 0)
            valid = (
                valid
                and len(raw) == current.st_size
                and _stable(os.fstat(owned.file_fd)) == _stable(held)
            )
            if owned.integrity is not None:
                valid = valid and _hash(raw) == owned.integrity
            raw = b""
        _before(deadline)
        # Held protected parent forbids a non-root replacement between this check
        # and unlink. Root-runtime isolation is an explicit qualification boundary.
        recheck = os.stat(name, dir_fd=owned.parent_fd, follow_symlinks=False)
        _require((recheck.st_dev, recheck.st_ino) == (owned.dev, owned.ino))
        if not valid:
            self._fail()
        self._cleanup_event(
            "deletion-intent",
            {
                "slot": slot,
                "device": owned.dev,
                "inode": owned.ino,
                "read_before_unlink": valid,
            },
            deadline,
        )
        _before(deadline)
        os.unlink(name, dir_fd=owned.parent_fd)
        os.fsync(owned.parent_fd)
        try:
            os.stat(name, dir_fd=owned.parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            absent = True
        else:
            absent = False
        valid = valid and absent and os.fstat(owned.file_fd).st_nlink == aliases - 1
        record = {
            "slot": slot,
            "device": owned.dev,
            "inode": owned.ino,
            "read_before_unlink": valid,
            "unlinked": True,
            "absent_after_unlink": absent,
        }
        self._cleanup_event("retired", record, deadline)
        self._retired[slot] = record
        del self._owned[slot]
        for descriptor in (owned.file_fd, owned.parent_fd):
            try:
                os.close(descriptor)
            except OSError:
                self._fail()
        self._refresh_aliases(owned.dev, owned.ino, cleanup=True)
        _before(deadline)
        if not valid:
            self._fail()
        return record

    def receive_original_job_credential(self) -> None:
        peer = None
        try:
            self._phase("courier", self._bounds.provisioning_end)
            _require(
                all(
                    slot in self._owned
                    for slot in (
                        FileSlot.A_KEY,
                        FileSlot.B_KEY,
                        FileSlot.A_CERTIFICATE,
                        FileSlot.B_CERTIFICATE,
                        FileSlot.JIT_SOURCE,
                    )
                )
            )
            public = canonical(
                {
                    "schema": "Gate0A9CourierSelection.v1",
                    "lifecycle_binding_digest": self._doc["lifecycle_binding_digest"],
                    "courier_uid": self._doc["courier_uid"],
                    "courier_gid": self._doc["courier_gid"],
                    "groups": self._doc["launcher"]["groups"],
                    "original_bounds": self._doc["original_bounds"],
                    "launcher": self._doc["launcher"],
                    "source_files": self._doc["source_files"],
                }
            )
            self._create_file(
                FileSlot.COURIER_SELECTION, public, 0, self._doc["courier_gid"], 0o640
            )
            self._jit = NativeJitInvocation(_SEAL, self)
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            self._listener = listener
            listener.settimeout(
                max(0.001, self._bounds.provisioning_end - time.monotonic())
            )
            _require(not os.path.lexists(_SOCKET))
            self._event(
                "intent",
                {"slot": FileSlot.COURIER_SOCKET},
                self._bounds.provisioning_end,
            )
            listener.bind(str(_SOCKET))
            os.chown(_SOCKET, 0, self._doc["courier_gid"], follow_symlinks=False)
            os.chmod(_SOCKET, 0o660, follow_symlinks=False)
            self._capture(FileSlot.COURIER_SOCKET, allow_empty=True)
            listener.listen(1)
            self._jit.start_once()
            _socket_before(listener, self._bounds.provisioning_end)
            peer, _ = listener.accept()
            peer.settimeout(
                max(0.001, self._bounds.provisioning_end - time.monotonic())
            )
            binding = self._jit.bind_protected_job()
            identity = self._jit.require_courier_peer(peer, binding)
            _socket_before(peer, self._bounds.provisioning_end)
            peer.sendall(_METADATA_READY)
            metadata = _courier_frame(peer, self._bounds.provisioning_end, 17408)
            report = _closed(strict_object(metadata), "schema url")
            _require(
                canonical(report) == metadata
                and report["schema"] == "Gate0A9BrokerMetadata.v1"
            )
            _require(self._jit.require_courier_peer(peer, binding) == identity)
            from vendor_cp.deployment.gate0_runner_supervisor import (
                _bind_actual_job_installation,
            )

            _bind_actual_job_installation(self, binding, report)
            self._jit.refresh_protected_job(binding)
            _require(self._jit.require_courier_peer(peer, binding) == identity)
            _socket_before(peer, self._bounds.provisioning_end)
            peer.sendall(_SECRET_READY)

            _socket_before(peer, self._bounds.provisioning_end)
            data, ancillary, flags, _ = peer.recvmsg(
                32768, socket.CMSG_SPACE(16 * struct.calcsize("i"))
            )
            _close_received_descriptors(ancillary)
            _require(
                not ancillary
                and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
                and 0 < len(data) <= 32768
                and all(32 < c < 127 for c in data)
            )
            _socket_before(peer, self._bounds.provisioning_end)
            extra, ancillary, flags, _ = peer.recvmsg(
                1, socket.CMSG_SPACE(16 * struct.calcsize("i"))
            )
            _close_received_descriptors(ancillary)
            _require(
                extra == b""
                and not ancillary
                and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
            )
            self._jit.refresh_protected_job(binding)
            _require(self._jit.require_courier_peer(peer, binding) == identity)
            self._create_file(FileSlot.OIDC_SOURCE, data, 0, 0, 0o600)
            data = b""
            _before(self._bounds.provisioning_end)
            self._event(
                "credential",
                {"slot": FileSlot.OIDC_SOURCE, "peer_start": identity[1]},
                self._bounds.provisioning_end,
            )
            _socket_before(peer, self._bounds.provisioning_end)
            peer.sendall(b"\x01")
            peer.close()
            peer = None
            listener.close()
            self._listener = None
            self._unlink_owned(FileSlot.COURIER_SOCKET, self._bounds.provisioning_end)
        except Exception:
            self._fail()
            if peer is not None:
                try:
                    peer.setblocking(False)
                    peer.send(b"\x00")
                except OSError:  # noqa: S110 -- no private error prose
                    self._fail()
            if self._jit is not None:
                try:
                    self._jit.stop_and_observe()
                except Exception:  # noqa: S110 -- retirement remains unobserved
                    self._fail()
            raise LifecycleRefused() from None
        finally:
            if peer is not None:
                peer.close()
            if self._listener is not None:
                self._listener.close()
                self._listener = None

    def retire_owned_files(
        self, manager: NativeSystemManager, retirement_fact: CollectorRetirementFact
    ) -> bytes:
        """Concrete same-manager handoff; source success is not required for safety."""
        reasons: list[str] = []
        try:
            self._phase("retire", self._bounds.finalization_end)
            _require(
                type(manager) is NativeSystemManager
                and manager.owns_retirement(retirement_fact)
            )
            process_digest = _digest(retirement_fact.observation_digest)
            _require(
                manager.installation.campaign == self._doc["campaign_digest"]
                and manager.installation.uid == self._doc["collector_uid"]
            )
            _require(
                not _uid_processes(
                    self._doc["collector_uid"], self._bounds.finalization_end
                )
            )
            try:
                self._capture_partial_stage_files()
            except Exception:
                self._fail()
                reasons.append("stage_recovery_failed")
            if self._listener is not None:
                try:
                    self._listener.close()
                except OSError:
                    self._fail()
                    reasons.append("listener_close_failed")
                self._listener = None
            # The actual admitted courier/collector chain proves JIT credential
            # delivery has completed. Its root source can retire; mounted/config
            # copies remain the later JIT/allocation owners' responsibility.
            for slot in tuple(self._owned):
                try:
                    self._unlink_owned(slot, self._bounds.finalization_end)
                except Exception:
                    self._fail()
                    reasons.append("owned_slot_retirement_failed")
            _require(
                not self._failed
                and not reasons
                and not self._unknown_intents
                and not self._owned
            )
            _before(self._bounds.finalization_end)
            return canonical(
                {
                    "schema": "Gate0A9OwnedFilesRetirement.v1",
                    "lifecycle_binding_digest": self._doc["lifecycle_binding_digest"],
                    "campaign_digest": self._doc["campaign_digest"],
                    "boot_id": self._bounds.boot_id,
                    "original_deadline_microseconds": math.floor(
                        self._bounds.finalization_end * 1000000
                    ),
                    "process_retirement_observation_digest": process_digest,
                    "files": [self._retired[s] for s in sorted(self._retired)],
                    "result": "owned_files_retired",
                }
            )
        except Exception:
            self._fail()
            return canonical(
                {
                    "schema": "Gate0A9OwnedFilesRetirementFailure.v1",
                    "lifecycle_binding_digest": self._doc["lifecycle_binding_digest"],
                    "campaign_digest": self._doc["campaign_digest"],
                    "boot_id": self._bounds.boot_id,
                    "files": [self._retired[s] for s in sorted(self._retired)],
                    "reasons": sorted(set(reasons or ["retirement_unobserved"])),
                    "result": "owned_files_retirement_failed",
                }
            )

    def _retire_owned_jit_invocation(self) -> bytes:
        if self._journal is None:
            self._open_journal(fresh=False)
        if self._jit is None:
            self._jit = NativeJitInvocation(_SEAL, self)
            self._jit._restore_owned_invocation()
        fact = self._jit.stop_and_observe()
        _require(self._jit.owns_retirement(fact))
        return canonical(fact.document())

    def close(self) -> None:
        if getattr(self, "_close_started", False):
            _require(not self._close_failed)
            return
        self._close_started = True
        self._close_failed = False
        owned, self._owned = tuple(self._owned.values()), {}
        handles = self._listener, self._jit
        self._listener = self._jit = None
        journal, self._journal = self._journal, None
        self._journal_unavailable = True
        # Detach the complete ownership set before a fallible native call.
        descriptors = dict.fromkeys(
            fd for item in owned for fd in (item.file_fd, item.parent_fd)
        )
        for fd in descriptors:
            try:
                os.close(fd)
            except BaseException:
                self._close_failed = True
        for handle in handles:
            if handle is not None:
                try:
                    handle.close()
                except BaseException:
                    self._close_failed = True
        if journal is not None and journal.fd not in descriptors:
            try:
                os.close(journal.fd)
            except BaseException:
                self._close_failed = True
        if self._close_failed:
            self._failed = True
            # Existing owned-journal provenance permits the same fixed marker
            # write. It cannot authorize a stale FD or extend original bounds.
            if journal is not None:
                try:
                    self._persist_failure_marker()
                except BaseException:
                    self._unknown_intents.add("failure_persistence")
        _require(not self._close_failed)


def _close_received_descriptors(ancillary: list[tuple[int, int, bytes]]) -> None:
    import array

    for level, kind, value in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            descriptors: array.array[int] = array.array("i")
            descriptors.frombytes(
                value[: len(value) - len(value) % descriptors.itemsize]
            )
            for fd in descriptors:
                os.close(fd)


def _courier_frame(channel: socket.socket, deadline: float, maximum: int) -> bytes:
    _socket_before(channel, deadline)
    data, ancillary, flags, _ = channel.recvmsg(
        maximum, socket.CMSG_SPACE(16 * struct.calcsize("i"))
    )
    _close_received_descriptors(ancillary)
    _require(
        not ancillary
        and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
        and 0 < len(data) <= maximum
    )
    _before(deadline)
    return data


_JIT_UNIT = "dotmac-gate0-a9-jit.service"
_JIT_GROUP = "/system.slice/" + _JIT_UNIT
_RUNNER = Path("/run/dotmac-gate0-jit/runner/bin/Runner.Listener")
_RUNNER_ROOT = Path("/run/dotmac-gate0-jit/runner")
_JIT_PROPERTIES = (
    "LoadState",
    "FragmentPath",
    "DropInPaths",
    "Type",
    "ExitType",
    "Restart",
    "RemainAfterExit",
    "KillMode",
    "KillSignal",
    "FinalKillSignal",
    "SendSIGKILL",
    "Delegate",
    "NoNewPrivileges",
    "AmbientCapabilities",
    "CapabilityBoundingSet",
    "User",
    "Group",
    "ExecStart",
    "ExecStop",
    "ExecStopPost",
    "WorkingDirectory",
    "LoadCredential",
    "Environment",
    "StandardOutput",
    "StandardError",
    "MainPID",
    "InvocationID",
    "ControlGroup",
    "ActiveState",
    "SubState",
    "Result",
    "ExecMainCode",
    "ExecMainStatus",
    "BindReadOnlyPaths",
)


class InstalledJitBinding:
    """Sealed live invocation/job association; no JSON/dataclass constructor."""

    __slots__ = ("owner", "facts", "reader", "invocation", "pid", "start")

    def __init__(
        self,
        seal: object,
        owner: NativeJitInvocation,
        reader: InstalledGate0GitHubReads,
        facts: ProducerFacts,
    ) -> None:
        _require(seal is _SEAL and reader.owns_facts(facts))
        self.owner, self.reader, self.facts = owner, reader, facts
        self.invocation, self.pid, self.start = owner.invocation, owner.pid, owner.start


class _JitRetirement:
    __slots__ = ("owner", "observation_digest", "_document")

    def __init__(
        self, seal: object, owner: NativeJitInvocation, document: dict[str, object]
    ) -> None:
        _require(seal is _SEAL)
        self.owner, self._document = owner, document
        self.observation_digest = _hash(canonical(document))

    def document(self) -> dict[str, object]:
        return dict(self._document)


class NativeJitInvocation:
    """Finite systemd adapter for one literal JIT unit; no callable factory seam."""

    def __init__(self, seal: object, lifecycle: InstalledA9Lifecycle) -> None:
        _require(seal is _SEAL and type(lifecycle) is InstalledA9Lifecycle)
        self.lifecycle, self.bounds = lifecycle, lifecycle._bounds
        self.selection = self._selection(lifecycle._doc["launcher"])
        self.invocation: str | None = None
        self.pid: int | None = None
        self.start: str | None = None
        self._events, self._pidfd = -1, -1
        self._binding: InstalledJitBinding | None = None
        self._peer_chain: tuple[tuple[int, int, str, bytes], ...] | None = None
        self._chain_pidfds: dict[int, tuple[str, int]] = {}
        self._retirement: _JitRetirement | None = None
        self._started, self._closed = False, False
        self._close_failed = False

    @staticmethod
    def _selection(value: object) -> JSONRecord:
        value = _closed(
            value,
            "schema runner_id runner_name runner_group_id owner_id workflow_id "
            "job_id job_name environment_id source_revision cli interpreter "
            "systemctl manager runner_binary runner_tree_digest unit_digest "
            "groups native_receipt_digest",
        )
        _require(value["schema"] == "Gate0A9JitLauncherSelection.v1")
        for field_name in (
            "runner_id",
            "runner_group_id",
            "owner_id",
            "workflow_id",
            "job_id",
            "environment_id",
        ):
            _positive(value[field_name])
        for field_name in ("runner_name", "job_name"):
            _require(
                type(value[field_name]) is str
                and 0 < len(value[field_name]) <= 512
                and all(32 <= ord(c) < 127 for c in value[field_name])
            )
        _require(
            type(value["source_revision"]) is str
            and re.fullmatch(r"[0-9a-f]{40}", value["source_revision"]) is not None
        )
        for field_name in (
            "runner_tree_digest",
            "unit_digest",
            "native_receipt_digest",
        ):
            _digest(value[field_name])
        for name in ("cli", "interpreter", "systemctl", "manager", "runner_binary"):
            pin = _closed(value[name], "path digest")
            _digest(pin["digest"])
            _require(
                type(pin["path"]) is str
                and Path(pin["path"]).is_absolute()
                and ".." not in Path(pin["path"]).parts
            )
        _require(
            value["systemctl"]["path"] == "/usr/bin/systemctl"
            and value["runner_binary"]["path"] == str(_RUNNER)
        )
        groups = value["groups"]
        _require(
            type(groups) is list
            and len(groups) <= 32
            and all(type(v) is int and v >= 0 for v in groups)
            and len(set(groups)) == len(groups)
        )
        return value

    def _qualify_installed(self) -> None:
        deadline = self.bounds.provisioning_end
        _before(deadline)
        for name in ("cli", "interpreter", "systemctl", "manager"):
            pin = self.selection[name]
            _require(
                _hash(_protected(Path(pin["path"]), 32 * 1024 * 1024)) == pin["digest"]
            )
        _require(os.readlink("/proc/1/exe") == self.selection["manager"]["path"])
        _require(
            _hash(_protected(Path("/run/systemd/system") / _JIT_UNIT))
            == self.selection["unit_digest"]
        )
        raw = _protected(_ROOT / "lifecycle-native.json", mode=0o600)
        _require(_hash(raw) == self.selection["native_receipt_digest"])
        native = _closed(
            strict_object(raw),
            "schema boot_id kernel_release runner_tree_digest systemd_version "
            "supplier_observation supplier_review",
        )
        _require(
            canonical(native) == raw and native["schema"] == "Gate0A9LifecycleNative.v2"
        )
        self._supplier_policy()
        _require(
            native["boot_id"] == self.bounds.boot_id
            and native["kernel_release"] == os.uname().release
            and native["runner_tree_digest"] == self.selection["runner_tree_digest"]
        )
        values = self._call(("show", "--all", "--property=Version"), deadline)
        _require(
            values
            == ("Version=" + cast(str, native["systemd_version"]) + "\n").encode(
                "ascii"
            )
        )
        _qualify_runner_mounts(
            self.selection["runner_binary"]["digest"],
            self.lifecycle._doc["courier_uid"],
        )
        _before(deadline)

    def _supplier_policy(self) -> JSONRecord:
        """Existing root-native custody, never a newly invented signature authority."""
        from vendor_cp.deployment.gate0_runner_tokens import (
            _SUPPLIER_AMENDMENT,
            _SUPPLIER_METHOD,
            _SUPPLIER_SOURCE,
        )

        _, prelaunch, inputs = _prelaunch(self.lifecycle._doc)
        policy = _closed(
            strict_object(inputs["broker_policy"]),
            "schema method amendment_digest supplier_commit origins profile",
        )
        _require(
            policy["schema"] == "Gate0A9BrokerPolicy.v1"
            and policy["method"] == _SUPPLIER_METHOD
            and policy["amendment_digest"] == _SUPPLIER_AMENDMENT
            and policy["supplier_commit"] == _SUPPLIER_SOURCE
        )
        profile = _closed(
            policy["profile"],
            "worker_binary shell_binary script_template script_directory "
            "workflow_source_digest worker_pipe_handle_format",
        )
        _require(profile["worker_pipe_handle_format"] == "unix-decimal-fd.v1")
        for name in ("worker_binary", "shell_binary", "script_template"):
            pin = _closed(profile[name], "path digest")
            path = Path(pin["path"])
            _require(
                path.is_absolute()
                and ".." not in path.parts
                and _hash(_protected(path, 32 * 1024 * 1024)) == _digest(pin["digest"])
            )
        _require(
            profile["worker_binary"]["path"]
            == "/opt/dotmac-gate0-jit/bin/Runner.Worker"
            and profile["shell_binary"]["path"] == "/usr/bin/bash"
        )
        directory = Path(profile["script_directory"])
        _require(
            directory.is_absolute()
            and ".." not in directory.parts
            and directory.is_relative_to(Path("/run/dotmac-gate0-jit"))
        )
        _digest(profile["workflow_source_digest"])
        native_raw = _protected(_ROOT / "lifecycle-native.json", mode=0o600)
        _require(_hash(native_raw) == self.selection["native_receipt_digest"])
        native = _closed(
            strict_object(native_raw),
            "schema boot_id kernel_release runner_tree_digest systemd_version "
            "supplier_observation supplier_review",
        )
        _require(
            canonical(native) == native_raw
            and native["schema"] == "Gate0A9LifecycleNative.v2"
        )
        records = {}
        for name in ("supplier_observation", "supplier_review"):
            pin = _closed(native[name], "path digest")
            path = Path(pin["path"])
            _require(path == _ROOT / (name.replace("_", "-") + ".json"))
            content = _protected(path, mode=0o600)
            _require(_hash(content) == _digest(pin["digest"]))
            records[name] = _closed(
                strict_object(content),
                "schema method amendment_digest supplier_commit "
                "prelaunch_selection_digest "
                "broker_policy_digest profile_digest workflow_source_digest evidence",
            )
            _require(canonical(records[name]) == content)
        observation, review = (
            records["supplier_observation"],
            records["supplier_review"],
        )
        for name, record in records.items():
            _require(
                record["schema"]
                == (
                    "Gate0A9SupplierNativeObservation.v1"
                    if name == "supplier_observation"
                    else "Gate0A9SupplierNativeReview.v1"
                )
            )
            for key, expected in (
                ("method", _SUPPLIER_METHOD),
                ("amendment_digest", _SUPPLIER_AMENDMENT),
                ("supplier_commit", _SUPPLIER_SOURCE),
                ("prelaunch_selection_digest", _prelaunch_selection_digest(prelaunch)),
                ("broker_policy_digest", _hash(inputs["broker_policy"])),
                ("profile_digest", _hash(canonical(profile))),
                ("workflow_source_digest", profile["workflow_source_digest"]),
            ):
                _require(record[key] == expected)
        evidence_names = (
            "listener_clean_inheritance worker_clean_inheritance "
            "all_workflow_environment_scopes "
            "startup_hooks preceding_writes missing_supplier_injection shell_survival "
            "executed_script_identity worker_pipe_handles metadata_first_ipc"
        )
        evidence = _closed(observation["evidence"], evidence_names)
        # Actual external native observation artifacts are mandatory pins, not
        # qualified:true/asserted capability values produced from expectations.
        for pin_value in evidence.values():
            pin = _closed(pin_value, "path digest")
            path = Path(pin["path"])
            _require(path.is_absolute() and ".." not in path.parts)
            _require(_hash(_protected(path, 8 * 1024 * 1024)) == _digest(pin["digest"]))
        reviewed = _closed(
            review["evidence"], "supplier_observation_digest reviewed_evidence"
        )
        _require(
            reviewed["supplier_observation_digest"]
            == native["supplier_observation"]["digest"]
            and reviewed["reviewed_evidence"]
            == {k: v["digest"] for k, v in evidence.items()}
        )
        _before(self.bounds.provisioning_end)
        return policy

    def _static_runtime_identity(self) -> JSONRecord:
        native_raw = _protected(_ROOT / "lifecycle-native.json", mode=0o600)
        native = strict_object(native_raw)
        return dict(
            boot_id=self.bounds.boot_id,
            kernel_release=os.uname().release,
            runner_tree_digest=self.selection["runner_tree_digest"],
            manager_identity=dict(
                executable_digest=self.selection["manager"]["digest"],
                version=native["systemd_version"],
                kernel_release=os.uname().release,
                boot_id=self.bounds.boot_id,
            ),
            lifecycle_source_digest=self.lifecycle._doc["source_files"][
                "gate0_runner_lifecycle"
            ],
            supervisor_source_digest=_hash(
                _protected(
                    Path(__file__).with_name("gate0_runner_supervisor.py"), 1024 * 1024
                )
            ),
            interpreter_digest=self.selection["interpreter"]["digest"],
            lifecycle_native_digest=_hash(native_raw),
            supplier_observation_digest=native["supplier_observation"]["digest"],
            supplier_review_digest=native["supplier_review"]["digest"],
        )

    def _retain_chain_process(self, pid: int, start: str) -> None:
        _require(self._started and not self._closed and hasattr(os, "pidfd_open"))
        existing = self._chain_pidfds.get(pid)
        if existing is not None:
            _require(
                existing[0] == start and not select.select([existing[1]], [], [], 0)[0]
            )
            return
        _require(len(self._chain_pidfds) < 3)
        fd = os.pidfd_open(pid, 0)
        try:
            _require(
                measure_handoff_process(pid)[2] == start
                and not select.select([fd], [], [], 0)[0]
            )
            self._chain_pidfds[pid] = (start, fd)
            fd = -1
        finally:
            if fd >= 0:
                try:
                    os.close(fd)
                except BaseException:
                    self._close_failed = True
                    raise LifecycleRefused() from None

    def _measure_supplier_chain(
        self, peer_pid: int
    ) -> tuple[tuple[int, int, str, bytes], ...]:
        original = set(self._chain_pidfds)
        try:
            return self._measure_supplier_chain_once(peer_pid)
        except BaseException:
            # Partial first measurement relinquishes only descriptors acquired
            # by that measurement. Refresh never discards prior retained proof.
            owned = [
                self._chain_pidfds.pop(pid)[1]
                for pid in set(self._chain_pidfds) - original
            ]
            for fd in owned:
                try:
                    os.close(fd)
                except BaseException:
                    self._close_failed = True
            if self._close_failed:
                raise LifecycleRefused() from None
            raise

    def _measure_supplier_chain_once(
        self, peer_pid: int
    ) -> tuple[tuple[int, int, str, bytes], ...]:
        """Finite live ancestry. Native exclusion evidence owns rewrite resistance.

        Re-reading path/argv is a current measurement, not proof of which bytes
        executed earlier; actual executed-script/native shell-survival evidence
        is separately required by the fixed root-native owner.
        """
        policy = self._supplier_policy()
        profile = policy["profile"]
        uid = self.lifecycle._doc["courier_uid"]
        current = peer_pid
        measured = []
        script_identity = None
        for index in range(4):
            _before(self.bounds.provisioning_end)
            parent, actual_uid, start = measure_handoff_process(current)
            _require(actual_uid == uid)
            command = _proc(Path(f"/proc/{current}/cmdline"), 16384)
            args = command.split(b"\0")
            _require(args[-1] == b"" and all(args[:-1]))
            expected_executable = (
                self.selection["interpreter"]["path"]
                if index == 0
                else profile["shell_binary"]["path"]
                if index == 1
                else str(_RUNNER_ROOT / "bin/Runner.Worker")
                if index == 2
                else self.selection["runner_binary"]["path"]
            )
            _require(os.readlink(f"/proc/{current}/exe") == expected_executable)
            executable_pin = (
                self.selection["interpreter"]
                if index == 0
                else profile["shell_binary"]
                if index == 1
                else profile["worker_binary"]
                if index == 2
                else self.selection["runner_binary"]
            )
            executable_fd = os.open(f"/proc/{current}/exe", os.O_RDONLY | os.O_NONBLOCK)
            try:
                actual_file = os.fstat(executable_fd)
                expected_file = os.stat(executable_pin["path"], follow_symlinks=False)
                _require(
                    (actual_file.st_dev, actual_file.st_ino)
                    == (expected_file.st_dev, expected_file.st_ino)
                    and _hash(_read_fd(executable_fd, 32 * 1024 * 1024, uid=0))
                    == executable_pin["digest"]
                )
            finally:
                os.close(executable_fd)
            status = _proc(Path(f"/proc/{current}/status"))
            groups = [
                line.split()[1:]
                for line in status.splitlines()
                if line.startswith(b"Groups:")
            ]
            uids = [
                line.split()[1:]
                for line in status.splitlines()
                if line.startswith(b"Uid:")
            ]
            gids = [
                line.split()[1:]
                for line in status.splitlines()
                if line.startswith(b"Gid:")
            ]
            _require(
                len(groups) == len(uids) == len(gids) == 1
                and {int(v) for v in groups[0]} == set(self.selection["groups"])
                and {int(v) for v in uids[0]} == {uid}
                and {int(v) for v in gids[0]} == {self.lifecycle._doc["courier_gid"]}
                and _proc(Path(f"/proc/{current}/cgroup"))
                == ("0::" + _JIT_GROUP + "\n").encode()
            )
            if index == 1:
                _require(
                    args[:-2]
                    == [
                        b"/bin/bash",
                        b"--noprofile",
                        b"--norc",
                        b"-p",
                        b"-e",
                        b"-o",
                        b"pipefail",
                    ]
                )
                script = Path(args[-2].decode("ascii"))
                _require(
                    script.parent == Path(profile["script_directory"])
                    and str(script) == args[-2].decode("ascii")
                    and ".." not in script.parts
                    and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}\.sh", script.name)
                    is not None
                )
                script_identity = self._measure_script(
                    script, profile["script_template"]["digest"]
                )
            elif index == 2:
                _require(
                    len(args) == 5
                    and args[0] == str(_RUNNER_ROOT / "bin/Runner.Worker").encode()
                    and args[1] == b"spawnclient"
                    and args[2] != args[3]
                )
                for handle in args[2:4]:
                    _require(
                        re.fullmatch(rb"[1-9][0-9]{0,9}", handle) is not None
                        and 2 < int(handle) <= 2147483647
                    )
                    target = os.readlink(f"/proc/{current}/fd/{int(handle)}")
                    _require(re.fullmatch(r"pipe:\[[0-9]+\]", target) is not None)
            elif index == 3:
                _require(
                    (current, start) == (self.pid, self.start)
                    and args
                    == [
                        str(_RUNNER).encode(),
                        b"run",
                        b"--startuptype",
                        b"service",
                        b"",
                    ]
                )
            _require(measure_handoff_process(current) == (parent, uid, start))
            if index < 3:
                self._retain_chain_process(current, start)
            measured.append((current, parent, start, command))
            current = parent
        for pid, parent, start, command in measured:
            _require(
                measure_handoff_process(pid) == (parent, uid, start)
                and _proc(Path(f"/proc/{pid}/cmdline"), 16384) == command
            )
        _require(script_identity is not None)
        actual_script = Path(measured[1][3].split(b"\0")[-2].decode("ascii"))
        _require(
            self._measure_script(actual_script, profile["script_template"]["digest"])
            == script_identity
        )
        self._require_current()
        return tuple(measured)

    def _measure_script(self, path: Path, digest: str) -> tuple[int, ...]:
        # Generated script directories are job-owned; walk held no-follow FDs
        # below the code-fixed job root, permitting only root/the isolated UID.
        root = Path("/run/dotmac-gate0-jit")
        _require(path.is_relative_to(root))
        parent = _directory(root)
        fd = -1
        try:
            for part in path.relative_to(root).parts[:-1]:
                child = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=parent,
                )
                os.close(parent)
                parent = child
                info = os.fstat(parent)
                _require(
                    info.st_uid in (0, self.lifecycle._doc["courier_uid"])
                    and not info.st_mode & 0o022
                )
            fd = os.open(
                path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent
            )
            info = os.fstat(fd)
            _require(
                info.st_uid == self.lifecycle._doc["courier_uid"]
                and info.st_nlink == 1
                and not info.st_mode & 0o022
            )
            raw = _read_fd(fd, 65536, uid=self.lifecycle._doc["courier_uid"])
            _require(
                _hash(raw) == _digest(digest)
                and _stable(os.fstat(fd)) == _stable(info)
                and _stable(os.stat(path.name, dir_fd=parent, follow_symlinks=False))
                == _stable(info)
            )
            _before(self.bounds.provisioning_end)
            return _stable(info)
        finally:
            if fd >= 0:
                os.close(fd)
            os.close(parent)

    def _call(self, arguments: tuple[str, ...], original: float) -> bytes:
        show = ("show", "--all", "--property=" + ",".join(_JIT_PROPERTIES), _JIT_UNIT)
        _require(
            arguments
            in (
                show,
                ("show", "--all", "--property=Version"),
                ("start", "--no-block", _JIT_UNIT),
                ("stop", "--no-block", _JIT_UNIT),
            )
        )
        deadline = min(original, time.monotonic() + 2)
        work_end = deadline - 0.1
        _before(work_end)
        process = subprocess.Popen(  # noqa: S603 -- finite pinned systemctl vectors
            (self.selection["systemctl"]["path"], "--system", "--no-pager", *arguments),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "SYSTEMD_PAGER": "cat"},
            close_fds=True,
            start_new_session=True,
        )
        output = bytearray()
        failed = False
        try:
            _require(process.stdout is not None)
            fd = cast(BinaryIO, process.stdout).fileno()
            os.set_blocking(fd, False)
            while True:
                _before(work_end)
                _require(
                    bool(select.select([fd], [], [], work_end - time.monotonic())[0])
                )
                chunk = os.read(fd, 8192)
                if not chunk:
                    break
                output.extend(chunk)
                _require(len(output) <= 262144)
            _require(process.wait(timeout=max(0, work_end - time.monotonic())) == 0)
            _before(work_end)
        except BaseException:
            failed = True
        finally:
            running = False
            try:
                running = process.poll() is None
            except BaseException:
                failed = True
            # Only a successful unreaped-state observation permits signalling.
            # An unknown state must not target a PID which may have been reaped.
            if running:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except BaseException:
                    failed = True
            try:
                process.wait(timeout=max(0, deadline - time.monotonic()))
            except BaseException:
                failed = True
            try:
                if process.stdout is not None:
                    process.stdout.close()
            except BaseException:
                failed = True
            try:
                _before(deadline)
            except BaseException:
                failed = True
        _require(not failed)
        return bytes(output)

    def _show(self, deadline: float) -> dict[str, str]:
        raw = self._call(
            ("show", "--all", "--property=" + ",".join(_JIT_PROPERTIES), _JIT_UNIT),
            deadline,
        )
        values = {}
        for line in raw.decode("ascii").splitlines():
            key, separator, value = line.partition("=")
            _require(separator == "=" and key in _JIT_PROPERTIES and key not in values)
            values[key] = value
        _require(set(values) == set(_JIT_PROPERTIES))
        return values

    def _unit_predicates(self, values: dict[str, str]) -> None:
        expected = {
            "LoadState": "loaded",
            "FragmentPath": "/run/systemd/system/" + _JIT_UNIT,
            "DropInPaths": "",
            "Type": "exec",
            "ExitType": "main",
            "Restart": "no",
            "RemainAfterExit": "no",
            "KillMode": "control-group",
            "KillSignal": "9",
            "FinalKillSignal": "9",
            "SendSIGKILL": "yes",
            "Delegate": "no",
            "NoNewPrivileges": "yes",
            "AmbientCapabilities": "",
            "CapabilityBoundingSet": "",
            "User": str(self.lifecycle._doc["courier_uid"]),
            "Group": str(self.lifecycle._doc["courier_gid"]),
            "ExecStop": "",
            "ExecStopPost": "",
            "WorkingDirectory": str(_RUNNER_ROOT),
            "LoadCredential": "jit-config:/run/dotmac-gate0-collector/jit-config",
            "StandardOutput": "null",
            "StandardError": "null",
            "BindReadOnlyPaths": (
                "/opt/dotmac-gate0-jit/bin:/run/dotmac-gate0-jit/runner/bin "
                "/opt/dotmac-gate0-jit/externals:/run/dotmac-gate0-jit/runner/externals"
            ),
        }
        _require(all(values[key] == value for key, value in expected.items()))
        import shlex

        environment = dict(
            part.split("=", 1) for part in shlex.split(values["Environment"])
        )
        _require(
            environment
            == {
                "PATH": "/usr/bin:/bin",
                "LC_ALL": "C",
                "HOME": "/run/dotmac-gate0-jit/home",
            }
        )
        cli = self.selection["cli"]["path"]
        _require(
            values["ExecStart"].startswith(
                "{ path="
                + cli
                + " ; argv[]="
                + cli
                + " gate0 jit-runner-credential ; ignore_errors=no ;"
            )
            and values["ExecStart"].count("path=") == 1
        )

    def _measure_main(
        self, values: dict[str, str], deadline: float
    ) -> tuple[int, str, str]:
        self._unit_predicates(values)
        _require(
            values["ActiveState"] == "active"
            and values["SubState"] == "running"
            and values["ControlGroup"] == _JIT_GROUP
            and re.fullmatch(r"[0-9a-f]{32}", values["InvocationID"]) is not None
            and re.fullmatch(r"[1-9][0-9]*", values["MainPID"]) is not None
        )
        pid = int(values["MainPID"])
        _, uid, start = measure_handoff_process(pid)
        _require(
            uid == self.lifecycle._doc["courier_uid"]
            and os.readlink(f"/proc/{pid}/exe") == str(_RUNNER)
        )
        status = _proc(Path(f"/proc/{pid}/status"))
        groups = [
            line.split()[1:]
            for line in status.splitlines()
            if line.startswith(b"Groups:")
        ]
        gids = [
            line.split()[1:] for line in status.splitlines() if line.startswith(b"Gid:")
        ]
        _require(
            len(groups) == len(gids) == 1
            and {int(v) for v in groups[0]} == set(self.selection["groups"])
            and {int(v) for v in gids[0]} == {self.lifecycle._doc["courier_gid"]}
        )
        _require(
            _proc(Path(f"/proc/{pid}/cgroup")) == ("0::" + _JIT_GROUP + "\n").encode()
        )
        for member in _uid_processes(uid, deadline):
            _require(
                _proc(Path(f"/proc/{member}/cgroup"))
                == ("0::" + _JIT_GROUP + "\n").encode()
            )
        _before(deadline)
        return pid, start, values["InvocationID"]

    def start_once(self) -> None:
        try:
            self._start_once()
        except Exception:
            self.lifecycle._fail()
            try:
                if self.lifecycle._jit_record is not None:
                    self.stop_and_observe()
                elif self._started:
                    self._stop_failed_start()
            except Exception:
                self.lifecycle._fail()
            raise LifecycleRefused() from None

    def _stop_failed_start(self) -> None:
        """Best effort for captured ID only; intent alone never adopts a unit."""
        self.lifecycle._fail()
        values = self._show(self.bounds.finalization_end)
        self._unit_predicates(values)
        _require(
            self.invocation is not None and values["InvocationID"] == self.invocation
        )
        # Fresh exact match precedes the fixed stop. External exclusive unit
        # control is required; this finite manager protocol has no CAS-stop.
        self._call(("stop", "--no-block", _JIT_UNIT), self.bounds.finalization_end)
        for _ in range(32):
            values = self._show(self.bounds.finalization_end)
            self._unit_predicates(values)
            _require(values["InvocationID"] == self.invocation)
            if values["MainPID"] == "0" and values["ActiveState"] in (
                "inactive",
                "failed",
            ):
                _require(self._show(self.bounds.finalization_end) == values)
                return
        raise LifecycleRefused()

    def _start_once(self) -> None:
        _require(not self._started and not self._closed)
        self.lifecycle._phase("jit", self.bounds.provisioning_end)
        self._started = True
        self._qualify_installed()
        before = self._show(self.bounds.provisioning_end)
        self._unit_predicates(before)
        _require(
            before["ActiveState"] == "inactive"
            and before["SubState"] == "dead"
            and before["MainPID"] == "0"
            and before["InvocationID"] == ""
        )
        _require(
            not _uid_processes(
                self.lifecycle._doc["courier_uid"], self.bounds.provisioning_end
            )
        )
        self.lifecycle._event(
            "jit-start-intent", {"unit": _JIT_UNIT}, self.bounds.provisioning_end
        )
        self.lifecycle._jit_start_intent = True
        self._call(("start", "--no-block", _JIT_UNIT), self.bounds.provisioning_end)
        for _ in range(32):
            _before(self.bounds.provisioning_end)
            values = self._show(self.bounds.provisioning_end)
            self._unit_predicates(values)
            observed = values["InvocationID"]
            if observed:
                _require(re.fullmatch(r"[0-9a-f]{32}", observed) is not None)
                if self.invocation is None:
                    self.invocation = observed  # retained even if journal/handles fail
                    self.lifecycle._jit_invocation = observed
                    self.lifecycle._event(
                        "jit-invocation",
                        {"invocation": observed},
                        self.bounds.provisioning_end,
                    )
                else:
                    _require(observed == self.invocation)
            if values["ActiveState"] == "active" and values["MainPID"] != "0":
                executable = os.readlink("/proc/" + values["MainPID"] + "/exe")
                if executable == self.selection["interpreter"]["path"]:
                    self._unit_predicates(values)
                    continue
                try:
                    measured = self._measure_main(values, self.bounds.provisioning_end)
                except FileNotFoundError:
                    continue
                self.pid, self.start, self.invocation = measured
                self._events = os.open(
                    "/sys/fs/cgroup" + _JIT_GROUP + "/cgroup.events",
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                )
                _require(hasattr(os, "pidfd_open"))
                self._pidfd = os.pidfd_open(self.pid, 0)
                _require(
                    self._measure_main(
                        self._show(self.bounds.provisioning_end),
                        self.bounds.provisioning_end,
                    )
                    == measured
                )
                events = os.fstat(self._events)
                self.lifecycle._jit_record = {
                    "pid": self.pid,
                    "start": self.start,
                    "invocation": self.invocation,
                    "cgroup": _JIT_GROUP,
                    "events_device": events.st_dev,
                    "events_inode": events.st_ino,
                }
                self.lifecycle._event(
                    "jit", self.lifecycle._jit_record, self.bounds.provisioning_end
                )
                return
            _require(values["ActiveState"] in ("activating", "active"))
        raise LifecycleRefused()

    def _require_current(self) -> None:
        _require(self._started and not self._closed and self.invocation is not None)
        _require(
            self._measure_main(
                self._show(self.bounds.provisioning_end), self.bounds.provisioning_end
            )
            == (self.pid, self.start, self.invocation)
        )
        _require(not select.select([self._pidfd], [], [], 0)[0])

    def _current_protected_job(self) -> tuple[InstalledGate0GitHubReads, ProducerFacts]:
        self._require_current()
        from vendor_cp.deployment.gate0_e_github import InstalledGate0GitHubReads

        reader = InstalledGate0GitHubReads.from_installed()
        facts = reader.protected_job_snapshot(deadline=self.bounds.provisioning_end)
        _require(
            reader.owns_facts(facts) and facts.stage.value == "PROTECTED_JOB_STARTED"
        )
        s, d = self.selection, self.lifecycle._doc
        for value, expected in (
            (facts.repository_id, d["repository_id"]),
            (facts.owner_id, s["owner_id"]),
            (facts.run_id, d["run_id"]),
            (facts.attempt, 1),
            (facts.workflow_id, s["workflow_id"]),
            (facts.head_sha, s["source_revision"]),
            (facts.environment_id, s["environment_id"]),
        ):
            _require(type(value) is type(expected) and value == expected)
        jobs = [
            job
            for job in facts.jobs
            if job.id == s["job_id"] and job.name == s["job_name"]
        ]
        _require(len(jobs) == 1)
        job = jobs[0]
        _require(
            (job.runner_id, job.runner_name, job.runner_group_id)
            == (s["runner_id"], s["runner_name"], s["runner_group_id"])
            and job.status == "in_progress"
            and job.conclusion is None
            and job.head_sha == s["source_revision"]
            and job.run_id == d["run_id"]
            and facts.review.state == "approved"
            and facts.review.environment_ids == (s["environment_id"],)
        )
        self._require_current()
        return reader, facts

    def bind_protected_job(self) -> InstalledJitBinding:
        _require(self._binding is None)
        reader, facts = self._current_protected_job()
        self._binding = InstalledJitBinding(_SEAL, self, reader, facts)
        return self._binding

    def refresh_protected_job(self, binding: InstalledJitBinding) -> None:
        _require(
            self.owns_binding(binding)
            and binding.invocation == self.invocation
            and (binding.pid, binding.start) == (self.pid, self.start)
        )
        reader, facts = self._current_protected_job()
        # Selection is fixed; a fresh snapshot may only replace observation custody.
        _require(facts.workflow_source == binding.facts.workflow_source)
        binding.reader, binding.facts = reader, facts

    def owns_binding(self, binding: object) -> bool:
        return (
            not self._closed
            and binding is self._binding
            and self._binding is not None
            and self._binding.reader.owns_facts(self._binding.facts)
        )

    def require_courier_peer(
        self, peer: socket.socket, binding: InstalledJitBinding
    ) -> tuple[int, str]:
        _require(
            self.owns_binding(binding)
            and peer.family == socket.AF_UNIX
            and (peer.type & socket.SOCK_SEQPACKET) != 0
        )
        self._require_current()
        pid, uid, gid = struct.unpack(
            "3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        _require(
            uid == self.lifecycle._doc["courier_uid"]
            and gid == self.lifecycle._doc["courier_gid"]
        )
        parent_pid, measured_uid, start = measure_handoff_process(pid)
        _require(
            measured_uid == uid
            and os.readlink(f"/proc/{pid}/exe") == self.selection["interpreter"]["path"]
        )
        command = _proc(Path(f"/proc/{pid}/cmdline"), 8192).split(b"\0")
        cli_bytes = _protected(Path(self.selection["cli"]["path"]), 32 * 1024 * 1024)
        _require(_hash(cli_bytes) == self.selection["cli"]["digest"])
        first = cli_bytes.split(b"\n", 1)[0]
        _require(first.startswith(b"#!") and len(first) <= 4096)
        shebang = first[2:].strip().split(b" ")
        _require(
            len(shebang) in (1, 2)
            and shebang[0].startswith(b"/")
            and (len(shebang) == 1 or shebang[1] == b"-I")
        )
        expected = shebang + [
            self.selection["cli"]["path"].encode(),
            b"gate0",
            b"courier-original-oidc",
            b"",
        ]
        _require(command == expected)
        status = _proc(Path(f"/proc/{pid}/status"))
        groups = [
            line.split()[1:]
            for line in status.splitlines()
            if line.startswith(b"Groups:")
        ]
        _require(
            len(groups) == 1
            and {int(v) for v in groups[0]} == set(self.selection["groups"])
        )
        _require(
            _proc(Path(f"/proc/{pid}/cgroup")) == ("0::" + _JIT_GROUP + "\n").encode()
        )
        members = _proc(Path("/sys/fs/cgroup" + _JIT_GROUP + "/cgroup.procs"))
        _require(str(pid).encode() in members.splitlines())
        _require(measure_handoff_process(pid) == (parent_pid, uid, start))
        chain = self._measure_supplier_chain(pid)
        if self._peer_chain is None:
            self._peer_chain = chain
        else:
            _require(chain == self._peer_chain)
        self._require_current()
        return pid, start

    def _restore_owned_invocation(self) -> None:
        record = self.lifecycle._jit_record
        for name in ("systemctl", "manager"):
            pin = self.selection[name]
            _require(
                _hash(_protected(Path(pin["path"]), 32 * 1024 * 1024)) == pin["digest"]
            )
        _require(os.readlink("/proc/1/exe") == self.selection["manager"]["path"])
        if record is None:
            _require(self.lifecycle._jit_start_intent)
            self._started = True
            self.invocation = self.lifecycle._jit_invocation
            # Native read is reconciliation only, never identity adoption.
            self._stop_failed_start()
            raise LifecycleRefused()
        _require(type(record) is dict and record["cgroup"] == _JIT_GROUP)
        self.pid, self.start, self.invocation = (
            record["pid"],
            record["start"],
            record["invocation"],
        )
        _require(
            type(self.pid) is int
            and self.pid > 0
            and type(self.start) is str
            and type(self.invocation) is str
            and re.fullmatch(r"[0-9a-f]{32}", self.invocation) is not None
        )
        values = self._show(self.bounds.finalization_end)
        self._unit_predicates(values)
        _require(values["InvocationID"] == self.invocation)
        try:
            self._events = os.open(
                "/sys/fs/cgroup" + _JIT_GROUP + "/cgroup.events",
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            )
        except FileNotFoundError:
            _require(
                values["ControlGroup"] == ""
                and values["MainPID"] == "0"
                and values["ActiveState"] in ("inactive", "failed")
            )
        else:
            actual = os.fstat(self._events)
            _require(
                (actual.st_dev, actual.st_ino)
                == (record["events_device"], record["events_inode"])
            )
        current_start: str | None
        try:
            _, _, current_start = measure_handoff_process(cast(int, self.pid))
        except FileNotFoundError:
            current_start = None
        if current_start == self.start:
            self._pidfd = os.pidfd_open(cast(int, self.pid), 0)
        else:
            _require(values["MainPID"] == "0")
        self._started = True
        _before(self.bounds.finalization_end)

    def stop_and_observe(self) -> _JitRetirement:
        _require(self._started and not self._closed and self.invocation is not None)
        if self._retirement is not None:
            return self._retirement
        if self.lifecycle._jit_record is None:
            self._stop_failed_start()
            raise LifecycleRefused()
        current = self._show(self.bounds.finalization_end)
        self._unit_predicates(current)
        _require(current["InvocationID"] == self.invocation)
        self._call(("stop", "--no-block", _JIT_UNIT), self.bounds.finalization_end)
        for _ in range(32):
            values = self._show(self.bounds.finalization_end)
            self._unit_predicates(values)
            _require(values["InvocationID"] == self.invocation)
            if (
                values["ActiveState"] in ("inactive", "failed")
                and values["SubState"] in ("dead", "failed")
                and values["MainPID"] == "0"
            ):
                try:
                    empty = (
                        b"populated 0" in os.pread(self._events, 4096, 0).splitlines()
                    )
                except OSError:
                    empty = False
                _require(
                    (empty or values["ControlGroup"] == "")
                    and (
                        self._pidfd < 0
                        or bool(select.select([self._pidfd], [], [], 0)[0])
                    )
                )
                final = self._show(self.bounds.finalization_end)
                self._unit_predicates(final)
                _require(final == values)
                _before(self.bounds.finalization_end)
                document = {
                    "schema": "Gate0A9JitInvocationRetirement.v1",
                    "lifecycle_binding_digest": self.lifecycle._doc[
                        "lifecycle_binding_digest"
                    ],
                    "allocation_id": self.lifecycle._doc["allocation_id"],
                    "invocation": self.invocation,
                    "pid": self.pid,
                    "start": self.start,
                    "state": values["ActiveState"],
                    "result": "jit_processes_retired",
                    "normal_success": values["Result"] == "success"
                    and values["ExecMainCode"] == "1"
                    and values["ExecMainStatus"] == "0",
                }
                self._retirement = _JitRetirement(_SEAL, self, document)
                return self._retirement
        raise LifecycleRefused()

    def owns_retirement(self, fact: object) -> bool:
        return (
            not self._closed
            and fact is self._retirement
            and self._retirement is not None
        )

    def close(self) -> None:
        if self._closed:
            _require(not getattr(self, "_close_failed", False))
            return
        descriptors = (
            self._events,
            self._pidfd,
            *(value[1] for value in getattr(self, "_chain_pidfds", {}).values()),
        )
        self._chain_pidfds = {}
        self._events = self._pidfd = -1
        self._closed = True
        self._retirement = None
        for fd in dict.fromkeys(descriptors):
            if fd >= 0:
                try:
                    os.close(fd)
                except BaseException:
                    self._close_failed = True
        _require(not getattr(self, "_close_failed", False))


def _qualify_runner_mounts(binary_digest: str, owner_uid: int) -> None:
    parent = _directory(_RUNNER_ROOT.parent)
    try:
        directory = os.open(
            "runner", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
        )
        try:
            metadata = os.fstat(directory)
            _require(
                metadata.st_uid == owner_uid and stat.S_IMODE(metadata.st_mode) == 0o700
            )
        finally:
            os.close(directory)
    finally:
        os.close(parent)
    approved_parent = _directory(Path("/opt/dotmac-gate0-jit"))
    os.close(approved_parent)
    mountinfo = _proc(Path("/proc/self/mountinfo"), 262144).decode("ascii")
    for name in ("bin", "externals"):
        target = _RUNNER_ROOT / name
        source = Path("/opt/dotmac-gate0-jit") / name
        actual, approved = (
            os.stat(target, follow_symlinks=False),
            os.stat(source, follow_symlinks=False),
        )
        _require(
            stat.S_ISDIR(actual.st_mode)
            and actual.st_uid == approved.st_uid == 0
            and not actual.st_mode & 0o022
            and (actual.st_dev, actual.st_ino) == (approved.st_dev, approved.st_ino)
        )
        records = [
            line.split()
            for line in mountinfo.splitlines()
            if len(line.split()) > 6 and line.split()[4] == str(target)
        ]
        _require(len(records) == 1 and "ro" in records[0][5].split(","))
    fd = os.open(_RUNNER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        _require(_hash(_read_fd(fd, 32 * 1024 * 1024, uid=0)) == _digest(binary_digest))
        approved = os.stat(
            "/opt/dotmac-gate0-jit/bin/Runner.Listener", follow_symlinks=False
        )
        actual = os.fstat(fd)
        _require(
            (actual.st_dev, actual.st_ino) == (approved.st_dev, approved.st_ino)
            and not actual.st_mode & 0o022
        )
    finally:
        os.close(fd)
