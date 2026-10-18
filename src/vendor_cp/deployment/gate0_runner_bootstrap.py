"""Candidate finite systemd A9 bootstrap, requiring actual installed qualification.

No design adoption, host qualification or E acceptance is established by these
source declarations. There is no generic command, unit or property interface.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import stat
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import cast

from vendor_cp.deployment.gate0_framing import canonical, strict_object
from vendor_cp.deployment.gate0_role_custody import ProviderRefused
from vendor_cp.deployment.gate0_runner_handoff import (
    ReceiverInstallation,
    measure_handoff_process,
    read_protected_handoff,
)
from vendor_cp.deployment.gate0_window import FrozenIssuerWindow, WindowDocument

_ROOT = Path("/run/dotmac-gate0-collector")
_INSTALLATION = _ROOT / "bootstrap.json"
_UNIT_ROOT = Path("/run/systemd/system")
_BOOTSTRAP = "dotmac-gate0-a9-bootstrap.service"
_COLLECTOR = "dotmac-gate0-a9-collector.service"
_TIMER = "dotmac-gate0-a9-deadline.timer"
_EXPIRED = "dotmac-gate0-a9-expired.target"
_UNITS = (_BOOTSTRAP, _COLLECTOR, _TIMER, _EXPIRED)
_STAGING = _ROOT / "session/collector.sock"
_FINAL = Path("/run/dotmac-gate0-handoff/collector.sock")
_RECEIVER = _FINAL.parent / "installation.json"
_STARTUP_SECONDS = 2.0
_CLIENT_CLEANUP_RESERVE = 0.1
_CLEANUP_SECONDS = 2.0  # Candidate native qualification must prove this bound.
_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "SYSTEMD_PAGER": "cat"}
_JOB_FIELDS = {
    "GITHUB_REPOSITORY": "repository",
    "GITHUB_REPOSITORY_ID": "repository_id",
    "GITHUB_REPOSITORY_OWNER_ID": "repository_owner_id",
    "GITHUB_RUN_ID": "run_id",
    "GITHUB_RUN_ATTEMPT": "run_attempt",
    "GITHUB_REF": "ref",
    "GITHUB_WORKFLOW_REF": "workflow_ref",
    "GITHUB_WORKFLOW_SHA": "workflow_sha",
    "GITHUB_EVENT_NAME": "event_name",
    "RUNNER_GROUP_ID": "runner_group_id",
    "RUNNER_NAME": "runner_name",
}
_SERVICE_PROPERTIES = (
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
    "BindsTo",
    "After",
    "ExecStart",
    "Environment",
    "LoadCredential",
    "MainPID",
    "InvocationID",
    "ControlGroup",
    "ActiveState",
    "SubState",
    "Result",
    "ExecMainCode",
    "ExecMainStatus",
    "StateChangeTimestampMonotonic",
    "ExecStop",
    "ExecStopPost",
    "RuntimeRandomizedExtraUSec",
    "TimeoutStartUSec",
    "TimeoutStopUSec",
)
_BOOTSTRAP_PROPERTIES = (
    "MainPID",
    "InvocationID",
    "ActiveState",
    "SubState",
    "FragmentPath",
    "DropInPaths",
    "Type",
    "ExitType",
    "Restart",
    "KillMode",
    "KillSignal",
    "FinalKillSignal",
    "SendSIGKILL",
    "Delegate",
    "NoNewPrivileges",
    "User",
    "Group",
    "ExecStart",
    "ExecStop",
    "ExecStopPost",
    "BindsTo",
    "After",
)
_TIMER_PROPERTIES = (
    "ActiveState",
    "SubState",
    "NextElapseUSecMonotonic",
    "AccuracyUSec",
    "RandomizedDelayUSec",
    "WakeSystem",
    "Unit",
    "FragmentPath",
    "DropInPaths",
)
_TARGET_PROPERTIES = ("FragmentPath", "DropInPaths", "Conflicts")
_SHOW_PROPERTIES: dict[str, tuple[str, ...]] = {
    "": ("Version",),
    _BOOTSTRAP: _BOOTSTRAP_PROPERTIES,
    _COLLECTOR: _SERVICE_PROPERTIES,
    _TIMER: _TIMER_PROPERTIES,
    _EXPIRED: _TARGET_PROPERTIES,
}


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _fields(value: object, names: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != set(names.split()):
        raise ProviderRefused()
    return cast(dict[str, object], value)


def _text(value: object) -> str:
    if (
        type(value) is not str
        or not 0 < len(value) <= 8192
        or any(ord(c) < 33 or ord(c) > 126 or c in '\\"' for c in value)
    ):
        raise ProviderRefused()
    return value


def _uint(value: object, *, positive: bool = True) -> int:
    if type(value) is not int or not (1 if positive else 0) <= value < 2**31:
        raise ProviderRefused()
    return value


def _number(value: str) -> int:
    if re.fullmatch(r"[0-9]{1,20}", value) is None:
        raise ProviderRefused()
    return int(value)


def _timer_microseconds(value: object) -> str:
    """Decode systemd v255 FORMAT_TIMESPAN(u, 0), without rounding.

    Only the native timer CLI boundary uses this grammar. Evidence retains its
    existing decimal-microsecond string representation.
    """
    if not isinstance(value, str) or not 1 <= len(value) <= 63:
        raise ProviderRefused()
    if value == "0":
        return "0"
    units = {
        "y": 31_557_600_000_000,
        "month": 2_629_800_000_000,
        "w": 604_800_000_000,
        "d": 86_400_000_000,
        "h": 3_600_000_000,
        "min": 60_000_000,
        "s": 1_000_000,
        "ms": 1_000,
        "us": 1,
    }
    total, previous = 0, 2**64
    parts = value.split(" ")
    for index, part in enumerate(parts):
        match = re.fullmatch(
            r"([1-9][0-9]*)(?:\.([0-9]+))?(y|month|w|d|h|min|s|ms|us)", part
        )
        if match is None:
            raise ProviderRefused()
        integer, fraction, unit = match.groups()
        scale = units[unit]
        if scale >= previous:
            raise ProviderRefused()
        component = int(integer) * scale
        if fraction is not None:
            precision = {"s": 6, "ms": 3}.get(unit)
            if (
                precision is None
                or len(fraction) > precision
                or index != len(parts) - 1
            ):
                raise ProviderRefused()
            component += int(fraction) * 10 ** (precision - len(fraction))
        total += component
        if total >= 2**64 - 1:
            raise ProviderRefused()
        previous = scale
    return str(total)


def _instant(value: object) -> datetime:
    result = datetime.fromisoformat(_text(value).replace("Z", "+00:00"))
    if result.tzinfo is None or result.utcoffset() != timedelta(0):
        raise ProviderRefused()
    return result


def _require_before(deadline: float | None) -> None:
    if deadline is not None and (
        not math.isfinite(deadline) or deadline < 0 or time.monotonic() >= deadline
    ):
        raise ProviderRefused()


def _measure_process(pid: int, deadline: float) -> tuple[int, int, str]:
    _require_before(deadline)
    measured = measure_handoff_process(pid)
    _require_before(deadline)
    return measured


@dataclass(frozen=True, slots=True)
class OriginalCutoff:
    """One original boot-domain mapping; no RuntimeMaxSec/start-time reset."""

    wall: datetime
    monotonic: float
    a_start: datetime
    b_end: datetime
    authoritative_end: float | None = None

    def __post_init__(self) -> None:
        if (
            any(
                v.tzinfo is None or v.utcoffset() != timedelta(0)
                for v in (self.wall, self.a_start, self.b_end)
            )
            or not math.isfinite(self.monotonic)
            or self.monotonic < 0
            or self.a_start >= self.b_end
            or self.wall >= self.b_end
            or (
                self.authoritative_end is not None
                and (
                    type(self.authoritative_end) not in (int, float)
                    or not math.isfinite(self.authoritative_end)
                    or self.authoritative_end <= self.monotonic
                )
            )
        ):
            raise ProviderRefused()

    @property
    def cutoff(self) -> float:
        if self.authoritative_end is not None:
            return self.authoritative_end
        return self.monotonic + (self.b_end - self.wall).total_seconds() + 2

    @property
    def microseconds(self) -> int:
        # Floor rather than delay the original deadline through rounding.
        return math.floor(self.cutoff * 1_000_000)

    def cleanup_end(self, trigger: float) -> float:
        if not math.isfinite(trigger) or trigger < 0:
            raise ProviderRefused()
        return min(trigger + _CLEANUP_SECONDS, self.cutoff + _CLEANUP_SECONDS)


def _installed_original_clock(
    collection: Pin,
    windows: list[WindowDocument],
    campaign: str,
    uid: int,
    lifecycle_binding: str,
) -> tuple[OriginalCutoff, bytes]:
    """Actual installed mode uses the existing qualified immutable clock owner."""
    from vendor_cp.deployment import gate0_runner_lifecycle as lifecycle

    owner = lifecycle.InstalledA9Lifecycle.from_installed()
    try:
        cases = owner._collection_cases()
        doc, bounds = owner._doc, owner._bounds
        if (
            doc["campaign_digest"] != campaign
            or doc["lifecycle_binding_digest"] != lifecycle_binding
            or doc["collector_uid"] != uid
            or tuple(canonical(case[1]) for case in cases)
            != tuple(canonical(window) for window in windows)
            or lifecycle._hash(lifecycle._protected(lifecycle._COLLECTION))
            != collection.digest
            or bounds.finalization
            > _instant(windows[1]["expires_at"]) + timedelta(seconds=2)
        ):
            raise ProviderRefused()
        _require_before(bounds.finalization_end)
        clock = OriginalCutoff(
            bounds.wall,
            bounds.elapsed,
            _instant(windows[0]["not_before"]),
            _instant(windows[1]["expires_at"]),
            authoritative_end=bounds.finalization_end,
        )
        projection = canonical(
            dict(
                schema="Gate0A9OriginalClockBinding.v1",
                method_scope="immutable-original-bounds-clock.v1",
                lifecycle_binding_digest=doc["lifecycle_binding_digest"],
                campaign_digest=campaign,
                boot_id=bounds.boot_id,
                collector_uid=uid,
                original_bounds_digest=lifecycle._hash(
                    canonical(doc["original_bounds"])
                ),
                original_end_microseconds=clock.microseconds,
                collection_digest=collection.digest,
                window_digests=[_digest(canonical(window)) for window in windows],
            )
        )
        return clock, projection
    finally:
        owner.close()


@dataclass(frozen=True, slots=True)
class Pin:
    path: str
    digest: str
    raw: bytes = field(repr=False)


def _pin(value: object, *, fixed: Path | None = None, maximum: int = 65536) -> Pin:
    doc = _fields(value, "path digest")
    path, digest = _text(doc["path"]), _text(doc["digest"])
    if (
        re.fullmatch(r"/[A-Za-z0-9_./-]+", path) is None
        or ".." in Path(path).parts
        or str(Path(path)) != path
        or (fixed is not None and path != str(fixed))
        or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
    ):
        raise ProviderRefused()
    raw = read_protected_handoff(Path(path), 0, maximum)
    if _digest(raw) != digest:
        raise ProviderRefused()
    return Pin(path, digest, raw)


def _directory(path: Path, uid: int = 0, *, deadline: float | None = None) -> int:
    _require_before(deadline)
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _require_before(deadline)
        for position, part in enumerate(path.parts[1:], start=1):
            _require_before(deadline)
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
            )
            os.close(descriptor)
            descriptor = child
            _require_before(deadline)
            info = os.fstat(descriptor)
            _require_before(deadline)
            if (
                info.st_uid != (uid if position == len(path.parts) - 1 else 0)
                or info.st_mode & 0o022
            ):
                raise ProviderRefused()
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _exclusive(
    path: Path, raw: bytes, *, mode: int = 0o600, deadline: float | None = None
) -> None:
    _require_before(deadline)
    parent = _directory(path.parent, deadline=deadline)
    try:
        descriptor = os.open(
            path.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            mode,
            dir_fd=parent,
        )
        try:
            _require_before(deadline)
            pending = memoryview(raw)
            while pending:
                _require_before(deadline)
                count = os.write(descriptor, pending)
                _require_before(deadline)
                if count <= 0:
                    raise ProviderRefused()
                pending = pending[count:]
            _require_before(deadline)
            os.fsync(descriptor)
            _require_before(deadline)
        finally:
            os.close(descriptor)
        _require_before(deadline)
        os.fsync(parent)
        _require_before(deadline)
    finally:
        os.close(parent)


def _publish_receiver(raw: bytes, gid: int, deadline: float) -> None:
    _require_before(deadline)
    pending = _FINAL.parent / ".installation.pending"
    _exclusive(pending, raw, deadline=deadline)
    parent = _directory(_FINAL.parent, deadline=deadline)
    descriptor = -1
    try:
        descriptor = os.open(pending.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        _require_before(deadline)
        os.fchown(descriptor, 0, gid)
        _require_before(deadline)
        os.fchmod(descriptor, 0o640)
        _require_before(deadline)
        os.fsync(descriptor)
        _require_before(deadline)
        os.link(
            pending.name,
            _RECEIVER.name,
            src_dir_fd=parent,
            dst_dir_fd=parent,
            follow_symlinks=False,
        )
        _require_before(deadline)
        os.fsync(parent)
        _require_before(deadline)
        os.unlink(pending.name, dir_fd=parent)
        _require_before(deadline)
        os.fsync(parent)
        _require_before(deadline)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


@dataclass(frozen=True, slots=True)
class BootstrapInstallation:
    """Root-loaded candidate policy; native qualification remains external truth."""

    document: bytes = field(repr=False)
    campaign: str
    uid: int
    gid: int
    groups: tuple[int, ...]
    socket_gid: int
    binary: Pin
    interpreter: Pin
    client: Pin
    manager: Pin
    sources: bytes
    assets: tuple[Pin, ...]
    collection: bytes = field(repr=False)
    receiver: bytes = field(repr=False)
    qualification: bytes = field(repr=False)
    native: Pin
    source_revision: str
    clock: OriginalCutoff
    original_clock: bytes | None = field(default=None, repr=False)

    @classmethod
    def from_installed(cls) -> BootstrapInstallation:
        if os.getuid() != 0 or os.geteuid() != 0:
            raise ProviderRefused()
        raw = read_protected_handoff(_INSTALLATION, 0)
        doc = _fields(
            strict_object(raw),
            "schema campaign_digest lifecycle_binding_digest collection_installation "
            "collector_binary "
            "collector_gid collector_groups socket_gid receiver_template qualification "
            "native_receipt source_revision source_files unit_assets manager_client "
            "manager_binary prelaunch job_broker_binding binding_marker",
        )
        if (
            canonical(doc) != raw
            or doc["schema"] != "Gate0CollectorBootstrapInstallation.v3"
        ):
            raise ProviderRefused()
        from vendor_cp.deployment.gate0_runner_installation import _a9_join

        binding, static_qualification = _a9_join(raw, "bootstrap")
        if (
            binding["lifecycle_binding_digest"] != doc["lifecycle_binding_digest"]
            or static_qualification["native_receipt"] != doc["native_receipt"]
        ):
            raise ProviderRefused()
        campaign = _text(doc["campaign_digest"])
        if re.fullmatch(r"sha256:[0-9a-f]{64}", campaign) is None:
            raise ProviderRefused()
        collection = _pin(
            doc["collection_installation"], fixed=_ROOT / "installation.json"
        )
        original = strict_object(collection.raw)
        if (
            original.get("schema") != "Gate0RunnerCollectionInstallation.v2"
            or original.get("campaign_digest") != campaign
        ):
            raise ProviderRefused()
        uid, gid = _uint(original.get("collector_uid")), _uint(doc["collector_gid"])
        groups = doc["collector_groups"]
        if type(groups) is not list or len(groups) > 32:
            raise ProviderRefused()
        numeric_groups = tuple(
            _uint(v, positive=False) for v in cast(list[object], groups)
        )
        if (
            len(set(numeric_groups)) != len(numeric_groups)
            or _uint(doc["socket_gid"]) not in numeric_groups
        ):
            raise ProviderRefused()
        receiver = _pin(doc["receiver_template"])
        template = _fields(
            strict_object(receiver.raw),
            " ".join(
                k for k in ReceiverInstallation.__annotations__ if k != "collector"
            ),
        )
        if (
            template["schema"] != "Gate0ReceiverInstallation.v1"
            or template["campaign_digest"] != campaign
            or template["receiver_uid"] != original.get("receiver_uid")
        ):
            raise ProviderRefused()
        cases = original.get("cases")
        if type(cases) is not list or len(cases) != 2:
            raise ProviderRefused()
        windows: list[WindowDocument] = []
        bindings: list[dict[str, object]] = []
        for case_value in cast(list[object], cases):
            case = _fields(
                case_value,
                "shared_packet frozen_window command_id hosts ssh_binary keygen "
                "private_key certificate known_hosts issuer_trust attester_trust",
            )
            window_pin = _pin(case["frozen_window"])
            windows.append(FrozenIssuerWindow.parse(window_pin.raw).document)
            hosts = _fields(case.get("hosts"), "IDP3 NS3")
            bindings.append(
                {
                    h: _fields(hosts[h], "binding local_packet endpoint")["binding"]
                    for h in ("IDP3", "NS3")
                }
            )
        if (
            (windows[0]["case_kind"], windows[1]["case_kind"])
            != ("consume_replay", "withdrawal_later_use")
            or windows[0]["github"] != windows[1]["github"]
            or _instant(windows[0]["expires_at"]) > _instant(windows[1]["not_before"])
            or template["cases"] != bindings
            or original.get("job") is None
        ):
            raise ProviderRefused()
        job = _fields(
            original["job"],
            " ".join(windows[0]["github"]) + " runner_group_id runner_name",
        )
        if any(job[k] != v for k, v in windows[0]["github"].items()):
            raise ProviderRefused()
        for value in job.values():
            _text(value)
        sources = _fields(
            doc["source_files"],
            "gate0_runner_bootstrap gate0_runner_credential gate0_runner_lifecycle",
        )
        for name, value in sources.items():
            _pin(
                value, fixed=Path(__file__).parent / (name + ".py"), maximum=1024 * 1024
            )
        assets = _fields(doc["unit_assets"], " ".join(_UNITS))
        pins = tuple(_pin(assets[name]) for name in _UNITS)
        revision = _text(doc["source_revision"])
        if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
            raise ProviderRefused()
        clock, original_clock = _installed_original_clock(
            collection, windows, campaign, uid, _text(doc["lifecycle_binding_digest"])
        )
        return cls(
            raw,
            campaign,
            uid,
            gid,
            numeric_groups,
            _uint(doc["socket_gid"]),
            _pin(doc["collector_binary"], maximum=32 * 1024 * 1024),
            _pin(original["executable"], maximum=32 * 1024 * 1024),
            _pin(
                doc["manager_client"],
                fixed=Path("/usr/bin/systemctl"),
                maximum=32 * 1024 * 1024,
            ),
            _pin(doc["manager_binary"], maximum=32 * 1024 * 1024),
            canonical(sources),
            pins,
            collection.raw,
            receiver.raw,
            _pin(doc["qualification"]).raw,
            _pin(doc["native_receipt"]),
            revision,
            clock,
            original_clock,
        )

    def render(self) -> tuple[bytes, ...]:
        collection = strict_object(self.collection)
        job = cast(dict[str, object], collection["job"])
        environment = ["Environment=GITHUB_ACTIONS=true"]
        environment.extend(
            f"Environment={env}={_text(job[key]).replace(chr(37), chr(37)*2)}"
            for env, key in _JOB_FIELDS.items()
        )
        broker = _fields(collection["broker"], "origin path query qualification")
        bound_url = (
            _text(broker["origin"])
            + _text(broker["path"])
            + "?"
            + _text(broker["query"])
        )
        # Quote one complete systemd assignment and escape specifiers across
        # BOTH opaque path and query. Single quotes are valid supplier bytes.
        escaped = bound_url.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
        environment.append('Environment="ACTIONS_ID_TOKEN_REQUEST_URL=' + escaped + '"')
        substitutions = {
            "@BINARY@": self.binary.path,
            "@UID@": str(self.uid),
            "@GID@": str(self.gid),
            "@DEADLINE_US@": str(self.clock.microseconds),
            "@JOB_ENV@": "\n".join(environment),
        }
        rendered = []
        for pin in self.assets:
            value = pin.raw.decode("ascii")
            for key, replacement in substitutions.items():
                value = value.replace(key, replacement)
            if re.search(r"@[A-Z_]+@", value):
                raise ProviderRefused()
            rendered.append(value.encode("ascii"))
        return tuple(rendered)


def _read_proc(
    path: Path, maximum: int = 65536, *, deadline: float | None = None
) -> bytes:
    _require_before(deadline)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        _require_before(deadline)
        raw = os.read(descriptor, maximum + 1)
        _require_before(deadline)
        if len(raw) > maximum or os.read(descriptor, 1):
            raise ProviderRefused()
        _require_before(deadline)
        return raw
    finally:
        os.close(descriptor)


def _cleanup_manager_request(process: subprocess.Popen[bytes], deadline: float) -> None:
    """Attempt every owned resource under the request's existing absolute end."""
    failed = False
    known_live = False
    if process.returncode is None:
        try:
            known_live = process.poll() is None
        except BaseException:
            # Unknown liveness cannot justify signaling a potentially reaped PID.
            failed = True
    if known_live and process.returncode is None:
        try:
            process.kill()
        except BaseException:
            failed = True
    try:
        process.wait(timeout=max(0, deadline - time.monotonic()))
    except BaseException:
        failed = True
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None:
            try:
                stream.close()
            except BaseException:
                failed = True
    if failed or process.returncode is None or time.monotonic() >= deadline:
        raise ProviderRefused()


_RETIREMENT_SEAL = object()


def _empty_cgroup_result(events: bytes, control_group: str) -> str:
    if events:
        populated = [
            line for line in events.splitlines() if line.startswith(b"populated ")
        ]
        if populated == [b"populated 0"]:
            return "observed_populated_zero"
        # A positive or malformed retained observation cannot be overridden by
        # an empty manager path, including contradictory duplicate fields.
        raise ProviderRefused()
    if control_group == "":
        return "manager_retired_control_group"
    raise ProviderRefused()


@dataclass(frozen=True, slots=True, repr=False)
class CollectorRetirementFact:
    observation_digest: str
    observation: bytes = field(repr=False)
    normal: bool
    _seal: object = field(repr=False)

    def __post_init__(self) -> None:
        if self._seal is not _RETIREMENT_SEAL:
            raise ProviderRefused()


class NativeSystemManager:
    """Only this campaign's fixed manager verbs; no service/command escape hatch."""

    def __init__(self, installation: BootstrapInstallation) -> None:
        if type(installation) is not BootstrapInstallation:
            raise ProviderRefused()
        self.installation = installation
        self.invocation: str | None = None
        self.pid: int | None = None
        self.start: str | None = None
        self.cgroup: str | None = None
        self._events = -1
        self._bound_identity: tuple[object, ...] | None = None
        self._events_identity: tuple[int, int] | None = None
        self._retirement: CollectorRetirementFact | None = None
        self._retirement_claimed = False
        self._closed = False
        self._bind_claimed = False

    def _call(self, arguments: tuple[str, ...], deadline: float) -> bytes:
        allowed: set[tuple[str, ...]] = {
            ("daemon-reload",),
            ("start", "--no-block", _TIMER),
            ("start", "--no-block", _COLLECTOR),
            ("stop", "--no-block", _COLLECTOR),
        }
        allowed.update(
            ("show", "--all", "--property=" + ",".join(properties))
            + ((unit,) if unit else ())
            for unit, properties in _SHOW_PROPERTIES.items()
        )
        call_start = time.monotonic()
        deadline = min(
            deadline, call_start + 2, self.installation.clock.cutoff + _CLEANUP_SECONDS
        )
        request_end = deadline - _CLIENT_CLEANUP_RESERVE
        if arguments not in allowed:
            raise ProviderRefused()
        _require_before(request_end)
        process = subprocess.Popen(  # noqa: S603 -- private fixed manager vectors only
            (self.installation.client.path, "--system", "--no-pager", *arguments),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_ENV,
            close_fds=True,
            start_new_session=True,
        )
        failed = False
        result: bytes | None = None
        try:
            if process.stdout is None:
                raise ProviderRefused()
            import select

            descriptor = process.stdout.fileno()
            os.set_blocking(descriptor, False)
            output = bytearray()
            while True:
                remaining = request_end - time.monotonic()
                if (
                    remaining <= 0
                    or not select.select([descriptor], [], [], remaining)[0]
                ):
                    raise ProviderRefused()
                chunk = os.read(descriptor, 8192)
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > 262144:
                    raise ProviderRefused()
            if (
                process.wait(timeout=max(0, request_end - time.monotonic())) != 0
                or time.monotonic() >= request_end
            ):
                raise ProviderRefused()
            result = bytes(output)
        except BaseException:
            failed = True
        finally:
            try:
                _cleanup_manager_request(process, deadline)
            except BaseException:
                failed = True
        if failed or result is None:
            raise ProviderRefused()
        _require_before(deadline)
        return result

    def _show(
        self, unit: str, properties: tuple[str, ...], deadline: float
    ) -> dict[str, str]:
        if _SHOW_PROPERTIES.get(unit) != properties:
            raise ProviderRefused()
        arguments = ("show", "--all", "--property=" + ",".join(properties)) + (
            (unit,) if unit else ()
        )
        raw = self._call(arguments, deadline).decode("ascii")
        values: dict[str, str] = {}
        for line in raw.splitlines():
            key, separator, value = line.partition("=")
            if not separator or key not in properties or key in values:
                raise ProviderRefused()
            values[key] = value
        if set(values) != set(properties):
            raise ProviderRefused()
        if "NextElapseUSecMonotonic" in values:
            values["NextElapseUSecMonotonic"] = _timer_microseconds(
                values["NextElapseUSecMonotonic"]
            )
        _require_before(deadline)
        return values

    def qualify(self) -> bytes:
        installed = self.installation
        if os.readlink("/proc/1/exe") != installed.manager.path:
            raise ProviderRefused()
        identity = dict(
            executable_digest=installed.manager.digest,
            version=self._show("", ("Version",), time.monotonic() + 2)["Version"],
            kernel_release=os.uname().release,
            boot_id=_read_proc(Path("/proc/sys/kernel/random/boot_id"), 64)
            .decode()
            .strip(),
        )
        document = strict_object(installed.document)
        from vendor_cp.deployment.gate0_runner_installation import _a9_join

        _, static_qualification = _a9_join(installed.document, "bootstrap")
        if (
            static_qualification["runtime_identity"]["manager_identity"] != identity
            or static_qualification["native_receipt"] != document["native_receipt"]
        ):
            raise ProviderRefused()
        bootstrap = self._show(_BOOTSTRAP, _BOOTSTRAP_PROPERTIES, time.monotonic() + 2)
        if (
            _number(bootstrap["MainPID"]) != os.getpid()
            or re.fullmatch(r"[0-9a-f]{32}", bootstrap["InvocationID"]) is None
            or bootstrap["ActiveState"] not in ("activating", "active")
            or bootstrap["FragmentPath"] != str(_UNIT_ROOT / _BOOTSTRAP)
            or bootstrap["DropInPaths"]
            or bootstrap["Type"] != "exec"
            or bootstrap["ExitType"] != "main"
            or bootstrap["Restart"] != "no"
            or bootstrap["KillMode"] != "control-group"
            or bootstrap["KillSignal"] != "9"
            or bootstrap["FinalKillSignal"] != "9"
            or bootstrap["SendSIGKILL"] != "yes"
            or bootstrap["Delegate"] != "no"
            or bootstrap["NoNewPrivileges"] != "yes"
            or bootstrap["User"] != "0"
            or bootstrap["Group"] != "0"
            or bootstrap["ExecStop"]
            or bootstrap["ExecStopPost"]
            or "dotmac-gate0-a9-lifecycle.service" not in bootstrap["BindsTo"].split()
            or "dotmac-gate0-a9-lifecycle.service" not in bootstrap["After"].split()
            or not bootstrap["ExecStart"].startswith(
                "{ path="
                + installed.binary.path
                + " ; argv[]="
                + installed.binary.path
                + " gate0 bootstrap-collector ; ignore_errors=no ;"
            )
            or bootstrap["ExecStart"].count("path=") != 1
            or _read_proc(Path("/proc/self/cgroup"))
            != ("0::/system.slice/" + _BOOTSTRAP + "\n").encode()
        ):
            raise ProviderRefused()
        rendered = installed.render()
        if read_protected_handoff(_UNIT_ROOT / _BOOTSTRAP, 0) != rendered[0]:
            raise ProviderRefused()
        if installed.original_clock is None:
            raise ProviderRefused()
        return canonical(
            dict(
                manager_identity=identity,
                bootstrap=bootstrap,
                original_clock=strict_object(installed.original_clock),
            )
        )

    def arm_original_timer(self) -> dict[str, str]:
        installed = self.installation
        rendered = installed.render()
        for name, raw in zip(_UNITS[1:], rendered[1:], strict=True):
            _exclusive(_UNIT_ROOT / name, raw, mode=0o644)
        end = min(installed.clock.cutoff, time.monotonic() + 2)
        self._call(("daemon-reload",), end)
        self._call(("start", "--no-block", _TIMER), end)
        values = self._show(_TIMER, _TIMER_PROPERTIES, end)
        target = self._show(_EXPIRED, _TARGET_PROPERTIES, end)
        if (
            target["FragmentPath"] != str(_UNIT_ROOT / _EXPIRED)
            or target["DropInPaths"]
            or not {_COLLECTOR, _BOOTSTRAP} <= set(target["Conflicts"].split())
        ):
            raise ProviderRefused()
        if (
            values["ActiveState"] != "active"
            or values["SubState"] != "waiting"
            or _number(values["NextElapseUSecMonotonic"])
            != installed.clock.microseconds
            or values["AccuracyUSec"] != "1us"
            or values["RandomizedDelayUSec"] != "0"
            or values["WakeSystem"] != "no"
            or values["Unit"] != _EXPIRED
            or values["FragmentPath"] != str(_UNIT_ROOT / _TIMER)
            or values["DropInPaths"]
            or time.monotonic() >= installed.clock.cutoff
        ):
            raise ProviderRefused()
        return values

    def start_fixed_collector(self, deadline: float) -> None:
        normal_end = min(deadline, self.installation.clock.cutoff)
        _require_before(normal_end)
        self._call(("start", "--no-block", _COLLECTOR), normal_end)
        _require_before(normal_end)

    def read_fixed_invocation(self, deadline: float) -> dict[str, str]:
        normal_end = min(deadline, self.installation.clock.cutoff)
        _require_before(normal_end)
        values = self._show(_COLLECTOR, _SERVICE_PROPERTIES, normal_end)
        _require_before(normal_end)
        return values

    def bind_actual_collector(self, values: dict[str, str], deadline: float) -> None:
        if (
            self._closed
            or self._bind_claimed
            or self._bound_identity is not None
            or self._events >= 0
        ):
            raise ProviderRefused()
        self._bind_claimed = True
        deadline = min(deadline, self.installation.clock.cutoff)
        _require_before(deadline)
        installed = self.installation
        expected = dict(
            LoadState="loaded",
            FragmentPath=str(_UNIT_ROOT / _COLLECTOR),
            DropInPaths="",
            Type="exec",
            ExitType="main",
            Restart="no",
            RemainAfterExit="no",
            KillMode="control-group",
            KillSignal="9",
            FinalKillSignal="9",
            SendSIGKILL="yes",
            Delegate="no",
            NoNewPrivileges="yes",
            AmbientCapabilities="",
            CapabilityBoundingSet="",
            User=str(installed.uid),
            Group=str(installed.gid),
            ActiveState="active",
            SubState="running",
            ExecStop="",
            ExecStopPost="",
            RuntimeRandomizedExtraUSec="0",
            TimeoutStartUSec="2s",
            TimeoutStopUSec="2s",
        )
        if (
            any(values[k] != v for k, v in expected.items())
            or _BOOTSTRAP not in values["BindsTo"].split()
            or _BOOTSTRAP not in values["After"].split()
            or values["LoadCredential"]
            != "oidc-request-token:/run/dotmac-gate0-collector/oidc-request-token"
            or "ACTIONS_ID_TOKEN_REQUEST_TOKEN" in values["Environment"]
            or not values["ExecStart"].startswith(
                "{ path="
                + installed.binary.path
                + " ; argv[]="
                + installed.binary.path
                + " gate0 collect-e-credential ; ignore_errors=no ;"
            )
            or values["ExecStart"].count("path=") != 1
        ):
            raise ProviderRefused()
        import shlex

        environment = dict(
            term.split("=", 1) for term in shlex.split(values["Environment"])
        )
        collection = strict_object(installed.collection)
        job = cast(dict[str, object], collection["job"])
        broker = _fields(collection["broker"], "origin path query qualification")
        expected_env = {env: _text(job[key]) for env, key in _JOB_FIELDS.items()}
        expected_env.update(
            GITHUB_ACTIONS="true",
            ACTIONS_ID_TOKEN_REQUEST_URL=_text(broker["origin"])
            + _text(broker["path"])
            + "?"
            + _text(broker["query"]),
        )
        if environment != expected_env:
            raise ProviderRefused()
        pid = _number(values["MainPID"])
        _, uid, start = _measure_process(pid, deadline)
        invocation = values["InvocationID"]
        cgroup = "/system.slice/" + _COLLECTOR
        status = _read_proc(Path(f"/proc/{pid}/status"), deadline=deadline)
        _require_before(deadline)
        actual_executable = os.readlink(f"/proc/{pid}/exe")
        _require_before(deadline)
        actual_cgroup = _read_proc(Path(f"/proc/{pid}/cgroup"), deadline=deadline)
        groups = [
            line.partition(b":")[2].split()
            for line in status.splitlines()
            if line.startswith(b"Groups:")
        ]
        if (
            uid != installed.uid
            or re.fullmatch(r"[0-9a-f]{32}", invocation) is None
            or values["ControlGroup"] != cgroup
            or actual_executable != installed.interpreter.path
            or actual_cgroup != ("0::" + cgroup + "\n").encode()
            or len(groups) != 1
            or {int(v) for v in groups[0]} != set(installed.groups)
        ):
            raise ProviderRefused()
        _require_before(deadline)
        self.pid, self.start, self.invocation, self.cgroup = (
            pid,
            start,
            invocation,
            cgroup,
        )
        self._events = os.open(
            "/sys/fs/cgroup" + cgroup + "/cgroup.events", os.O_RDONLY | os.O_NOFOLLOW
        )
        event_stat = os.fstat(self._events)
        self._events_identity = (event_stat.st_dev, event_stat.st_ino)
        _require_before(deadline)
        self._bound_identity = (self.invocation, self.pid, self.start, self.cgroup)

    def stop_fixed_collector(self, deadline: float) -> None:
        self._call(("stop", "--no-block", _COLLECTOR), deadline)

    def observe_fixed_empty(self, values: dict[str, str], deadline: float) -> str:
        # The cleanup failure tail cannot license a normal completion result.
        deadline = min(deadline, self.installation.clock.cutoff)
        _require_before(deadline)
        if (
            not math.isfinite(deadline)
            or deadline > self.installation.clock.cutoff + _CLEANUP_SECONDS
            or self.invocation is None
            or values["InvocationID"] != self.invocation
            or values["ActiveState"] != "inactive"
            or values["SubState"] != "dead"
            or values["MainPID"] != "0"
            or values["Result"] != "success"
            or values["ExecMainCode"] != "1"
            or values["ExecMainStatus"] != "0"
            or _number(values["StateChangeTimestampMonotonic"]) / 1_000_000 >= deadline
            or time.monotonic() >= deadline
        ):
            raise ProviderRefused()
        try:
            events = os.pread(self._events, 4096, 0)
        except OSError:
            events = b""
        _require_before(deadline)
        return _empty_cgroup_result(events, values["ControlGroup"])

    def retirement_facts(self, *, deadline: float) -> CollectorRetirementFact:
        """Measure this bound invocation's actual retirement, including failed exits.

        This factual cleanup capability grants no normal-completion or E claim.
        It remains owned only while this same manager retains its native handles.
        """
        try:
            if self._closed or self._retirement_claimed:
                raise ProviderRefused()
            self._retirement_claimed = True
            if type(deadline) not in (int, float) or not math.isfinite(deadline):
                raise ProviderRefused()
            end = min(deadline, self.installation.clock.cutoff + _CLEANUP_SECONDS)
            _require_before(end)
            identity = (self.invocation, self.pid, self.start, self.cgroup)
            if (
                self._bound_identity is None
                or identity != self._bound_identity
                or self._events < 0
                or self._events_identity is None
            ):
                raise ProviderRefused()
            event_stat = os.fstat(self._events)
            if (event_stat.st_dev, event_stat.st_ino) != self._events_identity:
                raise ProviderRefused()
            while time.monotonic() < end:
                values = self._show(_COLLECTOR, _SERVICE_PROPERTIES, end)
                if values["InvocationID"] != self.invocation:
                    raise ProviderRefused()
                if (
                    values["ActiveState"] in ("inactive", "failed")
                    and values["MainPID"] == "0"
                ):
                    break
                time.sleep(min(0.01, max(0, end - time.monotonic())))
            else:
                raise ProviderRefused()
            if (
                values["LoadState"] != "loaded"
                or values["FragmentPath"] != str(_UNIT_ROOT / _COLLECTOR)
                or values["DropInPaths"] != ""
                or (values["ActiveState"], values["SubState"])
                not in (("inactive", "dead"), ("failed", "failed"))
                or values["ControlGroup"] not in ("", self.cgroup)
            ):
                raise ProviderRefused()
            try:
                events = os.pread(self._events, 4096, 0)
            except OSError:
                events = b""
            retirement = _empty_cgroup_result(events, values["ControlGroup"])
            if self._show(_COLLECTOR, _SERVICE_PROPERTIES, end) != values:
                raise ProviderRefused()
            _require_before(end)
            normal = (
                values["Result"] == "success"
                and values["ExecMainCode"] == "1"
                and values["ExecMainStatus"] == "0"
                and values["ActiveState"] == "inactive"
            )
            observation = canonical(
                dict(
                    schema="Gate0A9CollectorRetirementObservation.v1",
                    campaign_digest=self.installation.campaign,
                    invocation_id=self.invocation,
                    original_pid=self.pid,
                    original_start=self.start,
                    original_cgroup=self.cgroup,
                    manager=values,
                    retirement=retirement,
                    normal=normal,
                )
            )
            fact = CollectorRetirementFact(
                "sha256:" + hashlib.sha256(observation).hexdigest(),
                observation,
                normal,
                _RETIREMENT_SEAL,
            )
            _require_before(end)
            self._retirement = fact
            return fact
        except Exception:
            self._retirement = None
            raise ProviderRefused() from None

    def owns_retirement(self, fact: object) -> bool:
        valid = (
            not self._closed
            and self._events >= 0
            and fact is self._retirement
            and type(fact) is CollectorRetirementFact
            and self._bound_identity
            == (self.invocation, self.pid, self.start, self.cgroup)
        )
        if not valid:
            return False
        try:
            event_stat = os.fstat(self._events)
            return (event_stat.st_dev, event_stat.st_ino) == self._events_identity
        except OSError:
            return False

    def close(self) -> None:
        self._retirement = None
        self._closed = True
        events, self._events = self._events, -1
        if events >= 0:
            # A native close may release the FD and still report an error.
            # Detaching first prevents finally/repeated close from hitting reuse.
            os.close(events)


def _promote_listener(
    manager: NativeSystemManager, deadline: float
) -> dict[str, object]:
    deadline = min(deadline, manager.installation.clock.cutoff)
    _require_before(deadline)
    installed = manager.installation
    pid, start = manager.pid, manager.start
    if pid is None or start is None:
        raise ProviderRefused()
    before = _measure_process(pid, deadline)
    if before[1:] != (installed.uid, start):
        raise ProviderRefused()
    fd_inodes: set[str] = set()
    for name in os.listdir(f"/proc/{pid}/fd"):
        _require_before(deadline)
        fd_target = os.readlink(f"/proc/{pid}/fd/{name}")
        _require_before(deadline)
        match = re.fullmatch(r"socket:\[([0-9]+)\]", fd_target)
        if match:
            fd_inodes.add(match[1])
    matches: list[str] = []
    for line in (
        _read_proc(Path(f"/proc/{pid}/net/unix"), 262144, deadline=deadline)
        .decode()
        .splitlines()[1:]
    ):
        terms = line.split()
        if len(terms) == 8 and terms[7] == str(_STAGING):
            if (
                terms[3] != "00010000"
                or terms[4] != "0001"
                or terms[5] != "01"
                or terms[6] not in fd_inodes
            ):
                raise ProviderRefused()
            matches.append(terms[6])
    if len(matches) != 1 or _measure_process(pid, deadline) != before:
        raise ProviderRefused()
    source_descriptor, target_descriptor = (
        _directory(_STAGING.parent, installed.uid, deadline=deadline),
        _directory(_FINAL.parent, deadline=deadline),
    )
    try:
        _require_before(deadline)
        target_info = os.fstat(target_descriptor)
        _require_before(deadline)
        if (
            target_info.st_gid != installed.socket_gid
            or stat.S_IMODE(target_info.st_mode) != 0o750
        ):
            raise ProviderRefused()
        info = os.stat(_STAGING.name, dir_fd=source_descriptor, follow_symlinks=False)
        _require_before(deadline)
        if (
            not stat.S_ISSOCK(info.st_mode)
            or info.st_uid != installed.uid
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise ProviderRefused()
        identity = (info.st_dev, info.st_ino)
        _require_before(deadline)
        os.link(
            _STAGING.name,
            _FINAL.name,
            src_dir_fd=source_descriptor,
            dst_dir_fd=target_descriptor,
            follow_symlinks=False,
        )
        _require_before(deadline)
        linked = os.stat(_FINAL.name, dir_fd=target_descriptor, follow_symlinks=False)
        _require_before(deadline)
        if (linked.st_dev, linked.st_ino) != identity:
            raise ProviderRefused()
        os.chown(
            _FINAL.name,
            installed.uid,
            installed.socket_gid,
            dir_fd=target_descriptor,
            follow_symlinks=False,
        )
        _require_before(deadline)
        os.chmod(_FINAL.name, 0o660, dir_fd=target_descriptor, follow_symlinks=False)
        _require_before(deadline)
        current = os.stat(
            _STAGING.name, dir_fd=source_descriptor, follow_symlinks=False
        )
        _require_before(deadline)
        if (current.st_dev, current.st_ino) != identity or measure_handoff_process(
            pid
        ) != before:
            raise ProviderRefused()
        _require_before(deadline)
        os.unlink(_STAGING.name, dir_fd=source_descriptor)
        _require_before(deadline)
        os.fsync(source_descriptor)
        _require_before(deadline)
        os.fsync(target_descriptor)
        _require_before(deadline)
        receiver = strict_object(installed.receiver)
        receiver["collector"] = {"uid": installed.uid, "pid": pid, "start": start}
        _require_before(deadline)
        _publish_receiver(canonical(receiver), installed.socket_gid, deadline)
        _require_before(deadline)
        return dict(
            filesystem_device=identity[0],
            filesystem_inode=identity[1],
            kernel_socket_inode=matches[0],
            collector=receiver["collector"],
        )
    finally:
        os.close(source_descriptor)
        os.close(target_descriptor)


def _publish_normal_observation(raw: bytes, deadline: float) -> None:
    """Commit only after publication, handle closure and final deadline check."""
    pending = _ROOT / "bootstrap-observation.pending"
    final = _ROOT / "bootstrap-observation.json"
    _exclusive(pending, raw, deadline=deadline)
    parent = _directory(_ROOT, deadline=deadline)
    linked = False
    identity: tuple[int, int] | None = None
    failed = False
    try:
        info = os.stat(pending.name, dir_fd=parent, follow_symlinks=False)
        identity = info.st_dev, info.st_ino
        _require_before(deadline)
        os.link(
            pending.name,
            final.name,
            src_dir_fd=parent,
            dst_dir_fd=parent,
            follow_symlinks=False,
        )
        linked = True
        _require_before(deadline)
        os.fsync(parent)
        _require_before(deadline)
    except BaseException:
        failed = True
    finally:
        # A failed close has uncertain FD state. Never reuse or close that
        # numeric descriptor again: obtain a fresh protected rollback handle.
        try:
            os.close(parent)
        except BaseException:
            failed = True
        try:
            _require_before(deadline)
        except BaseException:
            failed = True
    if failed:
        if linked:
            rollback_end = min(
                time.monotonic() + _CLEANUP_SECONDS, deadline + _CLEANUP_SECONDS
            )
            rollback = -1
            try:
                rollback = _directory(_ROOT, deadline=rollback_end)
                current = os.stat(final.name, dir_fd=rollback, follow_symlinks=False)
                _require_before(rollback_end)
                if (current.st_dev, current.st_ino) == identity:
                    os.unlink(final.name, dir_fd=rollback)
                    os.fsync(rollback)
            except BaseException:
                # Publication/cleanup uncertainty remains refusal; private
                # candidate and once claims are retained, never rearmed.
                failed = True
            finally:
                if rollback >= 0:
                    try:
                        os.close(rollback)
                    except BaseException:
                        failed = True
        raise ProviderRefused()
    # No caller-side deadline acceptance work may escape this transaction.
    return


def _retire_lifecycle_files(
    manager: NativeSystemManager,
    fact: CollectorRetirementFact,
    deadline: float,
    *,
    complete: bool,
) -> None:
    from vendor_cp.deployment.gate0_runner_supervisor import retire_and_export_collector

    retire_and_export_collector(manager, fact, deadline, complete=complete)


def _publish_lifecycle_failure(deadline: float) -> None:
    from vendor_cp.deployment.gate0_runner_supervisor import publish_bootstrap_failure

    publish_bootstrap_failure(deadline)


def run_installed_bootstrap() -> int:
    """Argument-free candidate root entry; success means normal manager retirement.

    No credential value, caller PID/unit/path, accepted flag or E claim enters
    this operation. The independent original deadline stays armed on every exit.
    """
    manager: NativeSystemManager | None = None
    retirement_fact: CollectorRetirementFact | None = None
    retirement_attempted = False
    handoff_attempted = False
    try:
        installed = BootstrapInstallation.from_installed()
        credential_source = read_protected_handoff(
            _ROOT / "oidc-request-token", 0, 32768, private=True
        )
        if any(byte <= 32 or byte >= 127 for byte in credential_source):
            raise ProviderRefused()
        credential_source = b""
        manager = NativeSystemManager(installed)
        qualification = manager.qualify()
        _exclusive(
            _ROOT / "bootstrap-claimed",
            canonical(dict(campaign_digest=installed.campaign)),
        )
        timer = manager.arm_original_timer()
        startup_deadline = min(
            time.monotonic() + _STARTUP_SECONDS, installed.clock.cutoff
        )
        manager.start_fixed_collector(startup_deadline)
        _require_before(startup_deadline)
        launch_observation: dict[str, str] | None = None
        socket_binding: dict[str, object] | None = None
        while time.monotonic() < startup_deadline:
            values = manager.read_fixed_invocation(startup_deadline)
            if time.monotonic() >= startup_deadline:
                raise ProviderRefused()
            if values["ActiveState"] == "failed":
                raise ProviderRefused()
            if values["ActiveState"] == "active" and values["SubState"] == "running":
                if launch_observation is None:
                    manager.bind_actual_collector(values, startup_deadline)
                    _require_before(startup_deadline)
                    launch_observation = values
                elif (
                    values["InvocationID"] != manager.invocation
                    or _number(values["MainPID"]) != manager.pid
                ):
                    raise ProviderRefused()
                try:
                    _require_before(startup_deadline)
                    socket_binding = _promote_listener(manager, startup_deadline)
                    _require_before(startup_deadline)
                    break
                except FileNotFoundError:
                    pass
            time.sleep(min(0.01, max(0, startup_deadline - time.monotonic())))
        else:
            raise ProviderRefused()
        while time.monotonic() < installed.clock.cutoff:
            values = manager.read_fixed_invocation(installed.clock.cutoff)
            _require_before(installed.clock.cutoff)
            if values["InvocationID"] != manager.invocation:
                raise ProviderRefused()
            if values["ActiveState"] in ("inactive", "failed"):
                retirement = manager.observe_fixed_empty(values, installed.clock.cutoff)
                _require_before(installed.clock.cutoff)
                retirement_attempted = True
                retirement_fact = manager.retirement_facts(
                    deadline=installed.clock.cutoff
                )
                handoff_attempted = True
                _retire_lifecycle_files(
                    manager, retirement_fact, installed.clock.cutoff, complete=True
                )
                _require_before(installed.clock.cutoff)
                manager.close()
                _require_before(installed.clock.cutoff)
                receipt = canonical(
                    dict(
                        schema="Gate0A9ManagerCompletion.v1",
                        campaign_digest=installed.campaign,
                        qualification_digest=_digest(installed.qualification),
                        bootstrap_manager_observation=strict_object(qualification),
                        timer=timer,
                        socket_binding=socket_binding,
                        manager_observations=[launch_observation, values],
                        retirement=retirement,
                        original_cutoff_microseconds=installed.clock.microseconds,
                        result="normal_collector_retired",
                    )
                )
                _publish_normal_observation(receipt, installed.clock.cutoff)
                return 0
            time.sleep(min(0.1, max(0, installed.clock.cutoff - time.monotonic())))
        raise ProviderRefused()
    except Exception:
        if manager is not None:
            cleanup_end = manager.installation.clock.cleanup_end(time.monotonic())
            try:
                manager.stop_fixed_collector(cleanup_end)
            except Exception:  # noqa: S110 -- private failure is never logged
                pass
            try:
                if manager._bound_identity is not None:
                    if not retirement_attempted:
                        retirement_attempted = True
                        retirement_fact = manager.retirement_facts(deadline=cleanup_end)
                    if retirement_fact is not None and not handoff_attempted:
                        handoff_attempted = True
                        _retire_lifecycle_files(
                            manager, retirement_fact, cleanup_end, complete=False
                        )
                if retirement_fact is None:
                    _publish_lifecycle_failure(cleanup_end)
            except Exception:  # noqa: S110 -- no forged retirement or success receipt
                pass
        return 3
    finally:
        if manager is not None:
            manager.close()
