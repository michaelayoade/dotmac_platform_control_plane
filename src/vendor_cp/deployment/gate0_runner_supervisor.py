"""Finite root A9 coordinator candidate; local exports never accept Gate 0."""

from __future__ import annotations

import fcntl
import math
import os
import re
import select
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from vendor_cp.deployment.gate0_framing import canonical, strict_object
from vendor_cp.deployment.gate0_role_custody import ProviderRefused
from vendor_cp.deployment.gate0_runner_bootstrap import (
    CollectorRetirementFact,
    NativeSystemManager,
    _cleanup_manager_request,
    _timer_microseconds,
)
from vendor_cp.deployment.gate0_runner_handoff import measure_handoff_process
from vendor_cp.deployment.gate0_runner_lifecycle import (
    InstalledA9Lifecycle,
    InstalledJitBinding,
    LifecycleRefused,
    NativeJitInvocation,
    _before,
    _closed,
    _digest,
    _directory,
    _hash,
    _OriginalBounds,
    _prelaunch,
    _proc,
    _protected,
    _read_fd,
    _require,
)

_ROOT = Path("/run/dotmac-gate0-collector")
_LIFECYCLE = "dotmac-gate0-a9-lifecycle.service"
_BOOTSTRAP = "dotmac-gate0-a9-bootstrap.service"
_JIT = "dotmac-gate0-a9-jit.service"
_TIMER = "dotmac-gate0-a9-lifecycle-deadline.timer"
_EXPIRED = "dotmac-gate0-a9-lifecycle-expired.target"
_UNITS = dict(
    lifecycle_service=_LIFECYCLE,
    lifecycle_timer=_TIMER,
    lifecycle_expired_target=_EXPIRED,
    jit_service=_JIT,
    bootstrap_service=_BOOTSTRAP,
)
_EXPORT = _ROOT / "export"
_SERVICE = (
    "LoadState",
    "AmbientCapabilities",
    "CapabilityBoundingSet",
    "MainPID",
    "ControlPID",
    "InvocationID",
    "ActiveState",
    "SubState",
    "ControlGroup",
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
    "User",
    "Group",
    "BindsTo",
    "After",
    "ExecStart",
    "ExecStop",
    "ExecStopPost",
    "StandardOutput",
    "StandardError",
    "Result",
    "ExecMainCode",
    "ExecMainStatus",
    "LoadCredential",
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
_SHOW = {
    _LIFECYCLE: _SERVICE,
    _BOOTSTRAP: _SERVICE,
    _JIT: _SERVICE,
    _TIMER: _TIMER_PROPERTIES,
    _EXPIRED: ("FragmentPath", "DropInPaths", "Conflicts"),
    "": ("Version",),
}
_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "SYSTEMD_PAGER": "cat"}
_CAPABILITIES = sum(1 << bit for bit in (0, 1, 3, 5, 6, 7, 19))
_EXPORT_NAMES = {
    "collector-retirement.json",
    "owned-files-retirement.json",
    "collection.json",
    "manifest.json",
    "failure.json",
}


def _text(value: object) -> str:
    _require(type(value) is str and 0 < len(value) <= 4096)
    result = cast(str, value)
    _require(all(32 <= ord(c) < 127 for c in result))
    return result


def _pinned(value: object, *, fixed: Path | None = None) -> tuple[Path, bytes]:
    pin = _closed(value, "path digest")
    path = Path(_text(pin["path"]))
    _require(path.is_absolute() and (fixed is None or path == fixed))
    raw = _protected(path, 32 * 1024 * 1024)
    _require(_hash(raw) == _digest(pin["digest"]))
    return path, raw


@dataclass(frozen=True)
class SupervisorInstallation:
    document: dict[str, Any]
    lifecycle: dict[str, Any]
    bounds: _OriginalBounds
    qualification: dict[str, Any]

    @classmethod
    def load(cls) -> SupervisorInstallation:
        _require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0)
        raw = _protected(_ROOT / "supervisor-installation.json", mode=0o600)
        doc = _closed(
            strict_object(raw),
            "schema lifecycle_installation_digest source_digest cli "
            "interpreter systemctl manager unit_assets qualification_digest",
        )
        _require(
            canonical(doc) == raw
            and doc["schema"] == "Gate0A9SupervisorInstallation.v1"
        )
        lifecycle_raw = _protected(_ROOT / "lifecycle-installation.json", mode=0o600)
        _require(_hash(lifecycle_raw) == _digest(doc["lifecycle_installation_digest"]))
        lifecycle = strict_object(lifecycle_raw)
        bounds = _OriginalBounds.parse(lifecycle["original_bounds"])
        _require(
            _hash(_protected(Path(__file__), 1024 * 1024))
            == _digest(doc["source_digest"])
        )
        launcher = NativeJitInvocation._selection(lifecycle["launcher"])
        for name in ("cli", "interpreter", "systemctl", "manager"):
            _require(doc[name] == launcher[name])
            _pinned(
                doc[name],
                fixed=Path("/usr/bin/systemctl") if name == "systemctl" else None,
            )
        assets = _closed(doc["unit_assets"], " ".join(_UNITS))
        for name, unit in _UNITS.items():
            _pinned(assets[name], fixed=Path("/run/systemd/system") / unit)
        _require(assets["jit_service"]["digest"] == launcher["unit_digest"])
        qualification_raw = _protected(
            _ROOT / "supervisor-qualification.json", mode=0o600
        )
        _require(_hash(qualification_raw) == _digest(doc["qualification_digest"]))
        qualification = _closed(
            strict_object(qualification_raw),
            "schema installation_digest source_digest boot_id kernel_release "
            "systemd_version runtime_identity unit_assets native_receipt_digest",
        )
        _require(canonical(qualification) == qualification_raw)
        _require(qualification["schema"] == "Gate0A9SupervisorQualification.v1")
        _require(
            qualification["installation_digest"]
            == _hash(
                canonical({k: v for k, v in doc.items() if k != "qualification_digest"})
            )
        )
        _require(
            qualification["source_digest"] == doc["source_digest"]
            and qualification["unit_assets"] == assets
        )
        _require(
            qualification["boot_id"] == bounds.boot_id
            and qualification["kernel_release"] == os.uname().release
        )
        _require(
            _hash(_protected(_ROOT / "supervisor-native.json", mode=0o600))
            == _digest(qualification["native_receipt_digest"])
        )
        _before(bounds.finalization_end)
        return cls(doc, lifecycle, bounds, qualification)


class JournalLock:
    """One fixed inode and advisory lock for every root journal entry."""

    def __init__(self, deadline: float) -> None:
        self.fd = -1
        parent = _directory(_ROOT)
        try:
            _before(deadline)
            try:
                self.fd = os.open(
                    "lifecycle-owner.lock",
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK,
                    0o600,
                    dir_fd=parent,
                )
                os.fsync(parent)
            except FileExistsError:
                self.fd = os.open(
                    "lifecycle-owner.lock",
                    os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=parent,
                )
            info = os.fstat(self.fd)
            _require(
                stat.S_ISREG(info.st_mode)
                and info.st_uid == 0
                and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600
            )
            while True:
                _before(deadline)
                try:
                    fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    time.sleep(min(0.01, max(0, deadline - time.monotonic())))
            current = os.stat(
                "lifecycle-owner.lock", dir_fd=parent, follow_symlinks=False
            )
            _require((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino))
            _before(deadline)
        except BaseException:
            self.close()
            raise
        finally:
            try:
                os.close(parent)
            except BaseException:
                self.close()
                raise

    def close(self) -> None:
        if self.fd >= 0:
            fd, self.fd = self.fd, -1
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


class SupervisorManager:
    """Only this fixed topology's show/start/stop vocabulary."""

    def __init__(self, installation: SupervisorInstallation) -> None:
        self.installation = installation

    def _call(self, arguments: tuple[str, ...], deadline: float) -> bytes:
        allowed: set[tuple[str, ...]] = {
            ("start", "--no-block", _TIMER),
            ("start", "--no-block", _BOOTSTRAP),
            ("stop", "--no-block", _BOOTSTRAP),
        }
        allowed.update(
            ("show", "--all", "--property=" + ",".join(properties))
            + ((unit,) if unit else ())
            for unit, properties in _SHOW.items()
        )
        _require(arguments in allowed)
        end = min(
            deadline, self.installation.bounds.finalization_end, time.monotonic() + 2
        )
        work = end - 0.1
        _before(work)
        process = subprocess.Popen(  # noqa: S603 -- fixed installed manager vectors
            (
                self.installation.document["systemctl"]["path"],
                "--system",
                "--no-pager",
                *arguments,
            ),
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
                raise LifecycleRefused()
            fd = process.stdout.fileno()
            os.set_blocking(fd, False)
            output = bytearray()
            while True:
                remaining = work - time.monotonic()
                _require(
                    remaining > 0 and bool(select.select([fd], [], [], remaining)[0])
                )
                chunk = os.read(fd, 8192)
                if not chunk:
                    break
                output.extend(chunk)
                _require(len(output) <= 262144)
            _require(process.wait(timeout=max(0, work - time.monotonic())) == 0)
            _before(work)
            result = bytes(output)
        except BaseException:
            failed = True
        finally:
            try:
                _cleanup_manager_request(process, end)
            except BaseException:
                failed = True
        _require(not failed and result is not None)
        _before(end)
        return cast(bytes, result)

    def show(self, unit: str, deadline: float) -> dict[str, str]:
        _require(unit in _SHOW)
        properties = _SHOW[unit]
        raw = self._call(
            ("show", "--all", "--property=" + ",".join(properties))
            + ((unit,) if unit else ()),
            deadline,
        )
        result: dict[str, str] = {}
        for line in raw.decode("ascii").splitlines():
            key, separator, value = line.partition("=")
            _require(separator == "=" and key in properties and key not in result)
            result[key] = value
        _require(set(result) == set(properties))
        if "NextElapseUSecMonotonic" in result:
            try:
                result["NextElapseUSecMonotonic"] = _timer_microseconds(
                    result["NextElapseUSecMonotonic"]
                )
            except ProviderRefused:
                raise LifecycleRefused() from None
        _before(deadline)
        return result

    def qualify(self, *, retirement: bool = False) -> dict[str, str]:
        installed = self.installation
        end = installed.bounds.finalization_end
        _require(os.readlink("/proc/1/exe") == installed.document["manager"]["path"])
        _require(
            self.show("", end)["Version"] == installed.qualification["systemd_version"]
        )
        unit = self.show(_LIFECYCLE, end)
        cli = installed.document["cli"]["path"]
        _service(unit, _LIFECYCLE, cli, "lifecycle-run", root=True)
        _require(unit["AmbientCapabilities"] == "")
        _require(
            set(unit["CapabilityBoundingSet"].split())
            == {
                "cap_chown",
                "cap_dac_override",
                "cap_fowner",
                "cap_kill",
                "cap_setgid",
                "cap_setuid",
                "cap_sys_ptrace",
            }
        )
        _require(
            unit["LoadCredential"]
            == "jit-config-delivery:/run/dotmac-gate0-provisioner/encoded-jit-config"
        )
        _require(
            unit["ExecStopPost"].startswith(
                "{ path="
                + cli
                + " ; argv[]="
                + cli
                + " gate0 lifecycle-retire-jit ; ignore_errors=no ;"
            )
            and unit["ExecStopPost"].count("path=") == 1
        )
        process = measure_handoff_process(os.getpid())
        _require(process[1] == 0)
        cgroup = "0::/system.slice/" + _LIFECYCLE + "\n"
        _require(_proc(Path("/proc/self/cgroup")) == cgroup.encode())
        _require(
            os.readlink("/proc/self/exe") == installed.document["interpreter"]["path"]
        )
        status = _proc(Path("/proc/self/status")).decode()
        caps = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
        _require(int(caps["CapEff"].strip(), 16) == _CAPABILITIES)
        identity = dict(
            uid=0,
            gid=0,
            cap_eff=_CAPABILITIES,
            executable_digest=installed.document["interpreter"]["digest"],
            cgroup=cgroup.strip(),
        )
        _require(
            _closed(
                installed.qualification["runtime_identity"],
                "uid gid cap_eff executable_digest cgroup",
            )
            == identity
        )
        if not retirement:
            _require(
                unit["MainPID"] == str(os.getpid())
                and unit["ActiveState"] in ("active", "activating")
            )
        else:
            # ExecStopPost is a distinct manager-owned helper in the same cgroup.
            argv = _proc(Path("/proc/self/cmdline")).split(b"\0")
            _require(
                argv
                == [
                    installed.document["interpreter"]["path"].encode(),
                    cli.encode(),
                    b"gate0",
                    b"lifecycle-retire-jit",
                    b"",
                ]
                and unit["ControlPID"] == str(os.getpid())
                and unit["ActiveState"] in ("deactivating", "failed", "inactive")
            )
        _require(re.fullmatch(r"[0-9a-f]{32}", unit["InvocationID"]) is not None)
        for subordinate in (_BOOTSTRAP, _JIT):
            values = self.show(subordinate, end)
            _require(
                _LIFECYCLE in values["BindsTo"].split()
                and _LIFECYCLE in values["After"].split()
            )
        _before(end)
        return unit

    def arm(self) -> None:
        end = self.installation.bounds.provisioning_end
        self._call(("start", "--no-block", _TIMER), end)
        values = self.show(_TIMER, end)
        _require(values["ActiveState"] == "active" and values["SubState"] == "waiting")
        _require(
            values["NextElapseUSecMonotonic"]
            == str(math.floor(self.installation.bounds.finalization_end * 1000000))
        )
        _require(
            values["AccuracyUSec"] == "1us"
            and values["RandomizedDelayUSec"] == "0"
            and values["WakeSystem"] == "no"
            and values["Unit"] == _EXPIRED
        )
        _require(
            values["FragmentPath"] == "/run/systemd/system/" + _TIMER
            and not values["DropInPaths"]
        )
        target = self.show(_EXPIRED, end)
        _require(
            target["FragmentPath"] == "/run/systemd/system/" + _EXPIRED
            and not target["DropInPaths"]
        )
        _require({_LIFECYCLE, _BOOTSTRAP, _JIT} <= set(target["Conflicts"].split()))

    def wait_inactive(
        self, unit: str, invocation: str, deadline: float
    ) -> dict[str, str]:
        _require(
            unit in (_BOOTSTRAP, _JIT)
            and re.fullmatch(r"[0-9a-f]{32}", invocation) is not None
        )
        while True:
            values = self.show(unit, deadline)
            _require(values["InvocationID"] == invocation)
            if (
                values["ActiveState"] in ("inactive", "failed")
                and values["MainPID"] == "0"
            ):
                _require(self.show(unit, deadline) == values)
                return values
            _before(deadline)
            time.sleep(min(0.01, max(0, deadline - time.monotonic())))


def _service(
    values: dict[str, str], unit: str, cli: str, route: str, *, root: bool
) -> None:
    expected = dict(
        LoadState="loaded",
        FragmentPath="/run/systemd/system/" + unit,
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
        StandardOutput="null",
        StandardError="null",
        ExecStop="",
    )
    if root:
        expected.update(User="0", Group="0")
    _require(all(values[key] == value for key, value in expected.items()))
    _require(
        values["ExecStart"].startswith(
            "{ path="
            + cli
            + " ; argv[]="
            + cli
            + " gate0 "
            + route
            + " ; ignore_errors=no ;"
        )
        and values["ExecStart"].count("path=") == 1
    )


def _read_outer_credential(deadline: float) -> bytes:
    """Only the literal outer unit's protected read-only credential mount."""
    _before(deadline)
    base = _directory(Path("/run/credentials"))
    directory = fd = -1
    try:
        _before(deadline)
        root = os.fstat(base)
        _before(deadline)
        _require(
            root.st_uid == 0 and stat.S_ISDIR(root.st_mode) and not root.st_mode & 0o022
        )
        directory = os.open(
            "dotmac-gate0-a9-lifecycle.service",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=base,
        )
        _before(deadline)
        info = os.fstat(directory)
        _before(deadline)
        _require(
            info.st_uid == 0 and stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o077
        )
        filesystem = os.fstatvfs(directory)
        _before(deadline)
        _require(bool(filesystem.f_flag & os.ST_RDONLY))
        # This literal unit directory may be a separate credential filesystem.
        # Ordinary lifecycle directory/device policy is deliberately unchanged.
        fd = os.open(
            "jit-config-delivery",
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
            dir_fd=directory,
        )
        _before(deadline)
        raw = _read_fd(fd, 65536, uid=0, mode=0o400)
        _before(deadline)
    finally:
        failed = False
        for descriptor in (fd, directory, base):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    failed = True
        _require(not failed)
    _before(deadline)
    return raw


def _publication_parent(path: Path, deadline: float) -> int:
    """Two fixed documentary parents; guard each filesystem step, including rollback."""
    _require(path in (_EXPORT, _ROOT / "lifecycle", _ROOT))
    _before(deadline)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _before(deadline)
        device = os.fstat(fd).st_dev
        _before(deadline)
        for part in path.parts[1:]:
            _before(deadline)
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=fd,
            )
            previous, fd = fd, child
            os.close(previous)
            _before(deadline)
            info = os.fstat(fd)
            _before(deadline)
            _require(
                stat.S_ISDIR(info.st_mode)
                and info.st_uid == 0
                and not info.st_mode & 0o022
            )
            if part == "run":
                device = info.st_dev
            _require(info.st_dev == device)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _publish(
    path: Path, raw: bytes, gid: int, deadline: float, *, mode: int = 0o640
) -> None:
    """Create-only owned-inode publication at the finite fixed documentary roster."""
    allowed = {
        _ROOT / "lifecycle/public-keys.json",
        _ROOT / "lifecycle/jit-retirement.json",
        _ROOT / "a9-prelaunch.json",
        _ROOT / "job-broker-binding.json",
        _ROOT / "collection-qualification.json",
        _ROOT / "bootstrap-qualification.json",
        _ROOT / "installation.json",
        _ROOT / "bootstrap.json",
        _ROOT / "job-broker-binding-complete.json",
    }
    allowed.update(_EXPORT / name for name in _EXPORT_NAMES)
    _require(path in allowed and 0 < len(raw) <= 8 * 1024 * 1024)
    if path.parent == _EXPORT:
        _require(gid == 0 and mode == 0o600)
    _before(deadline)
    parent = _publication_parent(path.parent, deadline)
    fd = -1
    linked = False
    rollback_safe = True
    identity: tuple[int, int] | None = None
    pending = path.name + ".pending"
    try:
        _before(deadline)
        fd = os.open(
            pending,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600,
            dir_fd=parent,
        )
        _before(deadline)
        info = os.fstat(fd)
        _before(deadline)
        identity = info.st_dev, info.st_ino
        offset = 0
        while offset < len(raw):
            _before(deadline)
            count = os.write(fd, raw[offset : offset + 65536])
            _require(count > 0)
            offset += count
        _before(deadline)
        os.fchown(fd, 0, gid)
        _before(deadline)
        os.fchmod(fd, mode)
        _before(deadline)
        os.fsync(fd)
        _before(deadline)
        closing, fd = fd, -1
        os.close(closing)
        _before(deadline)
        os.link(
            pending,
            path.name,
            src_dir_fd=parent,
            dst_dir_fd=parent,
            follow_symlinks=False,
        )
        linked = True
        _before(deadline)
        final = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        _before(deadline)
        _require((final.st_dev, final.st_ino) == identity)
        os.unlink(pending, dir_fd=parent)
        _before(deadline)
        os.fsync(parent)
        _before(deadline)
        closing_parent, parent = parent, -1
        try:
            os.close(closing_parent)
        except BaseException:
            rollback_safe = False
            raise
        _before(deadline)
    except BaseException:
        if linked and rollback_safe:
            # Never remove a foreign replacement or mint a fresh cleanup budget.
            _before(deadline)
            rollback = _publication_parent(path.parent, deadline)
            try:
                _before(deadline)
                current = os.stat(path.name, dir_fd=rollback, follow_symlinks=False)
                _before(deadline)
                if (current.st_dev, current.st_ino) == identity:
                    _before(deadline)
                    os.unlink(path.name, dir_fd=rollback)
                    _before(deadline)
                    os.fsync(rollback)
                    _before(deadline)
            finally:
                os.close(rollback)
        raise
    finally:
        cleanup_failed = False
        for descriptor in (fd, parent):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    cleanup_failed = True
        _require(not cleanup_failed)


def _export_directory(gid: int, deadline: float) -> None:
    _require(gid == 0)
    parent = _directory(_ROOT)
    try:
        _before(deadline)
        try:
            os.mkdir("export", 0o700, dir_fd=parent)
            os.chown("export", 0, gid, dir_fd=parent, follow_symlinks=False)
            os.fsync(parent)
        except FileExistsError:
            pass
        fd = _directory(_EXPORT, gid=gid, mode=0o700)
        os.close(fd)
        _before(deadline)
    finally:
        os.close(parent)


def _collection_bytes(uid: int, deadline: float) -> bytes:
    """Only the fixed dead collector's exact evidence file; no caller path."""
    path = _ROOT / "session/evidence/collection.json"
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for index, part in enumerate(path.parts[1:]):
            _before(deadline)
            last = index == len(path.parts) - 2
            child = os.open(
                part,
                os.O_RDONLY
                | os.O_NOFOLLOW
                | os.O_NONBLOCK
                | (0 if last else os.O_DIRECTORY),
                dir_fd=fd,
            )
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            _require(
                info.st_uid in ({uid} if last else {0, uid})
                and not info.st_mode & 0o022
            )
        raw = _read_fd(fd, 8 * 1024 * 1024, uid=uid)
        _before(deadline)
        return raw
    finally:
        os.close(fd)


def _failure(installed: SupervisorInstallation, reason: str, deadline: float) -> None:
    _require(
        reason
        in {
            "bootstrap_unobserved",
            "owned_files_retirement_failed",
            "collector_failed",
            "outer_failed",
        }
    )
    _before(deadline)
    gid = 0
    _export_directory(gid, deadline)
    _publish(
        _EXPORT / "failure.json",
        canonical(
            dict(
                schema="Gate0A9PrivateCollectionExportFailure.v1",
                lifecycle_binding_digest=installed.lifecycle[
                    "lifecycle_binding_digest"
                ],
                campaign_digest=installed.lifecycle["campaign_digest"],
                reason=reason,
                result="collection_export_unproven",
            )
        ),
        gid,
        deadline,
        mode=0o600,
    )


def retire_and_export_collector(
    manager: NativeSystemManager,
    fact: CollectorRetirementFact,
    deadline: float,
    *,
    complete: bool,
) -> None:
    """Actual same-manager capability stays alive until file retirement finishes."""
    _before(deadline)
    _require(type(manager) is NativeSystemManager and manager.owns_retirement(fact))
    installed = SupervisorInstallation.load()
    _require(manager.installation.campaign == installed.lifecycle["campaign_digest"])
    _require(manager.installation.uid == installed.lifecycle["collector_uid"])
    end = min(deadline, installed.bounds.finalization_end)
    lock = JournalLock(end)
    recovered: InstalledA9Lifecycle | None = None
    raw: bytes | None = None
    try:
        recovered = InstalledA9Lifecycle.from_installed()
        _before(end)
        raw = recovered.retire_owned_files(manager, fact)
        _before(end)
        _require(manager.owns_retirement(fact))
    finally:
        try:
            if recovered is not None:
                recovered.close()
        finally:
            lock.close()
    _before(end)
    _require(raw is not None)
    result = strict_object(raw)
    success = (
        result.get("schema") == "Gate0A9OwnedFilesRetirement.v1"
        and result.get("result") == "owned_files_retired"
    )
    gid = 0
    _export_directory(gid, end)
    files = {
        "collector-retirement.json": fact.observation,
        "owned-files-retirement.json": raw,
    }
    for name, data in files.items():
        _publish(_EXPORT / name, data, gid, end, mode=0o600)
    if not success or not complete or not fact.normal:
        _failure(
            installed,
            "owned_files_retirement_failed" if not success else "collector_failed",
            end,
        )
        raise LifecycleRefused()
    _require(manager.owns_retirement(fact))
    files["collection.json"] = _collection_bytes(manager.installation.uid, end)
    _publish(
        _EXPORT / "collection.json", files["collection.json"], gid, end, mode=0o600
    )
    observer = SupervisorManager(installed)
    bootstrap = observer.show(_BOOTSTRAP, end)
    _require(
        bootstrap["MainPID"] == str(os.getpid())
        and bootstrap["ActiveState"] == "active"
    )
    _require(re.fullmatch(r"[0-9a-f]{32}", bootstrap["InvocationID"]) is not None)
    manifest = canonical(
        dict(
            schema="Gate0A9PrivateCollectionExport.v1",
            lifecycle_binding_digest=installed.lifecycle["lifecycle_binding_digest"],
            campaign_digest=installed.lifecycle["campaign_digest"],
            bootstrap_invocation_id=bootstrap["InvocationID"],
            files={
                name: dict(bytes=len(data), digest=_hash(data))
                for name, data in files.items()
            },
            result="retained_bytes_exported",
        )
    )
    _publish(_EXPORT / "manifest.json", manifest, gid, end, mode=0o600)
    _before(end)


def publish_bootstrap_failure(deadline: float) -> None:
    installed = SupervisorInstallation.load()
    _failure(
        installed,
        "bootstrap_unobserved",
        min(deadline, installed.bounds.finalization_end),
    )


def _delivery(installed: SupervisorInstallation) -> None:
    end = installed.bounds.provisioning_end
    while True:
        _before(end)
        try:
            raw = _protected(_ROOT / "lifecycle/delivery.json", mode=0o600)
            break
        except FileNotFoundError:
            time.sleep(min(0.01, max(0, end - time.monotonic())))
    doc = _closed(
        strict_object(raw),
        "schema lifecycle_binding_digest campaign_digest prelaunch_digest "
        "ca_digest certificate_a_digest certificate_b_digest",
    )
    _require(canonical(doc) == raw and doc["schema"] == "Gate0A9LifecycleDelivery.v2")
    for name in ("lifecycle_binding_digest", "campaign_digest"):
        _require(doc[name] == installed.lifecycle[name])
    prelaunch_raw, _, _ = _prelaunch(installed.lifecycle)
    _require(doc["prelaunch_digest"] == _hash(prelaunch_raw))
    for key, path in (
        ("ca_digest", _ROOT / "lifecycle/ca.pub"),
        ("certificate_a_digest", _ROOT / "lifecycle/cert-a.pub"),
        ("certificate_b_digest", _ROOT / "lifecycle/cert-b.pub"),
    ):
        _require(_hash(_protected(path, mode=0o600)) == _digest(doc[key]))
        _before(end)
    _require(doc["ca_digest"] == installed.lifecycle["ca_digest"])


def _bind_actual_job_installation(
    lifecycle: InstalledA9Lifecycle,
    binding: InstalledJitBinding,
    report: dict[str, Any],
) -> None:
    """Fixed root publisher; no caller paths, qualification fabrication or callbacks."""
    _require(type(lifecycle) is InstalledA9Lifecycle and not lifecycle._failed)
    jit = lifecycle._jit
    _require(
        type(jit) is NativeJitInvocation
        and jit.lifecycle is lifecycle
        and type(binding) is InstalledJitBinding
        and jit.owns_binding(binding)
    )
    jit = cast(NativeJitInvocation, jit)
    end = lifecycle._bounds.provisioning_end
    _before(end)
    installed = SupervisorInstallation.load()
    _require(installed.lifecycle == lifecycle._doc)
    SupervisorManager(installed).qualify()
    jit._qualify_installed()
    prelaunch_raw, prelaunch, inputs = _prelaunch(lifecycle._doc)
    from vendor_cp.deployment.gate0_runner_installation import (
        _a9_inputs,
        _a9_join,
    )
    from vendor_cp.deployment.gate0_runner_tokens import _supplier_coordinates

    checked, public_inputs = _a9_inputs(prelaunch_raw)
    _require(checked == prelaunch and public_inputs == inputs)
    policy = jit._supplier_policy()
    _closed(report, "schema url")
    _require(report["schema"] == "Gate0A9BrokerMetadata.v1")
    origin, path, query = _supplier_coordinates(report["url"], policy["origins"])
    # Root custody is the existing static native trust boundary. Runtime never
    # emits a native receipt or promotes a dynamic URL to native qualification.
    for role in ("collection", "bootstrap"):
        static = strict_object(inputs[role + "_native_qualification"])
        native = _closed(static["native_receipt"], "path digest")
        _pinned(native)
        runtime = static["runtime_identity"]
        _require(runtime == jit._static_runtime_identity())
        if role == "bootstrap":
            _require(
                static["native_receipt"]
                == strict_object(inputs["bootstrap_template"])["native_receipt"]
            )
    jit.refresh_protected_job(binding)
    _require(jit.owns_binding(binding) and jit._peer_chain is not None)
    facts, selection = binding.facts, jit.selection
    _require(
        policy["profile"]["workflow_source_digest"]
        == "sha256:" + facts.workflow_source.bytes_sha256
    )
    job = next(job for job in facts.jobs if job.id == selection["job_id"])
    selected = dict(
        repository_id=facts.repository_id,
        owner_id=facts.owner_id,
        run_id=facts.run_id,
        attempt=facts.attempt,
        workflow_id=facts.workflow_id,
        source_revision=facts.head_sha,
        environment_id=facts.environment_id,
        job_id=job.id,
        job_name=job.name,
        runner_id=job.runner_id,
        runner_name=job.runner_name,
        runner_group_id=job.runner_group_id,
    )
    observation = _hash(
        canonical(
            dict(
                selected_job_coordinates=selected,
                workflow_source_digest=facts.workflow_source.bytes_sha256,
                review=dict(
                    state=facts.review.state,
                    reviewer_id=facts.review.reviewer_id,
                    environment_ids=list(facts.review.environment_ids),
                    observation_sha256=facts.review.observation_sha256,
                ),
                policy_observation_digests=list(facts.policy_observation_digests),
                observations=[
                    dict(
                        endpoint=o.endpoint.value,
                        page=o.page,
                        status=o.status,
                        response_sha256=o.response_sha256,
                        observed_at_utc=o.observed_at_utc,
                        observed_monotonic=o.observed_monotonic,
                    )
                    for o in facts.observations
                ],
            )
        )
    )
    broker_binding = dict(
        schema="Gate0A9JobBrokerBinding.v1",
        lifecycle_binding_digest=prelaunch["lifecycle_binding_digest"],
        campaign_digest=prelaunch["campaign_digest"],
        prelaunch_digest=_hash(prelaunch_raw),
        broker_policy_digest=_hash(inputs["broker_policy"]),
        static_native_qualification_digests={
            r: _hash(inputs[r + "_native_qualification"])
            for r in ("collection", "bootstrap")
        },
        boot_id=lifecycle._bounds.boot_id,
        jit_invocation_id=jit.invocation,
        selected_job_coordinates=selected,
        github_observation_digest=observation,
        courier_pid=cast(tuple[tuple[int, int, str, bytes], ...], jit._peer_chain)[0][
            0
        ],
        courier_start=cast(tuple[tuple[int, int, str, bytes], ...], jit._peer_chain)[0][
            2
        ],
        origin=origin,
        path=path,
        query=query,
        original_provisioning_end=end,
    )
    binding_raw = canonical(broker_binding)
    binding_pin = dict(
        path=str(_ROOT / "job-broker-binding.json"), digest=_hash(binding_raw)
    )
    prelaunch_pin = dict(
        path=str(_ROOT / "a9-prelaunch.json"), digest=_hash(prelaunch_raw)
    )
    collection = strict_object(inputs["collection_template"])
    bootstrap = strict_object(inputs["bootstrap_template"])
    _require(
        collection["schema"] == "Gate0RunnerCollectionTemplate.v1"
        and bootstrap["schema"] == "Gate0CollectorBootstrapTemplate.v1"
    )
    for doc in (collection, bootstrap):
        _require(
            "qualification" not in doc
            and "job_broker_binding" not in doc
            and doc["campaign_digest"] == prelaunch["campaign_digest"]
        )
        doc.update(
            prelaunch=prelaunch_pin,
            job_broker_binding=binding_pin,
            binding_marker=str(_ROOT / "job-broker-binding-complete.json"),
        )
    _require("broker" not in collection and "collection_installation" not in bootstrap)
    collection.update(
        schema="Gate0RunnerCollectionInstallation.v2",
        broker=dict(origin=origin, path=path, query=query, qualification=binding_pin),
    )
    originals = cast(dict[str, object], collection["job"])
    _require(
        originals["repository_id"] == str(facts.repository_id)
        and originals["run_id"] == str(facts.run_id)
        and originals["run_attempt"] == str(facts.attempt)
        and originals["runner_name"] == job.runner_name
        and originals["runner_group_id"] == str(job.runner_group_id)
        and originals["workflow_sha"] == facts.head_sha
    )
    outputs: list[tuple[Path, bytes]] = [
        (_ROOT / "a9-prelaunch.json", prelaunch_raw),
        (_ROOT / "job-broker-binding.json", binding_raw),
    ]

    def qualified(role: str, doc: dict[str, Any]) -> bytes:
        qualification = canonical(
            dict(
                schema="Gate0A9DerivedInstallationQualification.v1",
                role=role,
                template_digest=_hash(inputs[role + "_template"]),
                static_native_qualification_digest=_hash(
                    inputs[role + "_native_qualification"]
                ),
                job_broker_binding_digest=_hash(binding_raw),
                installation_digest=_hash(canonical(doc)),
            )
        )
        name = _ROOT / (role + "-qualification.json")
        doc["qualification"] = dict(path=str(name), digest=_hash(qualification))
        outputs.append((name, qualification))
        return canonical(doc)

    collection_raw = qualified("collection", collection)
    bootstrap.update(
        schema="Gate0CollectorBootstrapInstallation.v3",
        collection_installation=dict(
            path=str(_ROOT / "installation.json"), digest=_hash(collection_raw)
        ),
    )
    bootstrap_raw = qualified("bootstrap", bootstrap)
    outputs.extend(
        (
            (_ROOT / "installation.json", collection_raw),
            (_ROOT / "bootstrap.json", bootstrap_raw),
        )
    )
    marker_raw = canonical(
        dict(
            schema="Gate0A9JobBrokerBindingComplete.v1",
            prelaunch_digest=_hash(prelaunch_raw),
            collection_digest=_hash(collection_raw),
            bootstrap_digest=_hash(bootstrap_raw),
            binding_digest=_hash(binding_raw),
        )
    )
    outputs.append((_ROOT / "job-broker-binding-complete.json", marker_raw))
    # No final file exists before this once-only same-job bind, including marker.
    for output, _ in outputs:
        _before(end)
        _require(
            not os.path.lexists(output)
            and not os.path.lexists(str(output) + ".pending")
        )
    for output, content in outputs:
        _publish(output, content, lifecycle._doc["collector_gid"], end)
    _a9_join(collection_raw, "collection")
    _a9_join(bootstrap_raw, "bootstrap")
    _before(end)


def _retire_jit(installed: SupervisorInstallation) -> None:
    end = installed.bounds.finalization_end
    lock = JournalLock(end)
    recovered: InstalledA9Lifecycle | None = None
    try:
        recovered = InstalledA9Lifecycle.from_installed()
        raw = recovered._retire_owned_jit_invocation()
        _before(end)
        document = strict_object(raw)
        _require(
            document.get("schema") == "Gate0A9JitInvocationRetirement.v1"
            and document.get("result") == "jit_processes_retired"
        )
        try:
            _publish(_ROOT / "lifecycle/jit-retirement.json", raw, 0, end, mode=0o600)
        except FileExistsError:
            # A second manager post-stop entry still measures native retirement.
            # Existing documentary bytes cannot create or restore that fact.
            _require(
                _protected(_ROOT / "lifecycle/jit-retirement.json", mode=0o600) == raw
            )
            _before(end)
    finally:
        try:
            if recovered is not None:
                recovered.close()
        finally:
            lock.close()


def _read_original_e_input(name: str, deadline: float) -> tuple[bytes, dict[str, Any]]:
    """Code-fixed original owner files, stable protected descriptors and identity."""
    _require(
        name
        in (
            "collection.json",
            "collector-retirement.json",
            "owned-files-retirement.json",
            "manifest.json",
            "bootstrap-observation.json",
        )
    )
    parent_path = _ROOT if name == "bootstrap-observation.json" else _EXPORT
    parent = _directory(
        parent_path, **({} if parent_path == _ROOT else {"gid": 0, "mode": 0o700})
    )
    fd = -1
    try:
        _before(deadline)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        _require(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == before.st_gid == 0
            and stat.S_IMODE(before.st_mode) == 0o600
            and 0 < before.st_size <= 8 * 1024 * 1024
        )
        if name == "bootstrap-observation.json":
            # The actual bootstrap owner commits by linking its retained pending
            # file. Both exact names must be the same root-private inode.
            _require(before.st_nlink == 2)
            pending = os.stat(
                "bootstrap-observation.pending", dir_fd=parent, follow_symlinks=False
            )
            _require((pending.st_dev, pending.st_ino) == (before.st_dev, before.st_ino))
        else:
            _require(before.st_nlink == 1)
        _before(deadline)
        raw = os.pread(fd, before.st_size + 1, 0)
        _before(deadline)
        _require(len(raw) == before.st_size and not os.pread(fd, 1, len(raw)))
        fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        _require(
            tuple(getattr(before, k) for k in fields)
            == tuple(getattr(os.fstat(fd), k) for k in fields)
        )
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        _require((current.st_dev, current.st_ino) == (before.st_dev, before.st_ino))
        _before(deadline)
        return raw, dict(
            device=before.st_dev, inode=before.st_ino, bytes=len(raw), digest=_hash(raw)
        )
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(parent)


def _observe_original_e_export() -> dict[str, Any]:
    """Only this qualified root owner derives original runtime export bindings."""
    installed = SupervisorInstallation.load()
    manager = SupervisorManager(installed)
    lifecycle = manager.qualify()
    end = installed.bounds.finalization_end
    bootstrap = manager.show(_BOOTSTRAP, end)
    _require(
        bootstrap["ActiveState"] == "inactive"
        and bootstrap["SubState"] == "dead"
        and bootstrap["MainPID"] == "0"
        and bootstrap["Result"] == "success"
        and bootstrap["ExecMainCode"] == "1"
        and bootstrap["ExecMainStatus"] == "0"
        and re.fullmatch(r"[0-9a-f]{32}", bootstrap["InvocationID"]) is not None
    )
    collection_raw = _protected(_ROOT / "installation.json", 8 * 1024 * 1024)
    collection = strict_object(collection_raw)
    from vendor_cp.deployment.gate0_runner_installation import _a9_join

    _a9_join(collection_raw, "collection")
    _require(
        collection["schema"] == "Gate0RunnerCollectionInstallation.v2"
        and collection["campaign_digest"] == installed.lifecycle["campaign_digest"]
        and type(collection["collector_uid"]) is int
        and collection["collector_uid"] == installed.lifecycle["collector_uid"]
    )
    raw, identities = {}, {}
    for name in (
        "collection.json",
        "collector-retirement.json",
        "owned-files-retirement.json",
        "manifest.json",
        "bootstrap-observation.json",
    ):
        raw[name], identities[name] = _read_original_e_input(name, end)
    _require(manager.show(_BOOTSTRAP, end) == bootstrap)
    _require(manager.show(_LIFECYCLE, end) == lifecycle)
    _before(end)
    return dict(
        schema="Gate0ERootObservedExport.v1",
        boot_id=installed.bounds.boot_id,
        original_bounds=installed.lifecycle["original_bounds"],
        original_end_microseconds=math.floor(end * 1000000),
        lifecycle_binding_digest=installed.lifecycle["lifecycle_binding_digest"],
        campaign_digest=installed.lifecycle["campaign_digest"],
        collector_uid=installed.lifecycle["collector_uid"],
        courier_uid=installed.lifecycle["courier_uid"],
        courier_gid=installed.lifecycle["courier_gid"],
        supervisor_invocation_id=lifecycle["InvocationID"],
        bootstrap_invocation_id=bootstrap["InvocationID"],
        supervisor_installation_digest=_hash(canonical(installed.document)),
        supervisor_qualification_digest=installed.document["qualification_digest"],
        collection_installation_digest=_hash(collection_raw),
        files=identities,
        retained=raw,
    )


def prepare_original_e_export(
    installed: SupervisorInstallation, bootstrap_exit: dict[str, str]
) -> None:
    """Finite transform after this same bootstrap invocation, before JIT wait."""
    _before(installed.bounds.finalization_end)
    _require(
        bootstrap_exit["ActiveState"] == "inactive"
        and bootstrap_exit["SubState"] == "dead"
        and bootstrap_exit["MainPID"] == "0"
        and bootstrap_exit["Result"] == "success"
        and bootstrap_exit["ExecMainCode"] == "1"
        and bootstrap_exit["ExecMainStatus"] == "0"
    )
    _require(
        SupervisorManager(installed).show(_BOOTSTRAP, installed.bounds.finalization_end)
        == bootstrap_exit
    )
    from vendor_cp.deployment.gate0_e_root_finalization import prepare_original_export

    prepare_original_export()
    _before(installed.bounds.finalization_end)


def run_installed_lifecycle() -> int:
    """Argument-free fixed outer entry; original deadlines stay armed on failure."""
    installed: SupervisorInstallation | None = None
    lifecycle: InstalledA9Lifecycle | None = None
    lock: JournalLock | None = None
    try:
        installed = SupervisorInstallation.load()
        manager = SupervisorManager(installed)
        manager.qualify()
        manager.arm()
        lock = JournalLock(installed.bounds.provisioning_end)
        lifecycle = InstalledA9Lifecycle.from_installed()
        keys = lifecycle.create_controller_keys()
        public = canonical(
            dict(
                schema="Gate0A9ControllerPublicSelections.v1",
                lifecycle_binding_digest=installed.lifecycle[
                    "lifecycle_binding_digest"
                ],
                campaign_digest=installed.lifecycle["campaign_digest"],
                keys=[
                    dict(
                        case_kind=key.case_kind,
                        public_key=key.public_key.decode("ascii"),
                        controller_fingerprint=key.controller_fingerprint,
                    )
                    for key in keys
                ],
            )
        )
        _publish(
            _ROOT / "lifecycle/public-keys.json",
            public,
            0,
            installed.bounds.provisioning_end,
            mode=0o600,
        )
        _delivery(installed)
        lifecycle.install_controller_certificates()
        from vendor_cp.deployment.gate0_e_root_finalization import (
            initialize_original_export,
        )

        initialize_original_export()
        credential = _read_outer_credential(installed.bounds.provisioning_end)
        lifecycle._install_original_jit_config(credential)
        credential = b""
        lifecycle.receive_original_job_credential()
        jit = lifecycle._jit
        if jit is None or jit.invocation is None:
            raise LifecycleRefused()
        jit_invocation = jit.invocation
        del jit
        lifecycle.close()
        lifecycle = None
        lock.close()
        lock = None
        end = installed.bounds.finalization_end
        before = manager.show(_BOOTSTRAP, end)
        _require(
            before["ActiveState"] == "inactive"
            and before["MainPID"] == "0"
            and not before["InvocationID"]
        )
        startup_end = min(end, time.monotonic() + 2)
        manager._call(("start", "--no-block", _BOOTSTRAP), startup_end)
        while True:
            bootstrap = manager.show(_BOOTSTRAP, startup_end)
            _before(startup_end)
            if (
                bootstrap["ActiveState"] == "active"
                and bootstrap["SubState"] == "running"
            ):
                _service(
                    bootstrap,
                    _BOOTSTRAP,
                    installed.document["cli"]["path"],
                    "bootstrap-collector",
                    root=True,
                )
                pid = int(bootstrap["MainPID"])
                measured = measure_handoff_process(pid)
                _require(
                    measured[1] == 0
                    and re.fullmatch(r"[0-9a-f]{32}", bootstrap["InvocationID"])
                    is not None
                )
                _require(
                    _proc(Path(f"/proc/{pid}/cgroup"))
                    == ("0::/system.slice/" + _BOOTSTRAP + "\n").encode()
                )
                _require(
                    os.readlink(f"/proc/{pid}/exe")
                    == installed.document["interpreter"]["path"]
                )
                _require(manager.show(_BOOTSTRAP, startup_end) == bootstrap)
                break
            _require(bootstrap["ActiveState"] != "failed")
            time.sleep(min(0.01, max(0, startup_end - time.monotonic())))
        bootstrap_exit = manager.wait_inactive(
            _BOOTSTRAP, bootstrap["InvocationID"], end
        )
        _require(
            bootstrap_exit["Result"] == "success"
            and bootstrap_exit["ExecMainCode"] == "1"
            and bootstrap_exit["ExecMainStatus"] == "0"
        )
        prepare_original_e_export(installed, bootstrap_exit)
        jit_exit = manager.wait_inactive(_JIT, jit_invocation, end)
        _retire_jit(installed)
        for values in (bootstrap_exit, jit_exit):
            _require(
                values["Result"] == "success"
                and values["ExecMainCode"] == "1"
                and values["ExecMainStatus"] == "0"
            )
        _before(end)
        return 0
    except Exception:
        if installed is not None:
            try:
                _failure(installed, "outer_failed", installed.bounds.finalization_end)
            except Exception:  # noqa: S110 -- private failure never logs credentials
                pass
        return 3
    finally:
        try:
            if lifecycle is not None:
                lifecycle.close()
        finally:
            if lock is not None:
                lock.close()


def run_installed_lifecycle_retirement() -> int:
    """Fixed manager ExecStopPost; no fabricated collector retirement capability."""
    try:
        installed = SupervisorInstallation.load()
        manager = SupervisorManager(installed)
        manager.qualify(retirement=True)
        end = installed.bounds.finalization_end
        bootstrap = manager.show(_BOOTSTRAP, end)
        if bootstrap["MainPID"] != "0" or bootstrap["ActiveState"] not in (
            "inactive",
            "failed",
        ):
            _require(
                re.fullmatch(r"[0-9a-f]{32}", bootstrap["InvocationID"]) is not None
            )
            manager._call(("stop", "--no-block", _BOOTSTRAP), end)
            manager.wait_inactive(_BOOTSTRAP, bootstrap["InvocationID"], end)
        _retire_jit(installed)
        return 0
    except Exception:
        return 3
