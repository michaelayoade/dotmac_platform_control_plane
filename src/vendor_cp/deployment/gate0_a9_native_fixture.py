"""One-shot raw A9 fixture observations, never native qualification.

External root custody selects actual inputs and authenticated GitHub read artifacts.
This owner neither launches a runner nor accepts a production job/credential. Current
measurements do not establish historical execution or exclude same-UID rewrites.
"""

from __future__ import annotations

import os
import re
import select
import socket
import stat
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from vendor_cp.deployment.gate0_framing import canonical, strict_object
from vendor_cp.deployment.gate0_runner_handoff import measure_handoff_process
from vendor_cp.deployment.gate0_runner_lifecycle import (
    _METADATA_READY,
    _SOCKET,
    JSONRecord,
    LifecycleRefused,
    NativeJitInvocation,
    _before,
    _close_received_descriptors,
    _closed,
    _digest,
    _directory,
    _hash,
    _measure_courier_identity_readonly,
    _measure_generated_script,
    _measure_supplier_chain_readonly,
    _OriginalBounds,
    _positive,
    _proc,
    _protected,
    _qualify_runner_mounts,
    _read_fd,
    _require,
    _socket_before,
    _stable,
    _utc,
)
from vendor_cp.deployment.gate0_runner_tokens import (
    _SUPPLIER_AMENDMENT,
    _SUPPLIER_METHOD,
    _SUPPLIER_SOURCE,
    _supplier_coordinates,
)

_ROOT = Path("/run/dotmac-gate0-native-fixture")
_SELECTION = _ROOT / "selection.json"
_OUTPUT = _ROOT / "observation.json"
_ATTEMPT = _ROOT / "attempt"
_GITHUB = _ROOT / "github-observation.json"
_GROUP = "/dotmac-gate0-a9-native-fixture"
_COORDINATES = (
    "repository_id owner_id run_id attempt workflow_id source_revision "
    "environment_id job_id job_name runner_id runner_name runner_group_id"
)
_SELECTION_FIELDS = (
    "schema procedure_digest case fixture_id boot_id original_bounds "
    "courier_selection preliminary_inventory broker_policy runtime_pins "
    "listener coordinates github_observation negative_probe"
)
_RUNTIME_FIELDS = (
    "observer_module cli interpreter bash listener worker runner_tree_digest "
    "workflow script_template"
)


def run_installed_url_presence_probe() -> int:
    """Inspect names only. A present empty URL is still present."""
    try:
        for name in os.environ:
            if name == "ACTIONS_ID_TOKEN_REQUEST_URL":
                print("Gate0A9UrlPresence.v1 present")
                return 3
        print("Gate0A9UrlPresence.v1 absent")
        return 0
    except Exception:
        print("Gate0A9UrlPresence.v1 unavailable")
        return 4


def _record(raw: bytes, fields: str, schema: str) -> JSONRecord:
    doc = _closed(strict_object(raw), fields)
    _require(canonical(doc) == raw and doc["schema"] == schema)
    return doc


def _text(value: object, maximum: int = 512) -> str:
    _require(
        type(value) is str
        and 0 < len(value) <= maximum
        and all(32 <= ord(c) < 127 for c in value)
    )
    return cast(str, value)


def _pin(value: object, fixed: Path | None = None, maximum: int = 65536) -> bytes:
    pin = _closed(value, "path digest")
    path = Path(_text(pin["path"], 4096))
    _require(path.is_absolute() and ".." not in path.parts and str(path) == pin["path"])
    if fixed is not None:
        _require(path == fixed)
    raw = _protected(
        path,
        maximum,
        mode=0o600
        if path.is_relative_to(_ROOT)
        or path == _SOCKET.parents[1] / "broker-policy.json"
        else None,
    )
    if path.is_relative_to(_ROOT) or path == _SOCKET.parents[1] / "broker-policy.json":
        _require(os.stat(path, follow_symlinks=False).st_gid == 0)
    _require(_hash(raw) == _digest(pin["digest"]))
    return raw


def _coordinates(value: object) -> JSONRecord:
    value = _closed(value, _COORDINATES)
    for name in value:
        if name in ("job_name", "runner_name"):
            _text(value[name])
        elif name == "source_revision":
            _require(
                type(value[name]) is str
                and re.fullmatch(r"[0-9a-f]{40}", value[name]) is not None
            )
        else:
            _positive(value[name])
    _require(value["attempt"] == 1)
    return value


def _file(metadata: os.stat_result) -> JSONRecord:
    return dict(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        size=metadata.st_size,
        mtime_ns=metadata.st_mtime_ns,
        ctime_ns=metadata.st_ctime_ns,
    )


class _HeldRecord:
    """Protected bytes and the original held parent/file identity; no replacement."""

    def __init__(self, path: Path, maximum: int = 65536) -> None:
        self.path, self.maximum = path, maximum
        self.parent = _directory(path.parent)
        self.fd = -1
        try:
            self.fd = os.open(
                path.name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=self.parent,
            )
            self.raw = _read_fd(self.fd, maximum, uid=0, mode=0o600)
            _require(os.fstat(self.fd).st_gid == 0)
            self.identity = _stable(os.fstat(self.fd))
            self.recheck()
        except BaseException:
            self.close()
            raise

    def recheck(self) -> None:
        _require(_stable(os.fstat(self.fd)) == self.identity)
        _require(
            _stable(os.stat(self.path.name, dir_fd=self.parent, follow_symlinks=False))
            == self.identity
        )
        _require(_read_fd(self.fd, self.maximum, uid=0, mode=0o600) == self.raw)

    def close(self) -> None:
        descriptors, self.fd, self.parent = (self.fd, self.parent), -1, -1
        failed = False
        for fd in descriptors:
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    failed = True
        if failed:
            raise LifecycleRefused()


class _LiveProcesses:
    """Finite retained pidfds; observation-only ownership, no process signalling."""

    def __init__(self) -> None:
        self.owned: dict[int, tuple[str, int]] = {}

    def retain(self, pid: int, start: str) -> None:
        if not hasattr(os, "pidfd_open"):
            raise OSError("pidfd unavailable")
        if pid in self.owned:
            _require(self.owned[pid][0] == start)
            self.recheck()
            return
        _require(len(self.owned) < 4)
        fd = os.pidfd_open(pid, 0)
        try:
            _require(
                measure_handoff_process(pid)[2] == start
                and not select.select([fd], [], [], 0)[0]
            )
            self.owned[pid] = (start, fd)
            fd = -1
        finally:
            if fd >= 0:
                os.close(fd)

    def recheck(self) -> None:
        for pid, (start, fd) in self.owned.items():
            _require(
                measure_handoff_process(pid)[2] == start
                and not select.select([fd], [], [], 0)[0]
            )

    def close(self) -> None:
        owned, self.owned = self.owned, {}
        failed = False
        for _, fd in owned.values():
            try:
                os.close(fd)
            except OSError:
                failed = True
        if failed:
            raise LifecycleRefused()


def _fdinfo(pid: int, number: str) -> tuple[int, int]:
    raw = _proc(Path(f"/proc/{pid}/fdinfo/{number}"), 4096)
    fields = [line.split(b":", 1) for line in raw.splitlines()]
    positions = [v.strip() for k, v in fields if k == b"pos"]
    flags = [v.strip() for k, v in fields if k == b"flags"]
    _require(len(positions) == len(flags) == 1)
    _require(re.fullmatch(rb"[0-9]{1,20}", positions[0]) is not None)
    _require(re.fullmatch(rb"[0-7]{1,20}", flags[0]) is not None)
    return int(positions[0]), int(flags[0], 8)


class _ScriptDescriptor:
    """Exactly one retained script descriptor; pread never moves shell offset."""

    def __init__(
        self, pid: int, start: str, path: Path, digest: str, uid: int, deadline: float
    ) -> None:
        self.fd = -1
        self.pid, self.start, self.path = pid, start, path
        self.digest, self.uid, self.deadline = digest, uid, deadline
        _before(deadline)
        expected = _measure_generated_script(path, digest, uid, deadline)
        names: list[str] = []
        with os.scandir(f"/proc/{pid}/fd") as entries:
            for entry in entries:
                _require(
                    len(names) < 256
                    and re.fullmatch(r"[0-9]{1,10}", entry.name) is not None
                )
                names.append(entry.name)
        matches = []
        try:
            for number in names:
                _before(deadline)
                target = os.stat(f"/proc/{pid}/fd/{number}")
                if (target.st_dev, target.st_ino) != expected[:2]:
                    continue
                fd = os.open(f"/proc/{pid}/fd/{number}", os.O_RDONLY | os.O_NONBLOCK)
                try:
                    info = os.fstat(fd)
                    _require(_stable(info) == _stable(target))
                    position, flags = _fdinfo(pid, number)
                    _require(
                        stat.S_ISREG(info.st_mode)
                        and flags & os.O_ACCMODE == os.O_RDONLY
                    )
                    _require(0 < position <= info.st_size <= 65536)
                    raw = _read_fd(fd, 65536, uid=uid)
                    _require(_hash(raw) == digest and _stable(info) == expected)
                    matches.append((fd, number, position, _stable(info)))
                    fd = -1
                finally:
                    if fd >= 0:
                        os.close(fd)
            _require(len(matches) == 1)
            self.fd, self.number, self.position, self.identity = matches.pop()
            self.observed = time.monotonic()
            self.recheck()
        except BaseException:
            self.close()
            raise
        finally:
            for fd, *_ in matches:
                os.close(fd)

    def recheck(self) -> JSONRecord:
        _before(self.deadline)
        _require(measure_handoff_process(self.pid)[2] == self.start)
        position, flags = _fdinfo(self.pid, self.number)
        _require(flags & os.O_ACCMODE == os.O_RDONLY and position == self.position)
        info = os.fstat(self.fd)
        target = os.stat(f"/proc/{self.pid}/fd/{self.number}")
        path = os.stat(self.path, follow_symlinks=False)
        _require(_stable(info) == _stable(target) == _stable(path) == self.identity)
        _require(_hash(_read_fd(self.fd, 65536, uid=self.uid)) == self.digest)
        _require(
            _measure_generated_script(self.path, self.digest, self.uid, self.deadline)
            == self.identity
        )
        return dict(
            bash_pid=self.pid,
            bash_start=self.start,
            fd=int(self.number),
            file=_file(info),
            access_mode="O_RDONLY",
            position_before=self.position,
            position_after=position,
            content_digest=self.digest,
            argv_path=str(self.path),
            path_file=_file(path),
            observed_monotonic=self.observed,
        )

    def close(self) -> None:
        fd, self.fd = self.fd, -1
        if fd >= 0:
            os.close(fd)


def _installed_inputs(
    raw: bytes,
) -> tuple[JSONRecord, JSONRecord, JSONRecord, _OriginalBounds]:
    """Validate root-selected data without any native qualification call."""
    doc = _record(raw, _SELECTION_FIELDS, "Gate0A9NativeFixtureSelection.v1")
    _digest(doc["procedure_digest"])
    _text(doc["fixture_id"], 128)
    _require(doc["case"] in ("metadata-positive", "missing-url-negative"))
    bounds = _OriginalBounds.parse(doc["original_bounds"])
    _require(doc["boot_id"] == bounds.boot_id)
    _before(bounds.provisioning_end)
    coordinates = _coordinates(doc["coordinates"])
    courier_pin = _closed(doc["courier_selection"], "path digest")
    _require(courier_pin["path"] == str(_SOCKET.parent / "installation.json"))
    courier_raw = _protected(Path(courier_pin["path"]), mode=0o640)
    _require(_hash(courier_raw) == _digest(courier_pin["digest"]))
    courier = _record(
        courier_raw,
        "schema lifecycle_binding_digest courier_uid courier_gid groups "
        "original_bounds launcher source_files",
        "Gate0A9CourierSelection.v1",
    )
    launcher = NativeJitInvocation._selection(courier["launcher"])
    _positive(courier["courier_uid"])
    _positive(courier["courier_gid"])
    _digest(courier["lifecycle_binding_digest"])
    _require(
        courier["original_bounds"] == doc["original_bounds"]
        and courier["groups"] == launcher["groups"]
    )
    for name in coordinates:
        if name in launcher:
            _require(
                type(coordinates[name]) is type(launcher[name])
                and coordinates[name] == launcher[name]
            )
    sources = _closed(
        courier["source_files"], "gate0_runner_lifecycle gate0_runner_lifecycle_courier"
    )
    for name, digest in sources.items():
        _require(
            _hash(_protected(Path(__file__).parent / (name + ".py"), 1024 * 1024))
            == _digest(digest)
        )
    policy = _record(
        _pin(doc["broker_policy"], _SOCKET.parents[1] / "broker-policy.json"),
        "schema method amendment_digest supplier_commit origins profile",
        "Gate0A9BrokerPolicy.v1",
    )
    _require(
        policy["method"] == _SUPPLIER_METHOD
        and policy["amendment_digest"] == _SUPPLIER_AMENDMENT
        and policy["supplier_commit"] == _SUPPLIER_SOURCE
    )
    origins = policy["origins"]
    _require(type(origins) is list and 0 < len(origins) <= 16)
    # The existing parser validates EVERY independent configured origin. The
    # synthetic coordinates here validate grammar only; they never go on wire.
    for origin in origins:
        _require(type(origin) is str)
        _supplier_coordinates(origin + "/?fixture=grammar", origins)
    profile = _closed(
        policy["profile"],
        "worker_binary shell_binary script_template script_directory "
        "workflow_source_digest worker_pipe_handle_format",
    )
    _require(profile["worker_pipe_handle_format"] == "unix-decimal-fd.v1")
    _pin(
        profile["worker_binary"],
        Path("/opt/dotmac-gate0-jit/bin/Runner.Worker"),
        32 * 1024 * 1024,
    )
    _pin(profile["shell_binary"], Path("/usr/bin/bash"), 32 * 1024 * 1024)
    _pin(profile["script_template"], _ROOT / "script.sh")
    directory = Path(_text(profile["script_directory"], 4096))
    _require(
        directory.is_absolute()
        and ".." not in directory.parts
        and directory.is_relative_to(Path("/run/dotmac-gate0-jit"))
    )
    _digest(profile["workflow_source_digest"])
    runtime = _closed(doc["runtime_pins"], _RUNTIME_FIELDS)
    expected = dict(
        cli=launcher["cli"],
        interpreter=launcher["interpreter"],
        bash=profile["shell_binary"],
        listener=launcher["runner_binary"],
        worker=profile["worker_binary"],
        script_template=profile["script_template"],
    )
    for name, pin in expected.items():
        _require(runtime[name] == pin)
    _require(runtime["runner_tree_digest"] == launcher["runner_tree_digest"])
    _digest(runtime["runner_tree_digest"])
    # The Listener runtime ancestor is intentionally courier-owned0700. The
    # existing fixed RO topology verifier owns that join; never weaken _protected.
    _qualify_runner_mounts(runtime["listener"]["digest"], courier["courier_uid"])
    import sysconfig

    module = Path(__file__).absolute()
    _require(
        any(
            module.is_relative_to(Path(sysconfig.get_path(name)))
            for name in ("purelib", "platlib")
        )
    )
    for name in ("observer_module", "cli", "interpreter", "bash", "worker"):
        _pin(
            runtime[name],
            module if name == "observer_module" else None,
            32 * 1024 * 1024,
        )
    _require(os.readlink("/proc/self/exe") == runtime["interpreter"]["path"])
    _pin(runtime["workflow"], _ROOT / "workflow.yml")
    _pin(runtime["script_template"], _ROOT / "script.sh")
    _require(runtime["workflow"]["digest"] == profile["workflow_source_digest"])
    inventory_raw = _pin(doc["preliminary_inventory"], _ROOT / "inventory.json")
    _require(_hash(inventory_raw) == launcher["native_receipt_digest"])
    inventory = _record(
        inventory_raw,
        "schema disposition boot_id kernel_release systemd_version "
        "runner_tree_digest runtime_pins_digest observed_at_utc",
        "Gate0A9NativeFixtureInventory.v1",
    )
    _require(
        inventory["disposition"] == "UNQUALIFIED"
        and inventory["boot_id"] == bounds.boot_id
        and inventory["kernel_release"] == os.uname().release
        and inventory["runner_tree_digest"] == runtime["runner_tree_digest"]
        and inventory["runtime_pins_digest"] == _hash(canonical(runtime))
    )
    _text(inventory["systemd_version"], 128)
    _require(_utc(inventory["observed_at_utc"]) <= datetime.now(UTC))
    listener = _closed(doc["listener"], "pid start boot_id cgroup")
    _positive(listener["pid"])
    _require(
        type(listener["start"]) is str
        and re.fullmatch(r"[0-9]{1,20}", listener["start"]) is not None
        and listener["boot_id"] == bounds.boot_id
        and listener["cgroup"] == _GROUP
    )
    gh = _closed(
        doc["github_observation"],
        "path observer_identity read_provider_identity max_age_seconds",
    )
    _require(gh["path"] == str(_GITHUB))
    _text(gh["observer_identity"])
    _text(gh["read_provider_identity"])
    _require(_positive(gh["max_age_seconds"]) <= 30)
    if doc["case"] == "metadata-positive":
        _require(doc["negative_probe"] is None)
    else:
        negative = _closed(
            doc["negative_probe"],
            "probe_module workflow script_template absence_marker",
        )
        _require(
            negative["probe_module"] == runtime["observer_module"]
            and negative["workflow"] == runtime["workflow"]
            and negative["script_template"] == runtime["script_template"]
            and negative["absence_marker"] == "Gate0A9UrlPresence.v1 absent"
        )
        # Trusted control-flow inference requires these exact three simple lines.
        cli = _text(runtime["cli"]["path"], 4096)
        _require(re.fullmatch(r"/[A-Za-z0-9_./-]+", cli) is not None)
        expected_script = (
            cli
            + " gate0 native-url-presence\n"
            + cli
            + " gate0 courier-original-oidc\nbuiltin exit\n"
        ).encode("ascii")
        _require(
            _pin(runtime["script_template"], _ROOT / "script.sh") == expected_script
        )
    return doc, courier, policy, bounds


def _fresh_github(held: _HeldRecord, doc: JSONRecord, bounds: _OriginalBounds) -> None:
    held.recheck()
    _require(
        _proc(Path("/proc/sys/kernel/random/boot_id"), 64).decode("ascii").strip()
        == bounds.boot_id
    )
    policy = doc["github_observation"]
    packet = _record(
        held.raw,
        "schema observer_identity read_provider_identity observed_at_utc "
        "valid_until_utc fixture_id coordinates job_status job_conclusion "
        "environment_review workflow_source_digest evidence",
        "Gate0A9NativeFixtureGitHubObservation.v1",
    )
    _require(
        packet["observer_identity"] == policy["observer_identity"]
        and packet["read_provider_identity"] == policy["read_provider_identity"]
        and packet["fixture_id"] == doc["fixture_id"]
    )
    _require(_coordinates(packet["coordinates"]) == doc["coordinates"])
    _require(packet["job_status"] == "in_progress" and packet["job_conclusion"] is None)
    review = _closed(packet["environment_review"], "state environment_ids")
    _require(
        review["state"] == "approved"
        and type(review["environment_ids"]) is list
        and len(review["environment_ids"]) == 1
        and type(review["environment_ids"][0]) is int
        and review["environment_ids"] == [doc["coordinates"]["environment_id"]]
    )
    _require(
        packet["workflow_source_digest"] == doc["runtime_pins"]["workflow"]["digest"]
    )
    evidence = _closed(packet["evidence"], "job_snapshot review workflow_source")
    for name, filename in (
        ("job_snapshot", "github-job-read.json"),
        ("review", "github-review-read.json"),
        ("workflow_source", "workflow.yml"),
    ):
        _pin(evidence[name], _ROOT / filename)
    _require(evidence["workflow_source"] == doc["runtime_pins"]["workflow"])
    observed, valid = _utc(packet["observed_at_utc"]), _utc(packet["valid_until_utc"])
    wall = datetime.now(UTC)
    anchored = bounds.wall + timedelta(seconds=time.monotonic() - bounds.elapsed)
    _require(
        bounds.wall <= observed <= min(wall, anchored)
        and max(wall, anchored)
        < valid
        <= observed + timedelta(seconds=policy["max_age_seconds"])
        and valid <= bounds.provisioning
    )
    _before(bounds.provisioning_end)


def _quiet(peer: socket.socket, server: socket.socket, deadline: float) -> None:
    _before(deadline)
    # Any early packet/EOF or second peer is a refusal; do not read its payload.
    _require(not select.select([peer, server], [], [], 0)[0])


def _metadata_frame(peer: socket.socket, deadline: float) -> bytes:
    _socket_before(peer, deadline)
    raw, ancillary, flags, _ = peer.recvmsg(32768, socket.CMSG_SPACE(16 * 4))
    _close_received_descriptors(ancillary)
    _require(not ancillary and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
    _before(deadline)
    return raw


def _metadata(raw: bytes, case: str, origins: object) -> JSONRecord | None:
    if case == "missing-url-negative":
        _require(raw == b"")
        return None
    _require(case == "metadata-positive" and 0 < len(raw) <= 32768)
    frame = _record(raw, "schema url", "Gate0A9BrokerMetadata.v1")
    origin, path, query = _supplier_coordinates(frame["url"], origins)
    return dict(
        frame_digest=_hash(raw),
        origin=origin,
        path_digest=_hash(path.encode("ascii")),
        query_digest=_hash(query.encode("ascii")),
    )


def _chain_rows(
    chain: tuple[tuple[int, int, str, bytes], ...],
    doc: JSONRecord,
    launcher: JSONRecord,
) -> list[JSONRecord]:
    rows = []
    for role, (pid, parent, start, command), key in zip(
        ("courier", "bash", "worker", "listener"),
        chain,
        ("interpreter", "bash", "worker", "listener"),
        strict=True,
    ):
        pin = doc["runtime_pins"][key]
        fd = os.open(f"/proc/{pid}/exe", os.O_RDONLY | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            _require(_hash(_read_fd(fd, 32 * 1024 * 1024, uid=0)) == pin["digest"])
            _require(
                measure_handoff_process(pid) == (parent, doc["courier_uid"], start)
            )
            rows.append(
                dict(
                    role=role,
                    pid=pid,
                    parent_pid=parent,
                    start=start,
                    executable=dict(
                        path=os.readlink(f"/proc/{pid}/exe"),
                        digest=pin["digest"],
                        device=info.st_dev,
                        inode=info.st_ino,
                    ),
                    argv=[token.decode("ascii") for token in command.split(b"\0")[:-1]],
                    uid=doc["courier_uid"],
                    gid=doc["courier_gid"],
                    groups=launcher["groups"],
                    cgroup=_GROUP,
                )
            )
        finally:
            os.close(fd)
    return rows


def _absent(path: Path) -> None:
    try:
        os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise LifecycleRefused()


def _create_fixed(parent: int, name: str, raw: bytes, deadline: float) -> None:
    _require(name in ("attempt", "observation.json"))
    _before(deadline)
    fd = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent
    )
    identity = _stable(os.fstat(fd))
    try:
        os.fchmod(fd, 0o600)
        position = 0
        while position < len(raw):
            _before(deadline)
            written = os.write(fd, raw[position:])
            _require(written > 0)
            position += written
        os.fsync(fd)
        os.fsync(parent)
        _before(deadline)
    except BaseException:
        # A claimed attempt is deliberately never rearmed. Only our own output
        # inode can be removed on an incomplete publication.
        if name == "observation.json":
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            _require((current.st_dev, current.st_ino) == identity[:2])
            os.unlink(name, dir_fd=parent)
            os.fsync(parent)
        raise
    finally:
        os.close(fd)


def _observe(
    doc: JSONRecord,
    courier: JSONRecord,
    policy: JSONRecord,
    bounds: _OriginalBounds,
    selection: _HeldRecord,
    parent: int,
) -> None:
    """One fixed attempt. No token phase is representable in this protocol."""
    server = peer = None
    socket_parent = -1
    socket_identity = None
    held = script = None
    live = _LiveProcesses()
    events: list[JSONRecord] = []
    started = time.monotonic()
    deadline = bounds.provisioning_end

    def event(name: str) -> None:
        _before(deadline)
        events.append(dict(event=name, observed_monotonic=time.monotonic()))

    try:
        _create_fixed(parent, "attempt", b"Gate0A9NativeFixtureAttempt.v1\n", deadline)
        socket_parent = _directory(_SOCKET.parent)
        _absent(_SOCKET)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        server.bind(str(_SOCKET))
        socket_identity = os.stat(
            _SOCKET.name, dir_fd=socket_parent, follow_symlinks=False
        )
        _require(stat.S_ISSOCK(socket_identity.st_mode) and socket_identity.st_uid == 0)
        os.chown(
            _SOCKET.name,
            0,
            courier["courier_gid"],
            dir_fd=socket_parent,
            follow_symlinks=False,
        )
        os.chmod(_SOCKET.name, 0o660, dir_fd=socket_parent, follow_symlinks=False)
        server.listen(1)
        _socket_before(server, deadline)
        peer, _ = server.accept()
        event("peer_accepted")
        _quiet(peer, server, deadline)
        launcher = courier["launcher"]
        pid, _, start = _measure_courier_identity_readonly(
            peer, launcher, courier["courier_uid"], courier["courier_gid"], _GROUP
        )
        # Late owner packet is immutable once opened. No refresh/replacement.
        while held is None:
            _quiet(peer, server, deadline)
            try:
                held = _HeldRecord(_GITHUB)
            except FileNotFoundError:
                select.select(
                    [peer, server],
                    [],
                    [],
                    min(0.05, max(0, deadline - time.monotonic())),
                )
        _fresh_github(held, doc, bounds)
        listener = doc["listener"]
        live.retain(listener["pid"], listener["start"])
        chain = _measure_supplier_chain_readonly(
            pid,
            launcher,
            policy["profile"],
            courier["courier_uid"],
            courier["courier_gid"],
            _GROUP,
            listener["pid"],
            listener["start"],
            deadline,
            live.retain,
        )
        _require(chain[0][2] == start and len(live.owned) == 4)
        bash = chain[1]
        path = Path(bash[3].split(b"\0")[-2].decode("ascii"))
        script = _ScriptDescriptor(
            bash[0],
            bash[2],
            path,
            policy["profile"]["script_template"]["digest"],
            courier["courier_uid"],
            deadline,
        )
        # Pass selected fixture data to row construction without altering schemas.
        row_input = dict(
            doc, courier_uid=courier["courier_uid"], courier_gid=courier["courier_gid"]
        )
        rows = _chain_rows(chain, row_input, launcher)
        _require(
            _measure_supplier_chain_readonly(
                pid,
                launcher,
                policy["profile"],
                courier["courier_uid"],
                courier["courier_gid"],
                _GROUP,
                listener["pid"],
                listener["start"],
                deadline,
                live.retain,
            )
            == chain
        )
        descriptor = script.recheck()
        live.recheck()
        event("measurements_completed")
        selection.recheck()
        _require(_installed_inputs(selection.raw)[:3] == (doc, courier, policy))
        _fresh_github(held, doc, bounds)
        _quiet(peer, server, deadline)
        _socket_before(peer, deadline)
        _require(peer.send(_METADATA_READY) == len(_METADATA_READY))
        event("metadata_ready_sent")
        raw = _metadata_frame(peer, deadline)
        metadata = _metadata(raw, doc["case"], policy["origins"])
        raw = b""
        event("metadata_received" if metadata is not None else "eof_received")
        if metadata is not None:
            _require(not select.select([peer], [], [], 0)[0])
        _require(not select.select([server], [], [], 0)[0])
        server.close()
        server = None
        peer.close()
        peer = None
        event("socket_closed")
        # pidfd readiness establishes exit only; no invented exit status.
        fd = live.owned[pid][1]
        if not select.select([fd], [], [], max(0, deadline - time.monotonic()))[0]:
            raise TimeoutError("courier exit unavailable")
        event("courier_exited")
        negative = (
            None
            if doc["case"] == "metadata-positive"
            else dict(
                probe_module_digest=doc["runtime_pins"]["observer_module"]["digest"],
                script_template_digest=doc["runtime_pins"]["script_template"]["digest"],
                workflow_source_digest=doc["runtime_pins"]["workflow"]["digest"],
                method="pinned-errexit-control-flow",
            )
        )
        observation = dict(
            schema="Gate0A9NativeFixtureObservation.v1",
            fixture_id=doc["fixture_id"],
            case=doc["case"],
            selection_digest=_hash(selection.raw),
            procedure_digest=doc["procedure_digest"],
            boot_id=bounds.boot_id,
            started_monotonic=started,
            ended_monotonic=time.monotonic(),
            github_observation_digest=_hash(held.raw),
            chain=rows,
            script_descriptor=descriptor,
            protocol=events,
            url_metadata=metadata,
            negative_probe_inference=negative,
            courier_exit_observed=True,
            completion="CASE_OBSERVED",
        )
        encoded = canonical(observation)
        _require(len(encoded) <= 131072)
    finally:
        # Attempt/evidence persist; root external owner owns all runner teardown.
        failures = []
        for resource in (script, held, peer, server, live):
            if resource is not None:
                try:
                    resource.close()
                except Exception:
                    failures.append(True)
        if socket_parent >= 0:
            try:
                if socket_identity is not None:
                    current = os.stat(
                        _SOCKET.name, dir_fd=socket_parent, follow_symlinks=False
                    )
                    _require(
                        (current.st_dev, current.st_ino)
                        == (socket_identity.st_dev, socket_identity.st_ino)
                    )
                    os.unlink(_SOCKET.name, dir_fd=socket_parent)
                    os.fsync(socket_parent)
            except Exception:
                failures.append(True)
            finally:
                try:
                    os.close(socket_parent)
                except Exception:
                    failures.append(True)
        if failures:
            raise OSError("fixture cleanup unavailable")
    selection.recheck()
    _create_fixed(parent, "observation.json", encoded, deadline)


def run_installed_metadata_observer() -> int:
    """Fixed installed root entry. Raw observation cannot satisfy native acceptance."""
    held = None
    parent = -1
    result = 4
    try:
        _require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0)
        _require(set(os.environ) == {"PATH", "LC_ALL"})
        _require(os.environ["PATH"] == "/usr/bin:/bin" and os.environ["LC_ALL"] == "C")
        parent = _directory(_ROOT, gid=0, mode=0o700)
        for path in (
            _OUTPUT,
            _ATTEMPT,
            _GITHUB,
            _SOCKET,
            _SOCKET.parents[1] / "lifecycle-installation.json",
            _SOCKET.parents[1] / "installation.json",
            _SOCKET.parents[1] / "bootstrap.json",
        ):
            _absent(path)
        held = _HeldRecord(_SELECTION)
        doc, courier, policy, bounds = _installed_inputs(held.raw)
        held.recheck()
        _observe(doc, courier, policy, bounds, held, parent)
        result = 0
    except (LifecycleRefused, ValueError, TypeError, KeyError, UnicodeError):
        result = 3
    except Exception:
        result = 4
    finally:
        for resource in (held,):
            if resource is not None:
                try:
                    resource.close()
                except Exception:
                    result = 4
        if parent >= 0:
            try:
                os.close(parent)
            except Exception:
                result = 4
    print(
        "Gate0A9NativeFixture.v1 "
        + (
            "CASE_OBSERVED"
            if result == 0
            else "refused"
            if result == 3
            else "unavailable"
        )
    )
    return result
