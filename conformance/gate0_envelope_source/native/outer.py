#!/usr/bin/python3.12 -I
"""Inert fixed existing-owner completion seam, not native qualification.

Installation provenance and disposable-VM execution approval remain external.
No caller command, PID, module path, deadline or recovery selector is accepted.
"""

import array
import errno
import hashlib
import json
import os
import re
import select
import socket
import stat
import struct
import subprocess
import sys
import time
import types

OUTER = "/usr/local/libexec/dotmac-gate0-native-envelope/outer"
ADAPTER = "/usr/local/libexec/dotmac-gate0-native-envelope/adapter"
RECORD = "/var/lib/dotmac-gate0-native-envelope/fixture.json"


def require(condition):
    if not condition:
        raise ValueError("incomplete owner observation")


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def protected(path, directory=False):
    require(path.startswith("/") and ".." not in path.split("/"))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = path.strip("/").split("/")
        for index, part in enumerate(parts):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if directory or index < len(parts) - 1:
                flags |= os.O_DIRECTORY
            nxt = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = nxt
            info = os.fstat(fd)
            require(info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022)
            require(
                stat.S_ISDIR(info.st_mode)
                if directory or index < len(parts) - 1
                else stat.S_ISREG(info.st_mode)
            )
        return fd
    except BaseException:
        os.close(fd)
        raise


def bounded(fd, limit):
    before = os.fstat(fd)
    require(0 < before.st_size <= limit and before.st_nlink == 1)
    raw = os.pread(fd, limit + 1, 0)
    require(len(raw) == before.st_size)
    require(stable(before) == stable(os.fstat(fd)))
    return raw


def stable(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def load():
    fd = protected(RECORD)
    try:
        require(stat.S_IMODE(os.fstat(fd).st_mode) == 0o600)
        record = json.loads(bounded(fd, 65536), object_pairs_hook=unique)
    finally:
        os.close(fd)
    require(type(record) is dict and type(record.get("pins")) is dict)
    require(record.get("schema") == "DotmacNativeEnvelopeFixture.v2")
    pin = record["pins"].get("adapter")
    require(type(pin) is dict and set(pin) == {"sha256", "mode", "size"})
    require(type(pin["size"]) is int and 0 < pin["size"] <= 262144)
    require(type(pin["mode"]) is int and pin["mode"] in (0o555, 0o755))
    require(
        type(pin["sha256"]) is str
        and re.fullmatch("[0-9a-f]{64}", pin["sha256"]) is not None
        and pin["sha256"] != "0" * 64
    )
    fd = protected(ADAPTER)
    try:
        require(stat.S_IMODE(os.fstat(fd).st_mode) == pin["mode"])
        source = bounded(fd, pin["size"])
        require(
            len(source) == pin["size"]
            and hashlib.sha256(source).hexdigest() == pin["sha256"]
        )
    finally:
        os.close(fd)
    module = types.ModuleType("fixed_gate0_native_envelope_adapter")
    module.__file__ = ADAPTER
    # Exactly authenticated fixed source bytes; no import loader or pyc cache.
    exec(compile(source, ADAPTER, "exec"), module.__dict__)  # noqa: S102
    module.validate_record(record)
    return record, module


TEMPLATES = {
    "ready": (
        "[Unit]\n"
        "Description=Original finite Gate0 instance is armed\n"
        "DefaultDependencies=no\n"
        "StopWhenUnneeded=no\n"
    ),
    "timer": (
        "[Unit]\n"
        "Description=Original finite Gate0 manager cutoff\n"
        "DefaultDependencies=no\n"
        "[Timer]\n"
        "OnBootSec=@@S_US@@us\n"
        "AccuracySec=@@ACCURACY_US@@us\n"
        "RandomizedDelaySec=0\n"
        "WakeSystem=no\n"
        "RemainAfterElapse=yes\n"
        "Unit=@@EXPIRED@@\n"
    ),
    "expired": (
        "[Unit]\n"
        "Description=Original finite Gate0 cutoff\n"
        "DefaultDependencies=no\n"
        "Conflicts=@@READY@@ @@SERVICE@@\n"
    ),
    "observer": (
        "[Unit]\n"
        "Description=Fixed native envelope observer\n"
        "DefaultDependencies=no\n"
        "Conflicts=@@OBSERVER_EXPIRED@@\n"
        "Requisite=@@OBSERVER_READY@@\n"
        "After=@@OBSERVER_READY@@\n"
        "[Service]\n"
        "Type=exec\n"
        "ExitType=main\n"
        "ExecStart=/usr/local/libexec/dotmac-gate0-native-envelope/adapter\n"
        "User=0\n"
        "Group=0\n"
        "Restart=no\n"
        "SuccessExitStatus=\n"
        "RemainAfterExit=no\n"
        "KillMode=control-group\n"
        "KillSignal=SIGKILL\n"
        "FinalKillSignal=SIGKILL\n"
        "SendSIGKILL=yes\n"
        "TimeoutStopSec=@@T_US@@us\n"
        "Delegate=no\n"
        "LimitCORE=0\n"
        "LimitFSIZE=@@DIAGNOSTIC_MAX@@\n"
        "CPUQuota=@@CPU_QUOTA@@%\n"
        "MemoryMax=@@MEMORY_MAX@@\n"
        "TasksMax=@@TASKS_MAX@@\n"
        "StandardInput=null\n"
        "StandardOutput=append:@@OUTPUT@@\n"
        "StandardError=append:@@DIAGNOSTIC@@\n"
    ),
    "observer_timer": (
        "[Unit]\n"
        "Description=Original native observer cutoff\n"
        "DefaultDependencies=no\n"
        "[Timer]\n"
        "OnBootSec=@@C_US@@us\n"
        "AccuracySec=@@OBSERVER_ACCURACY_US@@us\n"
        "RandomizedDelaySec=0\n"
        "WakeSystem=no\n"
        "RemainAfterElapse=yes\n"
        "Unit=@@OBSERVER_EXPIRED@@\n"
    ),
    "observer_expired": (
        "[Unit]\n"
        "Description=Original native observer expiry\n"
        "DefaultDependencies=no\n"
        "Conflicts=@@OBSERVER_READY@@ @@OBSERVER@@\n"
    ),
    "observer_ready": (
        "[Unit]\n"
        "Description=Original native observer admission is armed\n"
        "DefaultDependencies=no\n"
        "StopWhenUnneeded=no\n"
    ),
}


def fragments(record, p):
    replacements = dict(
        S_US=record["s_us"],
        C_US=record["c_us"],
        T_US=record["t_us"],
        ACCURACY_US=record["accuracy_us"],
        OBSERVER_ACCURACY_US=record["observer_accuracy_us"],
        DIAGNOSTIC_MAX=record["diagnostic_max_bytes"],
        CPU_QUOTA=record["cpu_quota_percent"],
        MEMORY_MAX=record["memory_max_bytes"],
        TASKS_MAX=record["tasks_max"],
        OUTPUT=p["observer_output"],
        DIAGNOSTIC=p["observer_diagnostic"],
    )
    replacements.update({kind.upper(): name for kind, name in p["units"].items()})
    result = {}
    for kind, template in TEMPLATES.items():
        for key, value in replacements.items():
            template = template.replace("@@" + key + "@@", str(value))
        require("@@" not in template)
        raw = template.encode("ascii")
        pin = record["pins"][kind]
        require(
            len(raw) == pin["size"] and hashlib.sha256(raw).hexdigest() == pin["sha256"]
        )
        result[kind] = raw
    return result


def create(a, path, mode=0o600):
    parent, name = path.rsplit("/", 1)
    directory = a.protected(parent, True)
    try:
        fd = os.open(
            name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        os.fchmod(fd, mode)
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == info.st_gid == 0
            and info.st_nlink == 1
            and info.st_size == 0
        )
        return fd
    finally:
        os.close(directory)


def sinks(a, p):
    output = create(a, p["observer_output"])
    diagnostic = create(a, p["observer_diagnostic"])
    return output, diagnostic


def fixed_action(a, record, p, action):
    choices = {
        "reload": ["/usr/bin/systemctl", "--system", "--no-pager", "daemon-reload"],
        "arm-observer": [
            "/usr/bin/systemctl",
            "--system",
            "--no-pager",
            "start",
            p["units"]["observer_timer"],
        ],
        "arm-target": [
            "/usr/bin/systemctl",
            "--system",
            "--no-pager",
            "start",
            p["units"]["ready"],
            p["units"]["timer"],
        ],
        "arm-observer-ready": [
            "/usr/bin/systemctl",
            "--system",
            "--no-pager",
            "--job-mode=fail",
            "start",
            p["units"]["observer_ready"],
        ],
        "start-observer": [
            "/usr/bin/systemctl",
            "--system",
            "--no-pager",
            "--job-mode=fail",
            "start",
            p["units"]["observer"],
        ],
    }
    require(action in choices)
    a.clock(record, True)
    # Only the five closed fixed unit vectors above; no caller command selector.
    result = subprocess.run(  # noqa: S603
        choices[action],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={},
        close_fds=True,
        timeout=(min(record["e_mono_us"], record["s_us"]) - time.monotonic_ns() // 1000)
        / 1_000_000,
        check=False,
    )
    a.clock(record, True)
    require(result.returncode == 0)


def timer(a, record, p, observer=True):
    kind = "observer_timer" if observer else "timer"
    cutoff = record["c_us"] if observer else record["s_us"]
    accuracy = record["observer_accuracy_us"] if observer else record["accuracy_us"]
    expired = p["units"]["observer_expired" if observer else "expired"]
    a.roster(
        record,
        p,
        kind,
        dict(
            ActiveState="active",
            SubState="waiting",
            NextElapseUSecMonotonic=cutoff,
            AccuracyUSec=accuracy,
            RandomizedDelayUSec=0,
            WakeSystem="no",
            RemainAfterElapse="yes",
            Unit=expired,
        ),
    )
    require(
        a.show(record, p["units"][kind], ("LastTriggerUSecMonotonic",))
        == {"LastTriggerUSecMonotonic": "0"}
    )
    a.roster(
        record,
        p,
        "observer_expired" if observer else "expired",
        dict(ActiveState="inactive", SubState="dead"),
    )


def before_start(a, record, p):
    timer(a, record, p, True)
    timer(a, record, p, False)
    a.roster(
        record,
        p,
        "observer_ready",
        dict(ActiveState="active", SubState="active", StopWhenUnneeded="no"),
    )
    a.roster(
        record,
        p,
        "ready",
        dict(ActiveState="active", SubState="active", StopWhenUnneeded="no"),
    )
    require(
        a.show(record, p["units"]["service"], ("LoadState",))
        == {"LoadState": "not-found"}
    )
    a.clock(record, True)


def owner_server(a, p):
    directory = a.protected(p["owner_socket"].rsplit("/", 1)[0], True)
    try:
        require(stat.S_IMODE(os.fstat(directory).st_mode) == 0o700)
    finally:
        os.close(directory)
    require(not os.path.lexists(p["owner_socket"]))
    server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    server.bind(p["owner_socket"])
    os.chmod(p["owner_socket"], 0o600)
    metadata = os.stat(p["owner_socket"], follow_symlinks=False)
    require(
        stat.S_ISSOCK(metadata.st_mode)
        and metadata.st_uid == metadata.st_gid == 0
        and stat.S_IMODE(metadata.st_mode) == 0o600
    )
    server.listen(1)
    return server


def prepare(a, record):
    p, pin_paths = a.validate_record(record)
    a.clock(record, True)
    require(record["evidence_max_bytes"] <= record["diagnostic_max_bytes"])
    # Existing owner installs all runtime ancestry and the original FSIZE limit.
    for path in (p["base"], p["runc_root"], p["owner_socket"].rsplit("/", 1)[0]):
        fd = a.protected(path, True)
        try:
            require(stat.S_IMODE(os.fstat(fd).st_mode) == 0o700)
        finally:
            os.close(fd)
    for path in (
        p["outer_once"],
        p["once"],
        p["observer_output"],
        p["observer_diagnostic"],
        p["diagnostic"],
        p["socket"],
        p["owner_socket"],
    ):
        require(not os.path.lexists(path))
    generated = fragments(record, p)
    a.exclusive(
        p["outer_once"],
        (p["instance"] + "\n" + record["boot_id"] + "\n").encode("ascii"),
    )
    for kind, raw in generated.items():
        a.clock(record, True)
        fd = create(a, pin_paths[kind], record["pins"][kind]["mode"])
        try:
            require(os.write(fd, raw) == len(raw))
            os.fsync(fd)
        finally:
            os.close(fd)
    identities = a.prerequisites(record, p, pin_paths)
    output, diagnostic = sinks(a, p)
    server = owner_server(a, p)
    fixed_action(a, record, p, "reload")
    for kind in (
        "observer",
        "observer_timer",
        "observer_expired",
        "observer_ready",
        "ready",
        "timer",
        "expired",
    ):
        actual = a.show(record, p["units"][kind], ("ActiveState",))
        require(actual == {"ActiveState": "inactive"})
    require(
        a.show(record, p["units"]["service"], ("LoadState",))
        == {"LoadState": "not-found"}
    )
    fixed_action(a, record, p, "arm-observer")
    timer(a, record, p, True)
    fixed_action(a, record, p, "arm-observer-ready")
    a.roster(
        record,
        p,
        "observer_ready",
        dict(ActiveState="active", SubState="active", StopWhenUnneeded="no"),
    )
    fixed_action(a, record, p, "arm-target")
    before_start(a, record, p)
    fixed_action(a, record, p, "start-observer")
    return p, identities, output, diagnostic, server


def receive(a, record, p, server):
    a.clock(record, True)
    server.settimeout(
        (min(record["e_mono_us"], record["s_us"]) - time.monotonic_ns() // 1000)
        / 1_000_000
    )
    peer, _ = server.accept()
    server.close()
    rights = []
    try:
        peer.settimeout(
            (min(record["e_mono_us"], record["s_us"]) - time.monotonic_ns() // 1000)
            / 1_000_000
        )
        credentials = struct.unpack(
            "3i",
            peer.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            ),
        )
        raw, ancillary, flags, _ = peer.recvmsg(
            16385,
            socket.CMSG_SPACE(3 * array.array("i").itemsize),
            socket.MSG_CMSG_CLOEXEC,
        )
        for level, kind, data in ancillary:
            require(
                level == socket.SOL_SOCKET
                and kind == socket.SCM_RIGHTS
                and len(data) % array.array("i").itemsize == 0
            )
            values = array.array("i")
            values.frombytes(data)
            rights.extend(values)
        require(
            flags & ~socket.MSG_CMSG_CLOEXEC == 0
            and len(ancillary) == 1
            and len(rights) == 2
            and 0 < len(raw) <= 16384
        )
        require(all(not os.get_inheritable(fd) for fd in rights))
        packet = json.loads(raw, object_pairs_hook=unique)
        a.closed(packet, ("schema", "instance", "boot_id", "observer"))
        require(
            packet["schema"] == a.OWNER_SCHEMA
            and packet["instance"] == record["instance"]
            and packet["boot_id"] == record["boot_id"]
        )
        # Disable Python's positive-timeout readiness wait for this empty-queue check.
        peer.setblocking(False)
        try:
            peer.recvmsg(1, 0, socket.MSG_PEEK | socket.MSG_DONTWAIT)
            require(False)
        except BlockingIOError as error:
            require(error.errno in (errno.EAGAIN, errno.EWOULDBLOCK))
        peer.settimeout(
            (min(record["e_mono_us"], record["s_us"]) - time.monotonic_ns() // 1000)
            / 1_000_000
        )
        a.clock(record, True)
        return peer, credentials, packet, rights
    except BaseException:
        for fd in rights:
            os.close(fd)
        peer.close()
        raise


def bind_observer(
    a, record, p, identities, credentials, packet, rights, output, diagnostic
):
    pid, uid, gid = credentials
    require(pid > 0 and uid == gid == 0)
    actual = a.show(
        record,
        p["units"]["observer"],
        ("MainPID", "InvocationID", "ExecStart", "ActiveState"),
    )
    require(actual["MainPID"] == str(pid) and actual["ActiveState"] == "active")
    require(
        re.fullmatch("[0-9a-f]{32}", actual["InvocationID"]) is not None
        and actual["InvocationID"] != "0" * 32
    )
    a.fixed_exec(actual["ExecStart"], ADAPTER)
    expected = a.service_base(record)
    expected.update(
        Delegate="no",
        ControlGroup=p["observer_group"],
        TimeoutStopUSec=record["t_us"],
        CPUQuotaPerSecUSec=record["cpu_quota_percent"] * 10000,
        MemoryMax=str(record["memory_max_bytes"]),
        TasksMax=str(record["tasks_max"]),
    )
    a.roster(record, p, "observer", expected)
    process = a.process_snapshot(
        pid,
        p["observer_group"],
        a.PYTHON,
        identities["python"],
        [a.PYTHON, "-I", ADAPTER],
        single=False,
    )
    require(process["ppid"] == 1)
    observer = dict(invocation=actual["InvocationID"], process=process)
    require(packet["observer"] == observer)
    for namespace in ("pid", "cgroup"):
        own = os.stat("/proc/self/ns/" + namespace)
        target = os.stat("/proc/" + str(pid) + "/ns/" + namespace)
        require((own.st_dev, own.st_ino) == (target.st_dev, target.st_ino))
    directory = a.protected("/sys/fs/cgroup" + p["observer_group"], True)
    events = os.open("cgroup.events", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    require(a.fd_identity(rights[0]) == a.fd_identity(directory))
    require(a.fd_identity(rights[1]) == a.fd_identity(events))
    require(
        stat.S_ISDIR(os.fstat(rights[0]).st_mode)
        and stat.S_ISREG(os.fstat(rights[1]).st_mode)
    )
    require(os.listdir("/proc/" + str(pid) + "/task") == [str(pid)])
    null = os.stat("/proc/" + str(pid) + "/fd/0")
    require(stat.S_ISCHR(null.st_mode) and null.st_rdev == os.makedev(1, 3))
    for number, fd in ((1, output), (2, diagnostic)):
        actual_fd = os.stat("/proc/" + str(pid) + "/fd/" + str(number))
        selected = os.fstat(fd)
        require(
            (actual_fd.st_dev, actual_fd.st_ino) == (selected.st_dev, selected.st_ino)
        )
    pidfd = os.pidfd_open(pid, 0)
    retained = dict(
        directory=directory,
        events=events,
        group=a.fd_identity(directory),
        event=a.fd_identity(events),
        pidfd=pidfd,
    )
    before_start(a, record, p)
    # Bind once more after opening pidfd/handles, before the sole acknowledgement.
    require(
        a.process_snapshot(
            pid,
            p["observer_group"],
            a.PYTHON,
            identities["python"],
            [a.PYTHON, "-I", ADAPTER],
            single=False,
        )
        == process
    )
    require(a.show(record, p["units"]["observer"], actual.keys()) == actual)
    a.clock(record, True)
    return observer, retained


def recursive_empty(a, retained):
    require(a.fd_identity(retained["directory"]) == retained["group"])
    require(a.fd_identity(retained["events"]) == retained["event"])
    raw = os.pread(retained["events"], 4096, 0)
    values = {}
    for line in raw.decode("ascii").splitlines():
        pair = line.split()
        require(
            len(pair) == 2
            and pair[0] in ("populated", "frozen")
            and pair[1] in ("0", "1")
            and pair[0] not in values
        )
        values[pair[0]] = pair[1]
    require(values.get("populated") == "0")


def fixed_sink(a, path, fd, maximum, empty=False):
    info = os.fstat(fd)
    require(
        stat.S_ISREG(info.st_mode)
        and stat.S_IMODE(info.st_mode) == 0o600
        and info.st_uid == info.st_gid == 0
        and info.st_nlink == 1
    )
    require(0 <= info.st_size <= maximum and (not empty or info.st_size == 0))
    selected = a.protected(path)
    try:
        require(a.fd_identity(selected) == a.fd_identity(fd))
    finally:
        os.close(selected)
    return info


def output_document(a, record, p, observer, retained, output, identities):
    before = fixed_sink(a, p["observer_output"], output, record["evidence_max_bytes"])
    require(before.st_size > 0)
    raw = os.pread(output, record["evidence_max_bytes"] + 1, 0)
    require(len(raw) == before.st_size)
    document = json.loads(raw, object_pairs_hook=unique)
    require(
        raw
        == (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "ascii"
        )
    )
    a.closed(
        document,
        (
            "schema",
            "status",
            "case",
            "instance",
            "boot_id",
            "original_s_us",
            "original_c_us",
            "held_boundary",
            "target",
            "retirement",
            "observer",
            "observer_cgroup",
            "systemd_run_exit",
            "actual_stdout_empty_eof",
            "overall_native_pass",
        ),
    )
    require(document["schema"] == "DotmacNativeEnvelopeTargetObservation.v1")
    require(document["status"] == "target-cutoff-observed-observer-retirement-pending")
    require(
        document["overall_native_pass"] is False
        and document["actual_stdout_empty_eof"] is True
    )
    require(
        type(document["systemd_run_exit"]) is int and document["systemd_run_exit"] != 0
    )
    for key in ("instance", "boot_id", "case"):
        require(document[key] == record[key])
    require(
        document["original_s_us"] == record["s_us"]
        and document["original_c_us"] == record["c_us"]
    )
    require(
        document["observer"] == observer
        and document["observer_cgroup"]
        == {"group": retained["group"], "event": retained["event"]}
    )
    a.closed(
        document["retirement"],
        (
            "service",
            "expired",
            "expired_enter",
            "timer_trigger",
            "groups",
            "traced_wait_status",
            "wait_observed_interval",
            "post_s_live_witness",
            "original_process_disappeared",
            "retained_recursive_populated_zero",
        ),
    )
    witness = document["retirement"]["post_s_live_witness"]
    a.validate_live_witness(
        record, p, document["target"], identities, observer["process"]["pid"], witness
    )
    observed = document["retirement"]["wait_observed_interval"]
    a.death_interval(record, observed)
    require(witness["after_us"] <= observed["before_us"])
    require(stable(before) == stable(os.fstat(output)))
    fixed_sink(a, p["observer_output"], output, record["evidence_max_bytes"])
    a.clock(record)
    return document


def finish(a, record, p, observer, retained, output, diagnostic, identities):
    keys = (
        "LoadState",
        "InvocationID",
        "ActiveState",
        "SubState",
        "MainPID",
        "Result",
        "ExecMainCode",
        "ExecMainStatus",
        "ExecMainExitTimestampMonotonic",
        "ControlGroup",
    )
    while True:
        a.clock(record)
        values = a.show(record, p["units"]["observer"], keys)
        require(values["InvocationID"] == observer["invocation"])
        if values["MainPID"] == "0":
            break
        require(
            values["MainPID"] == str(observer["process"]["pid"])
            and values["ActiveState"] in ("activating", "active", "deactivating")
        )
        select.select([], [], [], 0.001)
    require(
        values["LoadState"] == "loaded"
        and values["ActiveState"] == "inactive"
        and values["SubState"] == "dead"
    )
    require(
        values["Result"] == "success"
        and values["ExecMainCode"] == "1"
        and values["ExecMainStatus"] == "0"
    )
    require(values["ControlGroup"] in ("", p["observer_group"]))
    exit_us = a.number(values["ExecMainExitTimestampMonotonic"])
    require(record["s_us"] <= exit_us < record["c_us"])
    require(select.select([retained["pidfd"]], [], [], 0)[0] == [retained["pidfd"]])
    require(a.original_gone(observer["process"]["pid"], observer["process"]["start"]))
    recursive_empty(a, retained)
    timer(a, record, p, True)
    fixed_sink(a, p["observer_diagnostic"], diagnostic, record["diagnostic_max_bytes"])
    document = output_document(a, record, p, observer, retained, output, identities)
    require(a.show(record, p["units"]["observer"], keys) == values)
    recursive_empty(a, retained)
    timer(a, record, p, True)
    a.roster(
        record,
        p,
        "observer_ready",
        dict(ActiveState="active", SubState="active", StopWhenUnneeded="no"),
    )
    a.clock(record)
    return dict(
        schema="DotmacNativeEnvelopeOwnerComponentObservation.v1",
        status="observer-normal-retirement-observed-unqualified",
        case=record["case"],
        instance=record["instance"],
        boot_id=record["boot_id"],
        original_s_us=record["s_us"],
        original_c_us=record["c_us"],
        observer=observer,
        observer_terminal=values,
        retained_observer_cgroup={
            "group": retained["group"],
            "event": retained["event"],
        },
        original_observer_disappeared=True,
        observer_pidfd_ready=True,
        observer_recursive_populated_zero=True,
        target_observation=document,
        overall_native_pass=False,
    )


def run(a, record):
    p, identities, output, diagnostic, server = prepare(a, record)
    peer, credentials, packet, rights = receive(a, record, p, server)
    try:
        observer, retained = bind_observer(
            a, record, p, identities, credentials, packet, rights, output, diagnostic
        )
        fixed_sink(
            a, p["observer_output"], output, record["evidence_max_bytes"], empty=True
        )
        fixed_sink(
            a,
            p["observer_diagnostic"],
            diagnostic,
            record["diagnostic_max_bytes"],
            empty=True,
        )
        a.clock(record, True)
        require(peer.send(a.OWNER_ACK) == len(a.OWNER_ACK))
        a.clock(record, True)
    finally:
        peer.close()
        for fd in rights:
            os.close(fd)
    # No waitpid for PID1's child, no kill, no retry/rearm/reset/unlink/recovery.
    return finish(a, record, p, observer, retained, output, diagnostic, identities)


def main():
    require(len(sys.argv) == 1 and os.path.abspath(__file__) == OUTER)
    record, a = load()
    result = run(a, record)
    raw = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )
    require(len(raw) <= record["evidence_max_bytes"])
    a.clock(record)
    require(os.write(1, raw) == len(raw))
    a.clock(record)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit(125) from None
