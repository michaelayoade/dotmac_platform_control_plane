#!/usr/bin/python3.12 -I
"""INERT CANDIDATE SOURCE: fixed disposable-VM intrusive component observer.

External installation/approval is required. This program never issues native
PASS: its normal result still owes the existing owner's observer retirement.
"""

import array
import ctypes
import errno
import hashlib
import json
import os
import re
import resource
import select
import socket
import stat
import struct
import subprocess
import sys
import time

RECORD = "/var/lib/dotmac-gate0-native-envelope/fixture.json"
ADAPTER = "/usr/local/libexec/dotmac-gate0-native-envelope/adapter"
HELPER = "/usr/local/libexec/dotmac-gate0-native-envelope/scratch-helper"
PYTHON = "/usr/bin/python3.12"
RUNC = "/usr/sbin/runc"
LIBC = "/usr/lib/x86_64-linux-gnu/libc.so.6"
OWNER_ACK = b"DOTMAC_NATIVE_ENVELOPE_OWNER_ACK_V1"
OWNER_SCHEMA = "DotmacNativeEnvelopeOwnerRendezvous.v1"
MARKER = b"DOTMAC_NATIVE_ENVELOPE_HELPER_V1"
RELEASE = b"R"
DEPS = (
    "Requires",
    "Wants",
    "BindsTo",
    "Upholds",
    "Requisite",
    "After",
    "Before",
    "Conflicts",
    "PartOf",
)
SEIZE, INTERRUPT, SETOPTIONS, CONT, GETEVENTMSG = 0x4206, 0x4207, 0x4200, 7, 0x4201
TRACEEXEC, EXITKILL, WALL = 0x10, 0x100000, 0x40000000


class Incomplete(Exception):
    pass


def require(condition):
    if not condition:
        raise Incomplete()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def closed(value, keys):
    require(type(value) is dict and set(value) == set(keys))


def integer(value, minimum=1):
    require(type(value) is int and minimum <= value < 2**64 - 1)


def protected(path, directory=False):
    require(path.startswith("/") and ".." not in path.split("/"))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = path.strip("/").split("/")
        for index, part in enumerate(parts):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if index < len(parts) - 1 or directory:
                flags |= os.O_DIRECTORY
            nxt = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = nxt
            s = os.fstat(fd)
            require(s.st_uid == 0 and s.st_gid == 0 and not s.st_mode & 0o022)
            require(
                stat.S_ISDIR(s.st_mode)
                if index < len(parts) - 1 or directory
                else stat.S_ISREG(s.st_mode)
            )
        return fd
    except BaseException:
        os.close(fd)
        raise


def public_bytes(path, limit):
    fd = protected(path)
    try:
        s = os.fstat(fd)
        require(0 < s.st_size <= limit)
        raw = os.read(fd, limit + 1)
        require(len(raw) == s.st_size)
        return raw
    finally:
        os.close(fd)


def paths(record):
    instance = record["instance"] + "-" + record["case"]
    base = "/var/lib/dotmac-gate0-native-envelope/" + instance
    target = "dotmac-gate0-" + instance
    observer = "dotmac-gate0-native-observer-" + instance
    units = dict(
        service=target + ".service",
        ready=target + "-ready.target",
        timer=target + "-cutoff.timer",
        expired=target + "-expired.target",
        observer=observer + ".service",
        observer_ready=observer + "-ready.target",
        observer_timer=observer + "-cutoff.timer",
        observer_expired=observer + "-expired.target",
    )
    return dict(
        base=base,
        instance=instance,
        units=units,
        group="/system.slice/" + units["service"],
        observer_group="/system.slice/" + units["observer"],
        bundle=base + "/bundle",
        runc_root="/run/dm-g0n/" + record["instance"] + "/runc",
        socket="/run/dm-g0n/" + record["instance"] + "/marker",
        diagnostic=base + "/diagnostics",
        once=base + "/observer-once",
        netns="/run/netns/" + instance,
        owner_socket="/run/dm-g0n/" + record["instance"] + "/owner",
        outer_once=base + "/outer-once",
        observer_output=base + "/observer-output",
        observer_diagnostic=base + "/observer-diagnostics",
    )


def validate_record(record):
    closed(
        record,
        (
            "schema",
            "isolation_scope",
            "case",
            "instance",
            "boot_id",
            "not_before_wall_us",
            "not_before_mono_us",
            "e_wall_us",
            "e_mono_us",
            "r_us",
            "t_us",
            "s_us",
            "c_us",
            "accuracy_us",
            "observer_accuracy_us",
            "cpu_quota_percent",
            "memory_max_bytes",
            "tasks_max",
            "diagnostic_max_bytes",
            "evidence_max_bytes",
            "manager_version",
            "kernel_release",
            "yama_scope",
            "libc_abi",
            "image_digest",
            "rootfs_tree_digest",
            "installation_evidence_digest",
            "pins",
            "rosters",
        ),
    )
    require(record["schema"] == "DotmacNativeEnvelopeFixture.v2")
    require(record["isolation_scope"] == "disposable-task-vm-only")
    require(record["case"] in ("pre-guard-stop", "runc-exec-stop"))
    require(
        type(record["instance"]) is str
        and re.fullmatch("[0-9a-f]{64}", record["instance"]) is not None
    )
    require(
        type(record["boot_id"]) is str
        and re.fullmatch("[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}", record["boot_id"])
        is not None
    )
    for key in (
        "not_before_wall_us",
        "not_before_mono_us",
        "e_wall_us",
        "e_mono_us",
        "r_us",
        "t_us",
        "s_us",
        "c_us",
        "accuracy_us",
        "observer_accuracy_us",
        "cpu_quota_percent",
        "memory_max_bytes",
        "tasks_max",
        "diagnostic_max_bytes",
        "evidence_max_bytes",
    ):
        integer(record[key])
    duration = record["e_wall_us"] - record["not_before_wall_us"]
    require(
        0 < duration <= 300_000_000
        and duration == record["e_mono_us"] - record["not_before_mono_us"]
    )
    require(
        record["t_us"] <= record["r_us"]
        and record["c_us"] == record["e_mono_us"] + record["r_us"]
        and record["s_us"] == record["c_us"] - record["t_us"]
    )
    require(
        record["accuracy_us"] <= record["t_us"]
        and record["observer_accuracy_us"] <= record["t_us"]
    )
    require(
        type(record["manager_version"]) is str
        and re.fullmatch("255([. -][A-Za-z0-9_.+() -]+)?", record["manager_version"])
        is not None
    )
    require(
        type(record["kernel_release"]) is str
        and re.fullmatch("[A-Za-z0-9_.+-]+", record["kernel_release"]) is not None
    )
    require(record["libc_abi"] == "linux-x86_64-glibc-ptrace-long")
    require(type(record["yama_scope"]) is int and record["yama_scope"] in (0, 1, 2))
    for key in ("image_digest", "rootfs_tree_digest", "installation_evidence_digest"):
        value = record[key]
        require(
            type(value) is str
            and re.fullmatch("[0-9a-f]{64}", value) is not None
            and value != "0" * 64
        )
    p = paths(record)
    pin_paths = dict(
        adapter=ADAPTER,
        helper=HELPER,
        python=PYTHON,
        runc=RUNC,
        libc=LIBC,
        systemd_run="/usr/bin/systemd-run",
        systemctl="/usr/bin/systemctl",
        manager="/usr/lib/systemd/systemd",
        bundle_config=p["bundle"] + "/config.json",
        rootfs_manifest=p["base"] + "/rootfs-manifest.json",
        installation_evidence=p["base"] + "/installation-evidence.json",
    )
    pin_paths.update(
        {
            kind: "/etc/systemd/system/" + unit
            for kind, unit in p["units"].items()
            if kind != "service"
        }
    )
    closed(record["pins"], pin_paths)
    for pin in record["pins"].values():
        closed(pin, ("sha256", "size", "mode"))
        integer(pin["size"])
        require(
            type(pin["mode"]) is int
            and pin["mode"] in (0o444, 0o600, 0o644, 0o555, 0o755)
        )
        require(
            type(pin["sha256"]) is str
            and re.fullmatch("[0-9a-f]{64}", pin["sha256"]) is not None
            and pin["sha256"] != "0" * 64
        )
    for key in (
        "adapter",
        "helper",
        "python",
        "runc",
        "systemd_run",
        "systemctl",
        "manager",
    ):
        require(record["pins"][key]["mode"] in (0o555, 0o755))
    require(
        record["pins"]["installation_evidence"]["sha256"]
        == record["installation_evidence_digest"]
    )
    closed(record["rosters"], p["units"])
    u = p["units"]
    special = {
        ("service", "Requisite"): {u["ready"]},
        ("service", "After"): {u["ready"]},
        ("service", "Conflicts"): {u["expired"]},
        ("ready", "Before"): {u["service"]},
        ("ready", "Conflicts"): {u["expired"]},
        ("timer", "Before"): {u["expired"]},
        ("expired", "Conflicts"): {u["ready"], u["service"]},
        ("observer", "Conflicts"): {u["observer_expired"]},
        ("observer", "Requisite"): {u["observer_ready"]},
        ("observer", "After"): {u["observer_ready"]},
        ("observer_ready", "Before"): {u["observer"]},
        ("observer_ready", "Conflicts"): {u["observer_expired"]},
        ("observer_timer", "Before"): {u["observer_expired"]},
        ("observer_expired", "Conflicts"): {u["observer_ready"], u["observer"]},
    }
    for kind, roster in record["rosters"].items():
        closed(roster, DEPS)
        for key, words in roster.items():
            require(
                type(words) is list
                and all(type(w) is str for w in words)
                and len(words) == len(set(words))
            )
            permitted = special.get((kind, key), set()) | (
                {"system.slice", "-.slice"}
                if kind in ("service", "observer")
                else set()
            )
            require(set(words) <= permitted)
    require(
        record["rosters"]["service"]["Requisite"] == [u["ready"]]
        and u["ready"] in record["rosters"]["service"]["After"]
    )
    require(
        set(record["rosters"]["expired"]["Conflicts"]) == {u["ready"], u["service"]}
    )
    require(
        set(record["rosters"]["observer_expired"]["Conflicts"])
        == {u["observer_ready"], u["observer"]}
    )
    require(
        record["rosters"]["observer"]["Requisite"] == [u["observer_ready"]]
        and u["observer_ready"] in record["rosters"]["observer"]["After"]
    )
    for key in ("Requires", "Wants", "BindsTo", "Upholds"):
        require(u["observer_ready"] not in record["rosters"]["observer"][key])
    return p, pin_paths


def clock(record, eligibility=False):
    with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as f:
        require(f.read() == record["boot_id"] + "\n")
    now = time.monotonic_ns() // 1000
    require(now < record["c_us"])
    if eligibility:
        wall = time.time_ns() // 1000
        require(record["not_before_wall_us"] <= wall < record["e_wall_us"])
        require(
            record["not_before_mono_us"]
            <= now
            < min(record["e_mono_us"], record["s_us"])
        )
    return now


def timespan(value):
    require(type(value) is str and 1 <= len(value) <= 63)
    if value == "0":
        return 0
    scales = {
        "y": 31557600000000,
        "month": 2629800000000,
        "w": 604800000000,
        "d": 86400000000,
        "h": 3600000000,
        "min": 60000000,
        "s": 1000000,
        "ms": 1000,
        "us": 1,
    }
    total, previous = 0, 2**64
    parts = value.split(" ")
    for index, part in enumerate(parts):
        match = re.fullmatch(
            r"([1-9][0-9]*)(?:\.([0-9]+))?(y|month|w|d|h|min|s|ms|us)", part
        )
        require(match is not None)
        whole, fraction, unit = match.groups()
        scale = scales[unit]
        require(scale < previous)
        component = int(whole) * scale
        if fraction is not None:
            precision = {"s": 6, "ms": 3}.get(unit)
            require(
                precision is not None
                and len(fraction) <= precision
                and index == len(parts) - 1
            )
            component += int(fraction) * 10 ** (precision - len(fraction))
        total += component
        require(total < 2**64 - 1)
        previous = scale
    return total


def number(value):
    require(type(value) is str and re.fullmatch("[0-9]{1,20}", value) is not None)
    return int(value)


def show(record, unit, keys):
    clock(record)
    vector = [
        "/usr/bin/systemctl",
        "--system",
        "--no-pager",
        "show",
        "--all",
        "--property=" + ",".join(sorted(keys)),
    ]
    if unit:
        vector.append(unit)
    # Fixed systemctl vector; command execution is mocked in source conformance.
    result = subprocess.run(  # noqa: S603
        vector,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={},
        timeout=(record["c_us"] - time.monotonic_ns() // 1000) / 1_000_000,
        check=False,
    )
    clock(record)
    require(result.returncode == 0 and len(result.stdout) <= 65536)
    values = {}
    for line in result.stdout.decode("ascii").splitlines():
        key, sep, value = line.partition("=")
        require(sep and key in keys and key not in values)
        values[key] = value
    require(set(values) == set(keys))
    return values


def file_pin(path, pin):
    fd = protected(path)
    try:
        before = os.fstat(fd)
        require(
            before.st_size == pin["size"]
            and stat.S_IMODE(before.st_mode) == pin["mode"]
        )
        digest = hashlib.sha256()
        count = 0
        while True:
            raw = os.read(fd, 65536)
            if not raw:
                break
            count += len(raw)
            require(count <= pin["size"])
            digest.update(raw)
        after = os.fstat(fd)
        require(count == pin["size"] and digest.hexdigest() == pin["sha256"])
        require(
            (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            == (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
        )
        return before.st_dev, before.st_ino
    finally:
        os.close(fd)


def fixed_exec(value, path):
    prefix = "{ path=" + path + " ; argv[]=" + path + " ; ignore_errors=no ; "
    require(
        value.startswith(prefix) and value.count("path=") == 1 and value.endswith(" }")
    )
    metadata = {}
    for field in value[len(prefix) : -2].split(" ; "):
        key, sep, raw = field.partition("=")
        require(
            sep and key not in metadata and raw and not any(c in raw for c in "{};\r\n")
        )
        metadata[key] = raw
    require(tuple(metadata) == ("start_time", "stop_time", "pid", "code", "status"))
    number(metadata["pid"])
    require(re.fullmatch(r"(?:\(null\)|[A-Za-z_]+)", metadata["code"]) is not None)
    require(
        re.fullmatch(r"[0-9]+(?:/[A-Za-z0-9_+-]+)?", metadata["status"]) is not None
    )


def roster(record, p, kind, extra):
    expected = dict(
        LoadState="loaded",
        DefaultDependencies="no",
        DropInPaths="",
        FragmentPath=(
            "/run/systemd/transient/" if kind == "service" else "/etc/systemd/system/"
        )
        + p["units"][kind],
    )
    expected.update({k: " ".join(v) for k, v in record["rosters"][kind].items()})
    expected.update(extra)
    actual = show(record, p["units"][kind], expected.keys())
    for key, value in expected.items():
        measured = (
            timespan(actual[key])
            if key
            in (
                "NextElapseUSecMonotonic",
                "AccuracyUSec",
                "RandomizedDelayUSec",
                "TimeoutStopUSec",
                "CPUQuotaPerSecUSec",
            )
            else actual[key]
        )
        require(measured == value)
    return actual


def service_base(record):
    return dict(
        Type="exec",
        ExitType="main",
        Restart="no",
        SuccessExitStatus="",
        RemainAfterExit="no",
        KillMode="control-group",
        KillSignal="9",
        FinalKillSignal="9",
        SendSIGKILL="yes",
        User="0",
        Group="0",
        LimitCORE="0",
        LimitFSIZE=str(record["diagnostic_max_bytes"]),
        ExecCondition="",
        ExecStartPre="",
        ExecStartPost="",
        ExecReload="",
        ExecStop="",
        ExecStopPost="",
        SuccessAction="none",
        FailureAction="none",
        OnSuccess="",
        OnFailure="",
    )


def validate_observer(record, p, identities):
    expected = service_base(record)
    expected.update(
        ControlGroup=p["observer_group"],
        Delegate="no",
        TimeoutStopUSec=record["t_us"],
        CPUQuotaPerSecUSec=record["cpu_quota_percent"] * 10000,
        MemoryMax=str(record["memory_max_bytes"]),
        TasksMax=str(record["tasks_max"]),
    )
    roster(record, p, "observer", expected)
    actual = show(
        record,
        p["units"]["observer"],
        ("MainPID", "InvocationID", "ExecStart", "ActiveState"),
    )
    require(actual["MainPID"] == str(os.getpid()) and actual["ActiveState"] == "active")
    invocation = actual["InvocationID"]
    require(
        re.fullmatch("[0-9a-f]{32}", invocation) is not None and invocation != "0" * 32
    )
    require(os.environ.get("INVOCATION_ID") == invocation)
    fixed_exec(actual["ExecStart"], ADAPTER)
    require(
        proc_bytes(os.getpid(), "cgroup")
        == ("0::" + p["observer_group"] + "\n").encode()
    )
    observer = process_snapshot(
        os.getpid(),
        p["observer_group"],
        PYTHON,
        identities["python"],
        [PYTHON, "-I", ADAPTER],
        single=False,
    )
    require(observer["ppid"] == 1)
    roster(
        record,
        p,
        "observer_timer",
        dict(
            ActiveState="active",
            SubState="waiting",
            NextElapseUSecMonotonic=record["c_us"],
            AccuracyUSec=record["observer_accuracy_us"],
            RandomizedDelayUSec=0,
            WakeSystem="no",
            RemainAfterElapse="yes",
            Unit=p["units"]["observer_expired"],
        ),
    )
    roster(record, p, "observer_expired", dict(ActiveState="inactive", SubState="dead"))
    roster(
        record,
        p,
        "observer_ready",
        dict(ActiveState="active", SubState="active", StopWhenUnneeded="no"),
    )
    return dict(invocation=invocation, process=observer)


def proc_bytes(pid, leaf):
    with open("/proc/" + str(pid) + "/" + leaf, "rb") as f:
        raw = f.read(65537)
        require(len(raw) <= 65536)
        return raw


def process_snapshot(pid, group, exe, identity, argv, single=True):
    raw = proc_bytes(pid, "stat")
    end = raw.rfind(b")")
    require(end > 0)
    fields = raw[end + 2 :].split()
    require(len(fields) >= 20 and fields[0] not in (b"Z", b"X"))
    start = number(fields[19].decode())
    require(start > 0)
    require(os.readlink("/proc/" + str(pid) + "/exe") == exe)
    s = os.stat("/proc/" + str(pid) + "/exe")
    require((s.st_dev, s.st_ino) == identity)
    require(proc_bytes(pid, "cmdline") == ("\0".join(argv) + "\0").encode("ascii"))
    require(proc_bytes(pid, "cgroup") == ("0::" + group + "\n").encode("ascii"))
    status = {}
    for line in proc_bytes(pid, "status").decode("ascii").splitlines():
        key, sep, value = line.partition(":")
        if sep:
            status[key] = value.strip()
    require(status["Uid"].split() == ["0"] * 4 and status["Gid"].split() == ["0"] * 4)
    require(os.listdir("/proc/" + str(pid) + "/task") == [str(pid)])
    if single:
        require(not proc_bytes(pid, "task/" + str(pid) + "/children").strip())
    return dict(
        pid=pid,
        start=start,
        ppid=number(fields[1].decode()),
        exe_device=s.st_dev,
        exe_inode=s.st_ino,
        cgroup=group,
    )


def target_snapshot(record, p, pid, identities):
    clock(record, True)
    expected = service_base(record)
    expected.update(
        Delegate="yes",
        DelegateSubgroup="launcher",
        ControlGroup=p["group"],
        TimeoutStopUSec=record["t_us"],
        CPUQuotaPerSecUSec=record["cpu_quota_percent"] * 10000,
        MemoryMax=str(record["memory_max_bytes"]),
        TasksMax=str(record["tasks_max"]),
    )
    roster(record, p, "service", expected)
    actual = show(
        record,
        p["units"]["service"],
        ("MainPID", "InvocationID", "ExecStart", "ActiveState"),
    )
    require(
        actual["MainPID"] == str(pid)
        and actual["ActiveState"] in ("activating", "active")
    )
    require(
        re.fullmatch("[0-9a-f]{32}", actual["InvocationID"]) is not None
        and actual["InvocationID"] != "0" * 32
    )
    fixed_exec(actual["ExecStart"], HELPER)
    proc = process_snapshot(
        pid,
        p["group"] + "/launcher",
        PYTHON,
        identities["python"],
        [PYTHON, "-I", HELPER],
    )
    require(proc["ppid"] == 1)
    return dict(invocation=actual["InvocationID"], process=proc)


def fd_identity(fd):
    s = os.fstat(fd)
    return [s.st_dev, s.st_ino, stat.S_IFMT(s.st_mode), s.st_rdev]


def tracer_identity(pid, tracer):
    values = [
        line.split(b":", 1)[1].strip()
        for line in proc_bytes(pid, "status").splitlines()
        if line.startswith(b"TracerPid:")
    ]
    require(values == [str(tracer).encode("ascii")])


def tracee_descriptors(pid, expected, rendezvous):
    directory = "/proc/" + str(pid) + "/fd"
    require(
        set(os.listdir(directory))
        == ({"0", "1", "2", "3"} if rendezvous else {"0", "1", "2"})
    )
    for fd in (0, 1, 2):
        s = os.stat(directory + "/" + str(fd))
        require([s.st_dev, s.st_ino, stat.S_IFMT(s.st_mode), s.st_rdev] == expected[fd])
    if rendezvous:
        require(os.readlink(directory + "/3").startswith("socket:["))
        raw = proc_bytes(pid, "fdinfo/3").decode("ascii")
        flags = [
            line.split(":", 1)[1].strip()
            for line in raw.splitlines()
            if line.startswith("flags:")
        ]
        require(len(flags) == 1 and int(flags[0], 8) & os.O_CLOEXEC)


class Groups:
    def __init__(self, p, pid):
        self.handles = []
        self.root = "/sys/fs/cgroup" + p["group"]
        for suffix in ("", "/launcher"):
            directory = protected(self.root + suffix, True)
            event = os.open(
                "cgroup.events", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory
            )
            self.handles.append(
                (directory, event, fd_identity(directory), fd_identity(event))
            )
        self.still_only(pid)
        self.evidence = [
            dict(group=identity, event=event_identity)
            for _, _, identity, event_identity in self.handles
        ]

    def no_payload(self):
        require(not os.path.lexists(self.root + "/payload"))

    def still_only(self, pid):
        require(
            [
                name
                for name in os.listdir(self.root)
                if os.path.isdir(self.root + "/" + name)
            ]
            == ["launcher"]
        )
        require(not public_cgroup(self.root + "/cgroup.procs").strip())
        require(
            public_cgroup(self.root + "/launcher/cgroup.procs").strip()
            == str(pid).encode()
        )

    def empty(self):
        for directory, event, identity, event_identity in self.handles:
            require(
                fd_identity(directory) == identity
                and fd_identity(event) == event_identity
            )
            raw = os.pread(event, 4096, 0)
            values = {}
            for line in raw.decode("ascii").splitlines():
                pair = line.split()
                require(
                    len(pair) == 2
                    and pair[0] in ("populated", "frozen")
                    and pair[0] not in values
                    and pair[1] in ("0", "1")
                )
                values[pair[0]] = pair[1]
            require("populated" in values)
            if values["populated"] != "0":
                return False
        return True


def public_cgroup(path):
    with open(path, "rb") as f:
        return f.read(4096)


class Trace:
    def __init__(self, pid):
        self.pid = pid
        self.libc = ctypes.CDLL(LIBC, use_errno=True)
        self.libc.ptrace.argtypes = [
            ctypes.c_uint,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        self.libc.ptrace.restype = ctypes.c_long

    def operation(self, request, data=0):
        require(request in (SEIZE, INTERRUPT, SETOPTIONS, CONT, GETEVENTMSG))
        if request == SEIZE:
            require(data == 0)
        if request == SETOPTIONS:
            require(data == TRACEEXEC | EXITKILL)
        if request in (INTERRUPT, CONT):
            require(data == 0)
        ctypes.set_errno(0)
        result = self.libc.ptrace(request, self.pid, None, ctypes.c_void_p(data))
        require(result != -1 or ctypes.get_errno() == 0)

    def old_exec_tid(self):
        value = ctypes.c_ulong()
        ctypes.set_errno(0)
        result = self.libc.ptrace(
            GETEVENTMSG,
            self.pid,
            None,
            ctypes.cast(ctypes.byref(value), ctypes.c_void_p),
        )
        require(result != -1 or ctypes.get_errno() == 0)
        return value.value


def wait_event(record, pid, wanted):
    while True:
        clock(record)
        actual, status = os.waitpid(pid, WALL | os.WNOHANG)
        if actual:
            require(
                actual == pid
                and os.WIFSTOPPED(status)
                and os.WSTOPSIG(status) == 5
                and status >> 16 == wanted
            )
            return status
        select.select(
            [],
            [],
            [],
            min((record["c_us"] - time.monotonic_ns() // 1000) / 1_000_000, 0.001),
        )


def launch_vector(record, p):
    properties = dict(
        Type="exec",
        ExitType="main",
        DefaultDependencies="no",
        Requisite=p["units"]["ready"],
        After=p["units"]["ready"],
        Restart="no",
        SuccessExitStatus="",
        RemainAfterExit="no",
        KillMode="control-group",
        KillSignal="SIGKILL",
        FinalKillSignal="SIGKILL",
        SendSIGKILL="yes",
        TimeoutStopSec=str(record["t_us"]) + "us",
        Delegate="yes",
        DelegateSubgroup="launcher",
        User="0",
        Group="0",
        LimitCORE="0",
        LimitFSIZE=str(record["diagnostic_max_bytes"]),
        CPUQuota=str(record["cpu_quota_percent"]) + "%",
        MemoryMax=str(record["memory_max_bytes"]),
        TasksMax=str(record["tasks_max"]),
    )
    return (
        [
            "/usr/bin/systemd-run",
            "--quiet",
            "--pipe",
            "--wait",
            "--expand-environment=no",
            "--unit=" + p["units"]["service"],
        ]
        + ["--property=" + k + "=" + v for k, v in properties.items()]
        + [HELPER]
    )


def runc_vector(p):
    return [
        RUNC,
        "--root",
        p["runc_root"],
        "run",
        "--keep",
        "--bundle",
        p["bundle"],
        p["instance"],
    ]


def original_gone(pid, start):
    try:
        raw = proc_bytes(pid, "stat")
        fields = raw[raw.rfind(b")") + 2 :].split()
        require(len(fields) >= 20)
        return number(fields[19].decode()) != start
    except OSError as error:
        require(error.errno in (errno.ENOENT, errno.ESRCH))
        return True


def death_interval(record, observed):
    closed(observed, ("before_us", "after_us"))
    integer(observed["before_us"])
    integer(observed["after_us"])
    require(
        record["s_us"] <= observed["before_us"] <= observed["after_us"] < record["c_us"]
    )


def validate_live_witness(record, p, bound, identities, tracer, witness):
    """Closed post-S observed liveness, never a kernel death/causality stamp."""
    closed(bound, ("invocation", "process"))
    require(
        type(bound["invocation"]) is str
        and re.fullmatch("[0-9a-f]{32}", bound["invocation"]) is not None
        and bound["invocation"] != "0" * 32
    )
    fields = ("pid", "start", "ppid", "exe_device", "exe_inode", "cgroup")
    closed(bound["process"], fields)
    initial = bound["process"]
    for key in ("pid", "start", "ppid", "exe_device", "exe_inode"):
        integer(initial[key])
    require(initial["ppid"] == 1 and initial["cgroup"] == p["group"] + "/launcher")
    require((initial["exe_device"], initial["exe_inode"]) == identities["python"])
    closed(
        witness,
        (
            "schema",
            "case",
            "before_us",
            "after_us",
            "process",
            "state",
            "tracer_pid",
            "pidfd_ready",
        ),
    )
    require(
        witness["schema"] == "DotmacNativeEnvelopePostSLiveWitness.v1"
        and witness["case"] == record["case"]
    )
    integer(witness["before_us"])
    integer(witness["after_us"])
    integer(witness["tracer_pid"])
    integer(tracer)
    require(
        record["s_us"] <= witness["before_us"] <= witness["after_us"] < record["c_us"]
    )
    require(
        witness["state"] == "t"
        and witness["tracer_pid"] == tracer
        and witness["pidfd_ready"] is False
    )
    closed(witness["process"], fields)
    process = witness["process"]
    for key in ("pid", "start", "ppid", "exe_device", "exe_inode"):
        integer(process[key])
    for key in ("pid", "start", "ppid", "cgroup"):
        require(process[key] == initial[key])
    identity = identities["python" if record["case"] == "pre-guard-stop" else "runc"]
    require((process["exe_device"], process["exe_inode"]) == identity)


def hold_to_post_s_witness(record, p, bound, pidfd, identities):
    """Never consume a terminal wait until original target is observed alive after S."""
    pid = bound["process"]["pid"]
    tracer = os.getpid()
    helper = record["case"] == "pre-guard-stop"
    exe, identity, argv = (
        (PYTHON, identities["python"], [PYTHON, "-I", HELPER])
        if helper
        else (RUNC, identities["runc"], runc_vector(p))
    )
    while True:
        before = clock(record)
        require(not select.select([pidfd], [], [], 0)[0])
        process = process_snapshot(pid, p["group"] + "/launcher", exe, identity, argv)
        require(
            process["pid"] == pid
            and process["start"] == bound["process"]["start"]
            and process["ppid"] == 1
        )
        raw = proc_bytes(pid, "stat")
        end = raw.rfind(b")")
        require(end > 0)
        fields = raw[end + 2 :].split()
        require(len(fields) >= 20 and fields[0] == b"t")
        require(number(fields[19].decode()) == bound["process"]["start"])
        tracer_identity(pid, tracer)
        require(not select.select([pidfd], [], [], 0)[0])
        after = clock(record)
        require(before <= after < record["c_us"])
        if before >= record["s_us"]:
            witness = dict(
                schema="DotmacNativeEnvelopePostSLiveWitness.v1",
                case=record["case"],
                before_us=before,
                after_us=after,
                process=process,
                state="t",
                tracer_pid=tracer,
                pidfd_ready=False,
            )
            validate_live_witness(record, p, bound, identities, tracer, witness)
            return witness
        # A pre-S sample, even one whose after-read crosses S, is not a witness.
        ready = select.select(
            [pidfd], [], [], min(0.001, (record["c_us"] - after) / 1_000_000)
        )[0]
        require(not ready)


def wait_death(record, pid):
    while True:
        before = clock(record)
        actual, status = os.waitpid(pid, WALL | os.WNOHANG)
        after = clock(record)
        if actual:
            require(
                actual == pid and os.WIFSIGNALED(status) and os.WTERMSIG(status) == 9
            )
            observed = dict(before_us=before, after_us=after)
            death_interval(record, observed)
            return status, observed
        select.select([], [], [], 0.001)


def retirement(
    record,
    p,
    bound,
    pidfd,
    groups,
    death_status,
    observed_death,
    witness,
    identities,
    tracer,
):
    require(os.WIFSIGNALED(death_status) and os.WTERMSIG(death_status) == 9)
    death_interval(record, observed_death)
    validate_live_witness(record, p, bound, identities, tracer, witness)
    require(witness["after_us"] <= observed_death["before_us"])
    while True:
        clock(record)
        values = show(
            record,
            p["units"]["service"],
            (
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
            ),
        )
        require(values["InvocationID"] == bound["invocation"])
        if values["MainPID"] == "0" and values["ActiveState"] in ("failed", "inactive"):
            break
        select.select([], [], [], 0.001)
    require(
        values["LoadState"] == "loaded"
        and (values["ActiveState"], values["SubState"])
        in (("failed", "failed"), ("inactive", "dead"))
    )
    # PID1 may classify an intentional stop as success; actual traced death and
    # ExecMainCode/status still must be SIGKILL. Never call this supervisor0.
    require(
        values["Result"] in ("signal", "success")
        and values["ExecMainCode"] == "2"
        and values["ExecMainStatus"] == "9"
    )
    exit_us = number(values["ExecMainExitTimestampMonotonic"])
    require(
        record["s_us"] <= exit_us < record["c_us"]
        and values["ControlGroup"] in ("", p["group"])
    )
    expired = roster(
        record, p, "expired", dict(ActiveState="active", SubState="active")
    )
    entered = show(record, p["units"]["expired"], ("ActiveEnterTimestampMonotonic",))
    entered_us = number(entered["ActiveEnterTimestampMonotonic"])
    require(record["s_us"] <= entered_us < record["c_us"])
    roster(
        record,
        p,
        "ready",
        dict(ActiveState="inactive", SubState="dead", StopWhenUnneeded="no"),
    )
    roster(
        record,
        p,
        "timer",
        dict(
            ActiveState="active",
            SubState="elapsed",
            AccuracyUSec=record["accuracy_us"],
            RandomizedDelayUSec=0,
            WakeSystem="no",
            RemainAfterElapse="yes",
            Unit=p["units"]["expired"],
        ),
    )
    trigger = show(record, p["units"]["timer"], ("LastTriggerUSecMonotonic",))
    trigger_us = timespan(trigger["LastTriggerUSecMonotonic"])
    require(record["s_us"] <= trigger_us < record["c_us"] and trigger_us <= entered_us)
    require(select.select([pidfd], [], [], 0)[0] == [pidfd])
    require(original_gone(bound["process"]["pid"], bound["process"]["start"]))
    require(groups.empty())
    require(show(record, p["units"]["service"], values.keys()) == values)
    clock(record)
    return dict(
        service=values,
        expired=expired,
        expired_enter=entered,
        timer_trigger=trigger,
        groups=groups.evidence,
        traced_wait_status=death_status,
        wait_observed_interval=observed_death,
        post_s_live_witness=witness,
        original_process_disappeared=True,
        retained_recursive_populated_zero=True,
    )


def exclusive(path, raw):
    parent, name = path.rsplit("/", 1)
    directory = protected(parent, True)
    try:
        fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        try:
            require(os.write(fd, raw) == len(raw))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(directory)
    finally:
        os.close(directory)


def prerequisites(record, p, pin_paths):
    require(
        os.geteuid() == 0
        and os.uname().sysname == "Linux"
        and os.uname().machine == "x86_64"
        and os.uname().release == record["kernel_release"]
    )
    identities = {
        key: file_pin(path, record["pins"][key]) for key, path in pin_paths.items()
    }
    for path in (p["base"], p["runc_root"], p["socket"].rsplit("/", 1)[0]):
        directory = protected(path, True)
        try:
            require(stat.S_IMODE(os.fstat(directory).st_mode) == 0o700)
        finally:
            os.close(directory)
    require(os.readlink("/proc/1/exe") == "/usr/lib/systemd/systemd")
    s = os.stat("/proc/1/exe")
    require((s.st_dev, s.st_ino) == identities["manager"])
    require(show(record, "", ("Version",)) == {"Version": record["manager_version"]})
    mountinfo = proc_bytes(os.getpid(), "mountinfo").decode("ascii").splitlines()
    cgroups = [
        line.split() for line in mountinfo if line.split()[4] == "/sys/fs/cgroup"
    ]
    require(len(cgroups) == 1 and cgroups[0][cgroups[0].index("-") + 1] == "cgroup2")
    for namespace in ("pid", "cgroup"):
        own, parent = (
            os.stat("/proc/self/ns/" + namespace),
            os.stat("/proc/1/ns/" + namespace),
        )
        require((own.st_dev, own.st_ino) == (parent.st_dev, parent.st_ino))
    with open("/proc/sys/kernel/yama/ptrace_scope", encoding="ascii") as f:
        require(f.read() == str(record["yama_scope"]) + "\n")
    require(
        ctypes.sizeof(ctypes.c_long) == 8
        and ctypes.sizeof(ctypes.c_ulong) == 8
        and ctypes.sizeof(ctypes.c_void_p) == 8
        and ctypes.sizeof(ctypes.c_int) == 4
    )
    maps = proc_bytes(os.getpid(), "maps").decode("ascii").splitlines()
    libc_maps = [line.split() for line in maps if line.split()[-1] == LIBC]
    require(libc_maps)
    for mapping in libc_maps:
        major, minor = mapping[3].split(":")
        require(
            (os.makedev(int(major, 16), int(minor, 16)), int(mapping[4]))
            == identities["libc"]
        )
    runc = protected(RUNC)
    try:
        require(not os.fstat(runc).st_mode & (stat.S_ISUID | stat.S_ISGID))
        elf = os.read(runc, 20)
        require(
            len(elf) == 20
            and elf[:6] == b"\x7fELF\x02\x01"
            and int.from_bytes(elf[18:20], "little") == 62
        )
    finally:
        os.close(runc)
    try:
        os.getxattr(RUNC, "security.capability")
        raise Incomplete()
    except OSError as error:
        require(error.errno == errno.ENODATA)
    config = json.loads(
        public_bytes(
            p["bundle"] + "/config.json", record["pins"]["bundle_config"]["size"]
        ),
        object_pairs_hook=unique,
    )
    require(config["root"] == {"path": p["base"] + "/rootfs", "readonly": True})
    require(config["linux"]["cgroupsPath"] == p["group"] + "/payload")
    require(
        config["process"]["terminal"] is False
        and config["process"]["user"] == {"uid": 0, "gid": 0, "additionalGids": []}
    )
    namespaces = config["linux"]["namespaces"]
    require(
        namespaces
        == [
            {"type": "pid"},
            {"type": "mount"},
            {"type": "ipc"},
            {"type": "uts"},
            {"type": "cgroup"},
            {"type": "network", "path": p["netns"]},
        ]
    )
    require(
        config["process"]["args"]
        == ["/opt/venv/bin/dotmac-platform", "gate0", "supervise"]
    )
    require(
        config["process"]["cwd"] == "/app"
        and config["process"]["env"]
        == [
            "PATH=/opt/venv/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "VIRTUAL_ENV=/opt/venv",
            "PYTHONDONTWRITEBYTECODE=1",
            "PYTHONUNBUFFERED=1",
        ]
    )
    p0 = [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_KILL",
        "CAP_SETGID",
        "CAP_SETUID",
        "CAP_SETPCAP",
        "CAP_NET_ADMIN",
        "CAP_SYS_CHROOT",
    ]
    require(
        config["process"]["noNewPrivileges"] is True
        and config["process"]["capabilities"]
        == {
            "bounding": p0,
            "effective": p0,
            "permitted": p0,
            "ambient": [],
            "inheritable": [],
        }
    )
    require(
        config["process"]["rlimits"]
        == [
            {"type": "RLIMIT_CORE", "hard": 0, "soft": 0},
            {
                "type": "RLIMIT_FSIZE",
                "hard": record["diagnostic_max_bytes"],
                "soft": record["diagnostic_max_bytes"],
            },
        ]
    )
    require(
        resource.getrlimit(resource.RLIMIT_FSIZE)
        == (record["diagnostic_max_bytes"], record["diagnostic_max_bytes"])
    )
    return identities


def owner_rendezvous(record, p, observer, groups):
    """No target can start until the existing installation owner retains identity."""
    clock(record, True)
    parent = protected(p["owner_socket"].rsplit("/", 1)[0], True)
    try:
        require(stat.S_IMODE(os.fstat(parent).st_mode) == 0o700)
    finally:
        os.close(parent)
    metadata = os.stat(p["owner_socket"], follow_symlinks=False)
    require(
        stat.S_ISSOCK(metadata.st_mode)
        and metadata.st_uid == metadata.st_gid == 0
        and stat.S_IMODE(metadata.st_mode) == 0o600
    )
    packet = dict(
        schema=OWNER_SCHEMA,
        instance=record["instance"],
        boot_id=record["boot_id"],
        observer=observer,
    )
    raw = json.dumps(packet, sort_keys=True, separators=(",", ":")).encode("ascii")
    require(len(raw) <= 16384)
    peer = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    try:
        peer.settimeout(
            (min(record["e_mono_us"], record["s_us"]) - time.monotonic_ns() // 1000)
            / 1_000_000
        )
        peer.connect(p["owner_socket"])
        pid, uid, gid = struct.unpack(
            "3i",
            peer.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            ),
        )
        require(pid > 0 and uid == gid == 0)
        rights = array.array("i", [groups.directory, groups.events])
        require(
            peer.sendmsg([raw], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
            == len(raw)
        )
        ack, ancillary, flags, _ = peer.recvmsg(
            len(OWNER_ACK) + 1, socket.CMSG_SPACE(4)
        )
        require(ack == OWNER_ACK and not ancillary and flags == 0)
        clock(record, True)
    finally:
        peer.close()
    clock(record, True)


def run(record):
    p, pin_paths = validate_record(record)
    clock(record, True)
    identities = prerequisites(record, p, pin_paths)
    observer = validate_observer(record, p, identities)
    require(
        show(record, p["units"]["service"], ("LoadState",))
        == {"LoadState": "not-found"}
    )
    roster(
        record,
        p,
        "ready",
        dict(ActiveState="active", SubState="active", StopWhenUnneeded="no"),
    )
    roster(record, p, "expired", dict(ActiveState="inactive", SubState="dead"))
    roster(
        record,
        p,
        "timer",
        dict(
            ActiveState="active",
            SubState="waiting",
            NextElapseUSecMonotonic=record["s_us"],
            AccuracyUSec=record["accuracy_us"],
            RandomizedDelayUSec=0,
            WakeSystem="no",
            RemainAfterElapse="yes",
            Unit=p["units"]["expired"],
        ),
    )
    observer_groups = GroupsObserver(p)
    exclusive(p["once"], (p["instance"] + "\n" + record["boot_id"] + "\n").encode())
    owner_rendezvous(record, p, observer, observer_groups)
    diagnostic_parent, diagnostic_name = p["diagnostic"].rsplit("/", 1)
    directory = protected(diagnostic_parent, True)
    try:
        diagnostic = os.open(
            diagnostic_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
    finally:
        os.close(directory)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    socket_parent = protected(p["socket"].rsplit("/", 1)[0], True)
    os.close(socket_parent)
    require(not os.path.lexists(p["socket"]))
    server.bind(p["socket"])
    os.chmod(p["socket"], 0o600)
    server.listen(1)
    clock(record, True)
    # Fixed launch vector; process creation is mocked in source conformance.
    client = subprocess.Popen(  # noqa: S603
        launch_vector(record, p),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=diagnostic,
        env={},
        close_fds=True,
    )
    require(client.stdout is not None)
    null = os.open("/dev/null", os.O_RDONLY | os.O_NOFOLLOW)
    try:
        expected = {
            0: fd_identity(null),
            1: fd_identity(client.stdout.fileno()),
            2: fd_identity(diagnostic),
        }
    finally:
        os.close(null)
    server.settimeout(
        (min(record["e_mono_us"], record["s_us"]) - time.monotonic_ns() // 1000)
        / 1_000_000
    )
    peer, _ = server.accept()
    server.close()
    peer.settimeout(
        (min(record["e_mono_us"], record["s_us"]) - time.monotonic_ns() // 1000)
        / 1_000_000
    )
    pid, uid, gid = struct.unpack(
        "3i",
        peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")),
    )
    require(pid > 0 and uid == 0 and gid == 0)
    marker, ancillary, flags, _ = peer.recvmsg(len(MARKER))
    require(marker == MARKER and not ancillary and flags == 0)
    bound = target_snapshot(record, p, pid, identities)
    tracer_identity(pid, 0)
    tracee_descriptors(pid, expected, True)
    pidfd = os.pidfd_open(pid, 0)
    groups = Groups(p, pid)
    groups.no_payload()
    require(validate_observer(record, p, identities) == observer)
    roster(
        record,
        p,
        "timer",
        dict(
            ActiveState="active",
            SubState="waiting",
            NextElapseUSecMonotonic=record["s_us"],
            AccuracyUSec=record["accuracy_us"],
            RandomizedDelayUSec=0,
            WakeSystem="no",
            RemainAfterElapse="yes",
            Unit=p["units"]["expired"],
        ),
    )
    clock(record, True)
    trace = Trace(pid)
    trace.operation(SEIZE, 0)
    require(target_snapshot(record, p, pid, identities) == bound)
    tracer_identity(pid, os.getpid())
    tracee_descriptors(pid, expected, True)
    trace.operation(INTERRUPT)
    wait_event(record, pid, 128)
    require(target_snapshot(record, p, pid, identities) == bound)
    tracer_identity(pid, os.getpid())
    trace.operation(SETOPTIONS, TRACEEXEC | EXITKILL)
    clock(record, True)
    held = "helper-before-first-runtime-guard"
    if record["case"] == "runc-exec-stop":
        require(peer.send(RELEASE) == 1)
        trace.operation(CONT)
        wait_event(record, pid, 4)
        require(trace.old_exec_tid() == pid)
        proc = process_snapshot(
            pid, p["group"] + "/launcher", RUNC, identities["runc"], runc_vector(p)
        )
        require(proc["start"] == bound["process"]["start"] and proc["ppid"] == 1)
        require(
            show(record, p["units"]["service"], ("MainPID", "InvocationID"))
            == {"MainPID": str(pid), "InvocationID": bound["invocation"]}
        )
        tracer_identity(pid, os.getpid())
        tracee_descriptors(pid, expected, False)
        groups.no_payload()
        groups.still_only(pid)
        held = "actual-pinned-runc-exec-stop-before-userspace"
    peer.close()
    # No CONT/release/signal/kill at S. Attribution beyond observation remains owed.
    witness = hold_to_post_s_witness(record, p, bound, pidfd, identities)
    status, observed_death = wait_death(record, pid)
    observed = retirement(
        record,
        p,
        bound,
        pidfd,
        groups,
        status,
        observed_death,
        witness,
        identities,
        os.getpid(),
    )
    os.set_blocking(client.stdout.fileno(), False)
    while True:
        clock(record)
        ready = select.select(
            [client.stdout],
            [],
            [],
            (record["c_us"] - time.monotonic_ns() // 1000) / 1_000_000,
        )[0]
        require(ready)
        chunk = os.read(client.stdout.fileno(), 1)
        require(chunk == b"")
        break
    result = client.wait(
        timeout=(record["c_us"] - time.monotonic_ns() // 1000) / 1_000_000
    )
    require(result != 0)
    require(os.fstat(diagnostic).st_size <= record["diagnostic_max_bytes"])
    clock(record)
    return dict(
        schema="DotmacNativeEnvelopeTargetObservation.v1",
        status="target-cutoff-observed-observer-retirement-pending",
        case=record["case"],
        instance=record["instance"],
        boot_id=record["boot_id"],
        original_s_us=record["s_us"],
        original_c_us=record["c_us"],
        held_boundary=held,
        target=bound,
        retirement=observed,
        observer=observer,
        observer_cgroup=observer_groups.evidence,
        systemd_run_exit=result,
        actual_stdout_empty_eof=True,
        overall_native_pass=False,
    )


class GroupsObserver:
    def __init__(self, p):
        self.directory = protected("/sys/fs/cgroup" + p["observer_group"], True)
        self.events = os.open(
            "cgroup.events", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.directory
        )
        self.evidence = dict(
            group=fd_identity(self.directory), event=fd_identity(self.events)
        )


def main():
    require(len(sys.argv) == 1 and os.path.abspath(__file__) == ADAPTER)
    record = json.loads(public_bytes(RECORD, 65536), object_pairs_hook=unique)
    result = run(record)
    raw = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )
    require(len(raw) <= record["evidence_max_bytes"])
    clock(record)
    require(os.write(1, raw) == len(raw))
    clock(record)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Early tracer exit may trigger EXITKILL: always recovery/incomplete.
        raise SystemExit(125) from None
