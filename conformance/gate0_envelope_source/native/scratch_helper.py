#!/usr/bin/python3.12 -I
"""INERT fixed helper: rendezvous before the first runtime eligibility guard.

Closed installation selection and protected local rendezvous authentication are
startup preludes. This is not literal first-instruction interception.
"""

import hashlib
import json
import os
import re
import resource
import socket
import stat
import struct
import sys
import time

RECORD = "/var/lib/dotmac-gate0-native-envelope/fixture.json"
HELPER = "/usr/local/libexec/dotmac-gate0-native-envelope/scratch-helper"
RUNC = "/usr/sbin/runc"
MARKER = b"DOTMAC_NATIVE_ENVELOPE_HELPER_V1"


def require(condition):
    if not condition:
        raise ValueError()


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
            s = os.fstat(fd)
            require(s.st_uid == s.st_gid == 0 and not s.st_mode & 0o022)
            require(
                stat.S_ISDIR(s.st_mode)
                if directory or index < len(parts) - 1
                else stat.S_ISREG(s.st_mode)
            )
        return fd
    except BaseException:
        os.close(fd)
        raise


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def load_selection():
    fd = protected(RECORD)
    try:
        s = os.fstat(fd)
        require(0 < s.st_size <= 65536)
        raw = os.read(fd, 65537)
        require(len(raw) == s.st_size)
    finally:
        os.close(fd)
    record = json.loads(raw, object_pairs_hook=unique)
    keys = (
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
    )
    require(type(record) is dict and set(record) == set(keys))
    require(
        record["schema"] == "DotmacNativeEnvelopeFixture.v1"
        and record["isolation_scope"] == "disposable-task-vm-only"
    )
    require(record["case"] in ("pre-guard-stop", "runc-exec-stop"))
    require(
        type(record["instance"]) is str
        and re.fullmatch("[0-9a-f]{64}", record["instance"]) is not None
    )
    instance = record["instance"] + "-" + record["case"]
    base = "/var/lib/dotmac-gate0-native-envelope/" + instance
    return record, dict(
        instance=instance,
        base=base,
        group="/system.slice/dotmac-gate0-" + instance + ".service",
        unit="dotmac-gate0-" + instance + ".service",
        socket="/run/dm-g0n/" + record["instance"] + "/marker",
        runc_root="/run/dm-g0n/" + record["instance"] + "/runc",
        bundle=base + "/bundle",
        diagnostic=base + "/diagnostics",
    )


def clock(record):
    with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as f:
        require(f.read() == record["boot_id"] + "\n")
    wall, mono = time.time_ns() // 1000, time.monotonic_ns() // 1000
    require(record["not_before_wall_us"] <= wall < record["e_wall_us"])
    require(
        record["not_before_mono_us"] <= mono < min(record["e_mono_us"], record["s_us"])
    )
    return (min(record["e_mono_us"], record["s_us"]) - mono) / 1_000_000


def pin(path, value):
    require(type(value) is dict and set(value) == {"size", "mode", "sha256"})
    fd = protected(path)
    try:
        before = os.fstat(fd)
        require(
            before.st_size == value["size"]
            and stat.S_IMODE(before.st_mode) == value["mode"]
        )
        digest = hashlib.sha256()
        count = 0
        while True:
            raw = os.read(fd, 65536)
            if not raw:
                break
            count += len(raw)
            require(count <= value["size"])
            digest.update(raw)
        require(count == value["size"] and digest.hexdigest() == value["sha256"])
        after = os.fstat(fd)
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
    finally:
        os.close(fd)


def runtime_guard(record, p, server_pid):
    # The pre-guard case never reaches this function before PID1's original stop.
    clock(record)
    require(os.geteuid() == 0 and os.getppid() == 1 and server_pid > 0)
    with open("/proc/self/cgroup", "rb") as f:
        require(f.read() == ("0::" + p["group"] + "/launcher\n").encode())
    pin(RUNC, record["pins"]["runc"])
    pin(p["bundle"] + "/config.json", record["pins"]["bundle_config"])
    invocation = os.environ.get("INVOCATION_ID", "")
    require(
        re.fullmatch("[0-9a-f]{32}", invocation) is not None and invocation != "0" * 32
    )
    # The adapter binds actual manager identity before release and at exec stop.
    # No child is spawned here: SIGCHLD would be an unexpected ptrace stop.
    require(
        not os.path.lexists("/sys/fs/cgroup" + p["group"] + "/payload")
        and not os.path.lexists(p["runc_root"] + "/" + p["instance"])
    )
    null = os.fstat(0)
    require(stat.S_ISCHR(null.st_mode) and null.st_rdev == os.makedev(1, 3))
    require(stat.S_ISFIFO(os.fstat(1).st_mode) or stat.S_ISSOCK(os.fstat(1).st_mode))
    fd = protected(p["diagnostic"])
    try:
        selected, actual = os.fstat(fd), os.fstat(2)
        require(
            (selected.st_dev, selected.st_ino) == (actual.st_dev, actual.st_ino)
            and stat.S_IMODE(selected.st_mode) == 0o600
            and selected.st_size <= record["diagnostic_max_bytes"]
        )
    finally:
        os.close(fd)
    require(
        resource.getrlimit(resource.RLIMIT_FSIZE)
        == (record["diagnostic_max_bytes"], record["diagnostic_max_bytes"])
    )
    clock(record)


def main():
    require(len(sys.argv) == 1 and os.path.abspath(__file__) == HELPER)
    record, p = load_selection()
    fd = protected(p["socket"].rsplit("/", 1)[0], True)
    try:
        require(stat.S_IMODE(os.fstat(fd).st_mode) == 0o700)
    finally:
        os.close(fd)
    s = os.stat(p["socket"], follow_symlinks=False)
    require(
        stat.S_ISSOCK(s.st_mode)
        and s.st_uid == s.st_gid == 0
        and stat.S_IMODE(s.st_mode) == 0o600
    )
    peer = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    require(peer.fileno() == 3 and not os.get_inheritable(peer.fileno()))
    peer.connect(p["socket"])
    server_pid, uid, gid = struct.unpack(
        "3i",
        peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")),
    )
    require(uid == 0 and gid == 0)
    require(peer.send(MARKER) == len(MARKER))
    require(peer.recv(2) == b"R")
    peer.close()  # Explicit close plus CLOEXEC.
    runtime_guard(record, p, server_pid)
    # Fixed RUNC vector; exec boundary mocked by source tests.
    os.execve(  # noqa: S606
        RUNC,
        [
            RUNC,
            "--root",
            p["runc_root"],
            "run",
            "--keep",
            "--bundle",
            p["bundle"],
            p["instance"],
        ],
        {},
    )


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit(125) from None
