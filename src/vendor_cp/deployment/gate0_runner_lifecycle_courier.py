"""Two fixed non-root entries: one secret courier and one JIT credential exec.

Neither accepts a destination, command, UID, PID, token argument or generic API.
Root/installed runtime provenance is an external native-qualification boundary.
"""

from __future__ import annotations

import base64
import os
import re
import socket
import stat
import struct
import time
from pathlib import Path
from typing import cast

from vendor_cp.deployment.gate0_framing import canonical, strict_object
from vendor_cp.deployment.gate0_runner_lifecycle import (
    _ROOT,
    _RUNNER,
    _RUNNER_ROOT,
    _SOCKET,
    JSONRecord,
    LifecycleRefused,
    NativeJitInvocation,
    _before,
    _closed,
    _directory,
    _hash,
    _OriginalBounds,
    _protected,
    _qualify_runner_mounts,
    _read_fd,
    _require,
    _socket_before,
)

_PUBLIC = _ROOT / "courier" / "installation.json"
_JIT_CREDENTIAL = Path("/run/credentials/dotmac-gate0-a9-jit.service/jit-config")
_TOKEN_ENV = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"  # noqa: S105 -- variable name only


def _installed_public_selection() -> tuple[JSONRecord, JSONRecord, _OriginalBounds]:
    raw = _protected(_PUBLIC, mode=0o640)
    value = _closed(
        strict_object(raw),
        "schema lifecycle_binding_digest courier_uid courier_gid groups "
        "original_bounds launcher source_files",
    )
    _require(
        canonical(value) == raw and value["schema"] == "Gate0A9CourierSelection.v1"
    )
    _require(
        type(value["courier_uid"]) is int
        and value["courier_uid"] > 0
        and os.getuid() == os.geteuid() == value["courier_uid"]
    )
    _require(
        type(value["courier_gid"]) is int
        and value["courier_gid"] > 0
        and os.getgid() == os.getegid() == value["courier_gid"]
    )
    launcher = NativeJitInvocation._selection(value["launcher"])
    _require(set(os.getgroups()) == set(launcher["groups"]) == set(value["groups"]))
    sources = _closed(
        value["source_files"], "gate0_runner_lifecycle gate0_runner_lifecycle_courier"
    )
    for name in sources:
        _require(
            _hash(_protected(Path(__file__).parent / (name + ".py"), 1024 * 1024))
            == sources[name]
        )
    for name in ("cli", "interpreter"):
        _require(
            _hash(_protected(Path(launcher[name]["path"]), 32 * 1024 * 1024))
            == launcher[name]["digest"]
        )
    _require(os.readlink("/proc/self/exe") == launcher["interpreter"]["path"])
    return value, launcher, _OriginalBounds.parse(value["original_bounds"])


def run_installed_job_courier() -> int:
    """Transfer original environment credential once to the literal root socket."""
    channel = None
    token = b""
    original = None
    try:
        _, _, bounds = _installed_public_selection()
        _before(bounds.provisioning_end)
        original = os.environ.pop(_TOKEN_ENV, None)
        _require(type(original) is str)
        original = cast(str, original)
        token = original.encode("ascii")
        _require(0 < len(token) <= 32768 and all(32 < byte < 127 for byte in token))
        original = None
        channel = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        channel.settimeout(max(0.001, bounds.provisioning_end - time.monotonic()))
        _socket_before(channel, bounds.provisioning_end)
        channel.connect(str(_SOCKET))
        _, uid, _ = struct.unpack(
            "3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        _require(uid == 0)
        _socket_before(channel, bounds.provisioning_end)
        _require(channel.send(token) == len(token))
        token = b""
        channel.shutdown(socket.SHUT_WR)
        _socket_before(channel, bounds.provisioning_end)
        response, ancillary, flags, _ = channel.recvmsg(
            2, socket.CMSG_SPACE(16 * struct.calcsize("i"))
        )
        from vendor_cp.deployment.gate0_runner_lifecycle import (
            _close_received_descriptors,
        )

        _close_received_descriptors(ancillary)
        _require(
            response == b"\x01"
            and not ancillary
            and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
        )
        _socket_before(channel, bounds.provisioning_end)
        _require(channel.recv(1) == b"")
        _before(bounds.provisioning_end)
        return 0
    except Exception:
        return 3
    finally:
        os.environ.pop(_TOKEN_ENV, None)
        original, token = None, b""
        if channel is not None:
            channel.close()


def _read_jit_credential(uid: int) -> bytes:
    """Fixed systemd read-only credential mount, not a job-writable secret path."""
    base = _directory(Path("/run/credentials"))
    directory = -1
    fd = -1
    try:
        root = os.fstat(base)
        _require(
            root.st_uid == 0 and stat.S_ISDIR(root.st_mode) and not root.st_mode & 0o022
        )
        directory = os.open(
            _JIT_CREDENTIAL.parent.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=base,
        )
        metadata = os.fstat(directory)
        _require(
            metadata.st_uid in (0, uid)
            and stat.S_ISDIR(metadata.st_mode)
            and not metadata.st_mode & 0o022
        )
        _require(os.fstatvfs(directory).f_flag & os.ST_RDONLY)
        fd = os.open(
            "jit-config", os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory
        )
        raw = _read_fd(fd, 65536, uid=uid, mode=0o400)
        _require(
            re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", raw) is not None
            and base64.b64encode(base64.b64decode(raw, validate=True)) == raw
        )
        return raw
    finally:
        for descriptor in (fd, directory, base):
            if descriptor >= 0:
                os.close(descriptor)


def run_installed_jit_runner() -> int:
    """Exec pinned listener with actual JIT config in private environment only."""
    fd = -1
    encoded = b""
    environment: dict[str, str] = {}
    try:
        _, launcher, bounds = _installed_public_selection()
        _before(bounds.provisioning_end)
        _require(not any(key.startswith("ACTIONS_RUNNER_INPUT_") for key in os.environ))
        encoded = _read_jit_credential(os.getuid())
        _qualify_runner_mounts(launcher["runner_binary"]["digest"], os.getuid())
        fd = os.open(_RUNNER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        _require(os.pread(fd, 4, 0) == b"\x7fELF")
        _require(
            _hash(_read_fd(fd, 32 * 1024 * 1024, uid=0))
            == launcher["runner_binary"]["digest"]
        )
        _require(os.execve in os.supports_fd)
        environment = {
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "HOME": "/run/dotmac-gate0-jit/home",
            "ACTIONS_RUNNER_INPUT_JITCONFIG": encoded.decode("ascii"),
        }
        encoded = b""
        os.chdir(_RUNNER_ROOT)
        _before(bounds.provisioning_end)
        os.execve(fd, (str(_RUNNER), "run", "--startuptype", "service"), environment)  # noqa: S606 -- pinned literal executable/vector
        raise LifecycleRefused()
    except Exception:
        return 3
    finally:
        encoded = b""
        environment.clear()
        if fd >= 0:
            os.close(fd)
