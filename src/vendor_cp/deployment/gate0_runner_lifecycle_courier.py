"""Fixed non-root courier and separate A9/public JIT credential exec leaves.

Neither accepts a destination, command, UID, PID, token argument or generic API.
Root/installed runtime provenance is an external native-qualification boundary.
"""

from __future__ import annotations

import base64
import math
import os
import re
import socket
import stat
import struct
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, cast

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
    _digest,
    _directory,
    _hash,
    _OriginalBounds,
    _positive,
    _proc,
    _protected,
    _qualify_runner_mounts,
    _read_fd,
    _require,
    _socket_before,
    _utc,
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
        channel = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        channel.settimeout(max(0.001, bounds.provisioning_end - time.monotonic()))
        _socket_before(channel, bounds.provisioning_end)
        channel.connect(str(_SOCKET))
        _, uid, _ = struct.unpack(
            "3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        _require(uid == 0)
        from vendor_cp.deployment.gate0_runner_lifecycle import (
            _METADATA_READY,
            _SECRET_READY,
            _courier_frame,
        )

        _require(
            _courier_frame(channel, bounds.provisioning_end, 128) == _METADATA_READY
        )
        actual = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
        _require(
            type(actual) is str
            and 0 < len(actual) <= 16384
            and all(32 < ord(c) < 127 for c in actual)
        )
        report = canonical(dict(schema="Gate0A9BrokerMetadata.v1", url=actual))
        _socket_before(channel, bounds.provisioning_end)
        _require(channel.send(report) == len(report))
        _require(_courier_frame(channel, bounds.provisioning_end, 128) == _SECRET_READY)
        original = os.environ.pop(_TOKEN_ENV, None)
        _require(type(original) is str)
        original = cast(str, original)
        token = original.encode("ascii")
        _require(0 < len(token) <= 32768 and all(32 < byte < 127 for byte in token))
        original = None

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
        try:
            del os.environ[_TOKEN_ENV]
        except KeyError:
            pass
        original, token = None, b""
        if channel is not None:
            channel.close()


def _read_jit_credential(uid: int) -> bytes:
    return _read_unit_jit_credential(uid, "a9")


def _read_unit_jit_credential(uid: int, slot: Literal["a9", "public"]) -> bytes:
    """Fixed systemd read-only credential mount, not a job-writable secret path."""
    _require(slot in ("a9", "public"))
    credential = _JIT_CREDENTIAL if slot == "a9" else _PUBLIC_JIT_CREDENTIAL
    base = _directory(Path("/run/credentials"))
    directory = -1
    fd = -1
    raw = b""
    failed = False
    interrupted = 0
    try:
        root = os.fstat(base)
        _require(
            root.st_uid == 0 and stat.S_ISDIR(root.st_mode) and not root.st_mode & 0o022
        )
        directory = os.open(
            credential.parent.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=base,
        )
        metadata = os.fstat(directory)
        _require(
            metadata.st_uid in (0, uid)
            and stat.S_ISDIR(metadata.st_mode)
            and not metadata.st_mode & 0o022
        )
        _require((os.fstatvfs(directory).f_flag & os.ST_RDONLY) != 0)
        fd = os.open(
            "jit-config", os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory
        )
        raw = _read_fd(fd, 65536, uid=uid, mode=0o400)
        _require(
            re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", raw) is not None
            and base64.b64encode(base64.b64decode(raw, validate=True)) == raw
        )
        if slot == "a9":
            return raw
    except KeyboardInterrupt:
        if slot == "a9":
            raise
        raw = b""
        interrupted = 1
    except SystemExit:
        if slot == "a9":
            raise
        raw = b""
        interrupted = 2
    except Exception:
        if slot == "a9":
            raise
        raw = b""
        failed = True
    finally:
        for descriptor in (fd, directory, base):
            if descriptor >= 0:
                if slot == "a9":
                    # Preserve the inherited A9 close/error behavior.
                    os.close(descriptor)
                    continue
                try:
                    os.close(descriptor)
                except KeyboardInterrupt:
                    raw = b""
                    if not interrupted:
                        interrupted = 1
                except SystemExit:
                    raw = b""
                    if not interrupted:
                        interrupted = 2
                except Exception:
                    raw = b""
                    failed = True
    # Only categories survive public cleanup; never retain its original errors.
    if interrupted == 1:
        raise KeyboardInterrupt() from None
    if interrupted == 2:
        raise SystemExit(3) from None
    if failed:
        raise LifecycleRefused() from None
    return raw


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


_PUBLIC_JIT_SELECTION = Path("/run/dotmac-gate0-e/public-jit.json")
_PUBLIC_JIT_QUALIFICATION = Path("/etc/dotmac-gate0-e/public-jit-qualification.json")
_PUBLIC_JIT_BINDING = Path("/etc/dotmac-gate0-e/public-jit-binding.json")
_PUBLIC_JIT_NATIVE = Path("/etc/dotmac-gate0-e/public-jit-native.json")
_PUBLIC_JIT_UNIT = Path("/run/systemd/system/dotmac-gate0-e-public-jit.service")
_PUBLIC_JIT_CREDENTIAL = Path(
    "/run/credentials/dotmac-gate0-e-public-jit.service/jit-config"
)
_PUBLIC_JIT_HOME = Path("/run/dotmac-gate0-jit/home")


def _public_jit_before(deadline: float, ends_at: datetime) -> None:
    _before(deadline)
    _require(datetime.now(UTC) < ends_at)


def _installed_public_jit_selection() -> tuple[JSONRecord, float, datetime]:
    """Closed public projection; authentic native measurements remain external."""

    def record(path: Path, fields: str, schema: str) -> tuple[JSONRecord, bytes]:
        raw = _protected(path)
        value = _closed(strict_object(raw), fields)
        _require(canonical(value) == raw and value["schema"] == schema)
        return value, raw

    selection, raw = record(
        _PUBLIC_JIT_SELECTION,
        "schema operation execution runtime_uid runtime_gid groups original_bounds "
        "cli interpreter runner_binary_digest runner_tree_digest "
        "runtime_artifact_digest unit_digest source_files",
        "Gate0EPublicJitSelection.v1",
    )
    qual, qual_raw = record(
        _PUBLIC_JIT_QUALIFICATION,
        "schema method_scope selection_digest boot_id kernel_release unit_digest "
        "runner_tree_digest runtime_artifact_digest credential_mount_profile_digest "
        "execution_binding_digest original_bounds_digest",
        "Gate0EPublicJitQualification.v1",
    )
    binding, _ = record(
        _PUBLIC_JIT_BINDING,
        "schema selection_digest qualification_digest native_receipt_digest",
        "Gate0EPublicJitBinding.v1",
    )
    native, native_raw = record(
        _PUBLIC_JIT_NATIVE,
        "schema qualification_measurements_digest runtime_identity_digest "
        "reviewer_record_digest",
        "Gate0ENativeReviewReceipt.v1",
    )
    # Existing native receipt convention is bare SHA256; lifecycle pins are tagged.
    for key in native.keys() - {"schema"}:
        _require(
            type(native[key]) is str
            and re.fullmatch(r"[0-9a-f]{64}", native[key]) is not None
        )
    for key in binding.keys() - {"schema"}:
        _digest(binding[key])
    _require(binding["selection_digest"] == qual["selection_digest"] == _hash(raw))
    _require(binding["qualification_digest"] == _hash(qual_raw))
    _require(binding["native_receipt_digest"] == _hash(native_raw))
    _require(qual["method_scope"] == "public-e-single-job-jit-exec.v1")
    for key in (
        "runner_binary_digest",
        "runner_tree_digest",
        "runtime_artifact_digest",
        "unit_digest",
    ):
        _digest(selection[key])
    for key in (
        "credential_mount_profile_digest",
        "execution_binding_digest",
        "original_bounds_digest",
    ):
        _digest(qual[key])
    for key in ("runner_tree_digest", "runtime_artifact_digest", "unit_digest"):
        _require(qual[key] == selection[key])
    uid, gid = _positive(selection["runtime_uid"]), _positive(selection["runtime_gid"])
    _require(os.getuid() == os.geteuid() == uid and os.getgid() == os.getegid() == gid)
    _require(selection["groups"] == [] and os.getgroups() == [])
    execution = _closed(
        selection["execution"],
        "repository_id owner_id workflow_id run_id attempt source_revision "
        "workflow_digest source_policy_digest job_id job_key job_name environment_id "
        "environment_name reviewer_id runner_group_id runner_id runner_name "
        "summary_digest",
    )
    for key in (
        "repository_id",
        "owner_id",
        "workflow_id",
        "run_id",
        "attempt",
        "job_id",
        "environment_id",
        "reviewer_id",
        "runner_group_id",
        "runner_id",
    ):
        _positive(execution[key])
    _require(execution["attempt"] == 1)
    _require(
        type(execution["source_revision"]) is str
        and re.fullmatch(r"[0-9a-f]{40}", execution["source_revision"]) is not None
    )
    for key in ("workflow_digest", "source_policy_digest"):
        _digest(execution[key])
    for key in ("job_key", "job_name", "environment_name", "runner_name"):
        _require(
            type(execution[key]) is str
            and 0 < len(execution[key]) <= 256
            and all(32 <= ord(c) < 127 for c in execution[key])
        )
    _require(selection["operation"] in ("prepare_draft", "publish"))
    if selection["operation"] == "publish":
        _digest(execution["summary_digest"])
    else:
        _require(execution["summary_digest"] is None)
    _require(qual["execution_binding_digest"] == _hash(canonical(execution)))
    bounds = _closed(selection["original_bounds"], "boot_id wall monotonic ends_at")
    boot = _proc(Path("/proc/sys/kernel/random/boot_id"), 64).decode("ascii").strip()
    _require(
        re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot) is not None
    )
    _require(bounds["boot_id"] == qual["boot_id"] == boot)
    _require(qual["kernel_release"] == os.uname().release)
    elapsed = bounds["monotonic"]
    _require(
        type(elapsed) in (int, float)
        and math.isfinite(elapsed)
        and 0 <= elapsed <= time.monotonic()
    )
    wall, ends_at = _utc(bounds["wall"]), _utc(bounds["ends_at"])
    _require(wall < ends_at)
    deadline = float(elapsed + (ends_at - wall).total_seconds())
    _public_jit_before(deadline, ends_at)
    _require(qual["original_bounds_digest"] == _hash(canonical(bounds)))
    _require(
        _proc(Path("/proc/self/cgroup"))
        == b"0::/system.slice/dotmac-gate0-e-public-jit.service\n"
    )
    _require(_hash(_protected(_PUBLIC_JIT_UNIT)) == selection["unit_digest"])
    from vendor_cp import cli
    from vendor_cp.cli import owners
    from vendor_cp.deployment import gate0_framing, gate0_runner_lifecycle

    source_paths = {
        "gate0_runner_lifecycle": Path(gate0_runner_lifecycle.__file__),
        "gate0_runner_lifecycle_courier": Path(__file__),
        "gate0_framing": Path(gate0_framing.__file__),
        "cli_init": Path(cli.__file__),
        "cli_owners": Path(owners.__file__),
    }
    sources = _closed(selection["source_files"], " ".join(source_paths))
    for name, path in source_paths.items():
        _require(_hash(_protected(path, 1024 * 1024)) == _digest(sources[name]))
    pins = {}
    for name in ("cli", "interpreter"):
        pin = _closed(selection[name], "path digest")
        _require(
            type(pin["path"]) is str
            and pin["path"].startswith("/")
            and "\x00" not in pin["path"]
        )
        _require(
            _hash(_protected(Path(pin["path"]), 32 * 1024 * 1024))
            == _digest(pin["digest"])
        )
        pins[name] = pin
    _require(os.readlink("/proc/self/exe") == pins["interpreter"]["path"])
    cli_raw = _protected(Path(pins["cli"]["path"]), 32 * 1024 * 1024)
    _require(_hash(cli_raw) == pins["cli"]["digest"])
    shebang = cli_raw.split(b"\n", 1)[0]
    _require(shebang.startswith(b"#!") and len(shebang) <= 4096)
    command = shebang[2:].strip().split(b" ")
    _require(
        command
        in (
            [pins["interpreter"]["path"].encode("ascii")],
            [pins["interpreter"]["path"].encode("ascii"), b"-I"],
        )
    )
    _require(
        _proc(Path("/proc/self/cmdline"), 8192).split(b"\0")
        == command
        + [
            pins["cli"]["path"].encode("ascii"),
            b"gate0",
            b"public-jit-runner-credential",
            b"",
        ]
    )
    _public_jit_before(deadline, ends_at)
    return selection, deadline, ends_at


def run_installed_public_jit_runner() -> int:
    """Replace this finite leaf; manager stop/one-job/retirement are external."""
    fd = -1
    encoded = b""
    environment: dict[str, str] = {}
    interrupted = 0
    status = 3
    try:
        _require(
            not any(
                key.startswith(("ACTIONS_RUNNER_INPUT_", "GITHUB_"))
                or key
                in {
                    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
                    "ACTIONS_ID_TOKEN_REQUEST_URL",
                    "ACTIONS_RUNTIME_TOKEN",
                    "GITHUB_TOKEN",
                    "GH_TOKEN",
                }
                for key in os.environ
            )
        )
        selection, deadline, ends_at = _installed_public_jit_selection()
        _qualify_runner_mounts(selection["runner_binary_digest"], os.getuid())
        home = _directory(_PUBLIC_JIT_HOME, uid=os.getuid(), mode=0o700)
        os.close(home)
        _public_jit_before(deadline, ends_at)
        encoded = _read_unit_jit_credential(os.getuid(), "public")
        fd = os.open(_RUNNER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        _require(os.pread(fd, 4, 0) == b"\x7fELF")
        _require(
            _hash(_read_fd(fd, 32 * 1024 * 1024, uid=0))
            == selection["runner_binary_digest"]
        )
        actual = os.fstat(fd)
        approved = os.stat(
            "/opt/dotmac-gate0-jit/bin/Runner.Listener", follow_symlinks=False
        )
        _require(
            (actual.st_dev, actual.st_ino) == (approved.st_dev, approved.st_ino)
            and not actual.st_mode & 0o022
        )
        _require(os.execve in os.supports_fd)
        environment = {
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "HOME": str(_PUBLIC_JIT_HOME),
            "ACTIONS_RUNNER_INPUT_JITCONFIG": encoded.decode("ascii"),
        }
        encoded = b""
        os.chdir(_RUNNER_ROOT)
        _public_jit_before(deadline, ends_at)
        os.execve(fd, (str(_RUNNER), "run", "--startuptype", "service"), environment)  # noqa: S606 -- pinned literal executable/vector
        raise LifecycleRefused()
    except KeyboardInterrupt:
        interrupted = 1
    except SystemExit:
        interrupted = 2
    except Exception:
        status = 3
    finally:
        encoded = b""
        environment.clear()
        if fd >= 0:
            try:
                os.close(fd)
            except KeyboardInterrupt:
                if not interrupted:
                    interrupted = 1
            except SystemExit:
                if not interrupted:
                    interrupted = 2
            except Exception:
                status = 3
    # Raise outside the original handler: no private exception context retained.
    if interrupted == 1:
        raise KeyboardInterrupt() from None
    if interrupted == 2:
        raise SystemExit(3) from None
    return status
