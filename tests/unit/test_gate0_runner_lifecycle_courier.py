"""Local courier/exec source seams only; no protected job or native qualification."""

from __future__ import annotations

import os
import socket
import struct
import time
from datetime import UTC
from types import SimpleNamespace

import pytest

from vendor_cp.deployment import gate0_runner_lifecycle as life
from vendor_cp.deployment import gate0_runner_lifecycle_courier as courier


@pytest.fixture
def selected(monkeypatch):
    launcher = {"runner_binary": {"digest": "sha256:" + "a" * 64}}
    bounds = SimpleNamespace(provisioning_end=time.monotonic() + 10)
    monkeypatch.setattr(
        courier, "_installed_public_selection", lambda: ({}, launcher, bounds)
    )
    return launcher, bounds


class CourierSocket:
    def __init__(self, *, uid=0, response=b"\x01", flags=0):
        self.uid, self.response, self.flags = uid, response, flags
        self.sent, self.closed, self.connected, self.timeout = [], False, None, None

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, path):
        self.connected = path

    def getsockopt(self, *args):
        return struct.pack("3i", 123, self.uid, 1)

    def send(self, data):
        self.sent.append(data)
        return len(data)

    def shutdown(self, how):
        assert how == socket.SHUT_WR

    def recvmsg(self, size, ancillary):
        return self.response, [], self.flags, None

    def recv(self, count):
        return b""

    def close(self):
        self.closed = True


def test_original_environment_token_is_one_private_packet_and_then_cleared(
    selected, monkeypatch
):
    channel = CourierSocket()
    monkeypatch.setenv(
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "private-original-request-token"
    )
    monkeypatch.setattr(courier.socket, "socket", lambda *args: channel)
    assert courier.run_installed_job_courier() == 0
    assert channel.connected == str(life._SOCKET)
    assert channel.sent == [b"private-original-request-token"]
    assert channel.closed and channel.timeout > 0
    assert "ACTIONS_ID_TOKEN_REQUEST_TOKEN" not in os.environ


@pytest.mark.parametrize(
    "bad", ["", "white space", "line\nbreak", "\u00e9", "x" * 32769]
)
def test_invalid_credential_never_sent_and_never_reflected(
    selected, monkeypatch, bad, capsys
):
    channel = CourierSocket()
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", bad)
    monkeypatch.setattr(courier.socket, "socket", lambda *args: channel)
    assert courier.run_installed_job_courier() == 3
    assert channel.sent == []
    assert capsys.readouterr() == ("", "")
    assert "ACTIONS_ID_TOKEN_REQUEST_TOKEN" not in os.environ


@pytest.mark.parametrize(
    ("uid", "response", "flags"),
    [
        (99, b"\x01", 0),
        (0, b"\x00", 0),
        (0, b"\x01extra", 0),
        (0, b"\x01", socket.MSG_TRUNC),
    ],
)
def test_peer_root_ack_and_complete_frame_are_required(
    selected, monkeypatch, uid, response, flags
):
    channel = CourierSocket(uid=uid, response=response, flags=flags)
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "original-token")
    monkeypatch.setattr(courier.socket, "socket", lambda *args: channel)
    assert courier.run_installed_job_courier() == 3
    assert channel.closed
    if uid != 0:
        assert channel.sent == []


def test_original_deadline_refuses_without_new_budget(selected, monkeypatch):
    _, bounds = selected
    bounds.provisioning_end = time.monotonic() - 1
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "original-token")
    assert courier.run_installed_job_courier() == 3
    assert "ACTIONS_ID_TOKEN_REQUEST_TOKEN" not in os.environ


def test_ancillary_descriptor_is_closed_before_refusal():
    read_fd, write_fd = os.pipe()
    try:
        life._close_received_descriptors(
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", read_fd))]
        )
        with pytest.raises(OSError):
            os.fstat(read_fd)
    finally:
        os.close(write_fd)


def test_jit_wrapper_uses_secret_environment_and_literal_exec_only(
    selected, monkeypatch
):
    captured = []
    actual_exec = courier.os.execve
    monkeypatch.setattr(
        courier, "_read_jit_credential", lambda uid: b"YWN0dWFsLWZpeHR1cmU="
    )
    monkeypatch.setattr(courier, "_qualify_runner_mounts", lambda digest, uid: None)
    monkeypatch.setattr(courier.os, "open", lambda *args: 123)
    monkeypatch.setattr(courier.os, "pread", lambda *args: b"\x7fELF")
    monkeypatch.setattr(courier.os, "close", lambda fd: None)
    monkeypatch.setattr(courier, "_read_fd", lambda *args, **kwargs: b"runner")
    monkeypatch.setattr(courier, "_hash", lambda raw: "sha256:" + "a" * 64)
    monkeypatch.setattr(courier.os, "chdir", lambda path: None)

    def execve(fd, arguments, environment):
        captured.append((fd, arguments, dict(environment)))
        raise RuntimeError("test seam prevents real exec")

    monkeypatch.setattr(courier.os, "execve", execve)
    monkeypatch.setattr(courier.os, "supports_fd", {execve, actual_exec})
    assert courier.run_installed_jit_runner() == 3
    fd, arguments, environment = captured[0]
    assert fd == 123
    assert arguments == (str(life._RUNNER), "run", "--startuptype", "service")
    assert environment["ACTIONS_RUNNER_INPUT_JITCONFIG"] == "YWN0dWFsLWZpeHR1cmU="
    assert all("YWN0dWFs" not in item for item in arguments)
    assert set(environment) == {
        "PATH",
        "LC_ALL",
        "HOME",
        "ACTIONS_RUNNER_INPUT_JITCONFIG",
    }


def test_jit_wrapper_rejects_inherited_runner_input_values(selected, monkeypatch):
    monkeypatch.setenv("ACTIONS_RUNNER_INPUT_JITCONFIG", "caller-token")
    calls = []
    monkeypatch.setattr(courier, "_read_jit_credential", lambda uid: calls.append(uid))
    assert courier.run_installed_jit_runner() == 3
    assert calls == []


def test_root_listener_is_listening_before_starting_one_job(monkeypatch):
    events = []
    owner = life.InstalledA9Lifecycle(
        life._SEAL,
        {
            "courier_gid": 10,
            "courier_uid": 11,
            "lifecycle_binding_digest": "sha256:" + "a" * 64,
            "launcher": {"groups": []},
            "original_bounds": {},
            "source_files": {},
        },
        life._OriginalBounds(
            "0" * 36,
            life.datetime.now(
                life.datetime.fromisoformat("2026-01-01T00:00:00+00:00").tzinfo
            ),
            time.monotonic(),
            life.datetime.fromisoformat("2099-01-01T00:00:00+00:00"),
            life.datetime.fromisoformat("2099-01-02T00:00:00+00:00"),
        ),
    )
    owner._owned = {
        slot: object()
        for slot in (
            life.FileSlot.A_KEY,
            life.FileSlot.B_KEY,
            life.FileSlot.A_CERTIFICATE,
            life.FileSlot.B_CERTIFICATE,
            life.FileSlot.JIT_SOURCE,
        )
    }
    monkeypatch.setattr(owner, "_phase", lambda *args: None)
    monkeypatch.setattr(owner, "_create_file", lambda *args: None)
    monkeypatch.setattr(owner, "_capture", lambda *args, **kwargs: None)
    monkeypatch.setattr(owner, "_event", lambda *args: None)

    class Native:
        def __init__(self, *args):
            pass

        def start_once(self):
            events.append("start")

        def stop_and_observe(self):
            events.append("stop")

    class Listener:
        def settimeout(self, value):
            pass

        def bind(self, path):
            events.append("bind")

        def listen(self, count):
            events.append("listen")

        def accept(self):
            events.append("accept")
            raise OSError("fixture ends before any credential is received")

        def close(self):
            events.append("close")

    monkeypatch.setattr(life, "NativeJitInvocation", Native)
    monkeypatch.setattr(life.socket, "socket", lambda *args: Listener())
    monkeypatch.setattr(life.os.path, "lexists", lambda path: False)
    monkeypatch.setattr(life.os, "chown", lambda *args, **kwargs: None)
    monkeypatch.setattr(life.os, "chmod", lambda *args, **kwargs: None)
    with pytest.raises(life.LifecycleRefused):
        owner.receive_original_job_credential()
    assert (
        events.index("bind")
        < events.index("listen")
        < events.index("start")
        < events.index("accept")
    )
    assert events.count("start") == 1


@pytest.fixture
def public_profile(monkeypatch):
    """Actual closed loader over protected-read/proc seams; no native claim."""
    for key in tuple(os.environ):
        if key.startswith(("GITHUB_", "ACTIONS_RUNNER_INPUT_")) or key in {
            "GH_TOKEN",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            "ACTIONS_RUNTIME_TOKEN",
        }:
            monkeypatch.delenv(key)
    from datetime import datetime

    from vendor_cp import cli
    from vendor_cp.cli import owners
    from vendor_cp.deployment import gate0_framing

    digest = "sha256:" + "a" * 64
    boot = "00000000-0000-0000-0000-000000000001"
    wall = "2026-10-16T00:00:00Z"
    ends = "2026-10-16T00:01:00Z"
    sources = {
        "gate0_runner_lifecycle": life.__file__,
        "gate0_runner_lifecycle_courier": courier.__file__,
        "gate0_framing": gate0_framing.__file__,
        "cli_init": cli.__file__,
        "cli_owners": owners.__file__,
    }
    execution = dict.fromkeys(
        (
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
        ),
        1,
    )
    execution.update(
        source_revision="a" * 40,
        workflow_digest=digest,
        source_policy_digest=digest,
        job_key="draft",
        job_name="draft",
        environment_name="review",
        runner_name="isolated-public",
        summary_digest=None,
    )
    cli_raw = b"#!/opt/runtime/python -I\ninstalled-cli"
    artifacts = {str(path): b"source" for path in sources.values()}
    artifacts.update(
        {
            "/opt/runtime/python": b"interpreter",
            "/opt/runtime/dotmac-platform": cli_raw,
            str(courier._PUBLIC_JIT_UNIT): b"unit",
        }
    )
    selection = {
        "schema": "Gate0EPublicJitSelection.v1",
        "operation": "prepare_draft",
        "execution": execution,
        "runtime_uid": 1001,
        "runtime_gid": 1002,
        "groups": [],
        "original_bounds": {
            "boot_id": boot,
            "wall": wall,
            "monotonic": 100.0,
            "ends_at": ends,
        },
        "cli": {"path": "/opt/runtime/dotmac-platform", "digest": life._hash(cli_raw)},
        "interpreter": {
            "path": "/opt/runtime/python",
            "digest": life._hash(b"interpreter"),
        },
        "runner_binary_digest": digest,
        "runner_tree_digest": digest,
        "runtime_artifact_digest": digest,
        "unit_digest": life._hash(b"unit"),
        "source_files": {key: life._hash(b"source") for key in sources},
    }
    qual = {
        "schema": "Gate0EPublicJitQualification.v1",
        "method_scope": "public-e-single-job-jit-exec.v1",
        "selection_digest": "",
        "boot_id": boot,
        "kernel_release": "qualified-kernel",
        "unit_digest": selection["unit_digest"],
        "runner_tree_digest": digest,
        "runtime_artifact_digest": digest,
        "credential_mount_profile_digest": digest,
        "execution_binding_digest": "",
        "original_bounds_digest": "",
    }
    native = {
        "schema": "Gate0ENativeReviewReceipt.v1",
        **dict.fromkeys(
            (
                "qualification_measurements_digest",
                "runtime_identity_digest",
                "reviewer_record_digest",
            ),
            "b" * 64,
        ),
    }
    records = {}

    def refresh():
        raw = life.canonical(selection)
        qual.update(
            selection_digest=life._hash(raw),
            execution_binding_digest=life._hash(life.canonical(selection["execution"])),
            original_bounds_digest=life._hash(
                life.canonical(selection["original_bounds"])
            ),
        )
        qual_raw, native_raw = life.canonical(qual), life.canonical(native)
        binding = {
            "schema": "Gate0EPublicJitBinding.v1",
            "selection_digest": life._hash(raw),
            "qualification_digest": life._hash(qual_raw),
            "native_receipt_digest": life._hash(native_raw),
        }
        records.update(
            {
                str(courier._PUBLIC_JIT_SELECTION): raw,
                str(courier._PUBLIC_JIT_QUALIFICATION): qual_raw,
                str(courier._PUBLIC_JIT_NATIVE): native_raw,
                str(courier._PUBLIC_JIT_BINDING): life.canonical(binding),
            }
        )

    refresh()
    reads = []

    def protected(path, *args, **kwargs):
        reads.append(str(path))
        return records[str(path)] if str(path) in records else artifacts[str(path)]

    proc = {
        "/proc/sys/kernel/random/boot_id": (boot + "\n").encode(),
        "/proc/self/cgroup": b"0::/system.slice/dotmac-gate0-e-public-jit.service\n",
        "/proc/self/cmdline": (
            b"/opt/runtime/python\x00-I\x00"
            b"/opt/runtime/dotmac-platform\x00gate0\x00"
            b"public-jit-runner-credential\x00"
        ),
    }
    monkeypatch.setattr(courier, "_protected", protected)
    monkeypatch.setattr(courier, "_proc", lambda path, *args: proc[str(path)])
    for name, value in (
        ("getuid", 1001),
        ("geteuid", 1001),
        ("getgid", 1002),
        ("getegid", 1002),
    ):
        monkeypatch.setattr(courier.os, name, lambda value=value: value)
    monkeypatch.setattr(courier.os, "getgroups", lambda: [])
    monkeypatch.setattr(
        courier.os, "uname", lambda: SimpleNamespace(release="qualified-kernel")
    )
    monkeypatch.setattr(courier.os, "readlink", lambda path: "/opt/runtime/python")
    monkeypatch.setattr(courier.time, "monotonic", lambda: 120.0)

    class Clock:
        @staticmethod
        def now(zone):
            return datetime(2026, 10, 16, 0, 0, 20, tzinfo=UTC)

    monkeypatch.setattr(courier, "datetime", Clock)
    return SimpleNamespace(
        selection=selection,
        qual=qual,
        native=native,
        records=records,
        artifacts=artifacts,
        proc=proc,
        refresh=refresh,
        reads=reads,
    )


def test_public_actual_closed_loader_uses_only_fixed_public_records(public_profile):
    selection, deadline, ends = courier._installed_public_jit_selection()
    assert selection == public_profile.selection
    assert deadline == 160.0  # delayed launch leaves 40, never a fresh 60 seconds
    assert ends.isoformat() == "2026-10-16T00:01:00+00:00"
    assert str(courier._PUBLIC) not in public_profile.reads
    assert str(courier._JIT_CREDENTIAL) not in public_profile.reads


@pytest.mark.parametrize(
    "change",
    [
        "extra",
        "missing",
        "nested-extra",
        "uid-bool",
        "uid",
        "gid",
        "groups",
        "attempt-bool",
        "attempt",
        "revision",
        "summary",
        "source",
        "cli",
        "interpreter",
        "unit",
        "boot",
        "future-monotonic",
        "nan-monotonic",
        "bool-monotonic",
        "expired",
        "qualification",
        "native",
        "kernel",
        "cgroup",
        "command",
        "binding",
    ],
)
def test_public_actual_loader_guards_refuse_before_credential(
    public_profile, monkeypatch, change, capsys
):
    p = public_profile
    if change == "extra":
        p.selection["extra"] = 1
    elif change == "missing":
        p.selection.pop("operation")
    elif change == "nested-extra":
        p.selection["execution"]["extra"] = 1
    elif change == "uid-bool":
        p.selection["runtime_uid"] = True
    elif change == "uid":
        p.selection["runtime_uid"] = 1003
    elif change == "gid":
        p.selection["runtime_gid"] = 1003
    elif change == "groups":
        p.selection["groups"] = [1002]
    elif change == "attempt-bool":
        p.selection["execution"]["attempt"] = True
    elif change == "attempt":
        p.selection["execution"]["attempt"] = 2
    elif change == "revision":
        p.selection["execution"]["source_revision"] = "a" * 39
    elif change == "summary":
        p.selection["execution"]["summary_digest"] = "sha256:" + "a" * 64
    elif change == "source":
        p.artifacts[courier.__file__] = b"changed-source"
    elif change == "cli":
        p.artifacts["/opt/runtime/dotmac-platform"] = b"changed-cli"
    elif change == "interpreter":
        p.artifacts["/opt/runtime/python"] = b"changed-interpreter"
    elif change == "unit":
        p.artifacts[str(courier._PUBLIC_JIT_UNIT)] = b"changed-unit"
    elif change == "boot":
        p.selection["original_bounds"]["boot_id"] = "wrong-boot"
    elif change == "future-monotonic":
        p.selection["original_bounds"]["monotonic"] = 121.0
    elif change == "bool-monotonic":
        p.selection["original_bounds"]["monotonic"] = True
    elif change == "expired":
        monkeypatch.setattr(courier.time, "monotonic", lambda: 160.0)
    elif change == "qualification":
        p.qual["runtime_artifact_digest"] = "sha256:" + "c" * 64
    elif change == "kernel":
        p.qual["kernel_release"] = "other-kernel"
    elif change == "cgroup":
        p.proc["/proc/self/cgroup"] = b"0::/other.service\n"
    elif change == "command":
        p.proc["/proc/self/cmdline"] += b"--path\x00"
    p.refresh()
    if change == "nan-monotonic":
        p.records[str(courier._PUBLIC_JIT_SELECTION)] = p.records[
            str(courier._PUBLIC_JIT_SELECTION)
        ].replace(b'"monotonic":100.0', b'"monotonic":NaN')
    elif change == "native":
        p.records[str(courier._PUBLIC_JIT_NATIVE)] += b" "
    elif change == "binding":
        p.records[str(courier._PUBLIC_JIT_BINDING)] = p.records[
            str(courier._PUBLIC_JIT_BINDING)
        ].replace(b'"selection_digest":"sha256:', b'"selection_digest":"sha255:')
    calls = []
    monkeypatch.setattr(
        courier, "_read_unit_jit_credential", lambda *args: calls.append(args)
    )
    assert courier.run_installed_public_jit_runner() == 3
    assert not calls
    assert capsys.readouterr() == ("", "")


def test_public_backward_wall_never_extends_original_monotonic_end(
    public_profile, monkeypatch
):
    from datetime import datetime

    monkeypatch.setattr(
        courier,
        "datetime",
        SimpleNamespace(now=lambda zone: datetime(2026, 10, 15, tzinfo=UTC)),
    )
    assert courier._installed_public_jit_selection()[1] == 160.0
    monkeypatch.setattr(courier.time, "monotonic", lambda: 160.0)
    with pytest.raises(life.LifecycleRefused):
        courier._installed_public_jit_selection()


def test_public_forward_wall_expiry_refuses(public_profile, monkeypatch):
    from datetime import datetime

    monkeypatch.setattr(
        courier,
        "datetime",
        SimpleNamespace(now=lambda zone: datetime(2026, 10, 16, 0, 1, tzinfo=UTC)),
    )
    with pytest.raises(life.LifecycleRefused):
        courier._installed_public_jit_selection()


@pytest.mark.parametrize(
    "key",
    [
        "ACTIONS_RUNNER_INPUT_JITCONFIG",
        "ACTIONS_RUNNER_INPUT_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "ACTIONS_RUNTIME_TOKEN",
        "GITHUB_TOKEN",
        "GITHUB_JOB",
        "GH_TOKEN",
    ],
)
def test_public_rejects_ambient_job_authority_before_loading(monkeypatch, key):
    monkeypatch.setenv(key, "synthetic-private-input")
    monkeypatch.setattr(
        courier,
        "_installed_public_jit_selection",
        lambda: pytest.fail("must refuse before loading"),
    )
    assert courier.run_installed_public_jit_runner() == 3


@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize(
    "close_failure", [None, OSError, KeyboardInterrupt, SystemExit]
)
def test_public_exec_uses_verified_fd_and_detaches_on_failure(
    public_profile, monkeypatch, failure, close_failure, capsys
):
    # Actual loader remains active; only OS mount/exec boundaries are synthetic.
    for key in tuple(os.environ):
        if key.startswith(("GITHUB_", "ACTIONS_RUNNER_INPUT_")) or key in {
            "GH_TOKEN",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            "ACTIONS_RUNTIME_TOKEN",
        }:
            monkeypatch.delenv(key)
    events, retained = [], []
    binary = b"\x7fELFfixture"
    public_profile.selection["runner_binary_digest"] = life._hash(binary)
    public_profile.refresh()
    monkeypatch.setattr(
        courier, "_qualify_runner_mounts", lambda *args: events.append(("mounts", args))
    )
    monkeypatch.setattr(courier, "_directory", lambda *args, **kwargs: 77)
    monkeypatch.setattr(
        courier,
        "_read_unit_jit_credential",
        lambda uid, slot: b"Zml4dHVyZQ=="
        if slot == "public"
        else pytest.fail("wrong credential slot"),
    )
    monkeypatch.setattr(courier.os, "open", lambda path, flags: 123)
    monkeypatch.setattr(courier.os, "pread", lambda *args: b"\x7fELF")
    monkeypatch.setattr(courier, "_read_fd", lambda *args, **kwargs: binary)
    metadata = SimpleNamespace(st_dev=1, st_ino=2, st_mode=0o100555)
    monkeypatch.setattr(courier.os, "fstat", lambda fd: metadata)
    monkeypatch.setattr(courier.os, "stat", lambda *args, **kwargs: metadata)

    def close(fd):
        events.append(("close", fd))
        if fd == 123 and close_failure is not None:
            raise close_failure("synthetic-private-close-detail")

    monkeypatch.setattr(courier.os, "close", close)
    monkeypatch.setattr(courier.os, "chdir", lambda path: events.append(("cwd", path)))

    def execve(fd, argv, env):
        retained.append(env)
        events.append(("exec", fd, argv, dict(env)))
        raise failure("synthetic-private-exec-detail")

    monkeypatch.setattr(courier.os, "execve", execve)
    monkeypatch.setattr(courier.os, "supports_fd", {execve})
    control = failure if failure in (KeyboardInterrupt, SystemExit) else close_failure
    if control not in (KeyboardInterrupt, SystemExit):
        assert courier.run_installed_public_jit_runner() == 3
    else:
        with pytest.raises(control) as caught:
            courier.run_installed_public_jit_runner()
        assert caught.value.__context__ is None
        assert caught.value.__cause__ is None
        assert "synthetic-private" not in str(caught.value)
        traceback = caught.value.__traceback__
        while traceback is not None:
            if traceback.tb_frame.f_code.co_name == "run_installed_public_jit_runner":
                assert traceback.tb_frame.f_locals["encoded"] == b""
                assert traceback.tb_frame.f_locals["environment"] == {}
            assert traceback.tb_frame.f_code.co_name not in {"close", "execve"}
            traceback = traceback.tb_next
    assert retained == [{}]
    executed = next(event for event in events if event[0] == "exec")
    assert executed[1:3] == (
        123,
        (str(life._RUNNER), "run", "--startuptype", "service"),
    )
    assert executed[3] == {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "HOME": "/run/dotmac-gate0-jit/home",
        "ACTIONS_RUNNER_INPUT_JITCONFIG": "Zml4dHVyZQ==",
    }
    assert ("cwd", life._RUNNER_ROOT) in events
    assert events.count(("close", 123)) == events.count(("close", 77)) == 1
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("failure", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("read_failure", [None, OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("failure_at", [0, 1, 2])
def test_public_credential_cleanup_attempts_each_fd_and_sanitizes_failures(
    tmp_path, monkeypatch, failure, read_failure, failure_at, capsys
):
    """Real file reads/closes, synthetic root/mount and close-result boundaries."""
    import stat
    from pathlib import Path

    unit = tmp_path / courier._PUBLIC_JIT_CREDENTIAL.parent.name
    unit.mkdir(mode=0o700)
    credential = unit / "jit-config"
    credential.write_bytes(b"Zml4dHVyZQ==")
    credential.chmod(0o400)
    base = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    original_open, original_close, original_fstat = os.open, os.close, os.fstat
    original_read = courier._read_fd
    opened, closed = [], []

    def open_file(*args, **kwargs):
        descriptor = original_open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    def fstat(fd):
        if fd == base:
            return SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o700)
        return original_fstat(fd)

    def read_file(*args, **kwargs):
        raw = original_read(*args, **kwargs)
        if read_failure is not None:
            raise read_failure("synthetic-private-read-detail")
        return raw

    def close(fd):
        closed.append(fd)
        original_close(fd)
        if len(closed) - 1 == failure_at:
            raise failure("synthetic-private-close-detail")

    monkeypatch.setattr(
        courier,
        "_directory",
        lambda path: base
        if path == Path("/run/credentials")
        else pytest.fail("unexpected path"),
    )
    monkeypatch.setattr(courier.os, "open", open_file)
    monkeypatch.setattr(courier.os, "close", close)
    monkeypatch.setattr(courier.os, "fstat", fstat)
    monkeypatch.setattr(
        courier.os, "fstatvfs", lambda fd: SimpleNamespace(f_flag=os.ST_RDONLY)
    )
    monkeypatch.setattr(courier, "_read_fd", read_file)
    control = (
        read_failure if read_failure in (KeyboardInterrupt, SystemExit) else failure
    )
    expected = (
        control if control in (KeyboardInterrupt, SystemExit) else life.LifecycleRefused
    )
    with pytest.raises(expected) as caught:
        courier._read_unit_jit_credential(os.getuid(), "public")
    assert closed == [opened[1], opened[0], base]
    assert len(set(closed)) == 3
    for descriptor in closed:
        with pytest.raises(OSError):
            original_fstat(descriptor)
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None
    assert "synthetic-private" not in str(caught.value)
    traceback = caught.value.__traceback__
    while traceback is not None:
        if traceback.tb_frame.f_code.co_name == "_read_unit_jit_credential":
            assert traceback.tb_frame.f_locals["raw"] == b""
        assert traceback.tb_frame.f_code.co_name not in {"close", "read_file"}
        traceback = traceback.tb_next
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize(
    "mutation",
    [
        "valid",
        "writable-mount",
        "mode",
        "hardlink",
        "symlink",
        "fifo",
        "oversize",
        "noncanonical",
        "wrong-unit",
    ],
)
def test_public_credential_actual_file_reader_guards(tmp_path, monkeypatch, mutation):
    """Real no-follow opens/read_fd; root ancestor/readonly mount are OS seams."""
    import stat
    from pathlib import Path

    unit = tmp_path / courier._PUBLIC_JIT_CREDENTIAL.parent.name
    unit.mkdir(mode=0o700)
    credential = unit / "jit-config"
    credential.write_bytes(b"Zml4dHVyZQ==")
    credential.chmod(0o400)
    if mutation == "mode":
        credential.chmod(0o600)
    elif mutation == "hardlink":
        os.link(credential, unit / "extra-link")
    elif mutation == "symlink":
        credential.unlink()
        credential.symlink_to(unit / "target")
    elif mutation == "fifo":
        credential.unlink()
        os.mkfifo(credential, 0o400)
    elif mutation == "oversize":
        credential.chmod(0o600)
        credential.write_bytes(b"A" * 65537)
        credential.chmod(0o400)
    elif mutation == "noncanonical":
        credential.chmod(0o600)
        credential.write_bytes(b"Zh==")  # nonzero pad bits
        credential.chmod(0o400)
    elif mutation == "wrong-unit":
        unit.rename(tmp_path / "dotmac-gate0-a9-jit.service")
    base = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    original_fstat = os.fstat
    monkeypatch.setattr(
        courier,
        "_directory",
        lambda path: base
        if path == Path("/run/credentials")
        else pytest.fail("unexpected path"),
    )

    def fstat(fd):
        if fd == base:
            return SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o700)
        return original_fstat(fd)

    monkeypatch.setattr(courier.os, "fstat", fstat)
    monkeypatch.setattr(
        courier.os,
        "fstatvfs",
        lambda fd: SimpleNamespace(
            f_flag=0 if mutation == "writable-mount" else os.ST_RDONLY
        ),
    )
    if mutation == "valid":
        assert (
            courier._read_unit_jit_credential(os.getuid(), "public") == b"Zml4dHVyZQ=="
        )
    else:
        with pytest.raises((life.LifecycleRefused, OSError)):
            courier._read_unit_jit_credential(os.getuid(), "public")
    with pytest.raises(OSError):
        original_fstat(base)


def test_public_duplicate_json_and_a9_schema_are_not_launch_authority(public_profile):
    p = public_profile
    path = str(courier._PUBLIC_JIT_SELECTION)
    p.records[path] = p.records[path].replace(
        b'{"cli":', b'{"schema":"duplicate","cli":', 1
    )
    with pytest.raises(ValueError):
        courier._installed_public_jit_selection()
    p.selection["schema"] = "Gate0A9CourierSelection.v1"
    p.refresh()
    with pytest.raises(life.LifecycleRefused):
        courier._installed_public_jit_selection()


def test_public_loader_real_protected_read_algorithm(
    public_profile, tmp_path, monkeypatch
):
    """Real file/protected read logic, with root identity and ancestry OS seams.

    This cannot establish actual nonroot Linux access or native qualification.
    """

    p = public_profile
    original_fstat = os.fstat
    monkeypatch.setattr(
        life, "_directory", lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    )

    def root_fstat(fd):
        actual = original_fstat(fd)
        values = {
            name: getattr(actual, name)
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
        }
        values["st_uid"] = 0  # root identity seam only
        return SimpleNamespace(**values)

    monkeypatch.setattr(life.os, "fstat", root_fstat)
    paths = {}
    for index, (name, raw) in enumerate({**p.artifacts, **p.records}.items()):
        target = tmp_path / str(index)
        target.write_bytes(raw)
        target.chmod(0o444)
        paths[name] = target

    def protected(path, *args, **kwargs):
        return life._protected(paths[str(path)], *args, **kwargs)

    monkeypatch.setattr(courier, "_protected", protected)
    assert courier._installed_public_jit_selection()[1] == 160.0
    paths[str(courier._PUBLIC_JIT_SELECTION)].chmod(0o666)
    with pytest.raises(life.LifecycleRefused):
        courier._installed_public_jit_selection()
    paths[str(courier._PUBLIC_JIT_SELECTION)].chmod(0o444)
    target = paths[str(courier._PUBLIC_JIT_SELECTION)]
    original = target.with_name("original-record")
    target.rename(original)
    target.symlink_to(original)
    with pytest.raises(OSError):
        courier._installed_public_jit_selection()


@pytest.mark.parametrize(
    "boundary", ["mount", "elf", "digest", "inode", "fd-support", "delayed-exec"]
)
def test_public_listener_and_original_exec_boundary_refusals(
    public_profile, monkeypatch, boundary
):
    p = public_profile
    binary = b"\x7fELFfixture"
    p.selection["runner_binary_digest"] = life._hash(binary)
    p.refresh()
    calls, closed = [], []

    def mounts(*args):
        if boundary == "mount":
            raise life.LifecycleRefused()

    monkeypatch.setattr(courier, "_qualify_runner_mounts", mounts)
    monkeypatch.setattr(courier, "_directory", lambda *args, **kwargs: 77)
    monkeypatch.setattr(
        courier,
        "_read_unit_jit_credential",
        lambda *args: calls.append("credential") or b"Zml4dHVyZQ==",
    )
    monkeypatch.setattr(courier.os, "open", lambda *args: 123)
    monkeypatch.setattr(courier.os, "close", closed.append)
    monkeypatch.setattr(
        courier.os, "pread", lambda *args: b"oops" if boundary == "elf" else b"\x7fELF"
    )
    monkeypatch.setattr(
        courier,
        "_read_fd",
        lambda *args, **kwargs: b"changed" if boundary == "digest" else binary,
    )
    monkeypatch.setattr(
        courier.os,
        "fstat",
        lambda fd: SimpleNamespace(st_dev=1, st_ino=2, st_mode=0o100555),
    )
    monkeypatch.setattr(
        courier.os,
        "stat",
        lambda *args, **kwargs: SimpleNamespace(
            st_dev=1, st_ino=3 if boundary == "inode" else 2
        ),
    )

    def chdir(path):
        if boundary == "delayed-exec":
            monkeypatch.setattr(courier.time, "monotonic", lambda: 160.0)

    monkeypatch.setattr(courier.os, "chdir", chdir)

    def execve(*args):
        calls.append("exec")

    monkeypatch.setattr(courier.os, "execve", execve)
    monkeypatch.setattr(
        courier.os, "supports_fd", set() if boundary == "fd-support" else {execve}
    )
    assert courier.run_installed_public_jit_runner() == 3
    assert "exec" not in calls
    if boundary == "mount":
        assert "credential" not in calls
    else:
        assert 123 in closed
