"""Local courier/exec source seams only; no protected job or native qualification."""

from __future__ import annotations

import os
import socket
import struct
import time
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
