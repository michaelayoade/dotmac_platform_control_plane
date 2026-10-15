"""Hosted-only executable protocol checks; synthetic evidence is not readiness."""

import json
import os
import socket
import struct
import time

import pytest

from vendor_cp.deployment.gate0_framing import FramedChannel, ServiceRefused
from vendor_cp.deployment.gate0_session import parse_auth_info


def test_frame_round_trip_and_clean_shutdown():
    left, right = socket.socketpair()
    try:
        deadline = time.monotonic() + 2
        client = FramedChannel(left.fileno(), left.fileno(), deadline=deadline)
        server = FramedChannel(right.fileno(), right.fileno(), deadline=deadline)
        client.send({"schema": "synthetic", "value": 1})
        assert server.receive() == {"schema": "synthetic", "value": 1}
        left.shutdown(socket.SHUT_WR)
        assert server.receive(allow_eof=True) is None
    finally:
        left.close()
        right.close()


@pytest.mark.parametrize("body", [b'{"x":1,"x":2}', b'{"x":NaN}', b"[]"])
def test_ambiguous_or_nonobject_frame_refuses(body):
    left, right = socket.socketpair()
    try:
        left.sendall(struct.pack("!I", len(body)) + body)
        with pytest.raises(ServiceRefused):
            FramedChannel(
                right.fileno(), right.fileno(), deadline=time.monotonic() + 1
            ).receive()
    finally:
        left.close()
        right.close()


def test_frame_size_checked_before_payload_allocation():
    left, right = socket.socketpair()
    try:
        left.sendall(struct.pack("!I", 2**32 - 1))
        with pytest.raises(ServiceRefused):
            FramedChannel(
                right.fileno(), right.fileno(), deadline=time.monotonic() + 1
            ).receive()
    finally:
        left.close()
        right.close()


def test_stalled_input_and_output_have_original_deadline():
    left, right = socket.socketpair()
    try:
        channel = FramedChannel(
            right.fileno(), right.fileno(), deadline=time.monotonic() + 0.02
        )
        with pytest.raises(ServiceRefused):
            channel.receive()
        with pytest.raises(ServiceRefused):
            channel.send({"never": "late"})
    finally:
        left.close()
        right.close()


def test_full_output_socket_cannot_block_past_original_deadline():
    left, right = socket.socketpair()
    try:
        right.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        channel = FramedChannel(
            right.fileno(), right.fileno(), deadline=time.monotonic() + 0.02
        )
        with pytest.raises(ServiceRefused):
            channel.send({"payload": "x" * (250 * 1024)})
    finally:
        left.close()
        right.close()


@pytest.mark.parametrize(
    "metadata",
    [
        b"",
        b"password\n",
        b"publickey ssh-ed25519 AAAA\n",
        b"publickey x y\npublickey x y\n",
    ],
)
def test_only_one_actual_certificate_authentication_is_accepted(metadata):
    with pytest.raises(ServiceRefused):
        parse_auth_info(metadata)


def test_installed_commands_have_no_production_fallback():
    from vendor_cp.cli import main

    assert main(["gate0", "issuer-run"]) == 3
    assert main(["gate0", "attester-session"]) == 3


def test_secret_fields_never_enter_public_result(capsys):
    from vendor_cp.cli import main

    os.environ["SSH_USER_AUTH"] = "synthetic-caller-created"
    try:
        assert main(["gate0", "attester-session"]) == 3
        assert "synthetic-caller-created" not in capsys.readouterr().out
    finally:
        del os.environ["SSH_USER_AUTH"]


def test_frame_budget_is_finite():
    left, right = socket.socketpair()
    try:
        channel = FramedChannel(
            right.fileno(),
            right.fileno(),
            deadline=time.monotonic() + 1,
            maximum_frames=1,
        )
        body = json.dumps({"x": 1}).encode()
        left.sendall(struct.pack("!I", len(body)) + body)
        assert channel.receive() == {"x": 1}
        with pytest.raises(ServiceRefused):
            channel.receive()
    finally:
        left.close()
        right.close()
