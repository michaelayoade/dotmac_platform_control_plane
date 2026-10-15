"""Hosted source vectors only; real WG namespace/packet qualification is separate."""

from __future__ import annotations

import base64
import hashlib
import io
import socket
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from vendor_cp.deployment import gate0_role_custody as custody


def endpoint(**changes):
    value = custody.WireGuardBaoEndpoint(
        role="issuer",
        address="10.50.0.1",
        port=8200,
        local_address="10.50.0.2",
        interface="wg0",
        interface_index=7,
        namespace_device=4,
        namespace_inode=123,
        peer_fingerprint="sha256:" + hashlib.sha256(bytes(range(32))).hexdigest(),
        peer_allowed_ip="10.50.0.1/32",
        wg_binary_digest="sha256:" + "a" * 64,
        network_config_digest="sha256:" + "b" * 64,
        launch_packet_digest="sha256:" + "c" * 64,
    )
    return replace(value, **changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"address": "127.0.0.1"},
        {"address": "192.0.2.1"},
        {"address": "bao.internal"},
        {"address": "::1"},
        {"local_address": "0.0.0.0"},  # noqa: S104 -- refusal vector
        {"port": True},
        {"interface": "wg0;other"},
        {"interface_index": 0},
        {"interface_index": 2147483648},
        {"namespace_inode": 0},
        {"namespace_inode": 18446744073709551616},
        {"peer_allowed_ip": "0.0.0.0/0"},
        {"peer_fingerprint": "unknown"},
        {"network_config_digest": ""},
        {"launch_packet_digest": ""},
        {"timeout": 6},
    ],
)
def test_closed_endpoint_refuses_missing_or_public_coordinates(changes):
    with pytest.raises(custody.ProviderRefused):
        endpoint(**changes)


def test_endpoint_and_transport_construction_are_pure(monkeypatch):
    forbidden = Mock(side_effect=AssertionError("constructor attempted I/O"))
    monkeypatch.setattr(custody.os, "stat", forbidden)
    monkeypatch.setattr(custody.socket, "if_nametoindex", forbidden)
    monkeypatch.setattr(custody.socket, "socket", forbidden)
    monkeypatch.setattr(custody, "_protected_digest", forbidden)
    transport = custody.WireGuardBaoTransport(endpoint())
    assert transport.endpoint.role == "issuer"
    forbidden.assert_not_called()


@pytest.mark.parametrize(
    "path,method",
    [
        ("/.well-known/jwks", "GET"),
        ("/v1/sys/health", "GET"),
        ("/v1/auth/token/renew-self", "POST"),
        ("/v1/secret/data/dotmac/platform-cp/rehearsal-attester/signing-key", "GET"),
        ("/v1/auth/token/lookup-self", "POST"),
    ],
)
def test_exact_bao_role_paths_refuse_before_spawn(monkeypatch, path, method):
    spawn = Mock(side_effect=AssertionError)
    monkeypatch.setattr(custody, "_spawn_request", spawn)
    with pytest.raises(custody.ProviderRefused):
        custody.WireGuardBaoTransport(endpoint()).request(
            path,
            method=method,
            token="synthetic-token",
            document=None,
            deadline=time.monotonic() + 1,
        )
    spawn.assert_not_called()


def test_request_uses_shared_child_and_original_deadline(monkeypatch):
    spawn = Mock(return_value=b'{"data":{}}')
    monkeypatch.setattr(custody, "_spawn_request", spawn)
    original = time.monotonic() + 1
    result = custody.WireGuardBaoTransport(endpoint()).request(
        "/v1/auth/token/lookup-self",
        method="GET",
        token="synthetic-token",
        document=None,
        deadline=original,
    )
    assert result == {"data": {}}
    assert spawn.call_args.args[0] is custody._wg_http_child
    assert spawn.call_args.args[1][-1] == original
    assert spawn.call_args.kwargs == {"process_group": True}


@pytest.mark.parametrize("token", ["synthetic\r\nOther: value", "", "x" * 8193])
def test_header_injection_refuses_before_spawn(monkeypatch, token):
    spawn = Mock(side_effect=AssertionError)
    monkeypatch.setattr(custody, "_spawn_request", spawn)
    with pytest.raises(custody.ProviderRefused):
        custody.WireGuardBaoTransport(endpoint()).request(
            "/v1/auth/token/lookup-self",
            method="GET",
            token=token,
            document=None,
            deadline=time.monotonic() + 1,
        )
    spawn.assert_not_called()


class SyntheticSocket:
    def __init__(self, response=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"):
        self.response = response
        self.sent = []
        self.events = []
        self.peer = ("10.50.0.1", 8200)
        self.source = ("10.50.0.2", 12345)
        self.device = b"wg0\0"

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.events.append("closed")

    def settimeout(self, value):
        assert 0 < value <= 5

    def setsockopt(self, level, option, value):
        assert (level, option, value) == (
            socket.SOL_SOCKET,
            socket.SO_BINDTODEVICE,
            b"wg0\0",
        )
        self.events.append("device-bound")

    def bind(self, address):
        assert address == ("10.50.0.2", 0)
        self.events.append("source-bound")

    def getsockopt(self, *_):
        self.events.append("device-readback")
        return self.device

    def connect(self, peer):
        assert peer == ("10.50.0.1", 8200)
        self.events.append("connected")

    def getsockname(self):
        self.events.append("source-readback")
        return self.source

    def getpeername(self):
        self.events.append("peer-readback")
        return self.peer

    def makefile(self, mode):
        assert mode == "rb"
        return io.BytesIO(self.response)

    def sendall(self, raw):
        self.events.append("sent")
        self.sent.append(raw)


def child_fixture(monkeypatch, connected):
    monkeypatch.setattr(custody.os, "setsid", lambda: None)
    monkeypatch.setattr(custody, "_wireguard_facts", Mock())
    monkeypatch.setattr(custody, "_namespace", Mock())
    create = Mock(return_value=connected)
    monkeypatch.setattr(custody.socket, "socket", create)
    return create, Mock()


def test_actual_socket_readbacks_precede_any_credential_bytes(monkeypatch):
    connected = SyntheticSocket()
    create, pipe = child_fixture(monkeypatch, connected)
    custody._wg_http_child(
        pipe,
        endpoint(),
        "/v1/auth/token/lookup-self",
        "GET",
        "synthetic-sensitive-token",
        None,
        time.monotonic() + 2,
    )
    create.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
    assert connected.events.index("sent") > connected.events.index("peer-readback")
    assert connected.events.index("sent") > connected.events.index("source-readback")
    assert connected.events.index("connected") > connected.events.index(
        "device-readback"
    )
    assert b"X-Vault-Token: synthetic-sensitive-token\r\n" in connected.sent[0]
    pipe.send_bytes.assert_called_once_with(b"{}")


@pytest.mark.parametrize("changed", ["source", "peer", "device", "permission"])
def test_socket_mismatch_or_bind_permission_failure_sends_no_secrets(
    monkeypatch, changed
):
    connected = SyntheticSocket()
    if changed == "source":
        connected.source = ("10.50.0.3", 12345)
    elif changed == "peer":
        connected.peer = ("10.50.0.3", 8200)
    elif changed == "device":
        connected.device = b"eth0\0"
    else:
        connected.setsockopt = Mock(side_effect=PermissionError)
    _, pipe = child_fixture(monkeypatch, connected)
    custody._wg_http_child(
        pipe,
        endpoint(),
        "/v1/auth/token/lookup-self",
        "GET",
        "synthetic-sensitive-token",
        None,
        time.monotonic() + 2,
    )
    assert connected.sent == []
    pipe.send_bytes.assert_called_once_with(b"")


def test_public_peer_and_allowed_ips_checks_use_no_secret_wg_views(monkeypatch):
    monkeypatch.setattr(custody, "_namespace", Mock())
    monkeypatch.setattr(
        custody,
        "_protected_digest",
        lambda path, *a, **k: "sha256:" + ("a" if path == "/usr/bin/wg" else "b") * 64,
    )
    public = base64.b64encode(bytes(range(32)))
    command = Mock(side_effect=[public + b"\n", public + b"\t10.50.0.1/32\n"])
    monkeypatch.setattr(custody, "_wg_public", command)
    deadline = time.monotonic() + 2
    custody._wireguard_facts(endpoint(), deadline)
    assert [call.args for call in command.call_args_list] == [
        ("wg0", "peers", deadline),
        ("wg0", "allowed-ips", deadline),
    ]
    command.side_effect = [public + b"\n", public + b"\t0.0.0.0/0\n"]
    with pytest.raises(custody.ProviderRefused):
        custody._wireguard_facts(endpoint(), deadline)


@pytest.mark.parametrize(
    "raw",
    [
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
    ],
)
def test_bounded_standard_http_decoder_accepts_explicit_framing(raw):
    assert custody._bao_response(SyntheticSocket(raw)) == b"{}"


@pytest.mark.parametrize(
    "raw",
    [
        b"HTTP/1.1 302 Found\r\nContent-Length: 2\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Length: 131073\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nX-Large: "
        + b"a" * 16384
        + b"\r\nContent-Length: 2\r\n\r\n{}",
    ],
)
def test_response_redirect_ambiguous_or_unbounded_framing_refuses(raw):
    with pytest.raises((custody.ProviderRefused, ValueError, OSError)):
        custody._bao_response(SyntheticSocket(raw))


def finite_provider(monkeypatch, role="issuer", remaining=31):
    seed = bytes(range(32))
    public = (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(
            Encoding.Raw,
            PublicFormat.Raw,
        )
    )
    paths = []

    def request(self, path, **kwargs):
        paths.append(path)
        if path.endswith("/wrapping/lookup"):
            return {
                "data": {
                    "creation_path": (
                        f"auth/approle/role/platform-cp-rehearsal-{role}/secret-id"
                    ),
                    "creation_time": datetime.now(UTC).isoformat(),
                    "creation_ttl": 120,
                }
            }
        if path.endswith("/unwrap"):
            return {
                "data": {
                    "secret_id": "synthetic-id",
                    "secret_id_num_uses": 1,
                    "secret_id_ttl": 120,
                }
            }
        if path.endswith("/login"):
            return {
                "auth": {
                    "client_token": "synthetic-token",
                    "renewable": False,
                    "lease_duration": 120,
                }
            }
        if path.endswith("/lookup-self"):
            return {"data": {"renewable": False, "num_uses": remaining, "ttl": 120}}
        if path.endswith("/signing-key"):
            return {
                "data": {
                    "data": {
                        "key_id": "synthetic",
                        "private_key_b64url": base64.urlsafe_b64encode(seed)
                        .rstrip(b"=")
                        .decode(),
                    }
                }
            }
        if path.endswith("/trust-state"):
            return {
                "data": {
                    "data": {
                        "version": 1,
                        "trusted_key_ids": {
                            "synthetic": "sha256:" + hashlib.sha256(public).hexdigest()
                        },
                        "revoked_key_ids": [],
                    }
                }
            }
        raise AssertionError("unexpected synthetic request")

    monkeypatch.setattr(custody.BoundedJSONTransport, "request", request)
    provider = custody.RoleCustody(
        role=role,
        role_id="synthetic-role",
        key_id="synthetic",
        public_key=public,
        minimum_versions={"issuer": 1, "attester": 1},
        transport=custody.BoundedJSONTransport("https://synthetic.invalid"),
        seed_format="a4-provisional-private-key-b64url",
        expires_at=datetime.now(UTC) + timedelta(seconds=120),
        profile=(
            custody.CustodyProfile.ISSUER_FINITE_V1
            if role == "issuer"
            else custody.CustodyProfile.ATTESTER_FINITE_V1
        ),
        launch_deadline=time.monotonic() + 90,
    )
    return provider, paths


@pytest.mark.parametrize(
    "role,phases,token_calls,http_calls",
    [
        ("issuer", ["submission"] * 8, 20, 23),
        ("attester", ["challenge", "complete"], 8, 11),
    ],
)
def test_named_finite_profiles_enforce_exact_role_allocations(
    monkeypatch, role, phases, token_calls, http_calls
):
    provider, paths = finite_provider(monkeypatch, role)
    material = provider.bootstrap("synthetic-wrap")
    for phase in phases:
        previous = provider._phases
        provider.precheck_phase(phase)
        assert provider._phases == previous
        provider.refresh(phase=phase)
    assert provider._token_attempts == token_calls
    assert provider._http_attempts == len(paths) == http_calls
    with pytest.raises(custody.ProviderRefused):
        provider.refresh(phase=phases[-1])
    assert len(paths) == http_calls
    assert not material.issuer_trust.available


def test_server_remaining_never_decreases_local_spent_count(monkeypatch):
    provider, _ = finite_provider(monkeypatch, remaining=32)
    provider.bootstrap("synthetic-wrap")
    assert provider._uses == 4
    assert provider._token_attempts == 4


def test_insufficient_server_remainder_refuses_before_seed(monkeypatch):
    provider, paths = finite_provider(monkeypatch, remaining=2)
    with pytest.raises(custody.ProviderRefused):
        provider.bootstrap("synthetic-wrap")
    assert len(paths) == 4
    assert not any(p.endswith("/signing-key") for p in paths)


def test_failed_refresh_is_counted_and_terminal(monkeypatch):
    provider, _ = finite_provider(monkeypatch, "attester")
    material = provider.bootstrap("synthetic-wrap")
    request = Mock(side_effect=RuntimeError("synthetic-sensitive-detail"))
    monkeypatch.setattr(custody.BoundedJSONTransport, "request", request)
    with pytest.raises(custody.ProviderRefused):
        provider.refresh(phase="challenge")
    assert provider._token_attempts == 5 and provider._http_attempts == 8
    assert provider._phases == 1
    request.assert_called_once()
    with pytest.raises(custody.ProviderRefused):
        material.attester_sign(b"synthetic")


def test_wrong_phase_refuses_without_network_or_rearming(monkeypatch):
    provider, paths = finite_provider(monkeypatch, "attester")
    provider.bootstrap("synthetic-wrap")
    with pytest.raises(custody.ProviderRefused):
        provider.refresh(phase="complete")
    assert len(paths) == 7
    assert provider._closed


@pytest.mark.parametrize(
    "profile,deadline",
    [
        (custody.CustodyProfile.ATTESTER_FINITE_V1, 90),
        ("issuer-finite-v1", 90),
        (custody.CustodyProfile.ISSUER_FINITE_V1, None),
        (custody.CustodyProfile.ISSUER_FINITE_V1, float("nan")),
        (custody.CustodyProfile.ISSUER_FINITE_V1, -1),
        (custody.CustodyProfile.ISSUER_FINITE_V1, 301),
    ],
)
def test_finite_profile_and_original_deadline_require_closed_inputs(
    monkeypatch, profile, deadline
):
    valid, _ = finite_provider(monkeypatch)
    with pytest.raises(custody.ProviderRefused):
        custody.RoleCustody(
            role="issuer",
            role_id=valid.role_id,
            key_id=valid.key_id,
            public_key=valid.public_key,
            minimum_versions=valid.minimum_versions,
            transport=valid.transport,
            seed_format="a4-provisional-private-key-b64url",
            expires_at=valid.expires_at,
            profile=profile,
            launch_deadline=None if deadline is None else time.monotonic() + deadline,
        )


def test_bootstrap_cannot_extend_original_launch_deadline(monkeypatch):
    provider, _ = finite_provider(monkeypatch)
    original = provider.deadline
    material = provider.bootstrap("synthetic-wrap")
    assert provider.deadline <= original
    assert material.key._deadline <= original
    monkeypatch.setattr(custody.time, "monotonic", lambda: original + 1)
    with pytest.raises(custody.ProviderRefused):
        provider.refresh(phase="submission")


def test_shared_parent_cancels_whole_transport_tool_group(monkeypatch):
    process = Mock(pid=12345)
    process.is_alive.side_effect = [True, False]
    parent, child = Mock(), Mock()
    context = Mock()
    context.Pipe.return_value = parent, child
    context.Process.return_value = process
    monkeypatch.setattr(custody.multiprocessing, "get_context", lambda mode: context)
    monkeypatch.setattr(
        custody, "_receive_message", Mock(side_effect=custody.ProviderRefused)
    )
    monkeypatch.setattr(custody.os, "getpgid", lambda pid: pid)
    kill = Mock()
    monkeypatch.setattr(custody.os, "killpg", kill)
    with pytest.raises(custody.ProviderRefused):
        custody._spawn_request(
            custody._wg_http_child, (), time.monotonic() + 1, process_group=True
        )
    kill.assert_called_once_with(12345, custody.signal.SIGKILL)
    process.kill.assert_called_once_with()
    process.join.assert_called_once()
    parent.close.assert_called_once_with()


def test_unqualified_network_facts_fail_before_socket_or_token_io(monkeypatch):
    connected = SyntheticSocket()
    create, pipe = child_fixture(monkeypatch, connected)
    monkeypatch.setattr(
        custody, "_wireguard_facts", Mock(side_effect=custody.ProviderRefused)
    )
    custody._wg_http_child(
        pipe,
        endpoint(),
        "/v1/auth/token/lookup-self",
        "GET",
        "synthetic-sensitive-token",
        None,
        time.monotonic() + 2,
    )
    create.assert_not_called()
    pipe.send_bytes.assert_called_once_with(b"")
    assert connected.sent == []
