"""Mechanism tests; these do not qualify a root/WG/sshd installation."""

import base64
import os
import socket
import struct
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID

import pytest

from vendor_cp.deployment import gate0_launch as launch
from vendor_cp.deployment.gate0_role_custody import ProviderRefused


def test_public_constructor_cannot_manufacture_measured_launch():
    with pytest.raises(ProviderRefused):
        launch.InstalledLaunchContext(packet_digest="sha256:" + "a" * 64)


def synthetic_local_packet():
    digest = "sha256:" + "a" * 64
    public = base64.b64encode(bytes(32)).decode("ascii")
    fingerprint = "SHA256:" + public.rstrip("=")
    selection = {
        "window_digest": digest,
        "plan_id": str(UUID(int=1)),
        "plan_digest": digest,
        "target_id": str(UUID(int=2)),
        "approval_request_id": str(UUID(int=3)),
    }
    return {
        "schema": "Gate0FiniteLaunch.v1",
        "host_role": "issuer",
        "run_end": datetime.now(UTC).isoformat(),
        "shared_run_digest": digest,
        "machine_id_digest": digest,
        "network": {
            "interface": "wgsynthetic",
            "index": 3,
            "namespace_device": 4,
            "namespace_inode": 1234,
            "bao_address": "10.0.0.2",
            "local_address": "10.0.0.1",
            "peer_public_key": public,
            "peer_allowed_ip": "10.0.0.2/32",
            "route_document": "[]",
            "nft_ruleset_digest": digest,
        },
        "binary_digests": {
            name: digest for name in ("/usr/bin/wg", "/usr/sbin/ip", "/usr/sbin/nft")
        },
        "captures": {"a": selection, "b": dict(selection, plan_id=str(UUID(int=4)))},
        "installation_digests": {"issuer": digest, "capture_sender": digest},
        "ssh_endpoints": {
            "issuer": {
                "local_address": "10.0.0.1",
                "local_port": 2224,
                "remote_address": "10.0.0.3",
            }
        },
        "sshd_digest": digest,
        "issuer_uid": 1234,
        "capture_sender_uid": 1235,
        "management_identity": {
            "holder_uid": 1235,
            "device": 4,
            "inode": 100,
            "public_key_fingerprint": fingerprint,
        },
        "cli_digest": digest,
        "issuer_sshd_config_digest": digest,
    }


@pytest.mark.parametrize(
    "field",
    [
        "uid_bool",
        "port_bool",
        "namespace_bool",
        "identity_bool",
        "hash_object",
        "endpoint_extra",
        "slot_extra",
        "network_extra",
    ],
)
def test_closed_typed_local_projection_refuses_bad_nested_values(field):
    packet = deepcopy(synthetic_local_packet())
    if field == "uid_bool":
        packet["issuer_uid"] = True
    elif field == "port_bool":
        packet["ssh_endpoints"]["issuer"]["local_port"] = True
    elif field == "namespace_bool":
        packet["network"]["namespace_inode"] = True
    elif field == "identity_bool":
        packet["management_identity"]["device"] = True
    elif field == "hash_object":
        packet["installation_digests"]["issuer"] = {"digest": "sha256:" + "a" * 64}
    elif field == "endpoint_extra":
        packet["ssh_endpoints"]["issuer"]["environment"] = {}
    elif field == "slot_extra":
        packet["installation_digests"]["fifth_slot"] = "sha256:" + "a" * 64
    else:
        packet["network"]["qualified"] = True
    with pytest.raises(ProviderRefused):
        launch._local_packet(launch.canonical(packet))


def test_valid_projection_preserves_public_values_without_qualification():
    packet = synthetic_local_packet()
    projected = launch._local_packet(launch.canonical(packet))
    assert projected == packet
    assert type(projected["issuer_uid"]) is int
    assert type(projected["network"]["namespace_inode"]) is int


@pytest.mark.parametrize("cancel", [False, True])
def test_postactivation_failure_is_unknown_and_cancellation_is_preserved(
    monkeypatch, cancel
):
    supervisor = object.__new__(launch.FiniteGate0Supervisor)
    supervisor._activated = False
    monkeypatch.setattr(launch, "_load_local_packet", lambda: {"host_role": "issuer"})
    client, listener = socket.socketpair()
    monkeypatch.setattr(supervisor, "_listen_wg", lambda role: listener)
    monkeypatch.setattr(supervisor, "_accept_wg", lambda *args: client)
    monkeypatch.setattr(supervisor, "close", lambda: None)

    def started_then_failed(connection):
        supervisor._activated = True
        if cancel:
            raise KeyboardInterrupt()
        raise ProviderRefused()

    monkeypatch.setattr(supervisor, "run_issuer_connection", started_then_failed)
    try:
        with pytest.raises(KeyboardInterrupt if cancel else launch.LaunchIncomplete):
            supervisor.run()
    finally:
        client.close()
        listener.close()


def test_issuer_terminal_success_record_is_required(tmp_path, monkeypatch):
    supervisor = object.__new__(launch.FiniteGate0Supervisor)
    supervisor.worker_uid, supervisor.packet_digest = os.geteuid(), "sha256:" + "a" * 64
    monkeypatch.setattr(
        launch,
        "_protected",
        lambda *args, **kwargs: os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY),
    )
    with pytest.raises(FileNotFoundError):
        supervisor._require_terminal_success("issuer")
    path = tmp_path / "terminal.json"
    path.write_bytes(
        launch.canonical(
            {
                "schema": "Gate0IssuerTerminal.v1",
                "launch_packet_digest": supervisor.packet_digest,
                "outcome": "success",
            }
        )
    )
    path.chmod(0o400)
    supervisor._require_terminal_success("issuer")


@pytest.mark.parametrize("role", ["issuer", "attester", "management"])
def test_only_designated_sender_can_open_management_key(role):
    context = object.__new__(launch.InstalledLaunchContext)
    object.__setattr__(context, "role", role)
    with pytest.raises(ProviderRefused):
        context.open_management_identity(expected_fingerprint="synthetic-public-pin")


def test_installed_supervisor_refuses_unknown_packet_owner(monkeypatch):
    monkeypatch.setattr(
        launch,
        "_read",
        lambda *args: b'{"schema":"Gate0FiniteLaunch.v1","host_role":"arbitrary"}',
    )
    with pytest.raises(ProviderRefused):
        launch.FiniteGate0Supervisor.from_installed()


@pytest.mark.parametrize(
    "cyclic_field", [None, "installation_digests", "packet_digest"]
)
def test_common_run_identity_excludes_runtime_digest_cycles(monkeypatch, cyclic_field):
    now = datetime.now(UTC)
    selection = {
        "window_digest": "sha256:" + "a" * 64,
        "plan_id": str(UUID(int=1)),
        "plan_digest": "sha256:" + "b" * 64,
        "target_id": str(UUID(int=2)),
        "approval_request_id": str(UUID(int=3)),
    }
    role = {
        "key_id": "synthetic-public-role",
        "public_key_b64": base64.b64encode(bytes(32)).decode("ascii"),
        "source_revision": "c" * 40,
        "image_digest": "sha256:" + "d" * 64,
        "profile_digest": "sha256:" + "e" * 64,
    }
    fingerprint = "SHA256:" + base64.b64encode(bytes(32)).decode("ascii").rstrip("=")
    document = {
        "schema": "Gate0RunIdentity.v1",
        "run_id": "synthetic-common-run",
        "not_before": (now - timedelta(seconds=1)).isoformat(),
        "expires_at": (now + timedelta(seconds=60)).isoformat(),
        "captures": {"a": selection, "b": dict(selection, plan_id=str(UUID(int=4)))},
        "roles": {"issuer": role, "attester": role},
        "controller_ca_fingerprint": fingerprint,
        "management_key_fingerprint": fingerprint,
    }
    if cyclic_field is not None:
        document[cyclic_field] = "sha256:" + "f" * 64
    raw = launch.canonical(document)
    monkeypatch.setattr(launch, "_read", lambda *args: raw)
    if cyclic_field is not None:
        with pytest.raises(ProviderRefused):
            launch.RunIdentity.from_installed()
    else:
        identity = launch.RunIdentity.from_installed()
        assert identity.digest == launch._digest(raw)


def test_late_zero_exit_cannot_advance_within_still_open_common_window(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(launch.time, "monotonic", lambda: clock[0])
    supervisor = object.__new__(launch.FiniteGate0Supervisor)
    supervisor.clocks = launch.LaunchClocks.start(
        datetime.now(UTC) + timedelta(seconds=120)
    )
    supervisor.state = launch.LaunchState.READY
    supervisor._index, supervisor._boundary = 0, None
    supervisor.packet_digest, supervisor.worker_uid = "sha256:" + "a" * 64, 1234
    monkeypatch.setattr(supervisor, "_require_ssh_connection", lambda *args: None)
    monkeypatch.setattr(supervisor, "_publish_context", lambda *args, **kwargs: None)
    raw = b"fixed synthetic pinned binary/config"
    digest = launch._digest(raw)
    packet = launch.canonical({"sshd_digest": digest, "sshd_config_digest": digest})
    monkeypatch.setattr(
        launch,
        "_read",
        lambda path, *args: packet if path.name == "packet.json" else raw,
    )
    monkeypatch.setattr(
        launch,
        "_load_local_packet",
        lambda: {"sshd_digest": digest, "sshd_config_digest": digest},
    )
    emptied = []

    class Boundary:
        def __init__(self, slot):
            pass

        def start_watchdog(self, deadline):
            assert deadline == 1030.0

        def require_watchdog(self):
            pass

        def enter_child(self):
            pass

        def terminate_and_confirm_empty(self):
            emptied.append(True)

    class Process:
        returncode = 0

        def wait(self, timeout):
            clock[0] = 1031.0

    monkeypatch.setattr(launch, "SlotExecutionBoundary", Boundary)
    monkeypatch.setattr(launch.subprocess, "Popen", lambda *args, **kwargs: Process())
    client, server = socket.socketpair()
    try:
        with pytest.raises(ProviderRefused):
            supervisor.run_attester_connection(server)
        assert supervisor.state == launch.LaunchState.TERMINAL
        assert supervisor._index == 0
        assert emptied
        supervisor.clocks.require_open()  # common window still has time
    finally:
        client.close()
        server.close()


@pytest.mark.parametrize("late_at", ["exit", "empty_proof"])
def test_issuer_zero_exit_and_valid_terminal_cannot_outlive_common_deadline(
    tmp_path, monkeypatch, late_at
):
    # Mechanism fixture isolates acceptance timing; no installation is qualified.
    clock = [1000.0]
    monkeypatch.setattr(launch.time, "monotonic", lambda: clock[0])
    supervisor = object.__new__(launch.FiniteGate0Supervisor)
    supervisor.clocks = launch.LaunchClocks.start(
        datetime.now(UTC) + timedelta(seconds=120)
    )
    deadline = supervisor.clocks.deadline
    supervisor.state = launch.LaunchState.AWAITING_CAPTURE
    supervisor._boundary, supervisor._activated = None, False
    supervisor.worker_uid = os.geteuid()
    supervisor.packet_digest = "sha256:" + "a" * 64
    (tmp_path / "terminal.json").write_bytes(
        launch.canonical(
            {
                "schema": "Gate0IssuerTerminal.v1",
                "launch_packet_digest": supervisor.packet_digest,
                "outcome": "success",
            }
        )
    )
    (tmp_path / "terminal.json").chmod(0o400)
    # Prove the fixture contains a valid success record, rather than relying on
    # a missing-record refusal to stand in for the deadline check.
    monkeypatch.setattr(
        launch,
        "_protected",
        lambda *args, **kwargs: os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY),
    )
    supervisor._require_terminal_success("issuer")
    raw = b"synthetic-fixed-issuer-binary-and-config"
    digest = launch._digest(raw)
    monkeypatch.setattr(
        launch,
        "_load_local_packet",
        lambda: {
            "host_role": "issuer",
            "sshd_digest": digest,
            "issuer_sshd_config_digest": digest,
        },
    )
    monkeypatch.setattr(launch, "_read", lambda *args: raw)
    monkeypatch.setattr(supervisor, "_publish_context", lambda *args, **kwargs: None)
    monkeypatch.setattr(supervisor, "_require_ssh_connection", lambda *args: None)
    closed_listener = SimpleNamespace(close=lambda: None)
    monkeypatch.setattr(supervisor, "_listen_wg", lambda *args: closed_listener)
    monkeypatch.setattr(supervisor, "_bind_issuer_export", lambda: closed_listener)
    monkeypatch.setattr(supervisor, "close", lambda: None)
    client, peer = socket.socketpair()
    export, export_peer = socket.socketpair()
    monkeypatch.setattr(supervisor, "_accept_wg", lambda *args: client)
    monkeypatch.setattr(
        supervisor,
        "_receive_issuer_export",
        lambda *args: (
            b"public-export",
            {
                "issuer_uid": os.geteuid(),
                "issuer_pid": os.getpid(),
                "issuer_start": "1",
            },
            export,
            deadline - 1,
        ),
    )
    monkeypatch.setattr(
        supervisor, "_run_capture_sender", lambda *args: b"public-readback"
    )
    emptied = []

    class Boundary:
        def __init__(self, slot):
            pass

        def start_watchdog(self, cap):
            assert cap == deadline

        def require_watchdog(self):
            pass

        def enter_child(self):
            pass

        def terminate_and_confirm_empty(self):
            emptied.append(True)
            if late_at == "empty_proof":
                clock[0] = deadline

    class Process:
        returncode = 0

        def wait(self, timeout):
            if late_at == "exit":
                clock[0] = deadline

    monkeypatch.setattr(launch, "SlotExecutionBoundary", Boundary)
    monkeypatch.setattr(launch.subprocess, "Popen", lambda *args, **kwargs: Process())
    try:
        with pytest.raises(launch.LaunchIncomplete):
            supervisor.run()
        assert supervisor._activated
        assert supervisor.state == launch.LaunchState.TERMINAL
        assert emptied
    finally:
        client.close()
        peer.close()
        export.close()
        export_peer.close()


def test_original_clocks_refuse_rollback_and_do_not_renew(monkeypatch):
    now = datetime.now(UTC)
    monkeypatch.setattr(launch.time, "monotonic", lambda: 1000.0)
    clocks = launch.LaunchClocks.start(now + timedelta(seconds=60))
    original = clocks.deadline
    monkeypatch.setattr(launch.time, "monotonic", lambda: 1020.0)
    clocks.require_open()
    assert clocks.deadline == original
    monkeypatch.setattr(launch.time, "monotonic", lambda: 999.0)
    with pytest.raises(ProviderRefused):
        clocks.require_open()
    monkeypatch.setattr(launch.time, "monotonic", lambda: original)
    with pytest.raises(ProviderRefused):
        clocks.require_open()


def test_exclusive_claim_precedes_wrapper_and_denies_concurrent_invocations(
    tmp_path, monkeypatch
):
    # Explicit mechanism fixture bypasses host authentication; no production
    # constructor accepts this substitution. Test the actual O_EXCL race.
    context = object.__new__(launch.InstalledLaunchContext)
    object.__setattr__(context, "role", "attester")
    object.__setattr__(context, "slot_id", "a_issue")
    object.__setattr__(context, "worker_uid", os.geteuid())
    object.__setattr__(context, "packet_digest", "sha256:" + "a" * 64)
    object.__setattr__(context, "expires_at", datetime.now(UTC) + timedelta(seconds=30))
    monkeypatch.setattr(
        launch.InstalledLaunchContext, "require_open", lambda self: None
    )
    monkeypatch.setattr(
        launch.InstalledLaunchContext, "require_installation", lambda *args: None
    )
    monkeypatch.setattr(
        launch,
        "_protected",
        lambda *args, **kwargs: os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY),
    )
    opened = []
    monkeypatch.setattr(
        launch, "open_slot_wrapper", lambda claim: opened.append(claim) or 42
    )

    def invoke():
        try:
            return context.open_wrapping_token()
        except FileExistsError:
            return None

    with ThreadPoolExecutor(max_workers=8) as workers:
        results = list(workers.map(lambda _: invoke(), range(8)))
    assert results.count(42) == 1
    assert len(opened) == 1
    assert (tmp_path / "a_issue").exists()
    assert invoke() is None  # sequential channel also refuses before secret open


def test_parent_rejects_trailing_staged_frame_before_publication(monkeypatch):
    parent, receiver = socket.socketpair()
    supervisor = object.__new__(launch.FiniteGate0Supervisor)
    supervisor.state = launch.LaunchState.AWAITING_CAPTURE
    supervisor.clocks = launch.LaunchClocks.start(
        datetime.now(UTC) + timedelta(seconds=30)
    )
    supervisor.packet_digest = "sha256:" + "a" * 64
    supervisor._active_deadline = None
    # Host-packet fixture only: no filesystem publication should be reached.
    monkeypatch.setattr(launch, "_read", lambda *args: b'{"captures":{"a":{},"b":{}}}')
    monkeypatch.setattr(
        launch, "_load_local_packet", lambda: {"captures": {"a": {}, "b": {}}}
    )
    monkeypatch.setattr(launch, "_coordinate_document", lambda value: {})
    touched = []
    monkeypatch.setattr(
        launch.os, "mkdir", lambda *args, **kwargs: touched.append(args)
    )
    try:
        receiver.sendall(struct.pack("!I", 2) + b"{}" + b"trailing")
        receiver.shutdown(socket.SHUT_WR)
        with pytest.raises(ProviderRefused):
            supervisor.commit_capture(parent.fileno(), (object(), object()))
        assert supervisor.state == launch.LaunchState.TERMINAL
        assert touched == []
    finally:
        parent.close()
        receiver.close()
