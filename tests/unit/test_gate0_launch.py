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
            "peers": [
                {"public_key": public, "allowed_ips": ["10.0.0.2/32"]},
                {
                    "public_key": base64.b64encode(bytes([1]) * 32).decode(),
                    "allowed_ips": ["10.0.0.3/32"],
                },
            ],
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
        "low_port",
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
    elif field == "low_port":
        packet["ssh_endpoints"]["issuer"]["local_port"] = 22
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


@pytest.mark.parametrize(
    "change",
    [
        "missing_inventory",
        "empty",
        "duplicate_peer",
        "duplicate_address",
        "wildcard",
        "subnet",
        "public_ip",
        "extra_field",
        "bao_moved",
        "bao_extra",
        "ssh_missing",
        "local_source",
        "bad_key",
    ],
)
def test_complete_peer_inventory_refuses_ambiguous_or_broader_scope(change):
    packet = deepcopy(synthetic_local_packet())
    network = packet["network"]
    peers = network["peers"]
    if change == "missing_inventory":
        del network["peers"]
    elif change == "empty":
        network["peers"] = []
    elif change == "duplicate_peer":
        peers.append(deepcopy(peers[0]))
    elif change == "duplicate_address":
        peers[1]["allowed_ips"].append("10.0.0.2/32")
    elif change in ("wildcard", "subnet", "public_ip"):
        peers[1]["allowed_ips"] = {
            "wildcard": ["0.0.0.0/0"],
            "subnet": ["10.0.0.0/24"],
            "public_ip": ["192.0.2.1/32"],
        }[change]
    elif change == "extra_field":
        peers[0]["qualified"] = True
    elif change == "bao_moved":
        peers[0]["allowed_ips"], peers[1]["allowed_ips"] = (
            peers[1]["allowed_ips"],
            peers[0]["allowed_ips"],
        )
    elif change == "bao_extra":
        peers[0]["allowed_ips"].append("10.0.0.4/32")
    elif change == "ssh_missing":
        packet["ssh_endpoints"]["issuer"]["remote_address"] = "10.0.0.4"
    elif change == "local_source":
        peers[1]["allowed_ips"] = [network["local_address"] + "/32"]
    else:
        peers[1]["public_key"] = "not-a-key"
    with pytest.raises(launch.ProviderRefused):
        launch._local_packet(launch.canonical(packet))


def test_actual_inventory_normalizes_order_but_keeps_exact_full_equality():
    network = synthetic_local_packet()["network"]
    first, second = network["peers"]
    expected = launch._peer_inventory(network["peers"])
    # Kernel listing order is not authorization; membership in both directions is.
    peers = (second["public_key"] + "\n" + first["public_key"] + "\n").encode()
    allowed = (
        first["public_key"]
        + "\t10.0.0.2/32\n"
        + second["public_key"]
        + "\t10.0.0.3/32\n"
    ).encode()
    assert launch._observed_peer_inventory(peers, allowed) == expected
    for changed_peers, changed_allowed in [
        (peers + peers.splitlines()[0] + b"\n", allowed),
        (peers, allowed + allowed.splitlines()[0] + b"\n"),
        (peers, allowed.replace(b"10.0.0.2/32", b"10.0.0.2/24")),
        (peers.splitlines()[0] + b"\n", allowed),
    ]:
        with pytest.raises(launch.ProviderRefused):
            launch._observed_peer_inventory(changed_peers, changed_allowed)
    subset = launch._observed_peer_inventory(
        peers.splitlines()[0] + b"\n", allowed.splitlines()[1] + b"\n"
    )
    assert subset != expected  # Valid subset is still not full installed equality.


def measured_request_context(monkeypatch):
    packet = synthetic_local_packet()
    public = base64.b64encode(bytes(range(32))).decode()
    packet["network"].update(
        peer_public_key=public,
        peers=[
            {"public_key": public, "allowed_ips": ["10.0.0.2/32"]},
            {
                "public_key": base64.b64encode(bytes([1]) * 32).decode(),
                "allowed_ips": ["10.0.0.3/32"],
            },
        ],
    )
    now = datetime.now(UTC)
    mono = launch.time.monotonic()
    context = object.__new__(launch.InstalledLaunchContext)
    values = dict(
        packet_digest=packet["shared_run_digest"],
        local_packet_digest=launch._digest(launch.canonical(packet)),
        machine_id_digest=packet["machine_id_digest"],
        role="issuer",
        worker_uid=os.geteuid(),
        slot_id=None,
        started_at=now,
        expires_at=now + timedelta(seconds=120),
        monotonic_origin=mono,
        deadline=mono + 90,
        _supervisor_pid=12345,
        _supervisor_start="synthetic-process-start",
    )
    for name, value in values.items():
        object.__setattr__(context, name, value)
    measurement = {
        "packet_digest": context.packet_digest,
        "local_packet_digest": context.local_packet_digest,
        "machine_id_digest": context.machine_id_digest,
        **{
            name: packet["network"][name]
            for name in (
                "namespace_device",
                "namespace_inode",
                "interface",
                "index",
                "bao_address",
                "local_address",
                "peer_public_key",
                "peer_allowed_ip",
                "peers",
            )
        },
        "route_digest": launch._digest(packet["network"]["route_document"].encode()),
        "nft_ruleset_digest": packet["network"]["nft_ruleset_digest"],
        "started_at": now.isoformat(),
        "monotonic_origin": mono,
        "deadline": mono + 120,
        "expires_at": context.expires_at.isoformat(),
        "supervisor_pid": 12345,
        "supervisor_start": "synthetic-process-start",
    }
    object.__setattr__(
        context,
        "network_measurement_digest",
        launch._digest(launch.canonical(measurement)),
    )
    monkeypatch.setattr(
        launch.InstalledLaunchContext, "require_open", lambda self: None
    )
    monkeypatch.setattr(
        launch,
        "_load_local_packet",
        lambda: launch._local_packet(launch.canonical(packet)),
    )

    def read(path, *args):
        if path == launch.ROOT / "packet.json":
            return launch.canonical(packet)
        if path == launch.ROOT / "network-measurement.json":
            return launch.canonical(measurement)
        if str(path) == "/etc/machine-id":
            return b"synthetic-machine"
        raise AssertionError(path)

    packet["machine_id_digest"] = launch._digest(b"synthetic-machine")
    object.__setattr__(context, "machine_id_digest", packet["machine_id_digest"])
    object.__setattr__(
        context, "local_packet_digest", launch._digest(launch.canonical(packet))
    )
    measurement.update(
        machine_id_digest=context.machine_id_digest,
        local_packet_digest=context.local_packet_digest,
    )
    object.__setattr__(
        context,
        "network_measurement_digest",
        launch._digest(launch.canonical(measurement)),
    )
    monkeypatch.setattr(launch, "_read", read)
    monkeypatch.setattr(
        launch.RunIdentity,
        "from_installed",
        lambda: SimpleNamespace(digest=context.packet_digest),
    )
    original_stat = launch.Path.stat
    monkeypatch.setattr(
        launch.Path,
        "stat",
        lambda self, *a, **k: SimpleNamespace(st_dev=4, st_ino=1234)
        if str(self) == "/proc/self/ns/net"
        else original_stat(self, *a, **k),
    )
    monkeypatch.setattr(launch.socket, "if_nametoindex", lambda interface: 3)
    return context, packet, measurement


def test_root_measurement_is_bound_to_original_context_and_endpoint(monkeypatch):
    context, packet, measurement = measured_request_context(monkeypatch)
    from vendor_cp.deployment.gate0_role_custody import WireGuardBaoEndpoint

    value = WireGuardBaoEndpoint(
        role="issuer",
        address="10.0.0.2",
        port=8200,
        local_address="10.0.0.1",
        interface="wgsynthetic",
        interface_index=3,
        namespace_device=4,
        namespace_inode=1234,
        peer_fingerprint="sha256:"
        + launch.hashlib.sha256(bytes(range(32))).hexdigest(),
        peer_allowed_ip="10.0.0.2/32",
        wg_binary_digest=packet["binary_digests"]["/usr/bin/wg"],
        network_config_digest="sha256:" + "b" * 64,
        launch_packet_digest=context.packet_digest,
    )
    context.require_bao_endpoint(value, context.deadline - 1)
    # No root measurement read/cache can renew the original operation bound.
    with pytest.raises(launch.ProviderRefused):
        context.require_bao_endpoint(value, context.deadline + 1)


@pytest.mark.parametrize(
    "field,value",
    [
        ("packet_digest", "sha256:" + "0" * 64),
        ("supervisor_start", "fresh-process"),
        ("supervisor_pid", 12346),
        ("monotonic_origin", 1),
        ("deadline", 1),
        ("interface", "other"),
        ("index", 4),
        ("namespace_inode", 1235),
        ("bao_address", "10.0.0.9"),
        ("local_address", "10.0.0.8"),
        ("peer_allowed_ip", "10.0.0.9/32"),
        ("route_digest", "sha256:" + "0" * 64),
        ("nft_ruleset_digest", "sha256:" + "0" * 64),
    ],
)
def test_changed_or_fresh_launch_measurement_cannot_authorize_request(
    monkeypatch, field, value
):
    context, packet, measurement = measured_request_context(monkeypatch)
    measurement[field] = value
    # Even a synthetic re-sealed digest must not make mismatched terms pass.
    object.__setattr__(
        context,
        "network_measurement_digest",
        launch._digest(launch.canonical(measurement)),
    )
    with pytest.raises(launch.ProviderRefused):
        context.require_installation(
            "issuer", context.packet_digest, context.expires_at
        )


class SyntheticCapabilities:
    """Syscall state model only; never evidence of actual kernel privilege drop."""

    def __init__(self):
        self.effective = self.permitted = self.bounding = (1 << 41) - 1
        self.inheritable = self.ambient = 1 << 12
        self.securebits = self.nnp = 0
        self.events = []

    def capget(self):
        return self.effective, self.permitted, self.inheritable

    def capset(self, effective, permitted, inheritable):
        assert effective & ~permitted == 0
        assert permitted & ~self.permitted == 0
        self.events.append(("capset", effective, permitted, inheritable))
        self.effective, self.permitted, self.inheritable = (
            effective,
            permitted,
            inheritable,
        )

    def prctl(self, option, argument=0):
        if option == 23:
            return int(bool(self.bounding & (1 << argument)))
        if option == 24:
            assert self.effective & (1 << 8)
            self.bounding &= ~(1 << argument)
            self.events.append(("drop", argument))
        elif option == 27:
            return self.securebits
        elif option == 28:
            self.securebits = argument
        elif option == 38:
            assert argument == 1
            self.nnp = 1
        elif option == 39:
            return self.nnp
        elif option == 47 and argument == 4:
            self.ambient = 0
        else:
            raise AssertionError((option, argument))
        return 0


def synthetic_capability_syscalls(monkeypatch):
    kernel = SyntheticCapabilities()
    monkeypatch.setattr(launch, "_require_initial_process", lambda: None)
    monkeypatch.setattr(launch, "_capget", kernel.capget)
    monkeypatch.setattr(launch, "_capset", kernel.capset)
    monkeypatch.setattr(launch, "_prctl", kernel.prctl)
    monkeypatch.setattr(launch, "_cap_last_cap", lambda: 40)
    monkeypatch.setattr(launch, "_ambient_set", lambda count: kernel.ambient)
    return kernel


def test_capability_normalization_then_irreversible_seal_exact_masks(monkeypatch):
    kernel = synthetic_capability_syscalls(monkeypatch)
    launch._prepare_network_privileges()
    assert (kernel.effective, kernel.permitted, kernel.bounding) == (0x411E3,) * 3
    assert kernel.inheritable == kernel.ambient == 0
    assert kernel.securebits == 234 and kernel.nnp == 1
    kernel.events.clear()
    launch._seal_network_privileges()
    assert (kernel.effective, kernel.permitted, kernel.bounding) == (0x400E3,) * 3
    assert kernel.inheritable == kernel.ambient == 0
    assert kernel.events[-1] == ("capset", 0x400E3, 0x400E3, 0)
    drops = [
        value for event, *values in kernel.events if event == "drop" for value in values
    ]
    assert drops[-1] == 8  # SETPCAP last; no authority remains to re-add NET_ADMIN.
    assert 12 in drops and 13 not in [
        i for i in range(41) if kernel.bounding & (1 << i)
    ]


@pytest.mark.parametrize("missing", [0, 5, 6, 7, 8, 12, 18])
def test_missing_required_initial_privilege_refuses_without_helpers(
    monkeypatch, missing
):
    kernel = synthetic_capability_syscalls(monkeypatch)
    kernel.permitted &= ~(1 << missing)
    with pytest.raises(launch.ProviderRefused):
        launch._prepare_network_privileges()
    assert kernel.events == []


def test_unsupported_securebits_or_capability_space_is_terminal(monkeypatch):
    kernel = synthetic_capability_syscalls(monkeypatch)
    kernel.securebits = 1
    with pytest.raises(launch.ProviderRefused):
        launch._prepare_network_privileges()
    kernel.securebits = 0
    monkeypatch.setattr(launch, "_cap_last_cap", lambda: 64)
    with pytest.raises(launch.ProviderRefused):
        launch._prepare_network_privileges()


@pytest.mark.parametrize("failure", ["capset", "drop", "readback"])
def test_failed_or_ineffective_privilege_seal_is_refused(monkeypatch, failure):
    kernel = synthetic_capability_syscalls(monkeypatch)
    launch._prepare_network_privileges()
    if failure == "capset":
        monkeypatch.setattr(
            launch,
            "_capset",
            lambda *args: (_ for _ in ()).throw(launch.ProviderRefused()),
        )
    elif failure == "drop":
        original = kernel.prctl
        monkeypatch.setattr(
            launch,
            "_prctl",
            lambda option, arg=0: (_ for _ in ()).throw(launch.ProviderRefused())
            if option == 24
            else original(option, arg),
        )
    else:
        monkeypatch.setattr(launch, "_capset", lambda *args: None)
    with pytest.raises(launch.ProviderRefused):
        launch._seal_network_privileges()


def test_preflight_guardian_empty_and_privilege_seal_precede_publication(monkeypatch):
    supervisor = object.__new__(launch.FiniteGate0Supervisor)
    supervisor.clocks = SimpleNamespace(
        deadline=launch.time.monotonic() + 30, require_open=lambda: None
    )
    events = []
    boundary = SimpleNamespace(
        start_watchdog=lambda end: events.append("watchdog"),
        terminate_and_confirm_empty=lambda: events.append("empty-and-reaped"),
    )
    monkeypatch.setattr(launch, "SlotExecutionBoundary", lambda slot: boundary)
    monkeypatch.setattr(
        supervisor,
        "_measure_network_scoped",
        lambda leaf: events.append("measured") or b"synthetic-public-measurement",
    )
    monkeypatch.setattr(
        launch, "_seal_network_privileges", lambda: events.append("sealed")
    )
    monkeypatch.setattr(
        supervisor,
        "_publish_network_measurement",
        lambda raw: events.append("published"),
    )
    supervisor._measure_network()
    assert events == ["watchdog", "measured", "empty-and-reaped", "sealed", "published"]
    events.clear()
    monkeypatch.setattr(
        boundary,
        "terminate_and_confirm_empty",
        lambda: (_ for _ in ()).throw(launch.ProviderRefused()),
    )
    with pytest.raises(launch.ProviderRefused):
        supervisor._measure_network()
    assert "sealed" not in events and "published" not in events


@pytest.mark.parametrize(
    "method,name,uid",
    [
        ("_bind_management_listener", "management.sock", 10033),
        ("_bind_issuer_export", "issuer-export.sock", 10031),
    ],
)
def test_new_root_owned_socket_mode_precedes_nonroot_ownership(
    monkeypatch, method, name, uid
):
    supervisor = object.__new__(launch.FiniteGate0Supervisor)
    supervisor.worker_uid = 10031
    supervisor.clocks = SimpleNamespace(deadline=launch.time.monotonic() + 10)
    supervisor._active_deadline = None
    events = []
    listener = SimpleNamespace(
        settimeout=lambda value: None,
        bind=lambda path: events.append(("bind", path)),
        listen=lambda count: events.append(("listen", count)),
        close=lambda: None,
    )
    monkeypatch.setattr(launch.socket, "socket", lambda *args: listener)
    monkeypatch.setattr(
        launch,
        "_load_local_packet",
        lambda: {"management_uid": 10033, "issuer_uid": 10031},
    )
    monkeypatch.setattr(
        launch.os, "chmod", lambda path, mode: events.append(("chmod", path, mode))
    )
    monkeypatch.setattr(
        launch.os,
        "chown",
        lambda path, owner, group: events.append(("chown", path, owner, group)),
    )
    assert getattr(supervisor, method)() is listener
    assert events == [
        ("bind", str(launch.ROOT / name)),
        ("chmod", launch.ROOT / name, 0o600),
        ("chown", launch.ROOT / name, uid, -1),
        ("listen", 1),
    ]


def test_missing_initial_bounding_capability_is_not_manufactured(monkeypatch):
    kernel = synthetic_capability_syscalls(monkeypatch)
    kernel.bounding &= ~(1 << 12)
    with pytest.raises(launch.ProviderRefused):
        launch._prepare_network_privileges()
    assert kernel.events == []


def test_future_supported_capabilities_are_removed_from_all_sets(monkeypatch):
    kernel = synthetic_capability_syscalls(monkeypatch)
    kernel.effective = kernel.permitted = kernel.bounding = (1 << 64) - 1
    monkeypatch.setattr(launch, "_cap_last_cap", lambda: 63)
    launch._prepare_network_privileges()
    launch._seal_network_privileges()
    assert (kernel.effective, kernel.permitted, kernel.bounding) == (0x400E3,) * 3
    assert ("drop", 63) in kernel.events


@pytest.mark.parametrize("existing", ["thread", "child"])
def test_initial_privileged_helpers_or_threads_refuse_before_normalization(
    monkeypatch, existing
):
    monkeypatch.setattr(launch.os, "geteuid", lambda: 0)
    monkeypatch.setattr(launch.os, "getpid", lambda: 1)
    monkeypatch.setattr(
        launch.os, "listdir", lambda path: ["1", "2"] if existing == "thread" else ["1"]
    )
    monkeypatch.setattr(launch, "_read", lambda *args: b"17")
    with pytest.raises(launch.ProviderRefused):
        launch._require_initial_process()


def test_measurement_digest_cannot_be_replaced_or_omitted(monkeypatch):
    context, _, measurement = measured_request_context(monkeypatch)
    measurement["index"] = 9
    with pytest.raises(launch.ProviderRefused):
        context.require_installation(
            "issuer", context.packet_digest, context.expires_at
        )
    monkeypatch.setattr(
        launch, "_read", lambda *args: (_ for _ in ()).throw(FileNotFoundError())
    )
    with pytest.raises(FileNotFoundError):
        context.require_installation(
            "issuer", context.packet_digest, context.expires_at
        )
