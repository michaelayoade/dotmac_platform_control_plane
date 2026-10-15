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
        "capture": selection,
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
    supervisor._boundaries = {}
    supervisor._daemon_observations = {}
    supervisor._daemon_live = {}
    supervisor._management_capture = None
    supervisor._capture_delivery = None
    supervisor._phase_completed = {}
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


def test_issuer_missing_or_legacy_success_terminal_is_refused(tmp_path, monkeypatch):
    supervisor = object.__new__(launch.FiniteGate0Supervisor)
    supervisor._boundaries = {}
    supervisor._daemon_observations = {}
    supervisor._daemon_live = {}
    supervisor._management_capture = None
    supervisor._capture_delivery = None
    supervisor._phase_completed = {}
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
    with pytest.raises(ProviderRefused):
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
        "run_id": "2",
        "run_attempt": "1",
        "case_kind": "consume_replay",
        "not_before": (now - timedelta(seconds=1)).isoformat(),
        "expires_at": (now + timedelta(seconds=60)).isoformat(),
        "capture": selection,
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
    supervisor._boundaries = {}
    supervisor._daemon_observations = {}
    supervisor._daemon_live = {}
    supervisor._management_capture = None
    supervisor._capture_delivery = None
    supervisor._phase_completed = {}
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
        pid = os.getpid()
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
def test_issuer_acceptance_deadline_excludes_bounded_cleanup_tail(
    tmp_path, monkeypatch, late_at
):
    # Mechanism fixture isolates acceptance timing; no installation is qualified.
    clock = [1000.0]
    monkeypatch.setattr(launch.time, "monotonic", lambda: clock[0])
    supervisor = object.__new__(launch.FiniteGate0Supervisor)
    supervisor._boundaries = {}
    supervisor._daemon_observations = {}
    supervisor._daemon_live = {}
    supervisor._management_capture = None
    supervisor._capture_delivery = None
    supervisor._phase_completed = {}
    supervisor.clocks = launch.LaunchClocks.start(
        datetime.now(UTC) + timedelta(seconds=120)
    )
    deadline = supervisor.clocks.deadline
    supervisor.state = launch.LaunchState.AWAITING_CAPTURE
    supervisor._boundary, supervisor._activated = None, False
    supervisor.worker_uid = os.geteuid()
    supervisor.packet_digest = "sha256:" + "a" * 64
    from vendor_cp.approvals.adapter import ApprovalHoldRefusal
    from vendor_cp.deployment.gate0_collection import IssuerOutcome, OutcomeKind
    from vendor_cp.deployment.gate0_services import IssuerProcessResult

    h = supervisor.packet_digest
    supervisor.local_packet_digest = h
    supervisor._run_terms = {
        "case_kind": "withdrawal_later_use",
        "capture": {"window_digest": h},
    }
    supervisor._terminals = {}
    outcome = IssuerOutcome(
        1,
        "consume",
        h,
        h,
        h,
        h,
        OutcomeKind.OWNER_REFUSED,
        "approvals",
        ApprovalHoldRefusal.WITHDRAWN.value,
        launch.canonical({}),
    )
    result = IssuerProcessResult(3, (outcome,))
    terminal = {
        "schema": "Gate0IssuerTerminal.v1",
        "launch_packet_digest": h,
        "local_packet_digest": h,
        "case_kind": "withdrawal_later_use",
        "window_digest": h,
        "worker_declared_exit_code": 3,
        "transcript_digest": result.transcript_digest,
        "terminal_outcome": outcome.document(),
    }
    (tmp_path / "terminal.json").write_bytes(launch.canonical(terminal))
    (tmp_path / "terminal.json").chmod(0o400)
    # Exercise the actual new terminal parser before isolating timing.
    monkeypatch.setattr(
        launch,
        "_protected",
        lambda *args, **kwargs: os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY),
    )
    supervisor._require_terminal_success("issuer")
    supervisor._terminals.clear()
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
        pid = os.getpid()
        returncode = 0

        def wait(self, timeout):
            if late_at == "exit":
                clock[0] = deadline

    monkeypatch.setattr(launch, "SlotExecutionBoundary", Boundary)
    monkeypatch.setattr(launch.subprocess, "Popen", lambda *args, **kwargs: Process())
    try:
        if late_at == "exit":
            with pytest.raises(launch.LaunchIncomplete):
                supervisor.run()
            assert not supervisor._terminals
        else:
            supervisor.run()
            assert supervisor._terminals["issuer"]["worker_terminal"] == terminal
            assert clock[0] == deadline
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
    object.__setattr__(context, "slot_id", "issue")
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
    assert (tmp_path / "issue").exists()
    assert invoke() is None  # sequential channel also refuses before secret open


def test_parent_rejects_trailing_staged_frame_before_publication(monkeypatch):
    parent, receiver = socket.socketpair()
    supervisor = object.__new__(launch.FiniteGate0Supervisor)
    supervisor._boundaries = {}
    supervisor._daemon_observations = {}
    supervisor._daemon_live = {}
    supervisor._management_capture = None
    supervisor._capture_delivery = None
    supervisor._phase_completed = {}
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
        lambda self, *a, **k: (
            SimpleNamespace(st_dev=4, st_ino=1234)
            if str(self) == "/proc/self/ns/net"
            else original_stat(self, *a, **k)
        ),
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
            lambda option, arg=0: (
                (_ for _ in ()).throw(launch.ProviderRefused())
                if option == 24
                else original(option, arg)
            ),
        )
    else:
        monkeypatch.setattr(launch, "_capset", lambda *args: None)
    with pytest.raises(launch.ProviderRefused):
        launch._seal_network_privileges()


def synthetic_cleanup_boundary(monkeypatch):
    """Synthetic cgroup I/O only; never evidence of kernel quiescence."""
    boundary = object.__new__(launch.SlotExecutionBoundary)
    boundary._closed = False
    boundary._cleanup_complete = False
    boundary._evidence = None
    boundary._identity = (1, 2)
    boundary.path = launch.CGROUP_ROOT / "issue"
    boundary._watchdog_start = "fixed-start"
    boundary._fd = 101
    boundary._watchdog_pid = 202
    boundary._watchdog_write = 303
    events = []
    monkeypatch.setattr(
        launch.os,
        "open",
        lambda name, flags, *, dir_fd: events.append(("open", name)) or 404,
    )
    monkeypatch.setattr(launch.os, "close", lambda fd: events.append(("close", fd)))
    monkeypatch.setattr(
        launch, "_write", lambda fd, value: events.append(("write", value))
    )
    monkeypatch.setattr(launch, "_bytes", lambda fd, size: b"populated 0\n")
    monkeypatch.setattr(launch.time, "monotonic", lambda: 0)
    return boundary, events


@pytest.mark.parametrize("failure", ["waitpid-error", "guardian-failure"])
def test_cleanup_failure_after_empty_readback_is_sticky(monkeypatch, failure):
    boundary, events = synthetic_cleanup_boundary(monkeypatch)

    def waitpid(pid, flags):
        events.append(("waitpid", pid))
        if failure == "waitpid-error":
            raise ChildProcessError()
        return pid, 1

    monkeypatch.setattr(launch.os, "waitpid", waitpid)
    with pytest.raises((ChildProcessError, launch.ProviderRefused)):
        boundary.terminate_and_confirm_empty()
    assert boundary._closed and not boundary._cleanup_complete
    assert ("close", boundary._fd) in events
    assert ("waitpid", 202) in events
    attempted = list(events)
    with pytest.raises(launch.ProviderRefused):
        boundary.terminate_and_confirm_empty()
    assert events == attempted


def test_cleanup_is_idempotent_only_after_empty_readback_and_guardian_reap(monkeypatch):
    boundary, events = synthetic_cleanup_boundary(monkeypatch)

    def waitpid(pid, flags):
        assert not boundary._cleanup_complete
        events.append(("waitpid", pid))
        return pid, 0

    monkeypatch.setattr(launch.os, "waitpid", waitpid)
    boundary.terminate_and_confirm_empty()
    assert boundary._closed and boundary._cleanup_complete
    assert events[-1] == ("waitpid", 202)
    completed = list(events)
    boundary.terminate_and_confirm_empty()
    assert events == completed


def test_preflight_guardian_empty_and_privilege_seal_precede_publication(monkeypatch):
    supervisor = object.__new__(launch.FiniteGate0Supervisor)
    supervisor._boundaries = {}
    supervisor._daemon_observations = {}
    supervisor._daemon_live = {}
    supervisor._management_capture = None
    supervisor._capture_delivery = None
    supervisor._phase_completed = {}
    supervisor.clocks = SimpleNamespace(
        deadline=launch.time.monotonic() + 30,
        monotonic_origin=launch.time.monotonic(),
        require_open=lambda: None,
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
    supervisor._boundaries = {}
    supervisor._daemon_observations = {}
    supervisor._daemon_live = {}
    supervisor._management_capture = None
    supervisor._capture_delivery = None
    supervisor._phase_completed = {}
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


@pytest.mark.parametrize("kind", ["consume_replay", "withdrawal_later_use"])
def test_fixed_finite_case_slots_reject_legacy_roster(kind):
    assert launch._case_kind(kind) == kind
    assert launch.SLOTS == ("issue", "consume")
    for stale in ("a_issue", "a_consume", "b_issue", "b_consume", "retry", ""):
        with pytest.raises(ProviderRefused):
            launch._case_kind(stale)
    packet = synthetic_local_packet()
    packet["captures"] = {"a": packet.pop("capture"), "b": {}}
    with pytest.raises(ProviderRefused):
        launch._local_packet(launch.canonical(packet))


def test_cleanup_returns_measured_immutable_evidence_after_guardian_reap(monkeypatch):
    boundary, events = synthetic_cleanup_boundary(monkeypatch)
    monkeypatch.setattr(launch.os, "waitpid", lambda pid, flags: (pid, 0))
    evidence = boundary.terminate_and_confirm_empty()
    assert evidence == launch.BoundaryCleanupEvidence(
        "issue", 1, 2, True, 0, 202, "fixed-start", 0
    )
    assert ("write", b"1") in events
    before = list(events)
    assert boundary.terminate_and_confirm_empty() is evidence
    assert events == before


@pytest.mark.parametrize("exit_code", [0, 5, -15, 255, True])
def test_issuer_unknown_or_success_cannot_publish_expected_negative(
    monkeypatch, exit_code
):
    from vendor_cp.deployment.gate0_services import IssuerProcessResult

    context = object.__new__(launch.InstalledLaunchContext)
    object.__setattr__(context, "role", "issuer")
    monkeypatch.setattr(
        launch.InstalledLaunchContext, "require_open", lambda self: None
    )
    monkeypatch.setattr(
        launch.RunIdentity,
        "from_installed",
        lambda: SimpleNamespace(canonical_bytes=b"{}"),
    )
    monkeypatch.setattr(launch, "_run_document", lambda raw: {"capture": {}})
    opened = []
    monkeypatch.setattr(launch, "_protected", lambda *a, **kw: opened.append(a))
    with pytest.raises(ProviderRefused):
        context.finish_issuer(IssuerProcessResult(exit_code))
    assert opened == []


def test_cleanup_document_reports_missing_final_close_or_boundary():
    supervisor = synthetic_cleanup_supervisor()
    supervisor._mechanics_complete = True
    supervisor._cleanup_complete = False
    document = supervisor.cleanup_document()
    assert document["outcome"] == "incomplete"
    assert document["reason"] == "cleanup_missing"
    assert document["cleanup_completed_at"] is None
    supervisor._cleanup_complete = True
    document = supervisor.cleanup_document()
    assert document["outcome"] == "incomplete"
    assert document["reason"] == "execution_incomplete"


@pytest.mark.parametrize(
    "change", [None, "local", "case", "window", "declared", "declared5", "extra"]
)
def test_post_cleanup_typed_terminal_is_case_bound_worker_declaration(
    monkeypatch, tmp_path, change
):
    from vendor_cp.approvals.adapter import ApprovalHoldRefusal
    from vendor_cp.deployment.gate0_collection import IssuerOutcome, OutcomeKind
    from vendor_cp.deployment.gate0_services import IssuerProcessResult

    h = "sha256:" + "a" * 64
    terms = {"case_kind": "withdrawal_later_use", "capture": {"window_digest": h}}
    context = object.__new__(launch.InstalledLaunchContext)
    for key, value in {
        "role": "issuer",
        "packet_digest": h,
        "local_packet_digest": h,
        "worker_uid": os.geteuid(),
    }.items():
        object.__setattr__(context, key, value)
    monkeypatch.setattr(launch, "ROOT", tmp_path)
    monkeypatch.setattr(
        launch.InstalledLaunchContext, "require_open", lambda self: None
    )
    monkeypatch.setattr(
        launch.RunIdentity,
        "from_installed",
        lambda: SimpleNamespace(canonical_bytes=b"{}"),
    )
    monkeypatch.setattr(launch, "_run_document", lambda raw: terms)
    monkeypatch.setattr(
        launch, "_protected", lambda path, **kwargs: os.open(path, os.O_RDONLY)
    )
    parent = tmp_path / "status" / "issuer"
    parent.mkdir(parents=True)
    outcome = IssuerOutcome(
        1,
        "consume",
        h,
        h,
        h,
        h,
        OutcomeKind.OWNER_REFUSED,
        "approvals",
        ApprovalHoldRefusal.WITHDRAWN.value,
        launch.canonical({}),
    )
    result = IssuerProcessResult(3, (outcome,))
    context.finish_issuer(result)
    path = parent / "terminal.json"
    document = launch.strict_object(path.read_bytes())
    assert document["worker_declared_exit_code"] == 3
    assert document["transcript_digest"] == result.transcript_digest
    if change:
        key, value = {
            "local": ("local_packet_digest", "sha256:" + "b" * 64),
            "case": ("case_kind", "consume_replay"),
            "window": ("window_digest", "sha256:" + "b" * 64),
            "declared": ("worker_declared_exit_code", 0),
            "declared5": ("worker_declared_exit_code", 5),
            "extra": ("cleanup", True),
        }[change]
        document[key] = value
        path.chmod(0o600)
        path.write_bytes(launch.canonical(document))
        path.chmod(0o400)
    supervisor = object.__new__(launch.FiniteGate0Supervisor)
    supervisor.worker_uid = os.geteuid()
    supervisor.packet_digest = h
    supervisor.local_packet_digest = h
    supervisor._run_terms = terms
    supervisor._terminals = {}
    if change:
        with pytest.raises(ProviderRefused):
            supervisor._require_terminal_success("issuer")
        assert not supervisor._terminals
    else:
        supervisor._require_terminal_success("issuer")
        observed = supervisor._terminals["issuer"]
        assert "daemon_returncode" not in observed
        assert observed["worker_terminal"] == document
        assert "observed_worker_exit_code" not in observed


def synthetic_cleanup_supervisor():
    supervisor = object.__new__(launch.FiniteGate0Supervisor)
    h = "sha256:" + "a" * 64
    supervisor._local_terms = {
        "host_role": "issuer",
        "issuer_uid": os.geteuid(),
        "management_uid": os.geteuid(),
    }
    supervisor._run_terms = {
        "case_kind": "consume_replay",
        "capture": {"window_digest": h},
    }
    supervisor._cleanup_complete = False
    supervisor._cleanup_failed = False
    supervisor._mechanics_complete = False
    supervisor._failure_reason = None
    supervisor._cleanup_completed_at = None
    supervisor._removed = []
    supervisor._boundaries = {}
    supervisor._daemon_observations = {}
    supervisor._daemon_live = {}
    supervisor._management_capture = None
    supervisor._capture_delivery = None
    supervisor._terminals = {}
    supervisor._phase_completed = {}
    supervisor._management_listener = None
    supervisor.packet_digest = h
    supervisor.local_packet_digest = h
    supervisor.machine_id_digest = h
    supervisor.network_measurement_digest = h
    supervisor.clocks = SimpleNamespace(
        started_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(seconds=30),
    )
    return supervisor


def test_boundary_failure_still_reaps_child_and_closes_every_descriptor():
    supervisor = synthetic_cleanup_supervisor()
    events = []
    first = ChildProcessError("synthetic-guardian-failure")

    def empty():
        events.append("boundary")
        raise first

    boundary = SimpleNamespace(terminate_and_confirm_empty=empty)
    process = SimpleNamespace(wait=lambda timeout: events.append(("wait", timeout)))
    descriptors = tuple(
        SimpleNamespace(close=lambda name=name: events.append(name))
        for name in ("accepted", "export-listener", "export-stream")
    )
    with pytest.raises(ChildProcessError) as raised:
        supervisor._retire_resources(boundary, process, descriptors)
    assert raised.value is first
    assert events == [
        "boundary",
        ("wait", 2),
        "accepted",
        "export-listener",
        "export-stream",
    ]
    assert supervisor._failure_reason is launch.CleanupReason.BOUNDARY_FAILED
    assert supervisor._cleanup_failed
    assert not supervisor._terminals


def test_failed_reap_stays_unknown_after_successful_retry_and_fd_closure():
    supervisor = synthetic_cleanup_supervisor()
    events = []
    calls = [0]

    def wait(timeout):
        calls[0] += 1
        events.append("wait")
        if calls[0] == 1:
            raise launch.subprocess.TimeoutExpired("synthetic", timeout)

    process = SimpleNamespace(wait=wait, kill=lambda: events.append("kill"))
    boundary = SimpleNamespace(
        terminate_and_confirm_empty=lambda: events.append("empty")
    )
    descriptor = SimpleNamespace(close=lambda: events.append("close"))
    with pytest.raises(launch.subprocess.TimeoutExpired):
        supervisor._retire_resources(boundary, process, (descriptor,))
    assert events == ["empty", "wait", "kill", "wait", "close"]
    assert supervisor._cleanup_failed
    assert supervisor._failure_reason is launch.CleanupReason.PROCESS_REAP_FAILED


@pytest.mark.parametrize("failure", [False, True])
def test_final_close_attempts_all_boundaries_and_fixed_transient_inventory(
    tmp_path, monkeypatch, failure
):
    supervisor = synthetic_cleanup_supervisor()
    monkeypatch.setattr(launch, "ROOT", tmp_path)
    monkeypatch.setattr(
        launch, "_protected", lambda path, **kwargs: os.open(path, os.O_RDONLY)
    )
    paths = supervisor._transient_paths()
    for relative in paths:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if relative in ("captures", "capture-commit"):
            path.mkdir(exist_ok=True)
        elif relative not in ("issuer-export.sock", "management.sock"):
            path.write_bytes(b"synthetic transient")
    sockets = []
    for relative in ("issuer-export.sock", "management.sock"):
        connection = socket.socket(socket.AF_UNIX)
        connection.bind(str(tmp_path / relative))
        sockets.append(connection)
    (tmp_path / "supervisor-once").touch()
    (tmp_path / "claims").mkdir()
    events = []

    def retire(name):
        events.append(name)
        if failure and name == "first":
            raise ChildProcessError("synthetic guardian failure")

    for name in ("first", "second"):
        supervisor._boundaries[name] = SimpleNamespace(
            terminate_and_confirm_empty=lambda name=name: retire(name), _evidence=None
        )
    try:
        if failure:
            with pytest.raises(ChildProcessError):
                supervisor.close()
            assert not supervisor._cleanup_complete
            assert supervisor._cleanup_completed_at is None
        else:
            supervisor.close()
            completed_at = supervisor._cleanup_completed_at
            monkeypatch.setattr(
                launch,
                "datetime",
                SimpleNamespace(
                    now=lambda tz: (_ for _ in ()).throw(
                        AssertionError("timestamp recomputed")
                    )
                ),
            )
            supervisor.close()
            assert supervisor.cleanup_document()["cleanup_completed_at"] == completed_at
        assert events == ["first", "second"]
        assert set(supervisor._removed) == set(paths)
        assert all(not (tmp_path / path).exists() for path in paths)
        assert (tmp_path / "supervisor-once").exists()
        assert (tmp_path / "claims").exists()
        document = supervisor.cleanup_document()
        assert document["outcome"] == "incomplete"  # No fabricated terminal evidence.
        assert document["delivery_status"] == "unconfirmed"
    finally:
        for connection in sockets:
            connection.close()


def test_kill_failure_still_attempts_final_reap_and_all_descriptor_closes():
    supervisor = synthetic_cleanup_supervisor()
    events = []
    initial = launch.subprocess.TimeoutExpired("synthetic", 2)
    calls = [0]

    def wait(timeout):
        events.append("wait")
        calls[0] += 1
        if calls[0] == 1:
            raise initial

    def kill():
        events.append("kill")
        raise ProcessLookupError("synthetic exited child")

    process = SimpleNamespace(wait=wait, kill=kill)
    boundary = SimpleNamespace(
        terminate_and_confirm_empty=lambda: events.append("empty")
    )
    descriptors = tuple(
        SimpleNamespace(close=lambda name=name: events.append(name))
        for name in ("first", "last")
    )
    with pytest.raises(launch.subprocess.TimeoutExpired) as raised:
        supervisor._retire_resources(boundary, process, descriptors)
    assert raised.value is initial
    assert events == ["empty", "wait", "kill", "wait", "first", "last"]
    assert supervisor._cleanup_failed
    assert not supervisor._terminals
    assert supervisor.cleanup_document()["outcome"] == "incomplete"


@pytest.mark.parametrize("cancel", [False, True])
def test_issuer_body_error_stays_primary_through_guardian_reap_and_fd_errors(
    monkeypatch, cancel
):
    supervisor = synthetic_cleanup_supervisor()
    supervisor.state = launch.LaunchState.AWAITING_CAPTURE
    supervisor._boundary = None
    supervisor._activated = False
    supervisor.clocks = SimpleNamespace(
        deadline=launch.time.monotonic() + 30,
        monotonic_origin=launch.time.monotonic(),
        require_open=lambda: None,
    )
    events = []
    execution = (
        KeyboardInterrupt("synthetic cancel")
        if cancel
        else RuntimeError("unique execution failure")
    )
    guardian = ChildProcessError("distinct guardian failure")
    closes = [0]

    def close_stream():
        events.append("accepted-close")
        closes[0] += 1
        if closes[0] > 1:
            raise OSError("distinct descriptor failure")

    connection = SimpleNamespace(fileno=lambda: 123, close=close_stream)

    def close_listener():
        events.append("listener-close")
        raise OSError("distinct listener failure")

    listener = SimpleNamespace(close=close_listener)

    def empty():
        events.append("boundary")
        raise guardian

    boundary = SimpleNamespace(
        start_watchdog=lambda end: None,
        require_watchdog=lambda: None,
        enter_child=lambda: None,
        terminate_and_confirm_empty=empty,
        _evidence=None,
    )
    waits = [0]

    def wait(timeout):
        events.append("wait")
        waits[0] += 1
        if waits[0] == 1:
            raise launch.subprocess.TimeoutExpired("synthetic", timeout)

    def kill():
        events.append("kill")
        raise ProcessLookupError("synthetic exited child")

    raw = b"synthetic pinned daemon/config"
    h = launch._digest(raw)
    monkeypatch.setattr(
        launch,
        "_load_local_packet",
        lambda: {"sshd_digest": h, "issuer_sshd_config_digest": h},
    )
    monkeypatch.setattr(launch, "_read", lambda *args: raw)
    monkeypatch.setattr(supervisor, "_require_ssh_connection", lambda *args: None)
    monkeypatch.setattr(supervisor, "_publish_context", lambda *args: None)
    monkeypatch.setattr(supervisor, "_bind_issuer_export", lambda: listener)
    monkeypatch.setattr(launch, "SlotExecutionBoundary", lambda slot: boundary)
    monkeypatch.setattr(
        launch.subprocess,
        "Popen",
        lambda *args, **kwargs: SimpleNamespace(
            pid=os.getpid(), returncode=None, wait=wait, kill=kill
        ),
    )

    def receive(*args):
        events.append("receive")
        raise execution

    monkeypatch.setattr(supervisor, "_receive_issuer_export", receive)
    monkeypatch.setattr(
        supervisor,
        "_require_terminal_success",
        lambda *args: events.append("terminal-inspection"),
    )
    with pytest.raises(type(execution)) as raised:
        supervisor.run_issuer_connection(connection)
    assert raised.value is execution
    assert execution.__cause__ is guardian
    assert events == [
        "accepted-close",
        "receive",
        "boundary",
        "wait",
        "kill",
        "wait",
        "accepted-close",
        "listener-close",
    ]
    assert supervisor._failure_reason is launch.CleanupReason.EXECUTION_INCOMPLETE
    assert supervisor._cleanup_failure_reason is launch.CleanupReason.BOUNDARY_FAILED
    assert supervisor._cleanup_failed
    assert not supervisor._terminals
    # Supply the original root clock fields solely for diagnostic projection.
    supervisor.clocks.started_at = datetime.now(UTC)
    supervisor.clocks.expires_at = datetime.now(UTC) + timedelta(seconds=30)
    assert supervisor.cleanup_document()["outcome"] == "incomplete"


@pytest.mark.parametrize("cancel", [False, True])
def test_outer_close_failure_preserves_original_run_exception_mapping(
    monkeypatch, cancel
):
    supervisor = synthetic_cleanup_supervisor()
    supervisor._activated = True
    execution = (
        KeyboardInterrupt("unique cancel")
        if cancel
        else RuntimeError("unique run failure")
    )
    cleanup = ChildProcessError("distinct outer cleanup")
    events = []
    listener = SimpleNamespace(close=lambda: events.append("listener-close"))
    monkeypatch.setattr(launch, "_load_local_packet", lambda: {"host_role": "issuer"})
    monkeypatch.setattr(supervisor, "_listen_wg", lambda role: listener)
    monkeypatch.setattr(supervisor, "_accept_wg", lambda *args: object())

    def execute(connection):
        raise execution

    def close():
        events.append("outer-close")
        raise cleanup

    monkeypatch.setattr(supervisor, "run_issuer_connection", execute)
    monkeypatch.setattr(supervisor, "close", close)
    with pytest.raises(
        KeyboardInterrupt if cancel else launch.LaunchIncomplete
    ) as raised:
        supervisor.run()
    if cancel:
        assert raised.value is execution
    else:
        assert raised.value.__cause__ is execution
    assert supervisor._failure_reason is launch.CleanupReason.EXECUTION_INCOMPLETE
    assert supervisor._cleanup_failed
    assert events[-1] == "outer-close"
    assert supervisor.cleanup_document()["outcome"] == "incomplete"


def test_first_guardian_failure_survives_sticky_boundary_retirement_repeat():
    supervisor = synthetic_cleanup_supervisor()
    guardian = ChildProcessError("initial measured guardian failure")
    sticky = ProviderRefused()
    calls = [0]

    def empty():
        calls[0] += 1
        raise guardian if calls[0] == 1 else sticky

    boundary = SimpleNamespace(terminate_and_confirm_empty=empty)
    with pytest.raises(ChildProcessError) as first:
        supervisor._retire_resources(boundary, None)
    assert first.value is guardian
    with pytest.raises(ChildProcessError) as repeated:
        supervisor._retire_resources(boundary, None, primary_failure=guardian)
    assert repeated.value is guardian
    assert guardian.__cause__ is sticky
    assert supervisor._failure_reason is launch.CleanupReason.BOUNDARY_FAILED
    assert supervisor._cleanup_failed
    assert supervisor.cleanup_document()["outcome"] == "incomplete"


@pytest.mark.parametrize("code", [0, 1, 3, 5, 42, 127, 255])
def test_normal_daemon_codes_are_lifecycle_observations_without_authority(
    monkeypatch, code
):
    supervisor = synthetic_cleanup_supervisor()
    clock = [1000.0]
    monkeypatch.setattr(launch.time, "monotonic", lambda: clock[0])
    supervisor.clocks = launch.LaunchClocks.start(
        datetime.now(UTC) + timedelta(seconds=120)
    )
    process = SimpleNamespace(
        pid=os.getpid(), returncode=code, wait=lambda timeout: None
    )
    supervisor._pin_daemon("issuer", process, 1030.0)
    clock[0] = 1001.0
    supervisor._wait_daemon(process, 1030.0)
    observed = supervisor._daemon_observations["issuer"]
    assert observed == {
        "schema": "Gate0DaemonObservation.v1",
        "boundary": "issuer",
        "pid": os.getpid(),
        "process_start": launch._process_identity(os.getpid()),
        "daemon_returncode": code,
        "termination": "exited",
        "completed_at": observed["completed_at"],
        "completed_elapsed_seconds": 1.0,
        "phase_deadline_elapsed_seconds": 30.0,
    }
    assert supervisor.cleanup_document()["outcome"] == "incomplete"
    assert not supervisor._terminals  # A daemon number cannot replace typed terminal.
    assert "observed_worker_exit_code" not in observed


@pytest.mark.parametrize("code", [-15, -9, None, True, 256])
def test_daemon_signal_or_invalid_status_never_satisfies_mechanics(monkeypatch, code):
    supervisor = synthetic_cleanup_supervisor()
    supervisor.clocks = launch.LaunchClocks.start(
        datetime.now(UTC) + timedelta(seconds=30)
    )
    process = SimpleNamespace(
        pid=os.getpid(), returncode=code, wait=lambda timeout: None
    )
    supervisor._pin_daemon("issuer", process, supervisor.clocks.deadline)
    with pytest.raises(launch.LaunchIncomplete):
        supervisor._wait_daemon(process, supervisor.clocks.deadline)
    assert supervisor._daemon_observations["issuer"]["termination"] in (
        "signaled",
        "wait_failed",
    )
    assert supervisor.cleanup_document()["outcome"] == "incomplete"


def test_daemon_timeout_then_normal_cleanup_wait_does_not_reclassify_completion():
    supervisor = synthetic_cleanup_supervisor()
    supervisor.clocks = launch.LaunchClocks.start(
        datetime.now(UTC) + timedelta(seconds=30)
    )
    calls = [0]
    process = SimpleNamespace(pid=os.getpid(), returncode=None)

    def wait(timeout):
        calls[0] += 1
        if calls[0] == 1:
            raise launch.subprocess.TimeoutExpired("synthetic daemon", timeout)
        process.returncode = 255

    process.wait = wait
    boundary = SimpleNamespace(terminate_and_confirm_empty=lambda: None)
    supervisor._pin_daemon("issuer", process, supervisor.clocks.deadline)
    with pytest.raises(launch.subprocess.TimeoutExpired):
        supervisor._wait_daemon(process, supervisor.clocks.deadline)
    supervisor._retire_resources(boundary, process)
    observation = supervisor._daemon_observations["issuer"]
    assert observation["termination"] == "wait_timeout"
    assert observation["daemon_returncode"] == 255
    assert supervisor.cleanup_document()["outcome"] == "incomplete"


def test_forced_cleanup_with_zero_reap_does_not_create_normal_daemon_acceptance():
    supervisor = synthetic_cleanup_supervisor()
    supervisor.clocks = launch.LaunchClocks.start(
        datetime.now(UTC) + timedelta(seconds=30)
    )
    process = SimpleNamespace(pid=os.getpid(), returncode=None)
    process.wait = lambda timeout: setattr(process, "returncode", 0)
    boundary = SimpleNamespace(terminate_and_confirm_empty=lambda: None)
    supervisor._pin_daemon("issuer", process, supervisor.clocks.deadline)
    supervisor._retire_resources(boundary, process)
    assert supervisor._daemon_observations["issuer"]["termination"] == "forced_cleanup"
    assert supervisor._daemon_observations["issuer"]["daemon_returncode"] == 0
    assert supervisor.cleanup_document()["outcome"] == "incomplete"


def test_normal_daemon255_observed_at_phase_end_is_late_without_deadline_refresh(
    monkeypatch,
):
    supervisor = synthetic_cleanup_supervisor()
    clock = [1000.0]
    monkeypatch.setattr(launch.time, "monotonic", lambda: clock[0])
    supervisor.clocks = launch.LaunchClocks.start(
        datetime.now(UTC) + timedelta(seconds=120)
    )
    original = supervisor.clocks.deadline
    process = SimpleNamespace(
        pid=os.getpid(),
        returncode=255,
        wait=lambda timeout: clock.__setitem__(0, 1030.0),
    )
    supervisor._pin_daemon("issuer", process, 1030.0)
    with pytest.raises(ProviderRefused):
        supervisor._wait_daemon(process, 1030.0)
    observation = supervisor._daemon_observations["issuer"]
    assert observation["termination"] == "exited"
    assert (
        observation["completed_elapsed_seconds"]
        == observation["phase_deadline_elapsed_seconds"]
    )
    assert supervisor.clocks.deadline == original
    assert supervisor.cleanup_document()["outcome"] == "incomplete"


def test_normal_daemon255_cannot_replace_missing_post_cleanup_worker_terminal(
    tmp_path, monkeypatch
):
    supervisor = synthetic_cleanup_supervisor()
    supervisor.worker_uid = os.geteuid()
    supervisor.clocks = launch.LaunchClocks.start(
        datetime.now(UTC) + timedelta(seconds=30)
    )
    process = SimpleNamespace(
        pid=os.getpid(), returncode=255, wait=lambda timeout: None
    )
    supervisor._pin_daemon("issuer", process, supervisor.clocks.deadline)
    supervisor._wait_daemon(process, supervisor.clocks.deadline)
    monkeypatch.setattr(
        launch,
        "_protected",
        lambda *args, **kwargs: os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY),
    )
    # These worker failures have no eligible post-custody typed terminal. Root's
    # normal daemon lifecycle is deliberately unable to infer their SSH status.
    with pytest.raises(FileNotFoundError):
        supervisor._require_terminal_success("issuer")
    assert not supervisor._terminals
    assert supervisor.cleanup_document()["outcome"] == "incomplete"
