"""Synthetic phase components; no root-channel or installed listener qualification."""

import base64
import hashlib
import os
import socket
import time
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID

import pytest

from vendor_cp.deployment import gate0_launch as launch
from vendor_cp.deployment.gate0_framing import canonical
from vendor_cp.deployment.gate0_launch_phase import decode_phase, encode_phase
from vendor_cp.deployment.gate0_role_custody import ProviderRefused

H = "sha256:" + "a" * 64


def phase_document(phase="management_listening"):
    start = datetime.now(UTC)
    document = {
        "schema": "Gate0RootLaunchPhase.v1",
        "host_role": "attester",
        "case_kind": "consume_replay",
        "launch_packet_digest": H,
        "local_packet_digest": H,
        "window_digest": H,
        "machine_id_digest": H,
        "network_measurement_digest": H,
        "supervisor_pid": 123,
        "supervisor_start": "456",
        "not_before": (start - timedelta(seconds=1)).isoformat(),
        "started_at": start.isoformat(),
        "expires_at": (start + timedelta(seconds=60)).isoformat(),
        "monotonic_origin": 100.0,
        "deadline": 160.0,
        "emitted_at": (start + timedelta(seconds=2)).isoformat(),
        "emitted_elapsed_seconds": 2.0,
        "phase": phase,
        "listener": {
            "role": "management",
            "interface": "wgtest",
            "local_address": "10.0.0.1",
            "local_port": 2223,
            "remote_address": "10.0.0.2",
        },
        "management_capture": None,
    }
    if phase == "issuer_listening":
        document["host_role"] = "issuer"
        document["listener"]["role"] = "issuer"
    elif phase == "attester_listening_after_capture":
        document["listener"]["role"] = "attester"
        readback = {
            "schema": "Gate0CaptureInstalled.v1",
            "launch_packet_digest": H,
            "effective_end": document["expires_at"],
            "capture": {
                "capture_digest": H,
                "window_digest": H,
                "plan_digest": H,
                "plan_id": str(UUID(int=1)),
                "target_id": str(UUID(int=2)),
                "approval_request_id": str(UUID(int=3)),
            },
        }
        document["management_capture"] = {
            "readback": readback,
            "readback_digest": "sha256:"
            + hashlib.sha256(canonical(readback)).hexdigest(),
        }
    return document


@pytest.mark.parametrize(
    "phase",
    ["issuer_listening", "management_listening", "attester_listening_after_capture"],
)
def test_closed_phase_codec_preserves_exact_public_bytes(phase):
    document = phase_document(phase)
    raw = canonical(document)
    assert decode_phase(raw) == document
    assert encode_phase(decode_phase(raw)) == raw


@pytest.mark.parametrize(
    "change",
    [
        "extra",
        "phase",
        "host",
        "listener",
        "listener_extra",
        "public_ip",
        "clock",
        "elapsed_bool",
        "elapsed_late",
        "capture",
        "capture_hash",
        "capture_foreign",
        "pid_bool",
        "noncanonical",
    ],
)
def test_phase_refuses_partial_or_inconsistent_state(change):
    document = phase_document("attester_listening_after_capture")
    if change == "extra":
        document["ready"] = True
    elif change == "phase":
        document["phase"] = "ready"
    elif change == "host":
        document["host_role"] = "issuer"
    elif change == "listener":
        document["listener"]["role"] = "issuer"
    elif change == "listener_extra":
        document["listener"]["bound"] = True
    elif change == "public_ip":
        document["listener"]["local_address"] = "8.8.8.8"
    elif change == "clock":
        document["deadline"] = 500.0
    elif change == "elapsed_bool":
        document["emitted_elapsed_seconds"] = True
    elif change == "elapsed_late":
        document["emitted_elapsed_seconds"] = 60.0
    elif change == "capture":
        document["management_capture"] = None
    elif change == "capture_hash":
        document["management_capture"]["readback_digest"] = "sha256:" + "b" * 64
    elif change == "capture_foreign":
        document["management_capture"]["readback"]["capture"]["window_digest"] = (
            "sha256:" + "b" * 64
        )
    elif change == "pid_bool":
        document["supervisor_pid"] = True
    raw = canonical(document)
    if change == "noncanonical":
        raw += b"\n"
    with pytest.raises(ProviderRefused):
        decode_phase(raw)


@pytest.fixture
def supervisor(monkeypatch):
    root = object.__new__(launch.FiniteGate0Supervisor)
    started = datetime.now(UTC)
    origin = time.monotonic()
    root.clocks = launch.LaunchClocks(
        started, origin, origin + 60, started + timedelta(seconds=60)
    )
    root.packet_digest = root.local_packet_digest = root.machine_id_digest = H
    root._startup_phases = []
    root._failure_reason = None
    root._cleanup_failed = False
    root._cleanup_failure_reason = None
    root._run_terms = {
        "case_kind": "consume_replay",
        "not_before": (started - timedelta(seconds=1)).isoformat(),
        "capture": {"window_digest": H},
    }
    root._local_terms = {
        "host_role": "attester",
        "network": {"interface": "wgtest"},
        "ssh_endpoints": {
            role: {
                "local_address": "10.0.0.1",
                "local_port": port,
                "remote_address": "10.0.0.2",
            }
            for role, port in (
                ("management", 2223),
                ("issuer", 2224),
                ("attester", 2225),
            )
        },
    }
    evidence = launch.BoundaryCleanupEvidence("preflight", 1, 2, True, 0, 3, "4", 0)
    root._boundaries = {"preflight": SimpleNamespace(_evidence=evidence)}
    root._management_capture = None
    root._phase_completed = {}
    root._boundary = root._management_listener = None
    root._daemon_observations = {}
    key = base64.b64encode(bytes(32)).decode()
    measurement = {
        "packet_digest": H,
        "local_packet_digest": H,
        "machine_id_digest": H,
        "namespace_device": 1,
        "namespace_inode": 2,
        "interface": "wgtest",
        "index": 3,
        "bao_address": "10.0.0.2",
        "local_address": "10.0.0.1",
        "peer_public_key": key,
        "peer_allowed_ip": "10.0.0.2/32",
        "peers": [{"public_key": key, "allowed_ips": ["10.0.0.2/32"]}],
        "route_digest": H,
        "nft_ruleset_digest": H,
        "started_at": started.isoformat(),
        "monotonic_origin": origin,
        "deadline": origin + 60,
        "expires_at": root.clocks.expires_at.isoformat(),
        "supervisor_pid": os.getpid(),
        "supervisor_start": "1",
    }
    raw = canonical(measurement)
    root.network_measurement_digest = launch._digest(raw)
    monkeypatch.setattr(launch, "_read", lambda *a: raw)
    monkeypatch.setattr(launch, "_process_identity", lambda pid: "1")
    sealed = []
    monkeypatch.setattr(
        launch, "_require_capability_profile", lambda value: sealed.append(value)
    )
    frames = []
    monkeypatch.setattr(
        launch,
        "_write_public_root_frame",
        lambda raw, *, deadline: frames.append((raw, deadline)),
    )

    def listener(role, *, listening=True):
        return SimpleNamespace(
            getsockname=lambda: (
                "10.0.0.1",
                root._local_terms["ssh_endpoints"][role]["local_port"],
            ),
            getsockopt=lambda level, option, *a: (
                b"wgtest\0" if option == socket.SO_BINDTODEVICE else int(listening)
            ),
        )

    return root, listener, frames, sealed


def complete_management(root):
    document = phase_document("attester_listening_after_capture")
    readback = deepcopy(document["management_capture"]["readback"])
    readback["effective_end"] = root.clocks.expires_at.isoformat()
    root._management_capture = {
        "readback": readback,
        "readback_digest": launch._digest(canonical(readback)),
    }
    root._phase_completed["management"] = datetime.now(UTC).isoformat()
    root._boundaries["management"] = SimpleNamespace(
        _evidence=launch.BoundaryCleanupEvidence("management", 1, 2, True, 0, 3, "4", 0)
    )
    root._daemon_observations["management"] = {
        "termination": "exited",
        "daemon_returncode": 255,
        "completed_elapsed_seconds": 1.0,
        "phase_deadline_elapsed_seconds": 10.0,
    }


def test_actual_emission_order_and_postcapture_join(supervisor):
    root, listener, frames, sealed = supervisor
    root._emit_phase("management_listening", listener("management"))
    complete_management(root)
    root._emit_phase("attester_listening_after_capture", listener("attester"))
    assert sealed == [launch._CONTINUING_CAPS] * 2
    assert [decode_phase(raw)["phase"] for raw, _ in frames] == [
        "management_listening",
        "attester_listening_after_capture",
    ]
    assert decode_phase(frames[-1][0])["management_capture"] == root._management_capture
    assert all(end <= root.clocks.deadline for _, end in frames)
    with pytest.raises(ProviderRefused):
        root._emit_phase("management_listening", listener("management"))
    assert len(frames) == 2
    assert root._failure_reason is launch.CleanupReason.EXPORT_FAILED


@pytest.mark.parametrize("missing", ["capture", "daemon", "boundary", "listener"])
def test_postcapture_barrier_requires_real_completion_and_actual_listener(
    supervisor, missing
):
    root, listener, frames, _ = supervisor
    root._emit_phase("management_listening", listener("management"))
    complete_management(root)
    if missing == "capture":
        root._management_capture = None
    elif missing == "daemon":
        root._daemon_observations["management"]["termination"] = "wait_timeout"
    elif missing == "boundary":
        root._boundaries["management"]._evidence = None
    with pytest.raises(ProviderRefused):
        root._emit_phase(
            "attester_listening_after_capture",
            listener("attester", listening=missing != "listener"),
        )
    assert len(frames) == 1


def test_partial_phase_write_is_sticky_and_cannot_retry(supervisor, monkeypatch):
    root, listener, frames, _ = supervisor
    monkeypatch.setattr(
        launch,
        "_write_public_root_frame",
        lambda *a, **k: (_ for _ in ()).throw(BrokenPipeError()),
    )
    with pytest.raises(BrokenPipeError):
        root._emit_phase("management_listening", listener("management"))
    assert root._failure_reason is launch.CleanupReason.EXPORT_FAILED
    assert root._startup_phases == []
    with pytest.raises(ProviderRefused):
        root._emit_phase("management_listening", listener("management"))
    assert frames == []


def test_run_orders_management_barrier_before_capture_and_attester_barrier(monkeypatch):
    root = object.__new__(launch.FiniteGate0Supervisor)
    root._activated = False
    root._failure_reason = None
    root._cleanup_failed = False
    root._cleanup_failure_reason = None
    events = []
    # Ordering-only fixture: native preflight has dedicated refusal coverage.
    monkeypatch.setattr(launch, "_prepare_network_privileges", lambda: None)
    monkeypatch.setattr(root, "_measure_network", lambda: None)
    monkeypatch.setattr(launch, "_load_local_packet", lambda: {"host_role": "attester"})
    monkeypatch.setattr(
        root,
        "_listen_wg",
        lambda role: (
            events.append(("bound", role)) or SimpleNamespace(close=lambda: None)
        ),
    )
    monkeypatch.setattr(
        root, "_emit_phase", lambda phase, listener: events.append(("phase", phase))
    )
    monkeypatch.setattr(
        root,
        "_accept_wg",
        lambda listener, role: events.append(("accept", role)) or object(),
    )
    monkeypatch.setattr(
        root,
        "run_management_connection",
        lambda connection: events.append("management-cleaned"),
    )
    monkeypatch.setattr(
        root,
        "run_attester_connection",
        lambda connection: events.append("attester-cleaned"),
    )
    monkeypatch.setattr(root, "close", lambda: events.append("outer-close"))
    root.run()
    assert events == [
        ("bound", "management"),
        ("phase", "management_listening"),
        ("accept", "management"),
        "management-cleaned",
        ("bound", "attester"),
        ("phase", "attester_listening_after_capture"),
        ("accept", "attester"),
        "attester-cleaned",
        ("accept", "attester"),
        "attester-cleaned",
        "outer-close",
    ]


@pytest.mark.parametrize("bad", [None, "legacy", "bundle", "invocation"])
def test_root_retains_exact_attester_bundle_and_signed_invocation(
    tmp_path, monkeypatch, bad
):
    root = object.__new__(launch.FiniteGate0Supervisor)
    root.worker_uid = os.geteuid()
    root.packet_digest = H
    root._terminals = {}
    monkeypatch.setattr(
        launch,
        "_protected",
        lambda *a, **k: os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY),
    )
    document = {
        "schema": "Gate0SlotTerminal.v1",
        "launch_packet_digest": H,
        "slot": "issue",
        "outcome": "success",
        "bundle_digest": H,
        "invocation_id": "b" * 64,
    }
    if bad == "legacy":
        del document["bundle_digest"]
    elif bad == "bundle":
        document["bundle_digest"] = "caller-success"
    elif bad == "invocation":
        document["invocation_id"] = ""
    file = tmp_path / "terminal.json"
    file.write_bytes(canonical(document))
    file.chmod(0o400)
    if bad is not None:
        with pytest.raises(ProviderRefused):
            root._require_terminal_success("issue")
        assert root._terminals == {}
    else:
        root._require_terminal_success("issue")
        assert root._terminals["issue"]["worker_terminal"] == document
        assert root._terminals["issue"]["worker_terminal_digest"] == launch._digest(
            canonical(document)
        )


def test_idp3_emits_only_its_actual_issuer_listener(supervisor):
    root, listener, frames, _ = supervisor
    root._local_terms["host_role"] = "issuer"
    root._emit_phase("issuer_listening", listener("issuer"))
    assert len(frames) == 1
    document = decode_phase(frames[0][0])
    assert document["host_role"] == "issuer"
    assert document["listener"]["role"] == "issuer"
    assert document["management_capture"] is None
    with pytest.raises(ProviderRefused):
        root._emit_phase("management_listening", listener("management"))
    assert len(frames) == 1
