"""Synthetic public framing checks; no SSH or installed launch qualification."""

import base64
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from time import monotonic
from types import SimpleNamespace
from uuid import UUID

import pytest

from vendor_cp.deployment.gate0_capture import CaptureCoordinates, export_approved_start
from vendor_cp.deployment.gate0_composition import WindowFreshness
from vendor_cp.deployment.gate0_framing import canonical
from vendor_cp.deployment.gate0_management_delivery import (
    CaptureSelection,
    parse_selection,
    selection_document,
)
from vendor_cp.deployment.gate0_role_custody import ProviderRefused
from vendor_cp.deployment.gate0_window import (
    ApprovedWindowBinding,
    FrozenIssuerWindow,
    OwnerWindowReader,
)
from vendor_cp.deployment.gate0_workload_admission import _FIXED_CLAIMS


def selected() -> CaptureSelection:
    return CaptureSelection(
        "sha256:" + "1" * 64,
        UUID(int=1),
        "sha256:" + "2" * 64,
        UUID(int=2),
        UUID(int=3),
    )


def test_selection_roundtrip_and_full_export_equality() -> None:
    selection = selected()
    assert parse_selection(selection_document(selection)) == selection
    coordinates = CaptureCoordinates(
        "sha256:" + "3" * 64,
        selection.window_digest,
        selection.plan_id,
        selection.plan_digest,
        selection.target_id,
        selection.approval_request_id,
    )
    selection.require_coordinates(coordinates)
    for field, value in [
        ("plan_id", UUID(int=4)),
        ("target_id", UUID(int=4)),
        ("approval_request_id", UUID(int=4)),
        ("window_digest", "sha256:" + "4" * 64),
        ("plan_digest", "sha256:" + "4" * 64),
    ]:
        with pytest.raises(ProviderRefused):
            selection.require_coordinates(replace(coordinates, **{field: value}))


def test_selection_is_not_a_capture_or_authority() -> None:
    document = selection_document(selected())
    for key, value in [
        ("capture_digest", "sha256:" + "3" * 64),
        ("authenticated", True),
        ("deadline", 123.0),
    ]:
        with pytest.raises(ProviderRefused):
            parse_selection(document | {key: value})
    with pytest.raises(ProviderRefused):
        parse_selection(
            document
            | {"plan_id": str(UUID(int=1)).upper().replace("00000000", "FFFFFFFF", 1)}
        )


@pytest.fixture
def captured(monkeypatch):
    now = datetime.now(UTC)
    fingerprint = "SHA256:" + base64.b64encode(bytes(32)).decode().rstrip("=")
    document = {
        "schema": "Gate0IssuerWindow.v1",
        "window_id": "synthetic-capture-window",
        "case_kind": "consume_replay",
        "not_before": (now - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(seconds=120)).isoformat().replace("+00:00", "Z"),
        "purpose": "rehearsal_issuer_operation",
        "allowed_phases": ["issue", "consume"],
        "authorization_binding": "control_parsed_full_envelope_v1",
        "github": dict(
            _FIXED_CLAIMS,
            run_id="2",
            run_attempt="1",
            sub="synthetic-subject",
            workflow_sha="a" * 40,
            environment_node_id="synthetic-node",
        ),
        "target": {
            "id": str(UUID(int=2)),
            "ref": "synthetic-target",
            "environment": "rehearsal",
            "operation": "deploy",
        },
        "approval_policy": {"code": "synthetic-policy", "version": 1},
        "plan_inputs": {
            "source_ref": "synthetic-source",
            "config_ref": "synthetic-config",
            "descriptor_digest": "sha256:" + "1" * 64,
            "execution_plan_digest": "sha256:" + "2" * 64,
        },
        "controller": {
            "lease_id": "synthetic-lease",
            "fingerprint": fingerprint,
            "certificate_digest": "sha256:" + "3" * 64,
            "ca_fingerprint": fingerprint,
            "principal": "dotmac-gate0-controller",
            "certificate_ttl_ceiling_seconds": 600,
        },
        "prerequisite_evidence_refs": ["sha256:" + "4" * 64],
    }
    target = SimpleNamespace(
        id=UUID(int=2), target_ref="synthetic-target", environment="rehearsal"
    )
    plan = SimpleNamespace(
        id=UUID(int=1),
        target_id=target.id,
        purpose="rehearsal_issuer_operation",
        operation="deploy",
        plan_digest="sha256:" + "5" * 64,
        descriptor_digest=document["plan_inputs"]["descriptor_digest"],
        execution_plan_digest=document["plan_inputs"]["execution_plan_digest"],
        approval_policy_code="synthetic-policy",
        approval_policy_version=1,
        requires_approval=True,
        approval_decision_ref=str(UUID(int=3)),
        snapshot={
            "spec": {"gate0_window_v1": document},
            "plan_purpose": "rehearsal_issuer_operation",
            "target_ref": target.target_ref,
            "environment": "rehearsal",
        },
    )
    window = FrozenIssuerWindow.parse(canonical(document))
    origin = monotonic()
    expected = window.expectation(
        plan, target, "issue", freshness=WindowFreshness(origin, origin + 120)
    )
    binding = ApprovedWindowBinding(
        expected, window, plan.descriptor_digest, ("sha256:" + "6" * 64,)
    )
    calls = []

    # Exact concrete type, but explicit synthetic method patches isolate codec
    # behavior. Actual owner/hold/withdrawal is covered in the migration suite.
    reader = object.__new__(OwnerWindowReader)
    monkeypatch.setattr(OwnerWindowReader, "_open", lambda self: None)

    def read(self, phase, plan_id, authorization_document=None):
        calls.append((phase, plan_id, authorization_document))
        return binding

    monkeypatch.setattr(OwnerWindowReader, "read", read)
    packet = export_approved_start(reader, (plan.id,))[0]
    return reader, binding, packet, calls


@pytest.fixture
def install_case(captured):
    from vendor_cp.deployment.gate0_management_delivery import install_document

    _, _, capture, _ = captured
    c = capture.coordinates
    selection = CaptureSelection(
        c.window_digest, c.plan_id, c.plan_digest, c.target_id, c.approval_request_id
    )
    packet = "sha256:" + "a" * 64
    return packet, capture, selection, install_document(packet, capture, selection)


def test_actual_canonical_single_capture_and_mutation_refusals(install_case):
    from copy import deepcopy

    from vendor_cp.deployment.gate0_management_delivery import validate_install

    packet, capture, selection, document = install_case
    assert validate_install(document, packet, selection) == capture.coordinates
    mutations = []
    mutations.append(document | {"authenticated": True})
    bad = deepcopy(document)
    bad["captures"] = [bad.pop("capture"), bad.get("capture")]
    mutations.append(bad)
    bad = deepcopy(document)
    bad["capture"]["coordinates"]["capture_digest"] = "sha256:" + "f" * 64
    mutations.append(bad)
    bad = deepcopy(document)
    bad["capture"]["coordinates"]["approval_request_id"] = str(UUID(int=99))
    mutations.append(bad)
    bad = deepcopy(document)
    bad["capture"]["capture_b64"] += "\n"
    mutations.append(bad)
    for mutation in mutations:
        with pytest.raises(ValueError):
            validate_install(mutation, packet, selection)


def _synthetic_management_context(monkeypatch, packet, end, parent):
    from vendor_cp.deployment.gate0_launch import InstalledLaunchContext

    context = object.__new__(InstalledLaunchContext)
    for key, value in {
        "role": "management",
        "packet_digest": packet,
        "expires_at": end,
        "deadline": monotonic() + 2,
    }.items():
        object.__setattr__(context, key, value)
    monkeypatch.setattr(
        InstalledLaunchContext, "require_installation", lambda *args: None
    )
    monkeypatch.setattr(InstalledLaunchContext, "require_open", lambda *args: None)
    monkeypatch.setattr(
        InstalledLaunchContext, "open_management_channel", lambda *args: parent
    )
    return context


def test_receiver_half_close_precedes_root_publication_and_exact_readback(
    install_case, monkeypatch
):
    import socket
    import threading

    from vendor_cp.deployment.gate0_framing import FramedChannel
    from vendor_cp.deployment.gate0_launch import CaptureInstallReadback
    from vendor_cp.deployment.gate0_management_delivery import receive_capture_install

    packet, capture, selection, document = install_case
    end = datetime.now(UTC) + timedelta(seconds=60)
    client, receiver = socket.socketpair()
    worker, parent = socket.socketpair()
    seen = []
    expected = CaptureInstallReadback(packet, capture.coordinates, end)
    context = _synthetic_management_context(monkeypatch, packet, end, worker)

    def commit():
        with parent:
            channel = FramedChannel(
                parent.fileno(),
                parent.fileno(),
                deadline=context.deadline,
                maximum_frames=2,
            )
            seen.append(channel.receive())
            assert channel.receive(allow_eof=True) is None
            seen.append("eof-before-commit")
            channel.send(expected.document())
            parent.shutdown(socket.SHUT_WR)

    thread = threading.Thread(target=commit)
    thread.start()
    try:
        outgoing = FramedChannel(
            client.fileno(),
            client.fileno(),
            deadline=context.deadline,
            maximum_frames=2,
        )
        outgoing.send(document)
        client.shutdown(socket.SHUT_WR)
        receive_capture_install(
            context=context,
            channel=FramedChannel(
                receiver.fileno(),
                receiver.fileno(),
                deadline=context.deadline,
                maximum_frames=2,
            ),
            selection=selection,
            absolute_end=end,
        )
        assert outgoing.receive() == expected.document()
        assert seen == [document, "eof-before-commit"]
    finally:
        client.close()
        receiver.close()
        thread.join(timeout=3)
    assert not thread.is_alive()


def test_receiver_missing_eof_never_opens_parent(install_case, monkeypatch):
    import socket

    from vendor_cp.deployment.gate0_framing import FramedChannel, ServiceRefused
    from vendor_cp.deployment.gate0_launch import InstalledLaunchContext
    from vendor_cp.deployment.gate0_management_delivery import receive_capture_install

    packet, _, selection, document = install_case
    end = datetime.now(UTC) + timedelta(seconds=60)
    context = _synthetic_management_context(monkeypatch, packet, end, None)
    opened = []
    monkeypatch.setattr(
        InstalledLaunchContext,
        "open_management_channel",
        lambda *args: opened.append(True),
    )
    client, receiver = socket.socketpair()
    try:
        deadline = monotonic() + 0.05
        FramedChannel(client.fileno(), client.fileno(), deadline=deadline).send(
            document
        )
        with pytest.raises(ServiceRefused):
            receive_capture_install(
                context=context,
                channel=FramedChannel(
                    receiver.fileno(), receiver.fileno(), deadline=deadline
                ),
                selection=selection,
                absolute_end=end,
            )
        assert opened == []
    finally:
        client.close()
        receiver.close()


def test_approved_at_start_uses_original_local_clock_before_first_admit(
    captured, monkeypatch
):
    import hashlib

    from dotmac_deployment_control import RehearsalIssuerAuthorizationSignerIdentity

    import vendor_cp.deployment.gate0_window as clocks
    from vendor_cp.deployment.gate0_role_custody import (
        BoundedJSONTransport,
        PublicIssuerVerifier,
    )
    from vendor_cp.deployment.gate0_window import WindowClockOrigin
    from vendor_cp.deployment.gate0_workload_admission import (
        GITHUB_ISSUER,
        ApprovedAtStartAdmission,
    )
    from vendor_cp.deployment.rehearsal_issuer_trust_state import (
        RehearsalIssuerTrustState,
    )

    _, binding, _, _ = captured
    now = datetime.now(UTC)
    monkeypatch.setattr(clocks.time, "monotonic", lambda: 140.0)
    origin = WindowClockOrigin(now - timedelta(seconds=40), 100.0, 200.0)
    document = binding.window.document
    until = now + timedelta(seconds=10)
    document["expires_at"] = until.isoformat().replace("+00:00", "Z")
    window = FrozenIssuerWindow.parse(canonical(document))
    binding = replace(
        binding,
        window=window,
        expectation=replace(
            binding.expectation,
            window_digest=window.digest,
            frozen_window_bytes=window.canonical_bytes,
            window_freshness=None,
        ),
    )
    public = bytes(range(32))
    fingerprint = "sha256:" + hashlib.sha256(public).hexdigest()
    identity = RehearsalIssuerAuthorizationSignerIdentity(
        "synthetic-issuer", "ed25519", fingerprint
    )
    trust = RehearsalIssuerTrustState.start(
        minimum_version=1,
        read_record=lambda: {
            "version": 1,
            "trusted_key_ids": {"synthetic-issuer": fingerprint},
            "revoked_key_ids": [],
        },
    )
    verifier = PublicIssuerVerifier(
        identity.key_id,
        public,
        trust,
        origin.deadline,
        now + timedelta(seconds=60),
        origin.started_at,
        origin.monotonic_origin,
    )
    admission = ApprovedAtStartAdmission(
        binding=binding,
        issuer_identity=identity,
        authorization_verifier=verifier,
        transport=BoundedJSONTransport(GITHUB_ISSUER),
        expires_at=until,
        clock_origin=origin,
    )
    assert admission._origin == 100.0
    assert admission._binding.expectation.window_freshness.deadline == pytest.approx(
        150.0
    )
    monkeypatch.setattr(clocks.time, "monotonic", lambda: 151.0)
    with pytest.raises(ProviderRefused):
        admission._open()
    assert admission._binding.expectation.window_freshness.deadline == pytest.approx(
        150.0
    )


def test_sender_uses_parent_export_fixed_ssh_and_returns_authenticated_ack(
    install_case, monkeypatch, tmp_path
):
    """Synthetic native boundary and SSH process; real framing/codecs exercised."""
    import hashlib
    import os
    import socket
    import subprocess
    import threading

    import vendor_cp.deployment.gate0_management_delivery as module
    from vendor_cp.deployment.gate0_framing import FramedChannel
    from vendor_cp.deployment.gate0_launch import (
        CaptureInstallReadback,
        InstalledLaunchContext,
    )

    packet, capture, selection, document = install_case
    now = datetime.now(UTC)
    end = now + timedelta(seconds=60)
    binary = b"synthetic-client"
    config = b"Host *\n    IdentityFile none\n"
    algorithm = b"ssh-ed25519"
    host_blob = (
        len(algorithm).to_bytes(4, "big")
        + algorithm
        + (32).to_bytes(4, "big")
        + bytes(range(32))
    )
    host_fp = "SHA256:" + base64.b64encode(
        hashlib.sha256(host_blob).digest()
    ).decode().rstrip("=")

    def pin(raw):
        return "sha256:" + hashlib.sha256(raw).hexdigest()

    installation = module.ManagementDeliveryInstallation(
        packet,
        now - timedelta(seconds=1),
        end,
        "10.1.0.1",
        "10.1.0.2",
        22,
        1002,
        "synthetic",
        "SHA256:" + "A" * 43,
        "ssh-ed25519",
        host_fp,
        pin(binary),
        packet,
        pin(config),
        selection,
    )
    context = object.__new__(InstalledLaunchContext)
    for key, value in {
        "role": "capture_sender",
        "packet_digest": packet,
        "expires_at": end,
        "deadline": monotonic() + 3,
    }.items():
        object.__setattr__(context, key, value)
    monkeypatch.setattr(
        InstalledLaunchContext, "require_installation", lambda *args: None
    )
    monkeypatch.setattr(InstalledLaunchContext, "require_open", lambda *args: None)
    installed = tmp_path / "synthetic-installation"
    installed.write_bytes(canonical(installation.document()))
    identity = tmp_path / "synthetic-placeholder-not-a-key"
    identity.write_bytes(b"not a key")
    monkeypatch.setattr(
        InstalledLaunchContext,
        "open_installation",
        lambda *args: os.open(installed, os.O_RDONLY),
    )
    identity_fds = []

    def open_identity(*args, **kwargs):
        assert kwargs == {
            "expected_fingerprint": installation.management_key_fingerprint
        }
        fd = os.open(identity, os.O_RDONLY)
        identity_fds.append(fd)
        return fd

    monkeypatch.setattr(
        InstalledLaunchContext, "open_management_identity", open_identity
    )
    known = b"[10.1.0.2]:22 ssh-ed25519 " + base64.b64encode(host_blob) + b"\n"
    monkeypatch.setattr(
        module,
        "_protected_bytes",
        lambda path, maximum: {
            "/usr/bin/ssh": binary,
            "/run/dotmac-gate0/management/ssh_config": config,
            "/run/dotmac-gate0/management/known_hosts": known,
        }[path],
    )
    supervisor, sender = socket.socketpair()
    monkeypatch.setattr(
        InstalledLaunchContext, "open_capture_export", lambda *args: sender.detach()
    )
    expected = CaptureInstallReadback(packet, capture.coordinates, end)
    seen = []

    def parent():
        with supervisor:
            channel = FramedChannel(
                supervisor.fileno(),
                supervisor.fileno(),
                deadline=context.deadline,
                maximum_frames=2,
            )
            channel.send(document)
            supervisor.shutdown(socket.SHUT_WR)
            seen.append(channel.receive())
            assert channel.receive(allow_eof=True) is None

    parent_thread = threading.Thread(target=parent)
    parent_thread.start()
    argv_seen = []

    class SyntheticSSH:
        def __init__(self, argv, **kwargs):
            argv_seen.append((argv, kwargs))
            child_input, parent_input = os.pipe()
            parent_output, child_output = os.pipe()
            self.stdin = os.fdopen(parent_input, "wb", buffering=0)
            self.stdout = os.fdopen(parent_output, "rb", buffering=0)
            self.returncode = None

            def run():
                try:
                    channel = FramedChannel(
                        child_input,
                        child_output,
                        deadline=context.deadline,
                        maximum_frames=2,
                    )
                    assert channel.receive() == document
                    assert channel.receive(allow_eof=True) is None
                    channel.send(expected.document())
                    self.returncode = 0
                finally:
                    os.close(child_input)
                    os.close(child_output)

            self.thread = threading.Thread(target=run)
            self.thread.start()

        def poll(self):
            return self.returncode

        def wait(self, timeout):
            self.thread.join(timeout=timeout)
            if self.thread.is_alive():
                raise subprocess.TimeoutExpired("synthetic", timeout)
            return self.returncode

        def kill(self):
            self.returncode = -9

    monkeypatch.setattr(subprocess, "Popen", SyntheticSSH)
    assert (
        module.push_capture_install(context=context, installation=installation)
        == expected
    )
    parent_thread.join(timeout=3)
    assert not parent_thread.is_alive()
    assert seen == [expected.document()]
    argv, options = argv_seen[0]
    assert argv[0] == "/usr/bin/ssh"
    assert argv[-1] == "10.1.0.2"
    assert (
        "-i" in argv
        and argv[argv.index("-i") + 1] == "/run/dotmac-gate0/management/identity"
    )
    assert "ProxyCommand=none" in argv and "RemoteCommand=none" in argv
    assert "pass_fds" not in options
    assert options["env"] == {"PATH": "/usr/bin:/bin", "LANG": "C"}
    for fd in identity_fds:
        with pytest.raises(OSError):
            os.fstat(fd)


def test_destination_server_pin_is_measured_not_accepted_as_json(monkeypatch):
    import hashlib

    import vendor_cp.deployment.gate0_management_delivery as module

    calls = []

    def binary(path, maximum):
        calls.append((path, maximum))
        return b"synthetic-server"

    monkeypatch.setattr(module, "_protected_bytes", binary)
    digest = "sha256:" + hashlib.sha256(b"synthetic-server").hexdigest()
    module.require_management_server_pin(digest)
    with pytest.raises(ProviderRefused):
        module.require_management_server_pin("sha256:" + "0" * 64)
    assert calls == [("/usr/sbin/sshd", 16 * 1024 * 1024)] * 2
