"""Hosted unit sources; test fixtures never count as installed provenance."""

from __future__ import annotations

import copy
import os
import socket
import struct
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from vendor_cp.deployment import gate0_runner_collector_handoff as owner_module
from vendor_cp.deployment.gate0_framing import canonical
from vendor_cp.deployment.gate0_launch import FiniteGate0Supervisor
from vendor_cp.deployment.gate0_observation import digest
from vendor_cp.deployment.gate0_role_custody import ProviderRefused
from vendor_cp.deployment.gate0_runner_collector_handoff import (
    OwnedCollectorHandoff,
    _mechanics,
    _terminal,
)
from vendor_cp.deployment.gate0_runner_handoff import (
    OwnedHandoffIO,
    decode_case_a_complete,
    measure_handoff_process,
)


def mechanics_fixture(role: str = "issuer") -> tuple[dict, SimpleNamespace]:
    start = datetime.now(UTC) - timedelta(seconds=2)
    end = start + timedelta(seconds=60)
    boundary_names = (
        ("preflight", "issuer", "capture_sender")
        if role == "issuer"
        else ("preflight", "management", "issue", "consume")
    )
    daemon_names = (
        ("issuer",) if role == "issuer" else ("management", "issue", "consume")
    )
    phase_names = ("issuer", "capture_sender") if role == "issuer" else daemon_names
    final = dict(
        started_at=start.isoformat(),
        expires_at=end.isoformat(),
        cleanup_completed_at=(start + timedelta(seconds=2)).isoformat(),
        terminals={
            name: {}
            for name in (("issuer",) if role == "issuer" else ("issue", "consume"))
        },
        daemon_observations={
            name: dict(
                schema="Gate0DaemonObservation.v1",
                boundary=name,
                pid=100 + index,
                process_start=str(200 + index),
                daemon_returncode=255,
                termination="exited",
                completed_at=(start + timedelta(seconds=1)).isoformat(),
                completed_elapsed_seconds=1.0,
                phase_deadline_elapsed_seconds=30.0,
            )
            for index, name in enumerate(daemon_names)
        },
        phase_completed_at={
            name: (start + timedelta(seconds=1)).isoformat() for name in phase_names
        },
        boundaries=[
            dict(
                boundary=name,
                cgroup_device=1,
                cgroup_inode=300 + index,
                kill_issued=True,
                populated=0,
                guardian_pid=400 + index,
                guardian_start=str(500 + index),
                guardian_wait_status=0,
            )
            for index, name in enumerate(boundary_names)
        ],
        delivery_status="unconfirmed",
        removed=list(FiniteGate0Supervisor._transient_paths()),
        expected_removed=list(FiniteGate0Supervisor._transient_paths()),
    )
    sequence = SimpleNamespace(
        binding=SimpleNamespace(terms={"host_role": role}),
        records=[canonical({"deadline": 160.0, "monotonic_origin": 100.0})],
        require_complete=lambda: None,
    )
    return final, sequence


@pytest.mark.parametrize("role", ["issuer", "attester"])
def test_exact_mechanics_accepts_normal_daemon255(role: str) -> None:
    final, sequence = mechanics_fixture(role)
    _mechanics(final, sequence)


@pytest.mark.parametrize(
    "field,value",
    [
        ("daemon_returncode", -15),
        ("daemon_returncode", None),
        ("daemon_returncode", True),
        ("termination", "forced_cleanup"),
        ("completed_elapsed_seconds", 30.0),
        ("phase_deadline_elapsed_seconds", 61.0),
    ],
)
def test_daemon_signal_late_or_unknown_is_not_normal(field: str, value: object) -> None:
    final, sequence = mechanics_fixture()
    final["daemon_observations"]["issuer"][field] = value
    with pytest.raises(ProviderRefused):
        _mechanics(final, sequence)


@pytest.mark.parametrize(
    "field,value",
    [
        ("kill_issued", False),
        ("populated", 1),
        ("populated", False),
        ("guardian_wait_status", 15),
        ("guardian_start", "swapped"),
        ("boundary", "other"),
    ],
)
def test_boundary_quiescence_and_guardian_required(field: str, value: object) -> None:
    final, sequence = mechanics_fixture()
    final["boundaries"][0][field] = value
    with pytest.raises(ProviderRefused):
        _mechanics(final, sequence)


@pytest.mark.parametrize("field", ["removed", "expected_removed"])
def test_peer_cannot_select_a_smaller_removal_inventory(field: str) -> None:
    final, sequence = mechanics_fixture()
    final[field].pop()
    with pytest.raises(ProviderRefused):
        _mechanics(final, sequence)


def test_boundary_and_daemon_rosters_are_exact() -> None:
    final, sequence = mechanics_fixture("attester")
    for mutate in (
        lambda value: value["daemon_observations"].pop("management"),
        lambda value: value["boundaries"].pop(),
        lambda value: value["phase_completed_at"].pop("consume"),
    ):
        candidate = copy.deepcopy(final)
        mutate(candidate)
        with pytest.raises(ProviderRefused):
            _mechanics(candidate, sequence)


def test_worker_terminal_digest_compares_exact_retained_bytes() -> None:
    terminal = {"schema": "test", "bundle_digest": "sha256:" + "1" * 64}
    final = {
        "terminals": {
            "issue": {
                "worker_terminal": terminal,
                "worker_terminal_digest": digest(canonical(terminal)),
            }
        }
    }
    assert _terminal(final, "issue") == terminal
    terminal["bundle_digest"] = "sha256:" + "2" * 64
    with pytest.raises(ProviderRefused):
        _terminal(final, "issue")


@pytest.mark.skipif(sys.platform != "linux", reason="Linux kernel peer/proc contract")
def test_actual_process_measurement_returns_parent_uid_and_start() -> None:
    parent, uid, start = measure_handoff_process(os.getpid())
    assert parent == os.getppid() and uid == os.getuid()
    raw = Path("/proc/self/stat").read_bytes()
    assert start == raw.rsplit(b")", 1)[-1].split()[19].decode("ascii")


def peer_fixture(tmp_path: Path) -> tuple[OwnedCollectorHandoff, socket.socket]:
    # Real Unix socket; only protected installation traversal is stubbed here.
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(tmp_path / "listener.sock"))
    listener.listen(1)
    writer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    writer.connect(str(tmp_path / "listener.sock"))
    peer, _ = listener.accept()
    owner = object.__new__(OwnedCollectorHandoff)
    owner._listener, owner._peer = listener, peer
    owner._closed = False
    owner._records = []
    owner._io = OwnedHandoffIO(peer.fileno(), peer.fileno(), time.monotonic() + 5)
    _, uid, start = measure_handoff_process(os.getpid())
    owner._peer_identity = uid, os.getpid(), start
    owner._verify_installation = lambda: None
    return owner, writer


@pytest.mark.skipif(
    sys.platform != "linux" or os.getuid() == 0, reason="nonroot Linux peer credentials"
)
def test_actual_kernel_peer_and_start_swaps_refuse(tmp_path: Path) -> None:
    owner, writer = peer_fixture(tmp_path)
    try:
        owner._require_single_peer()
        actual = owner._peer_identity
        for candidate in (
            (actual[0] + 1, actual[1], actual[2]),
            (actual[0], actual[1] + 1, actual[2]),
            (actual[0], actual[1], "0"),
        ):
            owner._peer_identity = candidate
            with pytest.raises(ProviderRefused):
                owner._require_single_peer()
        owner._peer_identity = actual
    finally:
        writer.close()
        owner.close()


@pytest.mark.skipif(
    sys.platform != "linux" or os.getuid() == 0, reason="nonroot Linux peer credentials"
)
def test_extra_queued_actual_peer_refuses(tmp_path: Path) -> None:
    owner, writer = peer_fixture(tmp_path)
    extra = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        extra.connect(str(tmp_path / "listener.sock"))
        with pytest.raises(ProviderRefused):
            owner._require_single_peer()
    finally:
        extra.close()
        writer.close()
        owner.close()


@pytest.mark.skipif(
    sys.platform != "linux" or os.getuid() == 0, reason="nonroot Linux peer credentials"
)
def test_final_receiver_exit_needs_real_eof_not_trailing_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner, writer = peer_fixture(tmp_path)
    owner._accept = lambda: None

    def gone(*_args: object) -> None:
        raise FileNotFoundError()

    monkeypatch.setattr(owner_module, "require_handoff_peer", gone)
    writer.sendall(struct.pack("!I", 2) + b"{}")
    writer.shutdown(socket.SHUT_WR)
    try:
        with pytest.raises(ProviderRefused):
            owner._receive(eof=True)
    finally:
        writer.close()
        owner.close()


def ack_fixture(
    tmp_path: Path,
) -> tuple[OwnedCollectorHandoff, socket.socket, SimpleNamespace]:
    owner, writer = peer_fixture(tmp_path)
    owner._case_index = 0
    owner._a_complete = owner._b_complete = False
    owner._joins = []
    owner._phase_index = 3
    owner._terminals = {}
    end = time.monotonic() + 5
    case = SimpleNamespace(projection=SimpleNamespace(deadline=end))
    owner.installation = SimpleNamespace(
        campaign_digest="sha256:" + "1" * 64, cases=(case, case)
    )
    owner._sequences = {
        host: SimpleNamespace(final_bytes=lambda: b"{}") for host in ("IDP3", "NS3")
    }
    owner._case = lambda _case: None
    owner._join = lambda *_args, **_kwargs: canonical({"test_join": "fixture"})
    owner._set_case = lambda index: setattr(owner, "_case_index", index)
    return owner, writer, case


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process fixture")
def test_ack_transmission_precedes_internal_a_join(tmp_path: Path) -> None:
    owner, writer, _ = ack_fixture(tmp_path)
    try:
        join = owner.complete_case_a(
            None, None, None, issue_expected=None, consume_expected=None
        )
        wire = OwnedHandoffIO(writer.fileno(), writer.fileno(), time.monotonic() + 5)
        ack = wire.receive()
        assert decode_case_a_complete(
            ack, owner.installation.campaign_digest, (b"{}", b"{}")
        ) == digest(join)
        assert owner.case_a_complete and owner._case_index == 1
    finally:
        writer.close()
        owner.close()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process fixture")
def test_expired_ack_does_not_unlock_b(tmp_path: Path) -> None:
    owner, writer, case = ack_fixture(tmp_path)
    case.projection.deadline = time.monotonic() - 1
    try:
        with pytest.raises(ProviderRefused):
            owner.complete_case_a(
                None, None, None, issue_expected=None, consume_expected=None
            )
        assert not owner.case_a_complete and owner._case_index == 0
        assert not owner.joins and owner._closed
    finally:
        writer.close()
        owner.close()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process fixture")
def test_b_final_eof_tail_is_bounded_and_never_sends_ack(tmp_path: Path) -> None:
    owner, writer, case = ack_fixture(tmp_path)
    owner._case_index = 1
    owner._a_complete = True
    case.projection.deadline = time.monotonic() - 0.25
    case.projection.start = time.monotonic() - 10
    wall = datetime.now(UTC)
    case.projection.window = SimpleNamespace(
        document={
            "not_before": (wall - timedelta(seconds=10)).isoformat(),
            "expires_at": (wall - timedelta(seconds=0.25)).isoformat(),
        }
    )
    owner._io.deadline = case.projection.deadline + 2
    owner._accept = lambda: None
    owner._require_single_peer = lambda **_kwargs: None
    writer.shutdown(socket.SHUT_WR)
    try:
        owner.complete_case_b(
            None, None, None, issue_expected=None, consume_expected=None
        )
        assert owner._b_complete and owner._io.sent == 0
        assert len(owner.joins) == 1
    finally:
        writer.close()
        owner.close()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process fixture")
def test_b_final_clock_cannot_extend_cleanup_tail(tmp_path: Path) -> None:
    owner, writer, case = ack_fixture(tmp_path)
    owner._case_index = 1
    case.projection.deadline = time.monotonic() - 2.1
    case.projection.start = time.monotonic() - 10
    case.projection.window = SimpleNamespace(
        document={
            "not_before": (datetime.now(UTC) - timedelta(seconds=10)).isoformat(),
            "expires_at": (datetime.now(UTC) - timedelta(seconds=2.1)).isoformat(),
        }
    )
    try:
        with pytest.raises(ProviderRefused):
            owner._final_clock(case)
    finally:
        writer.close()
        owner.close()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process fixture")
def test_a_final_clock_still_uses_original_window(tmp_path: Path) -> None:
    owner, writer, case = ack_fixture(tmp_path)

    def original_expired(_case: object) -> None:
        raise ProviderRefused()

    owner._case = original_expired
    try:
        with pytest.raises(ProviderRefused):
            owner._final_clock(case)
        assert not owner.case_a_complete
    finally:
        writer.close()
        owner.close()


def test_capture_exact_readback_scope_and_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = object.__new__(OwnedCollectorHandoff)
    wall = datetime.now(UTC)
    shared = b"protected-packet-fixture"
    capture = {
        "capture_digest": "sha256:" + "1" * 64,
        "window_digest": "sha256:" + "2" * 64,
        "plan_id": "plan",
        "plan_digest": "sha256:" + "3" * 64,
        "target_id": "target",
        "approval_request_id": "request",
    }
    packet = {
        "capture": capture,
        "not_before": wall.isoformat(),
        "expires_at": (wall + timedelta(seconds=60)).isoformat(),
    }
    case = SimpleNamespace(projection=SimpleNamespace(shared_packet=shared))
    monkeypatch.setattr(owner_module, "parse_run_document", lambda _raw: packet)
    readback = dict(
        schema="Gate0CaptureInstalled.v1",
        launch_packet_digest=digest(shared),
        capture=capture,
        effective_end=packet["expires_at"],
    )
    completion = dict(readback=readback, readback_digest=digest(canonical(readback)))
    assert owner._capture(case, completion) == completion
    for coordinate in capture:
        candidate = copy.deepcopy(completion)
        candidate["readback"]["capture"][coordinate] = "swapped"
        candidate["readback_digest"] = digest(canonical(candidate["readback"]))
        with pytest.raises(ProviderRefused):
            owner._capture(case, candidate)
    late = copy.deepcopy(completion)
    late["readback"]["effective_end"] = (wall + timedelta(seconds=61)).isoformat()
    late["readback_digest"] = digest(canonical(late["readback"]))
    with pytest.raises(ProviderRefused):
        owner._capture(case, late)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process/socket fixture")
def test_final_socket_same_inode_and_actual_self_descriptor_required(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    final_path = tmp_path / "final.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(final_path))
    listener.listen(1)
    info = final_path.stat()
    owner = object.__new__(OwnedCollectorHandoff)
    owner._inode = info.st_dev, info.st_ino
    _, uid, start = measure_handoff_process(os.getpid())
    owner._self = {"uid": uid, "pid": os.getpid(), "start": start}
    qualification = b"{}"
    owner.installation = SimpleNamespace(
        campaign_digest="sha256:" + "1" * 64,
        receiver_uid=1001,
        cases=(),
        qualification=canonical(
            {"receiver_qualification_digest": digest(qualification)}
        ),
    )
    descriptor = dict.fromkeys(owner_module.ReceiverInstallation.__annotations__)
    descriptor.update(
        schema="Gate0ReceiverInstallation.v1",
        campaign_digest=owner.installation.campaign_digest,
        receiver_uid=1001,
        collector=owner._self,
        cases=[],
        qualification={
            "path": str(tmp_path / "qualification"),
            "digest": digest(qualification),
        },
    )
    final_path.chmod(0o600)
    monkeypatch.setattr(owner_module, "_FINAL", final_path)
    monkeypatch.setattr(
        owner_module,
        "_directory",
        lambda _path, _uid: os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY),
    )
    monkeypatch.setattr(
        owner_module,
        "read_protected_handoff",
        lambda path, _uid: canonical(descriptor)
        if path == owner_module._RECEIVER
        else qualification,
    )
    try:
        owner._verify_installation()
        original = dict(owner._self)
        descriptor["collector"] = {**original, "pid": original["pid"] + 1}
        with pytest.raises(ProviderRefused):
            owner._verify_installation()
        descriptor["collector"] = original
        final_path.unlink()
        replacement.bind(str(final_path))
        final_path.chmod(0o600)
        with pytest.raises(ProviderRefused):
            owner._verify_installation()
    finally:
        replacement.close()
        listener.close()


def test_first_global_phase_cannot_be_issuer_even_if_host_sequence_accepts() -> None:
    from vendor_cp.deployment.gate0_runner_handoff import (
        RootFrameSequence,
        RootHostBinding,
        encode_root_event,
    )

    start = datetime.now(UTC) - timedelta(seconds=2)
    expiry = start + timedelta(seconds=60)
    terms = dict(
        host_role="issuer",
        case_kind="consume_replay",
        launch_packet_digest="sha256:" + "1" * 64,
        local_packet_digest="sha256:" + "2" * 64,
        window_digest="sha256:" + "3" * 64,
        machine_id_digest="sha256:" + "4" * 64,
        network_measurement_digest="sha256:" + "5" * 64,
        not_before=start.isoformat(),
        expires_at=expiry.isoformat(),
    )
    root = canonical(
        dict(
            **terms,
            schema="Gate0RootLaunchPhase.v1",
            supervisor_pid=123,
            supervisor_start="456",
            started_at=start.isoformat(),
            monotonic_origin=100.0,
            deadline=160.0,
            emitted_at=(start + timedelta(seconds=1)).isoformat(),
            emitted_elapsed_seconds=1.0,
            phase="issuer_listening",
            listener=dict(
                role="issuer",
                interface="wg0",
                local_address="10.1.1.2",
                local_port=2222,
                remote_address="10.1.1.3",
            ),
            management_capture=None,
        )
    )
    campaign = "sha256:" + "6" * 64
    sequence = RootFrameSequence(RootHostBinding(canonical(terms)))
    assert sequence.accept(root) == "issuer_listening"
    sequence = RootFrameSequence(RootHostBinding(canonical(terms)))
    owner = object.__new__(OwnedCollectorHandoff)
    owner._case = lambda _case: None
    owner._phase_index = 0
    owner.installation = SimpleNamespace(campaign_digest=campaign)
    owner._sequences = {"IDP3": sequence}
    owner._receive = lambda: encode_root_event(campaign, "IDP3", root)
    case = SimpleNamespace(attester_trust=SimpleNamespace(start=lambda: object()))
    with pytest.raises(ProviderRefused):
        owner._phase(case)


def b_join_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Focused B join fixture with real codecs/signatures, no installed claim."""
    from dataclasses import asdict
    from uuid import UUID

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from vendor_cp.approvals.adapter import ApprovalHoldRefusal
    from vendor_cp.deployment.gate0_attester import ProducedAttestation
    from vendor_cp.deployment.gate0_collection import (
        FramedCaseCollector,
        IssuerOutcome,
        OutcomeKind,
    )
    from vendor_cp.deployment.gate0_composition import AdmissionExpectation
    from vendor_cp.deployment.gate0_observation import (
        SignedSessionObservation,
        bundle_document,
        encode,
        observation_message,
    )
    from vendor_cp.deployment.gate0_runner_handoff import (
        RootFrameSequence,
        RootHostBinding,
    )
    from vendor_cp.deployment.gate0_runner_installation import InstalledPublicTrust
    from vendor_cp.deployment.gate0_runner_ssh import (
        OwnedAttesterSession,
        OwnedIssuerSession,
        RunnerClientCompletion,
    )
    from vendor_cp.deployment.gate0_runtime import (
        AdmittedOperation,
        AttestationContext,
        CompanionAttestation,
    )
    from vendor_cp.deployment.gate0_services import IssuerProcessResult

    owner, writer = peer_fixture(tmp_path)
    owner._case_index, owner._phase_index = 1, 3
    owner._a_complete, owner._b_complete, owner._b_final_drain = True, False, False
    owner._joins, owner._terminals = [], {}
    wall, elapsed = datetime.now(UTC), time.monotonic()
    start, expiry = wall - timedelta(seconds=2), wall + timedelta(seconds=58)
    frozen, shared = b"frozen-window-fixture", b"shared-packet-fixture"
    window_digest = digest(frozen)
    identifier = "00000000-0000-0000-0000-000000000001"
    capture = dict(
        capture_digest="sha256:" + "1" * 64,
        window_digest=window_digest,
        plan_id=identifier,
        plan_digest="sha256:" + "2" * 64,
        target_id=identifier,
        approval_request_id=identifier,
    )
    packet = dict(
        capture=capture, not_before=start.isoformat(), expires_at=expiry.isoformat()
    )
    monkeypatch.setattr(owner_module, "parse_run_document", lambda _raw: packet)
    readback = dict(
        schema="Gate0CaptureInstalled.v1",
        launch_packet_digest=digest(shared),
        capture=capture,
        effective_end=expiry.isoformat(),
    )
    completion = dict(readback=readback, readback_digest=digest(canonical(readback)))
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    trust = InstalledPublicTrust(
        "attester",
        public,
        1,
        canonical(
            dict(
                version=1,
                trusted_key_ids={"attester": digest(public)},
                revoked_key_ids=[],
            )
        ),
        "fixture",
        "sha256:" + "3" * 64,
    )
    case = SimpleNamespace(
        projection=SimpleNamespace(
            start=elapsed - 2,
            deadline=elapsed + 58,
            frozen_window=frozen,
            shared_packet=shared,
            window=SimpleNamespace(
                digest=window_digest,
                document=dict(
                    not_before=start.isoformat(), expires_at=expiry.isoformat()
                ),
            ),
            binding=dict(window_id="window-b", case_kind="withdrawal_later_use"),
        ),
        issuer="fixed-issuer",
        attester="fixed-attester",
        private_key="fixed-key",
        certificate="fixed-cert",
        attester_trust=trust,
    )
    ssh = SimpleNamespace(
        deadline=case.projection.deadline,
        issuer=case.issuer,
        attester=case.attester,
        private_key=case.private_key,
        certificate=case.certificate,
    )
    sessions, expectations, proof_ids = [], [], []
    for index, phase in enumerate(("issue", "consume")):
        operation = AdmittedOperation(
            repository_id="1",
            run_id="2",
            run_attempt="1",
            window_id="window-b",
            phase=phase,
            authorization_digest=None if phase == "issue" else "sha256:" + "4" * 64,
            authorization_issued_at=None if phase == "issue" else start.isoformat(),
            lease_id="lease",
            controller_fingerprint="SHA256:" + "A" * 43,
            target_ref="target",
            plan_id=identifier,
            plan_digest=capture["plan_digest"],
            plan_purpose="rehearsal_issuer_operation",
            operation="deploy",
            execution_plan_digest="sha256:" + "5" * 64,
            certificate_digest="sha256:" + "6" * 64,
            ca_fingerprint="SHA256:" + "A" * 42 + "E",
        )
        context = AttestationContext(
            **asdict(operation),
            challenge_digest="sha256:" + "7" * 64,
            proof_transcript_digest="sha256:" + "8" * 64,
        )
        control = canonical({"phase": phase, "issued_at": start.isoformat()})
        proof = ProducedAttestation(
            canonical({"canonical_bytes": encode(control)}),
            CompanionAttestation(b"companion", b"c" * 64),
            context,
            canonical({"phase": phase}),
        )
        invocation = str(index + 1) * 64
        message = observation_message(
            proof=proof,
            operation=operation,
            window_record_digest=window_digest,
            invocation_id=invocation,
            observed_from=start,
            observed_until=wall,
        )
        raw = canonical(
            bundle_document(proof, SignedSessionObservation(message, key.sign(message)))
        )
        session = object.__new__(OwnedAttesterSession)
        session.installation, session._bundle, session._invocation_id = (
            ssh,
            raw,
            invocation,
        )
        session._completion = RunnerClientCompletion(100 + index, 0, True, elapsed)
        session._closed, session._processes = False, []
        sessions.append(session)
        proof_ids.append((digest(control), digest(raw)))
        expectations.append(
            AdmissionExpectation(
                operation,
                UUID(identifier),
                "rehearsal",
                UUID(identifier),
                "policy",
                1,
                frozen,
                window_digest,
            )
        )
    outcomes = []
    for index, (verb, kind) in enumerate(
        (
            ("issue", OutcomeKind.ISSUE_COMMITTED),
            ("standing", OutcomeKind.STANDING),
            ("standing", OutcomeKind.STANDING),
            ("consume", OutcomeKind.OWNER_REFUSED),
        )
    ):
        proof_id, bundle_id = proof_ids[0] if index < 3 else (None, None)
        result = (
            dict(
                evidence_digest=proof_id,
                authorization_id="auth",
                lease_id="lease",
                authorization_document="e30=",
                single_use_reference=None,
                issuer_receipt="e30=",
            )
            if index == 0
            else dict(standing="valid", refusal=None)
            if index < 3
            else {}
        )
        outcomes.append(
            IssuerOutcome(
                index + 1,
                verb,
                "sha256:" + str(index + 1) * 64,
                window_digest,
                proof_id,
                bundle_id,
                kind,
                "approvals" if index == 3 else None,
                ApprovalHoldRefusal.WITHDRAWN.value if index == 3 else None,
                canonical(result),
            )
        )
    collector = object.__new__(FramedCaseCollector)
    collector._outcomes = outcomes
    issuer = object.__new__(OwnedIssuerSession)
    issuer.installation, issuer.collector = ssh, collector
    issuer._completion = RunnerClientCompletion(110, 3, True, elapsed)
    issuer._closed, issuer._processes = False, []
    bindings, finals, sequences = [], {}, {}
    for host, role in (("IDP3", "issuer"), ("NS3", "attester")):
        terms = dict(
            host_role=role,
            case_kind="withdrawal_later_use",
            launch_packet_digest=digest(shared),
            local_packet_digest="sha256:" + ("9" if role == "issuer" else "a") * 64,
            window_digest=window_digest,
            machine_id_digest="sha256:" + "b" * 64,
            network_measurement_digest="sha256:" + "c" * 64,
            not_before=start.isoformat(),
            expires_at=expiry.isoformat(),
        )
        binding = RootHostBinding(canonical(terms))
        bindings.append(binding)
        sequence = RootFrameSequence(binding)
        for phase in (
            ("issuer_listening",)
            if role == "issuer"
            else ("management_listening", "attester_listening_after_capture")
        ):
            raw = canonical(
                dict(
                    **terms,
                    schema="Gate0RootLaunchPhase.v1",
                    supervisor_pid=120,
                    supervisor_start="1000",
                    started_at=start.isoformat(),
                    monotonic_origin=100.0,
                    deadline=160.0,
                    emitted_at=(start + timedelta(seconds=1)).isoformat(),
                    emitted_elapsed_seconds=1.0,
                    phase=phase,
                    listener=dict(
                        role="issuer"
                        if role == "issuer"
                        else "management"
                        if phase == "management_listening"
                        else "attester",
                        interface="wg0",
                        local_address="10.1.1.2",
                        local_port=2222,
                        remote_address="10.1.1.3",
                    ),
                    management_capture=completion
                    if phase == "attester_listening_after_capture"
                    else None,
                )
            )
            sequence.accept(raw)
        final, _ = mechanics_fixture(role)
        final.update({k: v for k, v in terms.items() if k != "not_before"})
        final.update(
            schema="Gate0LaunchCleanup.v1",
            supervisor_pid=120,
            supervisor_start="1000",
            started_at=start.isoformat(),
            outcome="complete",
            reason="completed_mechanics",
            cleanup_completed_at=wall.isoformat(),
        )
        final["capture_delivery" if role == "issuer" else "management_capture"] = (
            completion
        )
        terminals = {}
        for slot in ("issuer",) if role == "issuer" else ("issue", "consume"):
            terminal = (
                dict(
                    schema="Gate0IssuerTerminal.v1",
                    launch_packet_digest=digest(shared),
                    local_packet_digest=terms["local_packet_digest"],
                    case_kind="withdrawal_later_use",
                    window_digest=window_digest,
                    worker_declared_exit_code=3,
                    transcript_digest=IssuerProcessResult(
                        3, tuple(outcomes)
                    ).transcript_digest,
                    terminal_outcome=outcomes[-1].document(),
                )
                if slot == "issuer"
                else dict(
                    schema="Gate0SlotTerminal.v1",
                    launch_packet_digest=digest(shared),
                    slot=slot,
                    outcome="success",
                    bundle_digest=digest(sessions[0 if slot == "issue" else 1].bundle),
                    invocation_id=sessions[0 if slot == "issue" else 1].invocation_id,
                )
            )
            terminals[slot] = dict(
                worker_terminal=terminal,
                worker_terminal_digest=digest(canonical(terminal)),
            )
        final["terminals"] = terminals
        finals[host], sequences[host] = canonical(final), sequence
    case.roots = tuple(bindings)
    owner.installation = SimpleNamespace(
        campaign_digest="sha256:" + "d" * 64, cases=(case, case)
    )
    owner._sequences, owner._attester_state = sequences, trust.start()
    return owner, writer, case, issuer, sessions, expectations, finals, proof_ids


@pytest.mark.skipif(
    sys.platform != "linux" or os.getuid() == 0, reason="nonroot Linux focused B join"
)
@pytest.mark.parametrize("evaluated", [False, True])
def test_real_b_join_issue_standing_and_actual_withdrawal_shapes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, evaluated: bool
) -> None:
    from dataclasses import replace

    from vendor_cp.deployment.gate0_runner_handoff import encode_root_event
    from vendor_cp.deployment.gate0_services import IssuerProcessResult

    owner, writer, case, issuer, sessions, expected, finals, ids = b_join_fixture(
        tmp_path, monkeypatch
    )
    if evaluated:
        issuer.collector._outcomes[-1] = replace(
            issuer.collector.outcomes[-1],
            proof_digest=ids[1][0],
            bundle_digest=ids[1][1],
        )
        doc = owner_module.strict_object(finals["IDP3"])
        terminal = doc["terminals"]["issuer"]["worker_terminal"]
        terminal["terminal_outcome"] = issuer.collector.outcomes[-1].document()
        terminal["transcript_digest"] = IssuerProcessResult(
            3, issuer.collector.outcomes
        ).transcript_digest
        doc["terminals"]["issuer"]["worker_terminal_digest"] = digest(
            canonical(terminal)
        )
        finals["IDP3"] = canonical(doc)
    for host in ("IDP3", "NS3"):
        for raw in (
            encode_root_event(owner.installation.campaign_digest, host, finals[host]),
            canonical(
                dict(
                    schema="Gate0RootHandoffTerminal.v1",
                    campaign_digest=owner.installation.campaign_digest,
                    host=host,
                    root_final_digest=digest(finals[host]),
                    stdout_eof=True,
                    management_returncode=0,
                )
            ),
        ):
            writer.sendall(struct.pack("!I", len(raw)) + raw)
    writer.shutdown(socket.SHUT_WR)
    try:
        join = owner.complete_case_b(
            issuer, *sessions, issue_expected=expected[0], consume_expected=expected[1]
        )
        assert owner._b_complete and owner.joins == (join,)
        assert issuer._closed and all(session._closed for session in sessions)
    finally:
        writer.close()
        owner.close()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process fixture")
@pytest.mark.parametrize(
    "failure",
    [
        "standing_consume_swap",
        "partial_null",
        "wrong_evaluated",
        "namespace",
        "ordinal",
        "operation",
        "window",
    ],
)
def test_real_b_outcome_join_refuses_wrong_proof_or_withdrawal_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    from dataclasses import replace

    owner, writer, case, issuer, sessions, _expected, _finals, ids = b_join_fixture(
        tmp_path, monkeypatch
    )
    outcomes = list(issuer.collector.outcomes)
    if failure == "standing_consume_swap":
        outcomes[2] = replace(
            outcomes[2], proof_digest=ids[1][0], bundle_digest=ids[1][1]
        )
    else:
        updates = {
            "partial_null": dict(proof_digest=ids[1][0]),
            "wrong_evaluated": dict(proof_digest=ids[0][0], bundle_digest=ids[0][1]),
            "namespace": dict(owner_namespace="control.issuance"),
            "ordinal": dict(ordinal=3),
            "operation": dict(operation="standing"),
            "window": dict(window_digest="sha256:" + "f" * 64),
        }[failure]
        outcomes[-1] = replace(outcomes[-1], **updates)
    try:
        with pytest.raises(ProviderRefused):
            owner._join_outcomes(case, tuple(outcomes), *sessions)
    finally:
        writer.close()
        owner.close()


@pytest.mark.skipif(
    sys.platform != "linux" or os.getuid() == 0,
    reason="nonroot Linux real receiver child",
)
@pytest.mark.parametrize("schedule", ["buffered_exit", "exit_during_join"])
@pytest.mark.parametrize(
    "fault", [None, "missing_terminal", "extra_data", "wrong_initial", "second_peer"]
)
def test_actual_receiver_exit_with_buffered_b_records_and_real_join(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    schedule: str,
    fault: str | None,
) -> None:
    import base64
    import subprocess

    from vendor_cp.deployment.gate0_runner_handoff import encode_root_event

    owner, old_writer, case, issuer, sessions, expected, finals, _ids = b_join_fixture(
        tmp_path, monkeypatch
    )
    old_writer.close()
    owner._peer.close()
    frames = []
    for host in ("IDP3", "NS3"):
        frames.append(
            encode_root_event(owner.installation.campaign_digest, host, finals[host])
        )
        if fault != "missing_terminal" or host != "NS3":
            frames.append(
                canonical(
                    dict(
                        schema="Gate0RootHandoffTerminal.v1",
                        campaign_digest=owner.installation.campaign_digest,
                        host=host,
                        root_final_digest=digest(finals[host]),
                        stdout_eof=True,
                        management_returncode=0,
                    )
                )
            )
    if fault == "extra_data":
        frames.append(b"{}")
    wire = b"".join(struct.pack("!I", len(frame)) + frame for frame in frames)
    script = (
        "import base64,socket,sys; "
        "peer=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); "
        "peer.connect(sys.argv[1]); sys.stdin.buffer.read(1); "
        "peer.sendall(base64.b64decode(sys.argv[2])); "
        "sys.stdin.buffer.read(1); peer.close()"
    )
    child = subprocess.Popen(  # noqa: S603 -- fixed focused Unix receiver fixture
        [
            sys.executable,
            "-c",
            script,
            str(tmp_path / "listener.sock"),
            base64.b64encode(wire).decode(),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    extra = None
    try:
        peer, _ = owner._listener.accept()
        owner._peer = peer
        pid, uid, _ = struct.unpack(
            "3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        _, measured_uid, start = measure_handoff_process(pid)
        assert pid == child.pid and uid == measured_uid
        owner._peer_identity = uid, pid, start
        owner._io = OwnedHandoffIO(
            peer.fileno(), peer.fileno(), case.projection.deadline
        )
        # Check the actual live identity before allowing the child to emit.
        owner._require_single_peer()
        if fault == "wrong_initial":
            owner._peer_identity = uid, pid, "0"
            with pytest.raises(ProviderRefused):
                owner._require_single_peer()
            return
        child.stdin.write(b"G")
        child.stdin.flush()
        if schedule == "buffered_exit" or fault == "missing_terminal":
            child.stdin.close()
            assert child.wait(timeout=5) == 0
        else:
            actual_session_join = owner._session

            def exit_then_session(*args, **kwargs):
                # All real final envelopes were drained before _session runs.
                if child.poll() is None:
                    child.stdin.close()
                    assert child.wait(timeout=5) == 0
                return actual_session_join(*args, **kwargs)

            monkeypatch.setattr(owner, "_session", exit_then_session)
        if fault == "second_peer":
            extra = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            extra.connect(str(tmp_path / "listener.sock"))
        if fault is None:
            join = owner.complete_case_b(
                issuer,
                *sessions,
                issue_expected=expected[0],
                consume_expected=expected[1],
            )
            assert owner._b_complete and owner.joins == (join,)
            assert len(owner.records) == 4 and owner._io.sent == 0
        else:
            with pytest.raises(ProviderRefused):
                owner.complete_case_b(
                    issuer,
                    *sessions,
                    issue_expected=expected[0],
                    consume_expected=expected[1],
                )
            assert not owner._b_complete and not owner.joins
    finally:
        if child.stdin is not None and not child.stdin.closed:
            child.stdin.close()
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        if extra is not None:
            extra.close()
        owner.close()
        for session in (issuer, *sessions):
            session.close()
