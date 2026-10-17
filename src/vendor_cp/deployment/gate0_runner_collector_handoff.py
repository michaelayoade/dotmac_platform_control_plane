"""One actual collector-created socket and finite authenticated root/session join.

Root provisioning moves this SAME listening inode into the protected handoff
path and records this process's actual identity. No parser or caller boolean
manufactures that provenance; no operational installation occurs in this module.
"""

from __future__ import annotations

import base64
import math
import os
import re
import select
import socket
import stat
import struct
import time
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from vendor_cp.approvals.adapter import ApprovalHoldRefusal
from vendor_cp.deployment.gate0_collection import IssuerOutcome, OutcomeKind
from vendor_cp.deployment.gate0_composition import AdmissionExpectation
from vendor_cp.deployment.gate0_framing import canonical, strict_object
from vendor_cp.deployment.gate0_launch import (
    FiniteGate0Supervisor,
    parse_run_document,
)
from vendor_cp.deployment.gate0_observation import (
    decode,
    digest,
    parse_bundle,
    verify_observation_signature,
)
from vendor_cp.deployment.gate0_role_custody import ProviderRefused
from vendor_cp.deployment.gate0_runner_handoff import (
    OwnedHandoffIO,
    ReceiverInstallation,
    RootFrameSequence,
    RootHostBinding,
    decode_root_event,
    decode_terminal,
    encode_case_a_complete,
    measure_handoff_process,
    read_protected_handoff,
    require_handoff_peer,
)
from vendor_cp.deployment.gate0_runner_installation import (
    InstalledRunnerCase,
    InstalledRunnerCollection,
)
from vendor_cp.deployment.gate0_runner_ssh import (
    OwnedAttesterSession,
    OwnedIssuerSession,
)
from vendor_cp.deployment.gate0_runtime import AdmittedOperation
from vendor_cp.deployment.gate0_services import IssuerProcessResult
from vendor_cp.deployment.rehearsal_issuer_trust_state import (
    RehearsalIssuerTrustState,
    TrustEligibility,
)

if TYPE_CHECKING:
    from vendor_cp.deployment.gate0_launch_phase import RootListener

_STAGING = Path("/run/dotmac-gate0-collector/session/collector.sock")
_FINAL = Path("/run/dotmac-gate0-handoff/collector.sock")
_RECEIVER = Path("/run/dotmac-gate0-handoff/installation.json")
_PHASES = (
    ("NS3", "management_listening"),
    ("IDP3", "issuer_listening"),
    ("NS3", "attester_listening_after_capture"),
)


def _fields(value: object, names: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != set(names.split()):
        raise ProviderRefused()
    return cast(dict[str, Any], value)


def _instant(value: object) -> datetime:
    if type(value) is not str:
        raise ProviderRefused()
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None or result.utcoffset() != timedelta(0):
        raise ProviderRefused()
    return result


def _number(value: object) -> float:
    if type(value) not in (int, float) or not math.isfinite(cast(int | float, value)):
        raise ProviderRefused()
    return float(cast(int | float, value))


def _integer(value: object, *, minimum: int = 1) -> int:
    if type(value) is not int or value < minimum:
        raise ProviderRefused()
    return value


def _directory(path: Path, uid: int) -> int:
    """Anchor fixed socket lookup without following any directory symlink."""
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for index, name in enumerate(path.parts[1:]):
            child = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=fd,
            )
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            last = index == len(path.parts) - 2
            if info.st_uid != (uid if last else 0) or info.st_mode & 0o022:
                raise ProviderRefused()
        return fd
    except BaseException:
        os.close(fd)
        raise


def _terminal(final: dict[str, Any], slot: str) -> dict[str, Any]:
    retained = _fields(
        final["terminals"][slot], "worker_terminal_digest worker_terminal"
    )
    terminal = retained["worker_terminal"]
    if retained["worker_terminal_digest"] != digest(canonical(terminal)):
        raise ProviderRefused()
    if type(terminal) is not dict:
        raise ProviderRefused()
    return terminal


def _mechanics(final: dict[str, Any], sequence: RootFrameSequence) -> None:
    """Check the root owner's exact completed-mechanics predicates, not flags."""
    sequence.require_complete()
    role = sequence.binding.terms["host_role"]
    slots = {"issuer"} if role == "issuer" else {"issue", "consume"}
    daemons = {"issuer"} if role == "issuer" else {"management", "issue", "consume"}
    boundaries = (
        {"preflight", "issuer", "capture_sender"}
        if role == "issuer"
        else {"preflight", "management", "issue", "consume"}
    )
    phases = (
        {"issuer", "capture_sender"}
        if role == "issuer"
        else {"management", "issue", "consume"}
    )
    start, expiry = _instant(final["started_at"]), _instant(final["expires_at"])
    cleanup = _instant(final["cleanup_completed_at"])
    if (
        set(final["terminals"]) != slots
        or set(final["daemon_observations"]) != daemons
        or set(final["phase_completed_at"]) != phases
        or not start <= cleanup <= expiry + timedelta(seconds=2)
        or final["delivery_status"] != "unconfirmed"
    ):
        raise ProviderRefused()
    for value in final["phase_completed_at"].values():
        if not start <= _instant(value) < expiry or _instant(value) > cleanup:
            raise ProviderRefused()
    first = strict_object(sequence.records[0])
    duration = _number(first["deadline"]) - _number(first["monotonic_origin"])
    seen_daemons: set[tuple[int, str]] = set()
    for name, value in final["daemon_observations"].items():
        doc = _fields(
            value,
            "schema boundary pid process_start daemon_returncode termination "
            "completed_at completed_elapsed_seconds phase_deadline_elapsed_seconds",
        )
        identity = (_integer(doc["pid"]), str(doc["process_start"]))
        elapsed, deadline = (
            _number(doc["completed_elapsed_seconds"]),
            _number(doc["phase_deadline_elapsed_seconds"]),
        )
        if (
            doc["schema"] != "Gate0DaemonObservation.v1"
            or doc["boundary"] != name
            or doc["termination"] != "exited"
            or type(doc["daemon_returncode"]) is not int
            or not 0 <= doc["daemon_returncode"] <= 255
            or re.fullmatch(r"[0-9]{1,32}", identity[1]) is None
            or identity in seen_daemons
            or not 0 <= elapsed < deadline <= duration
            or not start <= _instant(doc["completed_at"]) < expiry
            or _instant(doc["completed_at"]) > cleanup
        ):
            raise ProviderRefused()
        seen_daemons.add(identity)
    if type(final["boundaries"]) is not list or len(final["boundaries"]) != len(
        boundaries
    ):
        raise ProviderRefused()
    seen: set[str] = set()
    cgroups: set[tuple[int, int]] = set()
    guardians: set[tuple[int, str]] = set()
    for value in final["boundaries"]:
        doc = _fields(
            value,
            "boundary cgroup_device cgroup_inode kill_issued populated guardian_pid "
            "guardian_start guardian_wait_status",
        )
        cgroup = (
            _integer(doc["cgroup_device"], minimum=0),
            _integer(doc["cgroup_inode"]),
        )
        guardian = (_integer(doc["guardian_pid"]), str(doc["guardian_start"]))
        if (
            doc["boundary"] not in boundaries
            or doc["boundary"] in seen
            or doc["kill_issued"] is not True
            or type(doc["populated"]) is not int
            or doc["populated"] != 0
            or type(doc["guardian_wait_status"]) is not int
            or doc["guardian_wait_status"] != 0
            or re.fullmatch(r"[0-9]{1,32}", guardian[1]) is None
            or cgroup in cgroups
            or guardian in guardians
        ):
            raise ProviderRefused()
        seen.add(doc["boundary"])
        cgroups.add(cgroup)
        guardians.add(guardian)
    # Reuse the exact owner's fixed removal inventory, never the peer's roster.
    expected = set(FiniteGate0Supervisor._transient_paths())
    for key in ("removed", "expected_removed"):
        value = final[key]
        if (
            type(value) is not list
            or any(type(v) is not str for v in value)
            or len(value) != len(expected)
            or set(value) != expected
        ):
            raise ProviderRefused()


def verify_capture_completion(shared_packet: bytes, value: object) -> dict[str, Any]:
    """Shared exact capture/readback predicate; no live process or clock."""
    completion = _fields(value, "readback readback_digest")
    readback = _fields(
        completion["readback"], "schema launch_packet_digest capture effective_end"
    )
    packet = parse_run_document(shared_packet)
    coordinates = _fields(
        readback["capture"],
        "capture_digest window_digest plan_id plan_digest target_id "
        "approval_request_id",
    )
    if (
        type(coordinates["capture_digest"]) is not str
        or re.fullmatch(r"sha256:[0-9a-f]{64}", coordinates["capture_digest"]) is None
    ):
        raise ProviderRefused()
    if (
        readback["schema"] != "Gate0CaptureInstalled.v1"
        or readback["launch_packet_digest"] != digest(shared_packet)
        or {key: value for key, value in coordinates.items() if key != "capture_digest"}
        != packet["capture"]
        or completion["readback_digest"] != digest(canonical(readback))
        or not _instant(packet["not_before"])
        < _instant(readback["effective_end"])
        <= _instant(packet["expires_at"])
    ):
        raise ProviderRefused()
    return completion


def verify_case_outcome_proofs(
    case_kind: str,
    window_digest: str,
    outcomes: tuple[IssuerOutcome, ...],
    bundles: tuple[bytes, bytes],
) -> None:
    """Shared finite A/B proof mapping, including pre-proof withdrawal refusal."""
    if (
        case_kind not in ("consume_replay", "withdrawal_later_use")
        or type(bundles) is not tuple
        or len(bundles) != 2
    ):
        raise ProviderRefused()
    expected_kinds = (
        (
            OutcomeKind.ISSUE_COMMITTED,
            OutcomeKind.STANDING,
            OutcomeKind.CONSUME_COMMITTED,
            OutcomeKind.STANDING,
            OutcomeKind.OWNER_REFUSED,
        )
        if case_kind == "consume_replay"
        else (
            OutcomeKind.ISSUE_COMMITTED,
            OutcomeKind.STANDING,
            OutcomeKind.STANDING,
            OutcomeKind.OWNER_REFUSED,
        )
    )
    expected_operations = (
        ("issue", "standing", "consume", "standing", "consume")
        if case_kind == "consume_replay"
        else ("issue", "standing", "standing", "consume")
    )
    if tuple(item.kind for item in outcomes) != expected_kinds:
        raise ProviderRefused()
    identities: dict[str, tuple[str, str]] = {}
    for phase, raw in zip(("issue", "consume"), bundles, strict=True):
        proof, _ = parse_bundle(strict_object(raw, 128 * 1024))
        envelope = strict_object(proof.control_document)
        identities[phase] = (
            digest(decode(envelope.get("canonical_bytes"), 8192)),
            digest(raw),
        )
    for index, outcome in enumerate(outcomes):
        if (
            outcome.ordinal != index + 1
            or outcome.operation != expected_operations[index]
            or outcome.window_digest != window_digest
        ):
            raise ProviderRefused()
        actual = outcome.proof_digest, outcome.bundle_digest
        if case_kind == "withdrawal_later_use" and index == 3:
            # Authenticated admission can refuse withdrawal BEFORE _proof;
            # preserve that actual absence, not invented consume provenance.
            # ApprovalNotHeld after evaluation carries the exact consume pair.
            if (
                outcome.owner_namespace != "approvals"
                or outcome.owner_code != ApprovalHoldRefusal.WITHDRAWN.value
                or outcome.result_bytes != canonical({})
                or actual not in ((None, None), identities["consume"])
            ):
                raise ProviderRefused()
        else:
            # A: issue,issue,consume,consume,consume.
            # B: issue,issue,issue,then the refusal semantics above.
            phase = (
                "issue"
                if index < (2 if case_kind == "consume_replay" else 3)
                else "consume"
            )
            if actual != identities[phase]:
                raise ProviderRefused()


def verify_issuer_terminal(
    final: dict[str, Any],
    shared_packet: bytes,
    root: RootHostBinding,
    outcomes: tuple[IssuerOutcome, ...],
) -> dict[str, Any]:
    packet = parse_run_document(shared_packet)
    terminal = _terminal(final, "issuer")
    expected = dict(
        schema="Gate0IssuerTerminal.v1",
        launch_packet_digest=digest(shared_packet),
        local_packet_digest=root.terms["local_packet_digest"],
        case_kind=packet["case_kind"],
        window_digest=packet["capture"]["window_digest"],
        worker_declared_exit_code=3,
        transcript_digest=IssuerProcessResult(3, outcomes).transcript_digest,
        terminal_outcome=outcomes[-1].document(),
    )
    if terminal != expected:
        raise ProviderRefused()
    return terminal


def verify_slot_terminal(
    final: dict[str, Any],
    shared_packet: bytes,
    phase: str,
    raw: bytes,
    invocation: str,
) -> None:
    if _terminal(final, phase) != dict(
        schema="Gate0SlotTerminal.v1",
        launch_packet_digest=digest(shared_packet),
        slot=phase,
        outcome="success",
        bundle_digest=digest(raw),
        invocation_id=invocation,
    ):
        raise ProviderRefused()


class OwnedCollectorHandoff:
    """Finite actual listener/peer owner. Construction never accepts a channel."""

    def __init__(self, installation: InstalledRunnerCollection) -> None:
        if type(installation) is not InstalledRunnerCollection:
            raise ProviderRefused()
        installation.require_actual_job()
        self.installation = installation
        self._listener: socket.socket | None = None
        self._peer: socket.socket | None = None
        self._io: OwnedHandoffIO | None = None
        self._peer_identity: tuple[int, int, str] | None = None
        self._case_index = 0
        self._phase_index = 0
        self._a_complete = False
        self._b_complete = False
        self._closed = False
        self._cleanup_failed = False
        self._records: list[bytes] = []
        self._joins: list[bytes] = []
        self._terminals: dict[str, bytes] = {}
        self._sequences: dict[str, RootFrameSequence] = {}
        _, uid, start = measure_handoff_process(os.getpid())
        if uid != installation.collector_uid:
            raise ProviderRefused()
        self._self = {"uid": uid, "pid": os.getpid(), "start": start}
        directory = _directory(_STAGING.parent, uid)
        try:
            if stat.S_IMODE(os.fstat(directory).st_mode) != 0o700:
                raise ProviderRefused()
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._listener = listener
            # Binding never removes/replaces a prior socket. A failed attempt
            # stays claimed under the controller's existing once marker.
            listener.bind(str(_STAGING))
            os.chmod(_STAGING.name, 0o600, dir_fd=directory, follow_symlinks=False)
            listener.listen(1)
            info = os.stat(_STAGING.name, dir_fd=directory, follow_symlinks=False)
            self._inode = (info.st_dev, info.st_ino)
            self._set_case(0)
        except BaseException:
            self.close()
            raise
        finally:
            os.close(directory)

    @property
    def case_a_complete(self) -> bool:
        return self._a_complete and not getattr(self, "_cleanup_failed", False)

    @property
    def records(self) -> tuple[bytes, ...]:
        return tuple(self._records)

    @property
    def joins(self) -> tuple[bytes, ...]:
        return tuple(self._joins)

    def _set_case(self, index: int) -> None:
        case = self.installation.cases[index]
        self._case_index = index
        self._phase_index = 0
        self._b_final_drain = False
        self._terminals = {}
        self._attester_state: RehearsalIssuerTrustState | None = None
        self._sequences = {
            name: RootFrameSequence(binding)
            for name, binding in zip(("IDP3", "NS3"), case.roots, strict=True)
        }
        if self._io is not None:
            self._io.deadline = case.projection.deadline

    def _verify_installation(self) -> None:
        doc = strict_object(read_protected_handoff(_RECEIVER, 0), 65536)
        if (
            set(doc) != set(ReceiverInstallation.__annotations__)
            or doc.get("schema") != "Gate0ReceiverInstallation.v1"
            or doc.get("campaign_digest") != self.installation.campaign_digest
            or doc.get("receiver_uid") != self.installation.receiver_uid
            or doc.get("collector") != self._self
            or doc.get("cases")
            != [
                {
                    name: root.terms
                    for name, root in zip(("IDP3", "NS3"), case.roots, strict=True)
                }
                for case in self.installation.cases
            ]
        ):
            raise ProviderRefused()
        qualification = _fields(doc["qualification"], "path digest")
        accepted = strict_object(self.installation.qualification, 65536)
        if (
            qualification["digest"] != accepted["receiver_qualification_digest"]
            or digest(read_protected_handoff(Path(qualification["path"]), 0))
            != qualification["digest"]
        ):
            raise ProviderRefused()
        _, uid, start = measure_handoff_process(os.getpid())
        if self._self != {"uid": uid, "pid": os.getpid(), "start": start}:
            raise ProviderRefused()
        directory = _directory(_FINAL.parent, 0)
        try:
            info = os.stat(_FINAL.name, dir_fd=directory, follow_symlinks=False)
            if (
                not stat.S_ISSOCK(info.st_mode)
                or info.st_uid != uid
                or (info.st_dev, info.st_ino) != self._inode
                or stat.S_IMODE(info.st_mode) not in (0o600, 0o660)
            ):
                raise ProviderRefused()
        finally:
            os.close(directory)

    def _accept(self) -> None:
        if self._io is not None:
            return
        if self._listener is None or self._closed:
            raise ProviderRefused()
        end = self.installation.cases[0].projection.deadline
        timeout = end - time.monotonic()
        if timeout <= 0 or not select.select([self._listener], [], [], timeout)[0]:
            raise ProviderRefused()
        self._listener.settimeout(max(0.001, end - time.monotonic()))
        peer, _ = self._listener.accept()
        self._peer = peer
        self._verify_installation()
        if not hasattr(socket, "SO_PEERCRED"):
            raise ProviderRefused()
        pid, uid, _ = struct.unpack(
            "3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        _, measured_uid, start = measure_handoff_process(pid)
        if (
            uid != self.installation.receiver_uid
            or measured_uid != uid
            or uid == self.installation.collector_uid
        ):
            raise ProviderRefused()
        require_handoff_peer(peer, uid, pid, start)
        self._peer_identity = uid, pid, start
        # No second connection is accepted; a queued extra peer also fails.
        self._require_single_peer()
        self._io = OwnedHandoffIO(peer.fileno(), peer.fileno(), end)

    def _require_single_peer(self, *, final_eof: bool = False) -> None:
        if self._listener is None or self._peer is None or self._peer_identity is None:
            raise ProviderRefused()
        if select.select([self._listener], [], [], 0)[0]:
            raise ProviderRefused()
        pid, uid, _ = struct.unpack(
            "3i", self._peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        if (uid, pid) != self._peer_identity[:2]:
            raise ProviderRefused()
        try:
            require_handoff_peer(self._peer, *self._peer_identity)
            _, uid, start = measure_handoff_process(self._peer_identity[1])
            if (uid, start) != (self._peer_identity[0], self._peer_identity[2]):
                raise ProviderRefused()
        except FileNotFoundError:
            # The same authenticated receiver may exit with closed B-final
            # records already buffered, or while their offline join runs.
            # Initial admission/A/startup remain strict. Actual final EOF and
            # the exact root roster are still mandatory before B completion.
            if not (
                final_eof
                or (
                    self._case_index == 1
                    and self._phase_index == 3
                    and self._a_complete
                    and self._b_final_drain
                )
            ):
                raise ProviderRefused() from None
        self._verify_installation()

    def _receive(self, *, eof: bool = False) -> bytes | None:
        self._accept()
        self._require_single_peer(final_eof=eof)
        if self._io is None:
            raise ProviderRefused()
        raw = self._io.receive(eof=eof)
        if eof and raw is not None:
            raise ProviderRefused()
        if raw is not None:
            self._records.append(raw)
        return raw

    def _case(self, case: InstalledRunnerCase) -> None:
        if self._closed or case is not self.installation.cases[self._case_index]:
            raise ProviderRefused()
        case.projection.require_open()

    def _final_clock(self, case: InstalledRunnerCase) -> None:
        if self._case_index == 0:
            self._case(case)
            return
        # B final/root/EOF cleanup alone shares the existing original +2s tail.
        # No operation, credential, signature or trust lifetime is extended.
        if (
            self._closed
            or case is not self.installation.cases[1]
            or not case.projection.start
            <= time.monotonic()
            < case.projection.deadline + 2
            or not _instant(case.projection.window.document["not_before"])
            <= datetime.now(UTC)
            < _instant(case.projection.window.document["expires_at"])
            + timedelta(seconds=2)
        ):
            raise ProviderRefused()

    def _phase(self, case: InstalledRunnerCase) -> None:
        self._case(case)
        if self._phase_index == 0:
            self._attester_state = case.attester_trust.start()
        raw = self._receive()
        if raw is None or self._phase_index >= len(_PHASES):
            raise ProviderRefused()
        host, root = decode_root_event(raw, self.installation.campaign_digest)
        kind = self._sequences[host].accept(root)
        if (host, kind) != _PHASES[self._phase_index]:
            raise ProviderRefused()
        doc = strict_object(root)
        endpoint = case.issuer if host == "IDP3" else case.attester
        if kind != "management_listening":
            # RootFrameSequence.accept decoded and validated this phase above.
            listener = cast("RootListener", doc["listener"])
            if (
                listener["local_address"],
                listener["local_port"],
                listener["remote_address"],
            ) != (endpoint.host, endpoint.port, endpoint.source):
                raise ProviderRefused()
        if kind == "attester_listening_after_capture":
            self._capture(case, doc["management_capture"])
        self._phase_index += 1
        self._case(case)

    def await_issuer_start(self, case: InstalledRunnerCase) -> None:
        try:
            if self._phase_index != 0:
                raise ProviderRefused()
            self._phase(case)
            self._phase(case)
        except BaseException:
            self.close()
            raise

    def await_attester_start(self, case: InstalledRunnerCase) -> None:
        try:
            if self._phase_index != 2:
                raise ProviderRefused()
            self._phase(case)
        except BaseException:
            self.close()
            raise

    def _capture(self, case: InstalledRunnerCase, value: object) -> dict[str, Any]:
        return verify_capture_completion(case.projection.shared_packet, value)

    def _drain_finals(self, case: InstalledRunnerCase) -> None:
        if self._phase_index != 3:
            raise ProviderRefused()
        if self._io is None:
            raise ProviderRefused()
        self._b_final_drain = self._case_index == 1
        self._io.deadline = case.projection.deadline + (
            2 if self._case_index == 1 else 0
        )
        while len(self._terminals) < 2:
            self._final_clock(case)
            raw = self._receive()
            if raw is None:
                raise ProviderRefused()
            doc = strict_object(raw, 270336)
            if doc.get("schema") == "Gate0RootHandoff.v1":
                host, root = decode_root_event(raw, self.installation.campaign_digest)
                if (
                    host in self._terminals
                    or self._sequences[host].accept(root) != "final"
                ):
                    raise ProviderRefused()
            else:
                candidate_host = doc.get("host")
                if (
                    candidate_host not in self._sequences
                    or candidate_host in self._terminals
                ):
                    raise ProviderRefused()
                host = candidate_host
                sequence = self._sequences[host]
                if (
                    decode_terminal(
                        raw,
                        self.installation.campaign_digest,
                        host,
                        sequence.final_bytes(),
                    )
                    != 0
                ):
                    raise ProviderRefused()
                sequence.require_complete()
                self._terminals[host] = raw

    def _session(
        self,
        case: InstalledRunnerCase,
        session: OwnedAttesterSession,
        expected: AdmissionExpectation,
        phase: str,
    ) -> dict[str, Any]:
        if (
            type(session) is not OwnedAttesterSession
            or type(expected) is not AdmissionExpectation
        ):
            raise ProviderRefused()
        completed, raw = session.completion, session.bundle
        operation = expected.operation
        if (
            completed is None
            or completed.returncode != 0
            or not completed.stdout_eof
            or not case.projection.start
            <= completed.completed_at
            < case.projection.deadline
            or session.installation.deadline > case.projection.deadline
            or session.installation.attester != case.attester
            or session.installation.private_key != case.private_key
            or session.installation.certificate != case.certificate
            or raw is None
            or expected.frozen_window_bytes != case.projection.frozen_window
            or expected.window_digest != case.projection.window.digest
            or operation.phase != phase
            or operation.window_id != case.projection.binding["window_id"]
        ):
            raise ProviderRefused()
        proof, observation = parse_bundle(strict_object(raw, 128 * 1024))
        actual = {
            key: value
            for key, value in asdict(proof.context).items()
            if key not in {"challenge_digest", "proof_transcript_digest"}
        }
        trust = case.attester_trust
        state = self._attester_state
        if state is None:
            raise ProviderRefused()
        if (
            actual != asdict(operation)
            or state.eligibility(
                key_id=trust.key_id, public_key_fingerprint=digest(trust.public_key)
            )
            != TrustEligibility.ELIGIBLE
        ):
            raise ProviderRefused()
        start, end, invocation = verify_observation_signature(
            proof=proof,
            observation=observation,
            operation=operation,
            window_record_digest=expected.window_digest,
            public_key=trust.public_key,
        )
        if invocation != session.invocation_id or not _instant(
            case.projection.window.document["not_before"]
        ) <= start <= end < _instant(case.projection.window.document["expires_at"]):
            raise ProviderRefused()
        # Core already registered this exact bundle against the existing public
        # proof verifier. Here the retained signed invocation is reauthenticated
        # for its root terminal join, without backdating a fresh registration.
        verify_slot_terminal(
            strict_object(self._sequences["NS3"].final_bytes()),
            case.projection.shared_packet,
            phase,
            raw,
            invocation,
        )
        return {
            "bundle_digest": digest(raw),
            "invocation_id": session.invocation_id,
            "client_pid": completed.pid,
            "client_returncode": completed.returncode,
            "completed_at": completed.completed_at,
        }

    def _join_outcomes(
        self,
        case: InstalledRunnerCase,
        outcomes: tuple[IssuerOutcome, ...],
        issue_session: OwnedAttesterSession,
        consume_session: OwnedAttesterSession,
    ) -> None:
        issue, consume = issue_session.bundle, consume_session.bundle
        if issue is None or consume is None:
            raise ProviderRefused()
        verify_case_outcome_proofs(
            case.projection.binding["case_kind"],
            case.projection.window.digest,
            outcomes,
            (issue, consume),
        )

    def _join(
        self,
        issuer: OwnedIssuerSession,
        issue_session: OwnedAttesterSession,
        consume_session: OwnedAttesterSession,
        *,
        issue_expected: AdmissionExpectation,
        consume_expected: AdmissionExpectation,
    ) -> bytes:
        case = self.installation.cases[self._case_index]
        self._final_clock(case)
        if type(issuer) is not OwnedIssuerSession or issue_session is consume_session:
            raise ProviderRefused()
        completed = issuer.completion
        if completed is None:
            self._case(case)
            issuer.finish()
            completed = issuer.completion
        if (
            completed is None
            or completed.returncode != 3
            or not completed.stdout_eof
            or not case.projection.start
            <= completed.completed_at
            < case.projection.deadline
            or issuer.installation.issuer != case.issuer
            or issuer.installation.private_key != case.private_key
            or issuer.installation.certificate != case.certificate
            or issuer.installation.deadline > case.projection.deadline
        ):
            raise ProviderRefused()
        self._drain_finals(case)
        finals = {
            host: strict_object(sequence.final_bytes())
            for host, sequence in self._sequences.items()
        }
        for host, sequence in self._sequences.items():
            _mechanics(finals[host], sequence)
        outcomes = issuer.collector.outcomes
        self._join_outcomes(case, outcomes, issue_session, consume_session)
        terminal = verify_issuer_terminal(
            finals["IDP3"], case.projection.shared_packet, case.roots[0], outcomes
        )
        capture = self._capture(case, finals["IDP3"]["capture_delivery"])
        if (
            capture != self._capture(case, finals["NS3"]["management_capture"])
            or capture
            != strict_object(self._sequences["NS3"].records[1])["management_capture"]
        ):
            raise ProviderRefused()
        issue = self._session(case, issue_session, issue_expected, "issue")
        consume = self._session(case, consume_session, consume_expected, "consume")
        failure: BaseException | None = None
        for session in (issuer, issue_session, consume_session):
            try:
                session.close()
            except BaseException as error:
                if failure is None:
                    failure = error
        if failure is not None:
            raise failure
        self._final_clock(case)
        self._require_single_peer()
        return canonical(
            {
                "campaign_digest": self.installation.campaign_digest,
                "case_kind": case.projection.binding["case_kind"],
                "root_final_digests": [
                    digest(self._sequences[h].final_bytes()) for h in ("IDP3", "NS3")
                ],
                "issuer_transcript_digest": terminal["transcript_digest"],
                "issuer_client_pid": completed.pid,
                "issuer_client_returncode": completed.returncode,
                "issue": issue,
                "consume": consume,
                "capture": capture,
            }
        )

    def complete_case_a(
        self,
        issuer: OwnedIssuerSession,
        issue_session: OwnedAttesterSession,
        consume_session: OwnedAttesterSession,
        *,
        issue_expected: AdmissionExpectation,
        consume_expected: AdmissionExpectation,
    ) -> bytes:
        try:
            if self._closed or getattr(self, "_cleanup_failed", False):
                raise ProviderRefused()
            if self._case_index != 0 or self._a_complete:
                raise ProviderRefused()
            join = self._join(
                issuer,
                issue_session,
                consume_session,
                issue_expected=issue_expected,
                consume_expected=consume_expected,
            )
            case = self.installation.cases[0]
            self._case(case)
            if self._io is None:
                raise ProviderRefused()
            self._io.deadline = case.projection.deadline
            self._io.send(
                encode_case_a_complete(
                    self.installation.campaign_digest,
                    join,
                    (
                        self._sequences["IDP3"].final_bytes(),
                        self._sequences["NS3"].final_bytes(),
                    ),
                )
            )
            self._case(case)
            self._a_complete = True
            self._joins.append(join)
            self._set_case(1)
            return join
        except BaseException:
            self.close()
            raise

    def complete_case_b(
        self,
        issuer: OwnedIssuerSession,
        issue_session: OwnedAttesterSession,
        consume_session: OwnedAttesterSession,
        *,
        issue_expected: AdmissionExpectation,
        consume_expected: AdmissionExpectation,
    ) -> bytes:
        try:
            if self._closed or getattr(self, "_cleanup_failed", False):
                raise ProviderRefused()
            if self._case_index != 1 or not self._a_complete or self._b_complete:
                raise ProviderRefused()
            join = self._join(
                issuer,
                issue_session,
                consume_session,
                issue_expected=issue_expected,
                consume_expected=consume_expected,
            )
            if self._receive(eof=True) is not None:
                raise ProviderRefused()
            self._final_clock(self.installation.cases[1])
            self._b_complete = True
            self._joins.append(join)
            return join
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        if self._closed:
            if getattr(self, "_cleanup_failed", False):
                raise ProviderRefused()
            return
        self._closed = True
        channels = self._peer, self._listener
        self._peer = self._listener = None
        failure: ProviderRefused | None = None
        for channel in channels:
            if channel is not None:
                try:
                    channel.close()
                except BaseException:
                    self._cleanup_failed = True
                    if failure is None:
                        failure = ProviderRefused()
        if failure is not None:
            raise failure from None

    def __enter__(self) -> OwnedCollectorHandoff:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def verify_retained_root_case(
    campaign_digest: str,
    shared_packet: bytes,
    roots: tuple[RootHostBinding, RootHostBinding],
    envelopes: tuple[bytes, ...],
    join: bytes,
    outcomes: tuple[IssuerOutcome, ...],
    bundles: tuple[bytes, bytes],
) -> None:
    """Replay the SAME immutable root/session predicates, never fake a process.

    JSON cannot reconstruct historical SO_PEERCRED, EOF or actual child waits.
    Those facts still require the independently pinned qualified producer history.
    This rechecks its exact retained bytes, not a portable root authentication.
    """
    try:
        if (
            type(roots) is not tuple
            or len(roots) != 2
            or any(type(root) is not RootHostBinding for root in roots)
            or type(envelopes) is not tuple
            or len(envelopes) != 7
            or type(outcomes) is not tuple
            or not outcomes
            or any(type(outcome) is not IssuerOutcome for outcome in outcomes)
        ):
            raise ProviderRefused()
        packet = parse_run_document(shared_packet)
        if (
            roots[0].terms["host_role"] != "issuer"
            or roots[1].terms["host_role"] != "attester"
            or any(
                root.terms["launch_packet_digest"] != digest(shared_packet)
                or root.terms["window_digest"] != packet["capture"]["window_digest"]
                or root.terms["case_kind"] != packet["case_kind"]
                or _instant(root.terms["not_before"]) != _instant(packet["not_before"])
                or _instant(root.terms["expires_at"]) != _instant(packet["expires_at"])
                for root in roots
            )
        ):
            raise ProviderRefused()
        sequences = {
            host: RootFrameSequence(root)
            for host, root in zip(("IDP3", "NS3"), roots, strict=True)
        }
        terminals: set[str] = set()
        phase_index = 0
        for raw in envelopes:
            doc = strict_object(raw, 270336)
            if doc.get("schema") == "Gate0RootHandoff.v1":
                host, root = decode_root_event(raw, campaign_digest)
                if host in terminals:
                    raise ProviderRefused()
                kind = sequences[host].accept(root)
                if kind != "final":
                    if phase_index >= 3 or (host, kind) != _PHASES[phase_index]:
                        raise ProviderRefused()
                    phase_index += 1
                elif phase_index != 3:
                    raise ProviderRefused()
            else:
                terminal_host = doc.get("host")
                if type(terminal_host) is not str:
                    raise ProviderRefused()
                host = terminal_host
                if phase_index != 3 or host not in sequences or host in terminals:
                    raise ProviderRefused()
                if (
                    decode_terminal(
                        raw, campaign_digest, host, sequences[host].final_bytes()
                    )
                    != 0
                ):
                    raise ProviderRefused()
                sequences[host].require_complete()
                terminals.add(host)
        if phase_index != 3 or terminals != {"IDP3", "NS3"}:
            raise ProviderRefused()
        finals = {
            host: strict_object(sequence.final_bytes())
            for host, sequence in sequences.items()
        }
        for host, sequence in sequences.items():
            _mechanics(finals[host], sequence)
        verify_case_outcome_proofs(
            packet["case_kind"], packet["capture"]["window_digest"], outcomes, bundles
        )
        terminal = verify_issuer_terminal(
            finals["IDP3"], shared_packet, roots[0], outcomes
        )
        capture = verify_capture_completion(
            shared_packet, finals["IDP3"]["capture_delivery"]
        )
        if (
            capture
            != verify_capture_completion(
                shared_packet, finals["NS3"]["management_capture"]
            )
            or capture
            != strict_object(sequences["NS3"].records[1])["management_capture"]
        ):
            raise ProviderRefused()
        joined = _fields(
            strict_object(join, 196608),
            "campaign_digest case_kind root_final_digests issuer_transcript_digest "
            "issuer_client_pid issuer_client_returncode issue consume capture",
        )
        if (
            canonical(joined) != join
            or type(joined["issuer_client_returncode"]) is not int
            or joined["issuer_client_returncode"] != 3
        ):
            raise ProviderRefused()
        _integer(joined["issuer_client_pid"])
        observed: list[tuple[datetime, datetime]] = []
        invocations: set[str] = set()
        clients = {joined["issuer_client_pid"]}
        public = base64.b64decode(
            packet["roles"]["attester"]["public_key_b64"], validate=True
        )
        for phase, raw in zip(("issue", "consume"), bundles, strict=True):
            proof, observation = parse_bundle(strict_object(raw, 128 * 1024))
            if canonical(strict_object(raw, 128 * 1024)) != raw:
                raise ProviderRefused()
            values = asdict(proof.context)
            operation = AdmittedOperation(
                **{
                    key: value
                    for key, value in values.items()
                    if key not in {"challenge_digest", "proof_transcript_digest"}
                }
            )
            if (
                operation.phase != phase
                or operation.plan_id != packet["capture"]["plan_id"]
                or operation.plan_digest != packet["capture"]["plan_digest"]
                or operation.run_id != packet["run_id"]
                or operation.run_attempt != packet["run_attempt"]
            ):
                raise ProviderRefused()
            start, end, invocation = verify_observation_signature(
                proof=proof,
                observation=observation,
                operation=operation,
                window_record_digest=packet["capture"]["window_digest"],
                public_key=public,
            )
            if (
                not _instant(packet["not_before"])
                <= start
                <= end
                < _instant(packet["expires_at"])
            ):
                raise ProviderRefused()
            if invocation in invocations:
                raise ProviderRefused()
            invocations.add(invocation)
            observed.append((start, end))
            retained = _fields(
                joined[phase],
                "bundle_digest invocation_id client_pid client_returncode completed_at",
            )
            pid = _integer(retained["client_pid"])
            if (
                pid in clients
                or type(retained["client_returncode"]) is not int
                or retained["client_returncode"] != 0
                or _number(retained["completed_at"]) < 0
                or retained["bundle_digest"] != digest(raw)
                or retained["invocation_id"] != invocation
            ):
                raise ProviderRefused()
            clients.add(pid)
            verify_slot_terminal(finals["NS3"], shared_packet, phase, raw, invocation)
        if (
            observed[0][1] > observed[1][0]
            or joined["issue"]["completed_at"] > joined["consume"]["completed_at"]
        ):
            raise ProviderRefused()
        expected_join = dict(
            campaign_digest=campaign_digest,
            case_kind=packet["case_kind"],
            root_final_digests=[
                digest(sequences[h].final_bytes()) for h in ("IDP3", "NS3")
            ],
            issuer_transcript_digest=terminal["transcript_digest"],
            issuer_client_pid=joined["issuer_client_pid"],
            issuer_client_returncode=3,
            issue=joined["issue"],
            consume=joined["consume"],
            capture=capture,
        )
        if joined != expected_join:
            raise ProviderRefused()
    except Exception:
        raise ProviderRefused() from None
