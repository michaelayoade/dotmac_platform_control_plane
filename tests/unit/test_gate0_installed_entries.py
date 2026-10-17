"""Hosted-only entry sequencing with explicit synthetic native boundaries.

These tests do not qualify a real installed launch, identity mount, DB, Bao or
sshd. Existing possession fixtures exercise the actual cryptographic exchange;
custody spies isolate phase hooks, not finite token/HTTP budget accounting.
"""

from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from io import StringIO
from time import monotonic
from types import SimpleNamespace
from uuid import UUID

import pytest
from test_gate0_attester import proof_setup as _proof_setup
from test_gate0_management_delivery import captured as _captured
from test_gate0_session_observation import SyntheticExchange
from test_gate0_session_observation import session as _session

from vendor_cp.deployment import gate0_bootstrap as bootstrap
from vendor_cp.deployment import gate0_launch as launch
from vendor_cp.deployment import gate0_management_delivery as delivery
from vendor_cp.deployment import gate0_services as services
from vendor_cp.deployment.gate0_capture import CaptureCoordinates
from vendor_cp.deployment.gate0_collection import IssuerOutcome, OutcomeKind
from vendor_cp.deployment.gate0_composition import PhaseResult
from vendor_cp.deployment.gate0_framing import ServiceRefused, canonical
from vendor_cp.deployment.gate0_role_custody import (
    CustodyProfile,
    ProviderRefused,
    RoleCustody,
)

proof_setup = _proof_setup
captured = _captured


@pytest.fixture
def entry_stdio(monkeypatch):
    class Output(StringIO):
        def fileno(self):
            return 21

    stream = SimpleNamespace(
        stdin=SimpleNamespace(fileno=lambda: 20), stdout=Output(), stderr=StringIO()
    )
    # Only this module's sys binding changes; pytest/global process stdio does not.
    monkeypatch.setattr(services, "sys", stream)
    return stream


@pytest.fixture
def issuer_entry(monkeypatch, entry_stdio):
    from dotmac_deployment_control import RehearsalIssuerIssuanceRefusalCode

    events = []
    digest = "sha256:" + "a" * 64
    coordinate = CaptureCoordinates(
        digest, digest, UUID(int=1), digest, UUID(int=3), UUID(int=4)
    )
    startup = object()
    prepared = SimpleNamespace(
        startup=startup, capture=SimpleNamespace(coordinates=coordinate)
    )
    terminal = IssuerOutcome(
        1,
        "consume",
        digest,
        digest,
        digest,
        digest,
        OutcomeKind.OWNER_REFUSED,
        "control.issuance",
        RehearsalIssuerIssuanceRefusalCode.ENVELOPE_MISMATCH.value,
        canonical({}),
    )
    state = SimpleNamespace(
        ack=None,
        eof=None,
        teardown_error=False,
        serve_error=False,
        serve_result=services.IssuerProcessResult(3, (terminal,)),
        export_close_error=False,
        entry_error=False,
        terminal_error=False,
        terminal_written=False,
    )

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            events.append("export-closed")
            if state.export_close_error:
                raise RuntimeError("synthetic-sensitive-descriptor-close-canary")

        def fileno(self):
            return 22

        def shutdown(self, direction):
            import socket

            assert direction == socket.SHUT_WR
            events.append("half-close")

    def finish_issuer(result):
        assert result is state.serve_result
        assert events[-1] == "prepare-exit"
        assert "export-closed" in events
        events.append("issuer-terminal")
        if state.terminal_error:
            raise RuntimeError("synthetic-sensitive-terminal-write-canary")
        state.terminal_written = True

    context = SimpleNamespace(
        packet_digest=digest,
        expires_at=datetime.now(UTC) + timedelta(seconds=60),
        deadline=monotonic() + 5,
        open_issuer_capture_export=lambda: Connection(),
        require_open=lambda: events.append("require-open"),
        finish_issuer=finish_issuer,
    )
    installation = SimpleNamespace(
        plan_id=coordinate.plan_id,
        management_delivery=SimpleNamespace(capture=object()),
    )
    state.installation = installation
    state.ack = launch.CaptureInstallReadback(
        digest, coordinate, context.expires_at
    ).document()
    monkeypatch.setattr(
        launch.InstalledLaunchContext,
        "from_installed",
        classmethod(lambda cls: context),
    )
    monkeypatch.setattr(
        bootstrap, "load_issuer_installation", lambda selected: installation
    )

    @contextmanager
    def prepare(selected, installed):
        assert selected is context and installed is installation
        events.append("prepare-enter")
        try:
            if state.entry_error:
                raise RuntimeError("synthetic-sensitive-pre-yield-canary")
            yield prepared
        finally:
            events.append("prepare-exit")
            if state.teardown_error:
                raise RuntimeError("synthetic-sensitive-teardown-canary")

    monkeypatch.setattr(bootstrap, "prepare_installed_issuer", prepare)

    def install_document(packet_digest, capture, selection):
        assert packet_digest == digest and capture is prepared.capture
        assert selection is installation.management_delivery.capture
        return {"schema": "synthetic-export"}

    monkeypatch.setattr(delivery, "install_document", install_document)

    class Channel:
        def __init__(self, *args, **kwargs):
            assert kwargs["deadline"] == context.deadline
            self.reads = 0

        def send(self, document):
            assert document == {"schema": "synthetic-export"}
            events.append("send")

        def receive(self, allow_eof=False):
            self.reads += 1
            events.append("eof" if allow_eof else "ack")
            result = state.eof if allow_eof else state.ack
            if isinstance(result, BaseException):
                raise result
            return result

    monkeypatch.setattr(services, "FramedChannel", Channel)

    def serve(selected):
        assert selected is startup
        assert events.index("ack") < events.index("eof") < events.index("export-closed")
        events.append("serve")
        if state.serve_error:
            raise RuntimeError("synthetic-sensitive-execution-canary")
        return state.serve_result

    monkeypatch.setattr(services, "issuer_run_result", serve)
    return state, events, context, entry_stdio


def test_installed_issuer_requires_exact_ack_and_eof_before_serving(issuer_entry):
    _, events, _, stdio = issuer_entry
    assert services.run_installed_issuer() == 3
    assert events == [
        "prepare-enter",
        "send",
        "half-close",
        "ack",
        "eof",
        "export-closed",
        "require-open",
        "serve",
        "prepare-exit",
        "issuer-terminal",
    ]
    assert stdio.stdout.getvalue() == "" and stdio.stderr.getvalue() == ""


@pytest.mark.parametrize(
    "failure", ["missing-ack", "wrong-ack", "extra-frame", "eof-refusal", "cancel"]
)
def test_installed_issuer_capture_failure_prevents_serve(issuer_entry, failure):
    state, events, _, stdio = issuer_entry
    if failure == "missing-ack":
        state.ack = None
    elif failure == "wrong-ack":
        state.ack = state.ack | {"launch_packet_digest": "sha256:" + "b" * 64}
    elif failure == "extra-frame":
        state.eof = {"unexpected": True}
    elif failure == "eof-refusal":
        state.eof = ServiceRefused()
    else:
        state.eof = services.ServiceCancelled()
    assert services.run_installed_issuer() == (5 if failure == "cancel" else 3)
    assert "serve" not in events
    assert events[-1] == "prepare-exit"
    assert stdio.stdout.getvalue() == ""
    assert "Traceback" not in stdio.stderr.getvalue()


@pytest.mark.parametrize("failure", ["teardown", "execution"])
def test_installed_issuer_post_execution_failure_is_incomplete(issuer_entry, failure):
    state, events, _, stdio = issuer_entry
    state.teardown_error = failure == "teardown"
    state.serve_error = failure == "execution"
    assert services.run_installed_issuer() == 5
    assert "serve" in events and events[-1] == "prepare-exit"
    assert "issuer-terminal" not in events
    assert stdio.stderr.getvalue() == "GATE0_SERVICE_INCOMPLETE\n"
    assert stdio.stdout.getvalue() == ""


@pytest.mark.parametrize(
    "outcome",
    [
        "success",
        "refused",
        "exception",
        "teardown",
        "missing_completion",
        "late_completion",
    ],
)
def test_installed_attester_retains_original_deadline_and_finishes_after_cleanup(
    monkeypatch, entry_stdio, outcome
):
    events = []
    deadline = monotonic() + 7

    def require_open():
        if outcome == "late_completion" and "cleanup" in events:
            raise RuntimeError("synthetic expired request")

    completion = SimpleNamespace(
        bundle_digest="sha256:" + "a" * 64,
        invocation_id="b" * 64,
        require_open=require_open,
    )
    prepared = SimpleNamespace(
        session=SimpleNamespace(completion=None), reader=object(), deadline=deadline
    )

    def finish(result, **identity):
        assert identity == (
            {
                "bundle_digest": completion.bundle_digest,
                "invocation_id": completion.invocation_id,
            }
            if result == "success"
            else {}
        )
        events.append(("finish", result))

    context = SimpleNamespace(finish_slot=finish)
    monkeypatch.setattr(
        launch.InstalledLaunchContext,
        "from_installed",
        classmethod(lambda cls: context),
    )
    monkeypatch.setattr(
        bootstrap, "load_attester_installation", lambda selected: object()
    )

    @contextmanager
    def prepare(*args):
        try:
            yield prepared
        finally:
            events.append("cleanup")
            if outcome == "teardown":
                raise RuntimeError("synthetic-sensitive-teardown-canary")

    monkeypatch.setattr(bootstrap, "prepare_installed_attester", prepare)

    def exchange(session, reader, *, deadline):
        assert session is prepared.session and reader is prepared.reader
        assert deadline is prepared.deadline
        assert not events
        events.append("exchange-start")
        if outcome == "exception":
            raise RuntimeError("synthetic-sensitive-exchange-canary")
        events.append("exchange-return")
        if outcome not in ("refused", "missing_completion"):
            session.completion = completion
        return 3 if outcome == "refused" else 0

    monkeypatch.setattr(services, "attester_session", exchange)
    status = services.run_installed_attester()
    if outcome in ("exception", "teardown", "missing_completion", "late_completion"):
        assert status == 5
        assert not any(
            isinstance(event, tuple) and event[0] == "finish" for event in events
        )
        assert entry_stdio.stderr.getvalue() == "GATE0_SERVICE_INCOMPLETE\n"
    else:
        assert status == (0 if outcome == "success" else 3)
        assert events == [
            "exchange-start",
            "exchange-return",
            "cleanup",
            ("finish", "success" if outcome == "success" else "refused"),
        ]
    assert entry_stdio.stdout.getvalue() == ""


@pytest.mark.parametrize(
    "entry, operation",
    [
        ("run_installed_capture_sender", "push_capture_install"),
        ("run_installed_capture_receiver", "receive_capture_install"),
    ],
)
@pytest.mark.parametrize("failure", [None, "refused", "cancelled"])
def test_installed_management_entries_wait_for_exchange_and_sanitize_failure(
    monkeypatch, entry_stdio, entry, operation, failure
):
    events = []
    context = SimpleNamespace(
        deadline=monotonic() + 5, expires_at=datetime.now(UTC) + timedelta(seconds=60)
    )
    installation = SimpleNamespace(capture=object())
    monkeypatch.setattr(
        launch.InstalledLaunchContext,
        "from_installed",
        classmethod(lambda cls: context),
    )
    monkeypatch.setattr(
        bootstrap,
        "load_management_delivery_installation",
        lambda selected: installation,
    )
    monkeypatch.setattr(services, "FramedChannel", lambda *args, **kwargs: object())

    def exchange(**kwargs):
        assert kwargs["context"] is context
        if operation == "push_capture_install":
            assert kwargs["installation"] is installation
        else:
            assert kwargs["selection"] is installation.capture
            assert kwargs["absolute_end"] is context.expires_at
        events.append("exchange")
        if failure == "refused":
            raise RuntimeError("synthetic-sensitive-management-canary")
        if failure == "cancelled":
            raise services.ServiceCancelled()
        events.append("complete")

    monkeypatch.setattr(delivery, operation, exchange)
    assert (
        getattr(services, entry)() == ({None: 0, "refused": 3, "cancelled": 5}[failure])
    )
    assert events == (["exchange", "complete"] if failure is None else ["exchange"])
    assert entry_stdio.stdout.getvalue() == ""
    assert "canary" not in entry_stdio.stderr.getvalue()


@pytest.mark.parametrize("run_refused", [False, True])
@pytest.mark.parametrize("cleanup_failed", [False, True])
def test_installed_supervisor_cleanup_failure_overrides_success_or_refusal(
    monkeypatch, entry_stdio, run_refused, cleanup_failed
):
    events = []

    class Supervisor:
        mechanics_outcome = "complete"

        def export_cleanup(self):
            events.append("export")

        def run(self):
            events.append("run")
            if run_refused:
                raise ProviderRefused()

        def close(self):
            events.append("close")
            if cleanup_failed:
                raise RuntimeError("synthetic-sensitive-cleanup-canary")

    monkeypatch.setattr(
        launch.FiniteGate0Supervisor,
        "from_installed",
        classmethod(lambda cls: Supervisor()),
    )
    assert services.run_installed_supervisor() == (
        5 if cleanup_failed or run_refused else 0
    )
    assert events == ["run", "close", "export"]
    assert entry_stdio.stdout.getvalue() == ""
    assert "canary" not in entry_stdio.stderr.getvalue()
    if cleanup_failed:
        assert "GATE0_LAUNCH_INCOMPLETE" in entry_stdio.stderr.getvalue()


def test_installed_issuer_nonzero_never_publishes_success(issuer_entry):
    state, events, _, stdio = issuer_entry
    state.serve_result = services.IssuerProcessResult(3)
    assert services.run_installed_issuer() == 3
    assert events[-2:] == ["serve", "prepare-exit"]
    assert "issuer-terminal" not in events
    assert stdio.stdout.getvalue() == ""


def test_installed_supervisor_incomplete_run_remains_incomplete_after_cleanup(
    monkeypatch, entry_stdio
):
    events = []

    class Supervisor:
        mechanics_outcome = "incomplete"

        def export_cleanup(self):
            events.append("export")

        def run(self):
            events.append("run")
            raise launch.LaunchIncomplete()

        def close(self):
            events.append("close")

    monkeypatch.setattr(
        launch.FiniteGate0Supervisor,
        "from_installed",
        classmethod(lambda cls: Supervisor()),
    )
    assert services.run_installed_supervisor() == 5
    assert events == ["run", "close", "export"]
    assert entry_stdio.stderr.getvalue() == "GATE0_LAUNCH_INCOMPLETE\n"
    assert entry_stdio.stdout.getvalue() == ""


@pytest.mark.parametrize("failed_phase", [None, "submission"])
def test_issuer_submission_refresh_precedes_owner_operation(monkeypatch, failed_phase):
    events = []
    custody = object.__new__(RoleCustody)
    custody.profile = CustodyProfile.ISSUER_FINITE_V1

    def refresh(selected, *, phase):
        assert selected is custody and phase == "submission"
        events.append("refresh-submission")
        if failed_phase:
            raise ProviderRefused()

    monkeypatch.setattr(RoleCustody, "refresh", refresh)

    class Composition:
        def issue(self, command):
            events.append("issue")
            return PhaseResult(
                "sha256:" + "a" * 64,
                "synthetic-authorization",
                "synthetic-lease",
                b"synthetic-envelope",
            )

        def consume(self, plan, envelope):
            events.append("consume")
            return PhaseResult(
                "sha256:" + "b" * 64,
                "synthetic-authorization",
                "synthetic-lease",
                single_use_reference="synthetic-consumed",
            )

    monkeypatch.setattr(
        services, "assemble_gate0_composition", lambda **kwargs: Composition()
    )
    startup = services.IssuerStartup(
        admission=None,
        verifier=SimpleNamespace(_require_open=lambda: None),
        signer=object(),
        authorization_verifier=object(),
        authorization_ttl=timedelta(seconds=30),
        actor_ref="synthetic-admin",
        database_qualified=True,
        require_frozen_window=False,
        sessions=lambda: pytest.fail("dispatch must not acquire DB"),
        custody=custody,
    )
    requests = iter(
        [
            {
                "schema": "Gate0IssuerSubmission.v1",
                "operation": "issue",
                "workload_token": "synthetic-token",
                "plan_id": str(UUID(int=1)),
                "command_id": "synthetic-command",
                "proof": {},
            },
            {
                "schema": "Gate0IssuerSubmission.v1",
                "operation": "consume",
                "workload_token": "synthetic-token",
                "plan_id": str(UUID(int=1)),
                "authorization": "c3ludGhldGljLWVudmVsb3Bl",
                "proof": {},
            },
        ]
    )
    channel = SimpleNamespace(
        deadline=monotonic() + startup.authorization_ttl.total_seconds(),
        receive=lambda allow_eof=False: next(requests, None),
        send=lambda result: events.append("result"),
    )
    original_deadline = channel.deadline
    worker = services.IssuerWorker(startup)
    if failed_phase:
        with pytest.raises(ProviderRefused):
            worker.run(channel)
        assert events == ["refresh-submission"]
        assert channel.deadline == original_deadline
    else:
        worker.run(channel)
        assert channel.deadline == original_deadline
        assert events == [
            "refresh-submission",
            "issue",
            "result",
            "refresh-submission",
            "consume",
            "result",
        ]


@pytest.mark.parametrize("failed_phase", [None, "challenge", "complete"])
def test_attester_refresh_challenge_then_eof_then_complete_before_signing(
    proof_setup, monkeypatch, failed_phase
):
    from dataclasses import replace

    setup = proof_setup
    exchange = SyntheticExchange(setup)
    custody = object.__new__(RoleCustody)
    custody.profile = CustodyProfile.ATTESTER_FINITE_V1
    phases = []

    def refresh(selected, *, phase):
        assert selected is custody
        assert not setup["calls"]
        if phase == "challenge":
            assert exchange.reads == 1 and not exchange.output
        else:
            assert phase == "complete"
            assert exchange.reads == 3 and len(exchange.output) == 1
        phases.append(phase)
        if phase == failed_phase:
            raise ProviderRefused()

    monkeypatch.setattr(RoleCustody, "refresh", refresh)
    session = replace(_session(setup), custody=custody)
    if failed_phase:
        with pytest.raises(ProviderRefused):
            session.run(exchange, setup["cert"])
        assert phases == (
            ["challenge"] if failed_phase == "challenge" else ["challenge", "complete"]
        )
        assert not setup["calls"]
        assert len(exchange.output) == (0 if failed_phase == "challenge" else 1)
    else:
        session.run(exchange, setup["cert"])
        assert phases == ["challenge", "complete"]
        assert len(exchange.output) == 2 and len(setup["calls"]) == 3


@pytest.mark.parametrize(
    "failure", ["descriptor-close", "custody-close-before-serve", "terminal-write"]
)
def test_installed_issuer_failed_close_or_terminal_write_cannot_publish(
    issuer_entry, failure
):
    state, events, _, stdio = issuer_entry
    if failure == "descriptor-close":
        state.export_close_error = True
    elif failure == "custody-close-before-serve":
        state.ack = None
        state.teardown_error = True
    else:
        state.terminal_error = True
    assert services.run_installed_issuer() == 5
    assert not state.terminal_written
    assert events.count("prepare-exit") == 1
    assert events.count("export-closed") == 1
    if failure != "terminal-write":
        assert "serve" not in events and "issuer-terminal" not in events
    else:
        assert events[-2:] == ["prepare-exit", "issuer-terminal"]
    assert stdio.stderr.getvalue() == "GATE0_SERVICE_INCOMPLETE\n"
    assert stdio.stdout.getvalue() == ""


@pytest.mark.parametrize("exit_code", [0, 3, 5])
def test_installed_issuer_diagnostic_result_is_not_an_eligible_terminal(
    issuer_entry, exit_code
):
    state, events, _, _ = issuer_entry
    state.serve_result = services.IssuerProcessResult(exit_code)
    assert services.run_installed_issuer() == exit_code
    assert "issuer-terminal" not in events and not state.terminal_written
    assert events[-1] == "prepare-exit"


@pytest.mark.parametrize(
    "failure", [None, "run", "close", "export", "owner-incomplete", "cancel-close"]
)
def test_root_cleanup_export_occurs_once_after_outer_close_with_derived_outcome(
    monkeypatch, entry_stdio, failure
):
    events = []

    class Supervisor:
        mechanics_outcome = (
            "incomplete"
            if failure in ("run", "close", "owner-incomplete", "cancel-close")
            else "complete"
        )

        def run(self):
            events.append("run")
            if failure == "run":
                raise launch.LaunchIncomplete()

        def close(self):
            events.append("close")
            if failure == "close":
                raise RuntimeError("sensitive-close")
            if failure == "cancel-close":
                raise services.ServiceCancelled()

        def export_cleanup(self):
            assert events[-1] == "close"
            events.append("export")
            if failure == "export":
                raise RuntimeError("sensitive-export")

    monkeypatch.setattr(
        launch.FiniteGate0Supervisor,
        "from_installed",
        classmethod(lambda cls: Supervisor()),
    )
    assert services.run_installed_supervisor() == (0 if failure is None else 5)
    assert events == ["run", "close", "export"]
    assert entry_stdio.stdout.getvalue() == ""
    assert "sensitive" not in entry_stdio.stderr.getvalue()


def test_installed_issuer_rejects_capture_for_different_installed_plan(issuer_entry):
    state, events, _, stdio = issuer_entry
    state.installation.plan_id = UUID(int=99)
    assert services.run_installed_issuer() == 3
    assert events == ["prepare-enter", "prepare-exit"]
    assert not state.terminal_written
    assert stdio.stdout.getvalue() == ""


@pytest.mark.parametrize("cleanup_uncertain", [False, True])
def test_installed_issuer_pre_yield_failure_is_incomplete_without_terminal(
    issuer_entry, cleanup_uncertain
):
    state, events, _, stdio = issuer_entry
    state.entry_error = True
    state.teardown_error = cleanup_uncertain
    assert services.run_installed_issuer() == 5
    assert events == ["prepare-enter", "prepare-exit"]
    assert not state.terminal_written
    assert stdio.stderr.getvalue() == "GATE0_SERVICE_INCOMPLETE\n"
    assert stdio.stdout.getvalue() == ""


def test_installed_issuer_post_entry_refusal_with_confirmed_close_stays_refused(
    issuer_entry,
):
    state, events, _, stdio = issuer_entry
    state.ack = None
    assert services.run_installed_issuer() == 3
    assert events[-2:] == ["export-closed", "prepare-exit"]
    assert "serve" not in events and not state.terminal_written
    assert stdio.stderr.getvalue() == "DATABASE_BINDING_UNQUALIFIED\n"
    assert stdio.stdout.getvalue() == ""


@pytest.mark.parametrize("cleanup_failure", [None, "directory", "custody", "capture"])
def test_actual_attester_pre_yield_refusal_is_incomplete_after_resource_acquisition(
    monkeypatch, tmp_path, entry_stdio, captured, cleanup_failure
):
    """Run the actual preparation owner through all three resource finalizers."""
    import os
    from dataclasses import replace

    from test_gate0_bootstrap import synthetic_attester

    from vendor_cp.deployment.gate0_management_delivery import CaptureSelection

    _, _, capture, _ = captured
    coordinates = capture.coordinates
    installation = replace(
        synthetic_attester(),
        capture=CaptureSelection(
            coordinates.window_digest,
            coordinates.plan_id,
            coordinates.plan_digest,
            coordinates.target_id,
            coordinates.approval_request_id,
        ),
    )
    capture_path = tmp_path / "capture.json"
    capture_path.write_bytes(capture.encoded)
    events, descriptors, owned = [], {}, set()
    started_at, origin = datetime.now(UTC), monotonic()
    deadline = origin + (installation.identity.expires_at - started_at).total_seconds()

    def acquire(name, path):
        fd = os.open(path, os.O_RDONLY)
        descriptors[name] = fd
        owned.add(fd)
        events.append("open-" + name)
        return fd

    def close_descriptor(fd):
        name = next(name for name, value in descriptors.items() if value == fd)
        events.append("close-" + name)
        if cleanup_failure == name:
            raise RuntimeError("synthetic-sensitive-descriptor-cleanup")
        os.close(fd)
        owned.remove(fd)

    def close_custody():
        events.append("close-custody")
        if cleanup_failure == "custody":
            raise RuntimeError("synthetic-sensitive-custody-cleanup")

    def refuse_before_yield():
        events.append("refuse-before-yield")
        raise ProviderRefused()

    context = SimpleNamespace(
        slot_id=installation.slot_id,
        worker_uid=installation.worker_uid,
        required_phase=installation.phase,
        started_at=started_at,
        monotonic_origin=origin,
        deadline=deadline,
        require_run_role_terms=lambda **kwargs: None,
        capture_coordinates=lambda: coordinates,
        require_capture_slot=lambda *args: None,
        open_authenticated_capture=lambda *args: acquire("capture", capture_path),
        open_auth_info_directory=lambda: acquire("directory", tmp_path),
        require_open=refuse_before_yield,
        finish_slot=lambda *args, **kwargs: pytest.fail("pre-yield terminal published"),
    )

    def acquire_custody(*args):
        events.append("open-custody")
        return SimpleNamespace(deadline=deadline, close=close_custody), SimpleNamespace(
            issuer_trust=object()
        )

    # Native installation provenance, custody acquisition and session assembly
    # are synthetic boundaries. Keep the real generator, capture decoder, clock
    # mapping, approved-at-start admission construction and cleanup ordering.
    monkeypatch.setattr(
        launch.InstalledLaunchContext,
        "from_installed",
        classmethod(lambda cls: context),
    )
    monkeypatch.setattr(
        bootstrap, "load_attester_installation", lambda selected: installation
    )
    monkeypatch.setattr(bootstrap, "_installation", lambda *args: None)
    monkeypatch.setattr(bootstrap, "_custody", acquire_custody)
    monkeypatch.setattr(
        bootstrap,
        "assemble_attester_session",
        lambda **kwargs: events.append("assemble-session") or object(),
    )
    monkeypatch.setattr(
        bootstrap, "os", SimpleNamespace(read=os.read, close=close_descriptor)
    )
    monkeypatch.setattr(
        services,
        "attester_session",
        lambda *args, **kwargs: pytest.fail("pre-yield refusal reached serving"),
    )
    try:
        assert services.run_installed_attester() == 5
        assert events == [
            "open-capture",
            "open-custody",
            "assemble-session",
            "open-directory",
            "refuse-before-yield",
            "close-directory",
            "close-custody",
            "close-capture",
        ]
        assert owned == (
            {descriptors[cleanup_failure]}
            if cleanup_failure in ("directory", "capture")
            else set()
        )
        assert entry_stdio.stderr.getvalue() == "GATE0_SERVICE_INCOMPLETE\n"
        assert entry_stdio.stdout.getvalue() == ""
    finally:
        for fd in owned:
            os.close(fd)


@pytest.mark.parametrize("failure", ["context", "installation"])
def test_attester_refusal_before_preparation_keeps_safe_refusal(
    monkeypatch, entry_stdio, failure
):
    events = []

    def load_context():
        events.append("context")
        if failure == "context":
            raise ProviderRefused()
        return object()

    def load_installation(context):
        events.append("installation")
        raise ProviderRefused()

    monkeypatch.setattr(
        launch.InstalledLaunchContext,
        "from_installed",
        classmethod(lambda cls: load_context()),
    )
    monkeypatch.setattr(bootstrap, "load_attester_installation", load_installation)
    monkeypatch.setattr(
        bootstrap,
        "prepare_installed_attester",
        lambda *args: pytest.fail("pre-resource refusal reached preparation"),
    )
    assert services.run_installed_attester() == 3
    assert events == ["context"] + (
        ["installation"] if failure == "installation" else []
    )
    assert entry_stdio.stderr.getvalue() == "TRUSTED_SSHD_BINDING_UNCONFIGURED\n"
    assert entry_stdio.stdout.getvalue() == ""
