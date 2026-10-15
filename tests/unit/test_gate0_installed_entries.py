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
from test_gate0_session_observation import SyntheticExchange
from test_gate0_session_observation import session as _session

from vendor_cp.deployment import gate0_bootstrap as bootstrap
from vendor_cp.deployment import gate0_launch as launch
from vendor_cp.deployment import gate0_management_delivery as delivery
from vendor_cp.deployment import gate0_services as services
from vendor_cp.deployment.gate0_capture import CaptureCoordinates
from vendor_cp.deployment.gate0_composition import PhaseResult
from vendor_cp.deployment.gate0_framing import ServiceRefused
from vendor_cp.deployment.gate0_role_custody import (
    CustodyProfile,
    ProviderRefused,
    RoleCustody,
)

proof_setup = _proof_setup


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
    events = []
    digest = "sha256:" + "a" * 64
    coordinates = tuple(
        CaptureCoordinates(
            digest, digest, UUID(int=i), digest, UUID(int=3), UUID(int=i + 3)
        )
        for i in (1, 2)
    )
    startup = object()
    prepared = SimpleNamespace(
        startup=startup,
        captures=tuple(SimpleNamespace(coordinates=c) for c in coordinates),
    )
    state = SimpleNamespace(
        ack=None, eof=None, teardown_error=False, serve_error=False, serve_result=0
    )

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            events.append("export-closed")

        def fileno(self):
            return 22

        def shutdown(self, direction):
            import socket

            assert direction == socket.SHUT_WR
            events.append("half-close")

    context = SimpleNamespace(
        packet_digest=digest,
        expires_at=datetime.now(UTC) + timedelta(seconds=60),
        deadline=monotonic() + 5,
        open_issuer_capture_export=lambda: Connection(),
        require_open=lambda: events.append("require-open"),
        finish_issuer_success=lambda: events.append("issuer-success"),
    )
    installation = SimpleNamespace(
        management_delivery=SimpleNamespace(captures=("a", "b"))
    )
    state.ack = launch.CaptureInstallReadback(
        digest, coordinates, context.expires_at
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
            yield prepared
        finally:
            events.append("prepare-exit")
            if state.teardown_error:
                raise RuntimeError("synthetic-sensitive-teardown-canary")

    monkeypatch.setattr(bootstrap, "prepare_installed_issuer", prepare)
    monkeypatch.setattr(
        delivery, "install_document", lambda *args: {"schema": "synthetic-export"}
    )

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

    monkeypatch.setattr(services, "issuer_run", serve)
    return state, events, context, entry_stdio


def test_installed_issuer_requires_exact_ack_and_eof_before_serving(issuer_entry):
    _, events, _, stdio = issuer_entry
    assert services.run_installed_issuer() == 0
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
        "issuer-success",
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
    assert "issuer-success" not in events
    assert stdio.stderr.getvalue() == "GATE0_SERVICE_INCOMPLETE\n"
    assert stdio.stdout.getvalue() == ""


@pytest.mark.parametrize("outcome", ["success", "refused", "exception", "teardown"])
def test_installed_attester_retains_original_deadline_and_finishes_after_cleanup(
    monkeypatch, entry_stdio, outcome
):
    events = []
    deadline = monotonic() + 7
    prepared = SimpleNamespace(session=object(), reader=object(), deadline=deadline)
    context = SimpleNamespace(
        finish_slot=lambda result: events.append(("finish", result))
    )
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
        return 3 if outcome == "refused" else 0

    monkeypatch.setattr(services, "attester_session", exchange)
    status = services.run_installed_attester()
    if outcome in ("exception", "teardown"):
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
    installation = SimpleNamespace(captures=("a", "b"))
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
            assert kwargs["selections"] is installation.captures
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
        5 if cleanup_failed else 3 if run_refused else 0
    )
    assert events == ["run", "close"]
    assert entry_stdio.stdout.getvalue() == ""
    assert "canary" not in entry_stdio.stderr.getvalue()
    if cleanup_failed:
        assert "GATE0_LAUNCH_INCOMPLETE" in entry_stdio.stderr.getvalue()


def test_installed_issuer_nonzero_never_publishes_success(issuer_entry):
    state, events, _, stdio = issuer_entry
    state.serve_result = 3
    assert services.run_installed_issuer() == 3
    assert events[-2:] == ["serve", "prepare-exit"]
    assert "issuer-success" not in events
    assert stdio.stdout.getvalue() == ""


def test_installed_supervisor_incomplete_run_remains_incomplete_after_cleanup(
    monkeypatch, entry_stdio
):
    events = []

    class Supervisor:
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
    assert events == ["run", "close"]
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
        receive=lambda allow_eof=False: next(requests, None),
        send=lambda result: events.append("result"),
    )
    worker = services.IssuerWorker(startup)
    if failed_phase:
        with pytest.raises(ProviderRefused):
            worker.run(channel)
        assert events == ["refresh-submission"]
    else:
        worker.run(channel)
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
