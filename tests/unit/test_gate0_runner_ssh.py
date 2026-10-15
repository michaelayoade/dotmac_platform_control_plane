"""Focused hosted qualification sources; fixtures are never installed handles."""

from __future__ import annotations

import hashlib
import os
import signal
import stat
import subprocess
import sys
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import monotonic
from types import SimpleNamespace

import pytest

from vendor_cp.deployment import gate0_framing, gate0_runner_ssh, gate0_session
from vendor_cp.deployment.gate0_framing import FramedChannel, ServiceRefused, canonical
from vendor_cp.deployment.gate0_observation import encode
from vendor_cp.deployment.gate0_runner_ssh import (
    OwnedAttesterSession,
    OwnedIssuerSession,
    RunnerFilePin,
    RunnerSshEndpoint,
    RunnerSshInstallation,
    _cleanup,
    _command,
    close_owned_sessions,
    validate_challenge,
)
from vendor_cp.deployment.gate0_runtime import AdmittedOperation


def operation() -> AdmittedOperation:
    return AdmittedOperation(
        repository_id="1",
        run_id="2",
        run_attempt="1",
        window_id="window-a",
        phase="issue",
        authorization_digest=None,
        authorization_issued_at=None,
        lease_id="lease-a",
        controller_fingerprint="SHA256:" + "A" * 43,
        target_ref="target-a",
        plan_id="00000000-0000-0000-0000-000000000001",
        plan_digest="sha256:" + "1" * 64,
        plan_purpose="rehearsal_issuer_operation",
        operation="deploy",
        execution_plan_digest="sha256:" + "2" * 64,
        certificate_digest="sha256:" + "3" * 64,
        ca_fingerprint="SHA256:" + "B" * 43,
    )


def challenge(expected: AdmittedOperation, wall: datetime) -> dict[str, object]:
    return {
        "schema": "Gate0PossessionChallenge.v1",
        "instance_id": "1" * 64,
        "challenge_id": "2" * 64,
        "nonce": "3" * 64,
        "context": asdict(expected),
        "expires_at": (wall + timedelta(seconds=20)).isoformat().replace("+00:00", "Z"),
    }


def frame(document: dict[str, object]) -> dict[str, object]:
    return {
        "schema": "Gate0SessionChallenge.v1",
        "challenge_id": document["challenge_id"],
        "challenge": encode(canonical(document)),
    }


def test_challenge_exact_full_context_and_expiry() -> None:
    wall = datetime.now(UTC)
    expected = operation()
    document = challenge(expected, wall)
    raw, identity, expiry = validate_challenge(
        frame(document), expected, wall=wall, expires_at=wall + timedelta(seconds=25)
    )
    assert raw == canonical(document) and identity == "2" * 64
    assert expiry == wall + timedelta(seconds=20)


@pytest.mark.parametrize(
    "field,value",
    [
        ("instance_id", "z" * 64),
        ("nonce", ""),
        ("challenge_id", "4" * 63),
        ("schema", "other"),
        ("extra", True),
    ],
)
def test_malformed_challenge(field: str, value: object) -> None:
    wall = datetime.now(UTC)
    document = challenge(operation(), wall)
    document[field] = value
    with pytest.raises(ServiceRefused):
        validate_challenge(
            frame(document),
            operation(),
            wall=wall,
            expires_at=wall + timedelta(seconds=25),
        )


@pytest.mark.parametrize("field", list(asdict(operation())))
def test_every_admitted_coordinate_is_compared(field: str) -> None:
    wall = datetime.now(UTC)
    document = challenge(operation(), wall)
    context = dict(asdict(operation()))
    context[field] = "swapped"
    document["context"] = context
    with pytest.raises(ServiceRefused):
        validate_challenge(
            frame(document),
            operation(),
            wall=wall,
            expires_at=wall + timedelta(seconds=25),
        )


@pytest.mark.parametrize("seconds", [-1, 0, 26, 31])
def test_challenge_expiry_cannot_extend_case(seconds: int) -> None:
    wall = datetime.now(UTC)
    document = challenge(operation(), wall)
    document["expires_at"] = (wall + timedelta(seconds=seconds)).isoformat()
    with pytest.raises(ServiceRefused):
        validate_challenge(
            frame(document),
            operation(),
            wall=wall,
            expires_at=wall + timedelta(seconds=25),
        )


def test_outer_challenge_swap_and_noncanonical_bytes() -> None:
    wall = datetime.now(UTC)
    document = challenge(operation(), wall)
    swapped = frame(document)
    swapped["challenge_id"] = "5" * 64
    noncanonical = frame(document)
    noncanonical["challenge"] = encode(b" " + canonical(document))
    for candidate in (swapped, noncanonical):
        with pytest.raises(ServiceRefused):
            validate_challenge(
                candidate,
                operation(),
                wall=wall,
                expires_at=wall + timedelta(seconds=25),
            )


def installation() -> RunnerSshInstallation:
    pin = RunnerFilePin("/protected/controller", "1" * 64)
    return RunnerSshInstallation(
        RunnerSshEndpoint("192.0.2.1", 2222, "192.0.2.3", "issuer", "idp3-a"),
        RunnerSshEndpoint("192.0.2.2", 2223, "192.0.2.3", "attester", "ns3-a"),
        replace(pin, path="/usr/bin/ssh"),
        replace(pin, path="/usr/bin/ssh-keygen"),
        pin,
        replace(pin, path="/protected/controller-cert.pub"),
        replace(pin, path="/protected/known_hosts"),
        os.getuid(),
        datetime.now(UTC) + timedelta(seconds=60),
        monotonic() + 60,
    )


def test_closed_ssh_commands_have_no_agent_proxy_or_override() -> None:
    installed = installation()
    for attester in (False, True):
        command = _command(installed, attester=attester)
        assert command[:4] == ["/usr/bin/ssh", "-F", "/dev/null", "-T"]
        endpoint = installed.attester if attester else installed.issuer
        assert command[-1] == endpoint.user + "@" + endpoint.host
        assert command.index(command[-1]) == len(command) - 1
        assert not any("dotmac-platform" in argument for argument in command)
        assert "-oRequestTTY=no" in command
        assert "-oIdentityAgent=none" in command
        assert "-oProxyCommand=none" in command
        assert "-oControlPath=none" in command
        assert "-oClearAllForwardings=yes" in command
        assert "-oStrictHostKeyChecking=yes" in command
        assert command[command.index("-b") + 1] == installed.issuer.source


def owned_fixture(code: str, deadline: float) -> OwnedAttesterSession:
    # Only this test fixture bypasses installation qualification. Production
    # constructors have no process/channel injection seam.
    process = subprocess.Popen(  # noqa: S603 -- test-owned literal program fixtures
        [sys.executable, "-c", code],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        bufsize=0,
    )
    owner = object.__new__(OwnedAttesterSession)
    owner.installation = SimpleNamespace(deadline=deadline, require_open=lambda: None)
    owner._process = process
    owner._processes = [process]
    owner._closed = False
    owner._cleanup_failed = False
    owner._completion = None
    owner._bundle = None
    owner._invocation_id = None
    assert process.stdout is not None and process.stdin is not None
    owner.channel = FramedChannel(
        process.stdout.fileno(), process.stdin.fileno(), deadline=deadline
    )
    return owner


@pytest.mark.parametrize("status", [0, 3])
def test_actual_eof_and_wait_status_retained(status: int) -> None:
    owner = owned_fixture(f"raise SystemExit({status})", monotonic() + 5)
    try:
        owner._half_close()
        observed = owner._finish(status)
        assert observed.returncode == status and observed.stdout_eof
        assert observed.pid == owner._process.pid
        assert owner._process.returncode == status
    finally:
        owner.close()


@pytest.mark.parametrize("status", [5, 255, -signal.SIGTERM])
def test_client_failure_cannot_complete(status: int) -> None:
    code = (
        f"raise SystemExit({status})"
        if status >= 0
        else "import os,signal; os.kill(os.getpid(),signal.SIGTERM)"
    )
    owner = owned_fixture(code, monotonic() + 5)
    try:
        owner._half_close()
        with pytest.raises(ServiceRefused):
            owner._finish(0)
        assert owner.completion is None
    finally:
        owner.close()


@pytest.mark.parametrize(
    "code",
    [
        "import os; os.write(1,b'\\x00\\x00')",
        "import os; os.write(1,b'\\x00\\x00\\x00\\x02{}')",
        "import time; time.sleep(60)",
    ],
)
def test_partial_trailing_or_missing_eof_is_incomplete_and_reaped(code: str) -> None:
    owner = owned_fixture(code, monotonic() + 0.3)
    owner._half_close()
    try:
        with pytest.raises(ServiceRefused):
            owner._finish(0)
        assert owner.completion is None
    finally:
        owner.close()
    assert owner._process.returncode is not None


def test_common_cleanup_reaps_all_owned_children_after_deadline() -> None:
    children = [
        subprocess.Popen(  # noqa: S603 -- test-owned literal sleeping children
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            start_new_session=True,
        )
        for _ in range(3)
    ]
    started = monotonic()
    _cleanup(children, started - 1)
    assert monotonic() - started < 2.5
    assert all(child.returncode is not None for child in children)
    assert all(child.stdin.closed and child.stdout.closed for child in children)


def test_public_aggregate_cleanup_reaps_actual_owned_children_once() -> None:
    started = monotonic()
    owners = [
        owned_fixture("import time; time.sleep(60)", started - 1) for _ in range(3)
    ]
    close_owned_sessions(*owners)
    assert monotonic() - started < 2.5
    assert all(owner._closed and not owner._cleanup_failed for owner in owners)
    assert all(owner._process.returncode is not None for owner in owners)
    assert all(
        owner._process.stdin.closed and owner._process.stdout.closed for owner in owners
    )
    close_owned_sessions(*owners)


@pytest.mark.parametrize("failure", [None, "term", "kill", "wait", "pipe"])
@pytest.mark.parametrize("original_deadline", [90.0, 100.5])
def test_aggregate_cleanup_shares_one_end_attempts_all_and_retains_failure(
    monkeypatch: pytest.MonkeyPatch,
    failure: str | None,
    original_deadline: float,
) -> None:
    clock = [100.0]
    events = []

    class Pipe:
        def __init__(self, label: str) -> None:
            self.label = label

        def close(self) -> None:
            events.append(("close", self.label))
            if failure == "pipe" and self.label == "first-stdin":
                raise OSError("private fixture detail")

    class Child:
        def __init__(self, pid: int, label: str) -> None:
            self.pid = pid
            self.returncode = None
            self.stdin = Pipe(label + "-stdin")
            self.stdout = Pipe(label + "-stdout")
            self.stderr = Pipe(label + "-stderr")

        def wait(self, *, timeout: float) -> int:
            events.append(("wait", self.pid, timeout))
            clock[0] += 0.75
            if failure == "wait" and self.pid == 101:
                raise subprocess.TimeoutExpired("fixed-test-child", timeout)
            self.returncode = -signal.SIGKILL
            return self.returncode

    children = [Child(101, "first"), Child(102, "second"), Child(103, "third")]
    owners = []
    for kind, child in zip(
        (OwnedIssuerSession, OwnedAttesterSession, OwnedAttesterSession),
        children,
        strict=True,
    ):
        owner = object.__new__(kind)
        owner._closed = False
        owner._cleanup_failed = False
        owner._processes = [child]
        owner.installation = SimpleNamespace(deadline=original_deadline)
        owners.append(owner)

    def signal_child(pid: int, sig: int) -> None:
        assert all(owner._closed for owner in owners)
        events.append(("signal", pid, sig))
        if pid == 101 and (failure, sig) in (
            ("term", signal.SIGTERM),
            ("kill", signal.SIGKILL),
        ):
            raise PermissionError("private fixture detail")

    monkeypatch.setattr(gate0_runner_ssh, "monotonic", lambda: clock[0])
    monkeypatch.setattr(gate0_runner_ssh.os, "killpg", signal_child)
    if failure is None:
        close_owned_sessions(*owners, owners[0])
    else:
        with pytest.raises(ServiceRefused, match="gate0_service_refused"):
            close_owned_sessions(*owners, owners[0])
    assert [event for event in events if event[0] == "wait"] == (
        [("wait", 101, 2.0), ("wait", 102, 1.25), ("wait", 103, 0.5)]
        if original_deadline < 100.0
        else [("wait", 101, 0.5), ("wait", 102, 0), ("wait", 103, 0)]
    )
    assert len([event for event in events if event[0] == "signal"]) == 6
    assert len([event for event in events if event[0] == "close"]) == 9
    assert all(owner._cleanup_failed is (failure is not None) for owner in owners)
    retained = tuple(events)
    if failure is None:
        close_owned_sessions(*owners)
    else:
        with pytest.raises(ServiceRefused):
            close_owned_sessions(*owners)
    assert tuple(events) == retained  # No PID reuse/retry or fresh cleanup tail.


@pytest.mark.parametrize(
    "invalid", [object(), object.__new__(gate0_runner_ssh._OwnedClient)]
)
def test_aggregate_cleanup_rejects_every_wrong_owner_before_acting(
    monkeypatch: pytest.MonkeyPatch, invalid: object
) -> None:
    valid = object.__new__(OwnedIssuerSession)
    valid._closed = False
    valid._cleanup_failed = False
    monkeypatch.setattr(
        gate0_runner_ssh,
        "_cleanup",
        lambda *args: pytest.fail("cleanup began before validating all owners"),
    )
    with pytest.raises(ServiceRefused):
        close_owned_sessions(valid, invalid)
    assert not valid._closed


def test_already_closed_owner_and_reaped_child_never_signal_reused_pid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []
    closed = object.__new__(OwnedIssuerSession)
    closed._closed = True
    closed._cleanup_failed = False
    closed._processes = [SimpleNamespace(pid=123, returncode=None)]
    # A successful measured child may be reaped before its first owner close.
    reaped = object.__new__(OwnedAttesterSession)
    reaped._closed = False
    reaped._cleanup_failed = False
    reaped.installation = SimpleNamespace(deadline=monotonic() + 5)
    reaped._processes = [
        SimpleNamespace(
            pid=456,
            returncode=0,
            stdin=None,
            stdout=None,
            stderr=None,
            wait=lambda *, timeout: calls.append("wait-reaped") or 0,
        )
    ]
    monkeypatch.setattr(
        gate0_runner_ssh.os,
        "killpg",
        lambda *args: pytest.fail("signalled closed/reaped PID"),
    )
    close_owned_sessions(closed, reaped)
    assert calls == ["wait-reaped"]
    close_owned_sessions(closed, reaped)
    assert calls == ["wait-reaped"]


def test_prior_closed_failure_still_cleans_other_active_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failed = object.__new__(OwnedIssuerSession)
    failed._closed = True
    failed._cleanup_failed = True
    active = object.__new__(OwnedAttesterSession)
    active._closed = False
    active._cleanup_failed = False
    active._processes = []
    active.installation = SimpleNamespace(deadline=123.0)
    calls = []

    def clean(processes, deadline):
        assert active._closed
        calls.append((processes, deadline))

    monkeypatch.setattr(gate0_runner_ssh, "_cleanup", clean)
    with pytest.raises(ServiceRefused):
        close_owned_sessions(failed, active)
    assert calls == [([], 123.0)]
    assert active._closed and not active._cleanup_failed
    assert failed._cleanup_failed


def test_binary_pin_uses_explicit_large_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = b"binary-fixture" * 8192
    path = tmp_path / "binary"
    path.write_bytes(payload)
    path.chmod(0o600)
    original = Path.lstat

    def protected_parents(candidate: Path):
        if candidate != path:
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=os.getuid())
        return original(candidate)

    monkeypatch.setattr(Path, "lstat", protected_parents)
    pin = RunnerFilePin(str(path), hashlib.sha256(payload).hexdigest())
    with pytest.raises(ServiceRefused):
        pin.read(os.getuid())
    assert pin.read(os.getuid(), maximum=32 * 1024 * 1024) == payload
    with pytest.raises(ServiceRefused):
        replace(pin, sha256="0" * 64).read(os.getuid(), maximum=32 * 1024 * 1024)


def test_protected_pin_refuses_writable_parent(tmp_path: Path) -> None:
    path = tmp_path / "key"
    path.write_bytes(b"private-fixture")
    path.chmod(0o600)
    tmp_path.chmod(0o777)
    with pytest.raises(ServiceRefused):
        RunnerFilePin(str(path), hashlib.sha256(path.read_bytes()).hexdigest()).read(
            os.getuid(), private=True
        )


def test_deadline_cannot_exceed_wall_expiry() -> None:
    installed = replace(
        installation(), expires_at=datetime.now(UTC) + timedelta(seconds=1)
    )
    assert installed.deadline - monotonic() <= 1
    with pytest.raises(ServiceRefused):
        replace(installed, deadline=monotonic() - 1)


def test_no_remote_command_matches_actual_forced_command_reader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ReachedAuthRead(Exception):
        pass

    def lookup(*_args: object, **_kwargs: object) -> int:
        raise ReachedAuthRead()

    monkeypatch.setattr(gate0_session.os, "geteuid", lambda: 1001)
    monkeypatch.setattr(gate0_session.os, "open", lookup)
    reader = gate0_session.SshdSessionReader(directory_fd=0, worker_uid=1001)
    environment = {"SSH_USER_AUTH": "/tmp/sshauth." + "a" * 15}  # noqa: S108 -- exact server auth path grammar; lookup is intercepted
    # A shell-session request supplies no original command, reaches auth reading,
    # and lets the qualified server's ForceCommand choose the fixed service.
    with pytest.raises(ReachedAuthRead):
        reader.read(environment)
    for original in (
        "dotmac-platform gate0 issuer-run",
        "dotmac-platform gate0 attester-session",
    ):
        with pytest.raises(ServiceRefused):
            reader.read({**environment, "SSH_ORIGINAL_COMMAND": original})


@pytest.mark.parametrize("offset", [0.0, 0.001])
@pytest.mark.parametrize("boundary", ["wait_return", "completion_sample"])
def test_actual_wait_at_or_after_narrowed_deadline_cannot_publish(
    monkeypatch: pytest.MonkeyPatch,
    offset: float,
    boundary: str,
) -> None:
    original_end = monotonic() + 5
    owner = owned_fixture("raise SystemExit(0)", original_end)
    now = [monotonic()]
    narrowed_end = now[0] + 1
    owner.channel.deadline = narrowed_end
    checks = []

    def installation_open() -> None:
        checks.append(now[0])
        if now[0] >= original_end:
            raise ServiceRefused()
        if boundary == "completion_sample" and len(checks) == 2:
            now[0] = narrowed_end + offset

    owner.installation.require_open = installation_open
    actual_wait = owner._process.wait

    def wait_then_cross(*args: object, **kwargs: object) -> int:
        status = actual_wait(*args, **kwargs)
        # EOF was read before this actual wait. Deterministically plant the
        # scheduling boundary at return from wait while the case is still open.
        now[0] = (
            narrowed_end + offset if boundary == "wait_return" else narrowed_end - 0.001
        )
        return status

    monkeypatch.setattr(gate0_framing, "monotonic", lambda: now[0])
    monkeypatch.setattr(gate0_runner_ssh, "monotonic", lambda: now[0])
    monkeypatch.setattr(owner._process, "wait", wait_then_cross)
    try:
        owner._half_close()
        with pytest.raises(ServiceRefused):
            owner._finish(0)
        assert owner._process.returncode == 0
        assert now[0] < original_end and checks
        assert owner.completion is None and owner.bundle is None
        assert owner.invocation_id is None
    finally:
        owner.close()
