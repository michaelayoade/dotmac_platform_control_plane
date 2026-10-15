"""Candidate systemd source mechanisms; these are not native qualification."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from vendor_cp.deployment import gate0_runner_bootstrap as owner
from vendor_cp.deployment.gate0_framing import canonical
from vendor_cp.deployment.gate0_role_custody import ProviderRefused


@pytest.fixture
def candidate():
    wall = datetime(2026, 10, 15, tzinfo=UTC)
    clock = owner.OriginalCutoff(
        wall, 1000.0, wall + timedelta(seconds=1), wall + timedelta(seconds=300)
    )
    base = Path(__file__).resolve().parents[2] / "deploy/gate0-a9"
    assets = tuple(
        owner.Pin(
            str(base / (name + ".in")),
            owner._digest((base / (name + ".in")).read_bytes()),
            (base / (name + ".in")).read_bytes(),
        )
        for name in owner._UNITS
    )
    job = {key: "test-value" for key in owner._JOB_FIELDS.values()}
    job["workflow_ref"] = (
        "dotmac-tech/gate0-issuer-execution/.github/workflows/gate0-issuer.yml@refs/heads/main"
    )
    collection = canonical(
        dict(
            job=job,
            broker=dict(
                origin="https://test.invalid",
                path="/token",
                query="x=a%2Fb",
                qualification={},
            ),
        )
    )
    pin = owner.Pin(
        "/opt/dotmac-gate0/bin/dotmac-platform",
        owner._digest(b"candidate"),
        b"candidate",
    )
    return owner.BootstrapInstallation(
        b"{}",
        owner._digest(b"campaign"),
        1001,
        1002,
        (1002, 1003),
        1003,
        pin,
        pin,
        replace(pin, path="/usr/bin/systemctl"),
        pin,
        b"{}",
        assets,
        collection,
        b"{}",
        b"{}",
        pin,
        "a" * 40,
        clock,
    )


def test_original_cutoff_never_moves_with_delayed_manager_start(candidate, monkeypatch):
    expected = 1_302_000_000
    assert candidate.clock.microseconds == expected
    first = candidate.render()[2]
    monkeypatch.setattr(owner.time, "monotonic", lambda: 1200.0)
    assert candidate.clock.microseconds == expected
    assert candidate.render()[2] == first
    assert b"OnBootSec=1302000000us" in first
    assert candidate.clock.cleanup_end(1301.0) == 1303.0
    assert candidate.clock.cleanup_end(1303.0) == 1304.0
    long_gap = replace(
        candidate.clock, b_end=candidate.clock.wall + timedelta(seconds=2000)
    )
    assert (
        long_gap.microseconds == 3_002_000_000
    )  # No invented900/600s campaign ceiling.


@pytest.mark.parametrize(
    "field,value",
    [
        ("monotonic", float("nan")),
        ("monotonic", -1.0),
        ("b_end", datetime(2026, 10, 14, tzinfo=UTC)),
        ("wall", datetime(2026, 10, 15)),
    ],
)
def test_original_clock_refuses_invalid_coordinates(candidate, field, value):
    with pytest.raises(ProviderRefused):
        replace(candidate.clock, **{field: value})


def test_fixed_assets_use_manager_owner_and_only_private_loadcredential(candidate):
    root, collector, timer, target = candidate.render()
    assert b"Type=exec" in collector and b"ExitType=main" in collector
    assert b"KillMode=control-group" in collector and b"KillSignal=SIGKILL" in collector
    assert b"FinalKillSignal=SIGKILL" in collector and b"Delegate=no" in collector
    assert b"Restart=no" in collector and b"RemainAfterExit=no" in collector
    assert (
        b"CapabilityBoundingSet=\n" in collector
        and b"AmbientCapabilities=\n" in collector
    )
    assert (
        b"LoadCredential=oidc-request-token:/run/dotmac-gate0-collector/oidc-request-token"
        in collector
    )
    assert b"Environment=ACTIONS_ID_TOKEN_REQUEST_TOKEN" not in collector
    assert (
        b"x=a%%2Fb" in collector
    )  # Native specifier escaping preserves exact broker bytes.
    assert b"@refs/heads/main" in collector
    assert b"StandardOutput=null" in collector and b"StandardError=null" in collector
    assert b"AccuracySec=1us" in timer and b"RandomizedDelaySec=0" in timer
    assert b"WakeSystem=no" in timer and b"OnUnitActiveSec" not in timer
    assert b"RuntimeMax" not in collector and b"ExecStop" not in collector
    assert b"dotmac-gate0-a9-bootstrap.service" in target
    assert b"dotmac-gate0-a9-collector.service" in target
    assert b"User=0" in root


@pytest.mark.parametrize(
    "arguments",
    [
        ("restart", owner._COLLECTOR),
        ("start", "--no-block", "foreign.service"),
        ("reset-failed", owner._COLLECTOR),
        ("set-property", owner._COLLECTOR, "RuntimeMaxUSec=99999999"),
        ("daemon-reexec",),
    ],
)
def test_no_arbitrary_manager_command_or_unit_surface(
    candidate, monkeypatch, arguments
):
    monkeypatch.setattr(owner.time, "monotonic", lambda: 1000.0)

    def forbidden(*args, **kwargs):
        raise AssertionError("foreign manager operation must not spawn")

    monkeypatch.setattr(owner.subprocess, "Popen", forbidden)
    with pytest.raises(ProviderRefused):
        owner.NativeSystemManager(candidate)._call(arguments, 1002.0)


@pytest.mark.parametrize(
    "change",
    [
        None,
        "invocation",
        "forced-kill",
        "failed",
        "populated",
        "late",
        "main-still-present",
    ],
)
def test_normal_retirement_requires_actual_closed_manager_observations(
    candidate, monkeypatch, change
):
    manager = owner.NativeSystemManager(candidate)
    manager.invocation = "a" * 32
    manager._events = 99
    values = dict(
        InvocationID="a" * 32,
        ActiveState="inactive",
        SubState="dead",
        MainPID="0",
        Result="success",
        ExecMainCode="1",
        ExecMainStatus="0",
        StateChangeTimestampMonotonic="1010000000",
        ControlGroup="/system.slice/" + owner._COLLECTOR,
    )
    monkeypatch.setattr(owner.time, "monotonic", lambda: 1010.0)
    monkeypatch.setattr(owner.os, "pread", lambda *args: b"populated 0\nfrozen 0\n")
    if change == "invocation":
        values["InvocationID"] = "b" * 32
    elif change == "forced-kill":
        values["ExecMainCode"] = "2"
        values["ExecMainStatus"] = "9"
    elif change == "failed":
        values["Result"] = "signal"
        values["ActiveState"] = "failed"
    elif change == "populated":
        monkeypatch.setattr(owner.os, "pread", lambda *args: b"populated 1\n")
    elif change == "late":
        monkeypatch.setattr(owner.time, "monotonic", lambda: 1012.0)
    elif change == "main-still-present":
        values["MainPID"] = "123"
    if change is None:
        assert manager.observe_fixed_empty(values, 1012.0) == "observed_populated_zero"
    else:
        with pytest.raises(ProviderRefused):
            manager.observe_fixed_empty(values, 1012.0)


def test_vanished_read_handle_alone_cannot_mean_empty(candidate, monkeypatch):
    manager = owner.NativeSystemManager(candidate)
    manager.invocation = "a" * 32
    values = dict(
        InvocationID="a" * 32,
        ActiveState="inactive",
        SubState="dead",
        MainPID="0",
        Result="success",
        ExecMainCode="1",
        ExecMainStatus="0",
        StateChangeTimestampMonotonic="1010000000",
        ControlGroup="/system.slice/" + owner._COLLECTOR,
    )
    monkeypatch.setattr(owner.time, "monotonic", lambda: 1010.0)

    def vanished(*args):
        raise OSError("synthetic vanished kernfs handle")

    monkeypatch.setattr(owner.os, "pread", vanished)
    with pytest.raises(ProviderRefused):
        manager.observe_fixed_empty(values, 1012.0)
    # A qualified, matching manager retirement result is explicitly distinct evidence.
    values["ControlGroup"] = ""
    assert (
        manager.observe_fixed_empty(values, 1012.0) == "manager_retired_control_group"
    )


def test_credential_adapter_never_uses_argv_unit_environment_or_diagnostics(
    monkeypatch, capsys
):
    import stat

    from vendor_cp.deployment import gate0_collection, gate0_runner_credential

    monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", raising=False)
    monkeypatch.setattr(gate0_runner_credential.os, "getuid", lambda: 1001)
    monkeypatch.setattr(gate0_runner_credential.os, "geteuid", lambda: 1001)
    opened = []
    monkeypatch.setattr(
        gate0_runner_credential.os,
        "open",
        lambda path, flags: opened.append(path) or 99,
    )
    token = b"synthetic-private-request-token"
    reads = iter((token, b""))
    monkeypatch.setattr(gate0_runner_credential.os, "read", lambda *args: next(reads))
    monkeypatch.setattr(
        gate0_runner_credential.os,
        "fstat",
        lambda *args: SimpleNamespace(
            st_mode=stat.S_IFREG | 0o400, st_uid=1001, st_size=len(token)
        ),
    )
    monkeypatch.setattr(gate0_runner_credential.os, "close", lambda *args: None)

    def existing_owner():
        assert (
            gate0_runner_credential.os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]
            == token.decode()
        )
        return 0

    monkeypatch.setattr(gate0_collection, "run_installed_collection", existing_owner)
    assert gate0_runner_credential.run_installed_credential_collection() == 0
    assert opened == [
        "/run/credentials/dotmac-gate0-a9-collector.service/oidc-request-token"
    ]
    assert "ACTIONS_ID_TOKEN_REQUEST_TOKEN" not in gate0_runner_credential.os.environ
    assert capsys.readouterr().out == "" and capsys.readouterr().err == ""


@pytest.mark.parametrize(
    "phase", ["start", "read", "bind", "promote", "normal-show", "normal-empty", None]
)
def test_one_start_budget_and_original_cutoff_propagate_through_orchestration(
    candidate, monkeypatch, phase
):
    """Synthetic transport timing traces, never actual manager/native acceptance."""
    now = [1000.0]
    calls = []
    published = []
    monkeypatch.setattr(owner.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(
        owner.BootstrapInstallation,
        "from_installed",
        classmethod(lambda cls: candidate),
    )
    monkeypatch.setattr(
        owner,
        "read_protected_handoff",
        lambda *args, **kwargs: b"synthetic-private-input",
    )
    monkeypatch.setattr(owner, "_exclusive", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        owner,
        "_publish_normal_observation",
        lambda raw, deadline: published.append((raw, deadline, now[0])),
    )

    class SyntheticManager:
        def __init__(self, installation):
            self.installation = installation
            self.invocation = None
            self.pid = None
            self.reads = 0

        def qualify(self):
            return b"{}"

        def arm_original_timer(self):
            return {}

        def start_fixed_collector(self, deadline):
            calls.append(("start", deadline))
            if phase == "start":
                now[0] = 1002.1

        def read_fixed_invocation(self, deadline):
            self.reads += 1
            calls.append(("show", deadline))
            if self.reads == 1:
                now[0] = 1002.1 if phase == "read" else 1001.9
                return dict(
                    ActiveState="active",
                    SubState="running",
                    InvocationID="a" * 32,
                    MainPID="123",
                )
            now[0] = 1302.1 if phase == "normal-show" else 1301.9
            return dict(
                ActiveState="inactive",
                SubState="dead",
                InvocationID="a" * 32,
                MainPID="0",
                StateChangeTimestampMonotonic="1302050000"
                if phase == "normal-show"
                else "1301800000",
            )

        def bind_actual_collector(self, values, deadline):
            calls.append(("bind", deadline))
            self.invocation = "a" * 32
            self.pid = 123
            if phase == "bind":
                now[0] = 1002.1

        def observe_fixed_empty(self, values, deadline):
            calls.append(("empty", deadline))
            if phase == "normal-empty":
                now[0] = 1302.1
            return "observed_populated_zero"

        def stop_fixed_collector(self, deadline):
            calls.append(("failure-stop", deadline))

        def close(self):
            pass

    def promote(manager, deadline):
        calls.append(("promote", deadline))
        if phase == "promote":
            now[0] = 1002.1
        return {"fixture": "same-inode"}

    monkeypatch.setattr(owner, "NativeSystemManager", SyntheticManager)
    monkeypatch.setattr(owner, "_promote_listener", promote)
    result = owner.run_installed_bootstrap()
    for name, deadline in calls:
        if name in ("start", "bind", "promote") or (name == "show" and deadline < 1302):
            assert deadline == 1002.0
        elif name == "empty" or (name == "show" and deadline >= 1302):
            assert deadline == 1302.0
    if phase is None:
        assert result == 0 and len(published) == 1
        assert published[0][1] == 1302.0 and published[0][2] < 1302.0
    else:
        assert result == 3 and published == []
        if phase in ("start", "read", "bind", "promote"):
            assert not any(name == "empty" for name, _ in calls)
        if phase == "bind":
            assert not any(name == "promote" for name, _ in calls)


def test_show_cannot_refresh_startup_budget_or_return_normal_after_original_d(
    candidate, monkeypatch
):
    manager = owner.NativeSystemManager(candidate)
    now = [1001.9]
    passed = []
    monkeypatch.setattr(owner.time, "monotonic", lambda: now[0])

    def slow_show(unit, properties, deadline):
        passed.append(deadline)
        now[0] = deadline + 0.1
        return {"ActiveState": "inactive"}

    monkeypatch.setattr(manager, "_show", slow_show)
    with pytest.raises(ProviderRefused):
        manager.read_fixed_invocation(1002.0)
    assert passed == [1002.0]
    now[0] = 1301.9
    with pytest.raises(ProviderRefused):
        manager.read_fixed_invocation(1304.0)
    assert passed == [
        1002.0,
        1302.0,
    ]  # Failure cleanup tail never becomes normal polling.


@pytest.mark.parametrize(
    "state_at,read_at,read_end", [(1302.05, 1302.1, 1302.1), (1301.8, 1301.9, 1302.1)]
)
def test_manager_empty_read_must_finish_before_original_d(
    candidate, monkeypatch, state_at, read_at, read_end
):
    manager = owner.NativeSystemManager(candidate)
    manager.invocation = "a" * 32
    manager._events = 99
    now = [read_at]
    monkeypatch.setattr(owner.time, "monotonic", lambda: now[0])

    def slow_pread(*args):
        now[0] = read_end
        return b"populated 0\n"

    monkeypatch.setattr(owner.os, "pread", slow_pread)
    values = dict(
        InvocationID="a" * 32,
        ActiveState="inactive",
        SubState="dead",
        MainPID="0",
        Result="success",
        ExecMainCode="1",
        ExecMainStatus="0",
        StateChangeTimestampMonotonic=str(int(state_at * 1_000_000)),
        ControlGroup="",
    )
    with pytest.raises(ProviderRefused):
        manager.observe_fixed_empty(values, 1304.0)


def test_receiver_publication_cannot_finish_after_fixed_start_budget(
    candidate, monkeypatch
):
    now = [1001.9]
    monkeypatch.setattr(owner.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(owner, "_exclusive", lambda *args, **kwargs: None)
    monkeypatch.setattr(owner, "_directory", lambda *args, **kwargs: 77)
    monkeypatch.setattr(owner.os, "open", lambda *args, **kwargs: 88)
    monkeypatch.setattr(owner.os, "fchown", lambda *args, **kwargs: None)
    monkeypatch.setattr(owner.os, "fchmod", lambda *args, **kwargs: None)
    monkeypatch.setattr(owner.os, "close", lambda *args, **kwargs: None)

    def delayed_fsync(*args):
        now[0] = 1002.1

    monkeypatch.setattr(owner.os, "fsync", delayed_fsync)

    def forbidden_link(*args, **kwargs):
        raise AssertionError("late receiver must not publish")

    monkeypatch.setattr(owner.os, "link", forbidden_link)
    with pytest.raises(ProviderRefused):
        owner._publish_receiver(b"{}", candidate.socket_gid, 1002.0)


def test_late_normal_publish_keeps_candidate_and_removes_only_owned_link(
    candidate, monkeypatch
):
    now = [1301.9]
    removed = []
    monkeypatch.setattr(owner.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(owner, "_exclusive", lambda *args, **kwargs: None)
    monkeypatch.setattr(owner, "_directory", lambda *args, **kwargs: 77)
    monkeypatch.setattr(
        owner.os, "stat", lambda *args, **kwargs: SimpleNamespace(st_dev=1, st_ino=2)
    )
    monkeypatch.setattr(owner.os, "close", lambda *args, **kwargs: None)
    monkeypatch.setattr(owner.os, "fsync", lambda *args, **kwargs: None)
    monkeypatch.setattr(owner.os, "unlink", lambda path, **kwargs: removed.append(path))

    def late_link(*args, **kwargs):
        now[0] = 1302.1

    monkeypatch.setattr(owner.os, "link", late_link)
    with pytest.raises(ProviderRefused):
        owner._publish_normal_observation(b"candidate", 1302.0)
    assert removed == ["bootstrap-observation.json"]
    assert "bootstrap-observation.pending" not in removed


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "poll",
        "kill",
        "wait",
        "stdin-close",
        "stdout-close",
        "stderr-close",
        "zero-budget-wait",
        "already-reaped",
    ],
)
def test_manager_cleanup_attempts_every_owned_stream_and_wait_with_sticky_failure(
    candidate, monkeypatch, fault
):
    events = []
    now = 1002.0 if fault == "zero-budget-wait" else 1001.95
    monkeypatch.setattr(owner.time, "monotonic", lambda: now)

    class Stream:
        def __init__(self, name):
            self.name = name

        def close(self):
            events.append(self.name + "-close")
            if fault == self.name + "-close":
                raise OSError("synthetic close failure")

    class Process:
        returncode = 0 if fault == "already-reaped" else None
        stdin, stdout, stderr = (Stream(name) for name in ("stdin", "stdout", "stderr"))

        def poll(self):
            events.append("poll")
            if fault == "poll":
                raise OSError("synthetic unknown child state")
            return self.returncode

        def kill(self):
            events.append("kill")
            if fault == "kill":
                raise OSError("synthetic kill failure")

        def wait(self, timeout):
            events.append(("wait", timeout))
            if fault in ("wait", "zero-budget-wait"):
                raise owner.subprocess.TimeoutExpired("synthetic-systemctl", timeout)
            self.returncode = 0
            return 0

    process = Process()
    if fault in (None, "already-reaped"):
        owner._cleanup_manager_request(process, 1002.0)
    else:
        with pytest.raises(ProviderRefused):
            owner._cleanup_manager_request(process, 1002.0)
    assert events[-3:] == ["stdin-close", "stdout-close", "stderr-close"]
    waits = [event for event in events if isinstance(event, tuple)]
    assert len(waits) == 1 and waits[0][1] == pytest.approx(max(0, 1002.0 - now))
    if fault in ("already-reaped", "poll"):
        assert "kill" not in events  # Never signal a reaped or unknown/reusable PID.


@pytest.mark.parametrize(
    "shared_deadline,expected_end", [(1302.0, 1002.0), (1000.4, 1000.4)]
)
def test_manager_request_two_second_cap_intersects_shared_absolute_deadline(
    candidate, monkeypatch, shared_deadline, expected_end
):
    import select

    waits = []
    selected = []
    closed = []
    monkeypatch.setattr(owner.time, "monotonic", lambda: 1000.0)

    class Stream:
        def fileno(self):
            return 99

        def close(self):
            closed.append("stdout")

    class Process:
        stdin = stderr = None
        stdout = Stream()
        returncode = None

        def wait(self, timeout):
            waits.append(timeout)
            self.returncode = 0
            return 0

        def poll(self):
            raise AssertionError("already reaped child must not be polled/signaled")

        def kill(self):
            raise AssertionError("already reaped child must not be signaled")

    monkeypatch.setattr(owner.subprocess, "Popen", lambda *args, **kwargs: Process())
    monkeypatch.setattr(owner.os, "set_blocking", lambda *args: None)
    monkeypatch.setattr(owner.os, "read", lambda *args: b"")

    def ready(reads, writes, errors, timeout):
        selected.append(timeout)
        return reads, [], []

    monkeypatch.setattr(select, "select", ready)
    assert (
        owner.NativeSystemManager(candidate)._call(
            ("show", "--all", "--property=Version"), shared_deadline
        )
        == b""
    )
    assert selected == [
        pytest.approx(expected_end - owner._CLIENT_CLEANUP_RESERVE - 1000.0)
    ]
    assert waits == [
        pytest.approx(expected_end - owner._CLIENT_CLEANUP_RESERVE - 1000.0),
        pytest.approx(expected_end - 1000.0),
    ]
    assert closed == ["stdout"]


def test_transport_cleanup_failure_cannot_become_successful_output(
    candidate, monkeypatch
):
    import select

    events = []
    monkeypatch.setattr(owner.time, "monotonic", lambda: 1000.0)

    class Stream:
        def fileno(self):
            return 99

        def close(self):
            events.append("close")
            raise OSError("synthetic close failure after successful request")

    class Process:
        stdin = stderr = None
        stdout = Stream()
        returncode = None

        def wait(self, timeout):
            events.append("wait")
            self.returncode = 0
            return 0

        def poll(self):
            raise AssertionError("already reaped")

        def kill(self):
            raise AssertionError("already reaped")

    monkeypatch.setattr(owner.subprocess, "Popen", lambda *args, **kwargs: Process())
    monkeypatch.setattr(owner.os, "set_blocking", lambda *args: None)
    monkeypatch.setattr(owner.os, "read", lambda *args: b"")
    monkeypatch.setattr(select, "select", lambda reads, *args: (reads, [], []))
    with pytest.raises(ProviderRefused):
        owner.NativeSystemManager(candidate)._call(
            ("show", "--all", "--property=Version"), 1302.0
        )
    assert events == ["wait", "wait", "close"]


@pytest.mark.parametrize(
    "fault", ["close-error", "close-late", "foreign-inode", "preexisting-conflict"]
)
def test_normal_publication_close_and_final_check_share_owned_rollback_path(
    candidate, monkeypatch, fault
):
    now = [1301.95]
    directories = []
    closes = []
    removed = []
    stats = []
    monkeypatch.setattr(owner.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(owner, "_exclusive", lambda *args, **kwargs: None)

    def directory(*args, **kwargs):
        directories.append(kwargs.get("deadline"))
        return 77 if len(directories) == 1 else 88

    monkeypatch.setattr(owner, "_directory", directory)

    def measured(path, **kwargs):
        stats.append(path)
        return SimpleNamespace(
            st_dev=9 if fault == "foreign-inode" and len(stats) > 1 else 1, st_ino=2
        )

    monkeypatch.setattr(owner.os, "stat", measured)

    def linked(*args, **kwargs):
        if fault == "preexisting-conflict":
            raise FileExistsError("synthetic existing receipt")

    monkeypatch.setattr(owner.os, "link", linked)
    monkeypatch.setattr(owner.os, "fsync", lambda *args: None)
    monkeypatch.setattr(owner.os, "unlink", lambda path, **kwargs: removed.append(path))

    def close(descriptor):
        closes.append(descriptor)
        if descriptor == 77:
            if fault in ("close-error", "foreign-inode"):
                raise OSError("synthetic uncertain close")
            if fault == "close-late":
                now[0] = 1302.05

    monkeypatch.setattr(owner.os, "close", close)
    with pytest.raises(ProviderRefused):
        owner._publish_normal_observation(b"candidate", 1302.0)
    if fault in ("close-error", "close-late"):
        assert removed == ["bootstrap-observation.json"]
        assert closes == [77, 88]
        assert len(directories) == 2 and directories[1] <= 1304.0
    elif fault == "foreign-inode":
        assert removed == [] and closes == [77, 88]
    else:
        assert removed == [] and closes == [77] and len(directories) == 1
    assert "bootstrap-observation.pending" not in removed
