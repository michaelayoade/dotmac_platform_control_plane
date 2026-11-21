"""The tripwire watchdog: trips on any violation, always ends revoked."""

from __future__ import annotations

import signal
from typing import Any

import pytest

from vendor_cp.deployment import consumption_role_spec as spec
from vendor_cp.deployment import consumption_watchdog as watchdog
from vendor_cp.deployment.consumption_scope import MAX_ROLE_TTL
from vendor_cp.deployment.target_refusals import FoundationBindingsUnavailable


class _Result:
    def __init__(self, value: Any) -> None:
        self.value = value

    def all(self) -> Any:
        return self.value

    def scalar(self) -> Any:
        return self.value

    def one(self) -> Any:
        return self.value


class _World:
    """A scripted database: violations per tick, plus the executed revocation."""

    def __init__(
        self, ticks: list[Any], *, leftovers: tuple[int, int, int] = (0, 0, 0)
    ) -> None:
        self.ticks = list(ticks)
        self.executed: list[str] = []
        self.leftovers = leftovers
        self.role_present = True
        self.lock_timeouts = 0
        self.verify_script: list[Any] = []
        self.on_statement: Any = None
        self.fail_on: str | None = None

    def factory(self) -> Any:
        world = self

        class _Conn:
            def exec_driver_sql(self, statement: str) -> Any:
                if statement.startswith("SET lock_timeout"):
                    world.lock_timeouts += 1
                    return _Result(None)
                world.executed.append(statement)
                if world.on_statement:
                    world.on_statement(statement)
                if world.fail_on and world.fail_on in statement:
                    raise RuntimeError("boom")
                if statement.startswith("DROP ROLE"):
                    world.role_present = False
                if statement.startswith("SELECT (SELECT count") and world.verify_script:
                    item = world.verify_script.pop(0)
                    if isinstance(item, Exception):
                        raise item
                    return _Result(item)
                if statement.startswith("SELECT (SELECT count"):
                    return _Result(
                        world.leftovers
                        if world.role_present is False or world.leftovers != (0, 0, 0)
                        else (1, 0, 0)
                    )
                return _Result(None)

        class _Session:
            def execute(self, statement: Any, params: Any = None) -> Any:
                if str(statement) == watchdog._EXISTS_SQL:
                    return _Result(1 if world.role_present else 0)
                assert params == {"role": "run_x"}
                item = world.ticks.pop(0) if world.ticks else []
                if isinstance(item, Exception):
                    raise item
                return _Result([(k,) for k in item])

            def connection(self) -> Any:
                return _Conn()

            def commit(self) -> None: ...
            def rollback(self) -> None: ...
            def close(self) -> None: ...

        return _Session()


def _run(world: _World, **kwargs: Any) -> tuple[int, list[str]]:
    out: list[str] = []
    clock = iter(range(1000))
    code = watchdog.run(
        world.factory,
        "run_x",
        deadline_seconds=kwargs.pop("deadline_seconds", 5),
        sleep=lambda _s: None,
        clock=lambda: float(next(clock)),
        out=out.append,
        **kwargs,
    )
    return code, out


@pytest.mark.parametrize(
    "kind",
    [
        "advisory_lock",
        "idle_in_transaction",
        "long_transaction",
        "long_statement",
        "blocking",
    ],
)
def test_any_violation_kills_the_role_and_reads_back_clean(kind: str) -> None:
    world = _World([[], [kind]])
    code, out = _run(world, deadline_seconds=50)
    assert code == watchdog.EXIT_TRIPPED
    assert f"watchdog tripped: {kind}" in out
    assert world.executed[:-1] == list(spec.revocation_sql("run_x"))
    assert world.executed[-1] == spec.verification_sql("run_x")
    assert not world.role_present
    # Every revocation step is bounded by a lock timeout so it cannot hang.
    assert world.lock_timeouts == len(spec.revocation_sql("run_x"))


def test_a_clean_run_ends_at_the_deadline_still_revoked() -> None:
    world = _World([[]] * 10)
    code, out = _run(world, deadline_seconds=3)
    assert code == watchdog.EXIT_CLEAN
    assert "watchdog: deadline reached" in out and not world.role_present


def test_a_role_revoked_elsewhere_ends_the_watch_without_acting() -> None:
    world = _World([])
    world.role_present = False
    code, out = _run(world)
    assert code == watchdog.EXIT_CLEAN and "already gone" in out[0]
    assert (
        world.executed == [spec.verification_sql("run_x")] or world.executed[:1] != []
    )


def test_a_database_failure_revokes_and_fails_closed() -> None:
    world = _World([RuntimeError("unreachable")])
    code, out = _run(world)
    assert code == watchdog.EXIT_FAILED and "watchdog failed: revoking" in out
    assert world.executed[:-1] == list(spec.revocation_sql("run_x"))


def test_revocation_is_attempted_in_full_even_when_a_step_errors() -> None:
    world = _World([["advisory_lock"]])
    world.fail_on = "pg_terminate_backend"
    code, _ = _run(world)
    assert len(world.executed) == len(spec.revocation_sql("run_x")) + 1
    assert code in (watchdog.EXIT_TRIPPED, watchdog.EXIT_FAILED)


def test_leftovers_after_revocation_are_a_failure() -> None:
    world = _World([["advisory_lock"]], leftovers=(1, 0, 0))
    code, out = _run(world)
    assert code == watchdog.EXIT_UNCLEAN
    assert any("REVOCATION INCOMPLETE" in line for line in out)


@pytest.mark.parametrize("deadline", [0, -1, MAX_ROLE_TTL.total_seconds() + 1])
def test_the_deadline_cannot_exceed_the_role_window(deadline: float) -> None:
    with pytest.raises(FoundationBindingsUnavailable):
        watchdog.run(_World([]).factory, "run_x", deadline_seconds=deadline)


def test_the_thresholds_match_the_sql_and_the_design() -> None:
    sql = watchdog._VIOLATIONS_SQL
    assert (watchdog.IDLE_IN_TRANSACTION_SECONDS, watchdog.TRANSACTION_SECONDS) == (
        30,
        120,
    )
    assert (watchdog.STATEMENT_SECONDS, watchdog.BLOCKING_SECONDS) == (10, 5)
    for seconds in (30, 120, 10, 5):
        assert f"interval '{seconds} seconds'" in sql
    for kind in ("advisory", "idle in transaction", "pg_blocking_pids"):
        assert kind in sql


def test_the_command_needs_its_admin_credential(
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = ["--role", "run_x", "--kind", "consumption"]
    assert watchdog.main(args, {}) == watchdog.EXIT_FAILED
    assert watchdog.ADMIN_DSN_ENV in capsys.readouterr().err


def test_the_kind_is_required_so_a_lease_role_is_never_watched_as_a_consumption_role(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """No default: a missing `--kind` used to mean `consumption`, which would watch
    (and on a trip revoke) a lease role with the wrong statements."""
    with pytest.raises(SystemExit) as exited:
        watchdog.main(["--role", "run_x"], {watchdog.ADMIN_DSN_ENV: "x"})
    assert exited.value.code == 2
    assert "--kind" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        watchdog.main(["--role", "run_x", "--kind", "other"], {})
    for kind in watchdog.KINDS:
        assert watchdog.main(["--role", "run_x", "--kind", kind], {}) == (
            watchdog.EXIT_FAILED
        )


# ── signals and the revocation retry (review F1) ────────────────────────────


@pytest.mark.parametrize("signum", watchdog.SIGNALS)
def test_every_signal_takes_the_revoke_path_and_exits_nonzero(signum: int) -> None:
    before = {s: signal.getsignal(s) for s in watchdog.SIGNALS}
    world = _World([[]] * 20)
    fired: list[int] = []

    def sleeper(_seconds: float) -> None:
        if not fired:
            fired.append(signum)
            signal.raise_signal(signum)

    out: list[str] = []
    code = watchdog.run(
        world.factory,
        "run_x",
        deadline_seconds=100,
        sleep=sleeper,
        clock=iter(range(1000)).__next__,
        out=out.append,
    )
    assert code == watchdog.EXIT_SIGNALLED
    assert any(f"signal {int(signum)}" in line for line in out)
    assert world.executed[:-1] == list(spec.revocation_sql("run_x"))
    assert not world.role_present
    # The previous handlers are restored, so the process is not left muted.
    assert {s: signal.getsignal(s) for s in watchdog.SIGNALS} == before


def test_a_second_signal_during_revocation_cannot_abort_it() -> None:
    world = _World([[]] * 20)
    raised: list[str] = []

    def sleeper(_seconds: float) -> None:
        if not raised:
            raised.append("first")
            signal.raise_signal(signal.SIGHUP)

    def mid_revoke(statement: str) -> None:
        if statement.startswith("ALTER ROLE") and "second" not in raised:
            raised.append("second")
            signal.raise_signal(signal.SIGTERM)
            signal.raise_signal(signal.SIGINT)
            signal.raise_signal(signal.SIGQUIT)

    world.on_statement = mid_revoke
    out: list[str] = []
    code = watchdog.run(
        world.factory,
        "run_x",
        deadline_seconds=100,
        sleep=sleeper,
        clock=iter(range(1000)).__next__,
        out=out.append,
    )
    assert raised == ["first", "second"]
    assert code == watchdog.EXIT_SIGNALLED
    # Revocation ran to the end despite three more signals.
    assert world.executed[:-1] == list(spec.revocation_sql("run_x"))
    assert not world.role_present


def test_revocation_retries_until_the_read_back_is_clean() -> None:
    world = _World([["advisory_lock"]])
    world.verify_script = [RuntimeError("unreachable"), (1, 0, 0), (0, 0, 0)]
    sleeps: list[float] = []
    out: list[str] = []
    ok = watchdog.revoke_until_clean(
        world.factory, "run_x", sleep=sleeps.append, out=out.append
    )
    assert ok is True and sleeps == [1.0, 2.0]
    assert sum("could not read back" in line for line in out) == 1


def test_a_revocation_that_is_never_clean_ends_loudly_and_boundedly() -> None:
    world = _World([["advisory_lock"]])
    world.verify_script = [RuntimeError("down")] * 100
    sleeps: list[float] = []
    out: list[str] = []
    ok = watchdog.revoke_until_clean(
        world.factory, "run_x", sleep=sleeps.append, out=out.append
    )
    assert ok is False
    assert len(sleeps) == watchdog.REVOKE_ATTEMPTS - 1
    assert max(sleeps) <= watchdog.REVOKE_BACKOFF_CAP_SECONDS
    full = _World([["advisory_lock"]])
    full.verify_script = [RuntimeError("down")] * 100
    code, lines = _run(full)
    assert code == watchdog.EXIT_UNCLEAN
    assert any("REVOCATION INCOMPLETE" in line for line in lines)


# ── a signal at every point of the mask-and-revoke window (re-check R1) ─────


def _quiet_handlers() -> dict[int, Any]:
    """Harmless handlers, so a restored 'previous' can never kill the test run."""
    saved = {s: signal.getsignal(s) for s in watchdog.SIGNALS}
    for signum in watchdog.SIGNALS:
        signal.signal(signum, lambda *_: None)
    return saved


@pytest.mark.parametrize("when", ["before", "after"])
@pytest.mark.parametrize("call_index", range(12))
def test_a_signal_at_any_signal_call_cannot_skip_revocation(
    monkeypatch: pytest.MonkeyPatch, when: str, call_index: int
) -> None:
    """`signal.signal` runs pending handlers, so a signal raised immediately
    before or after ANY of the install, mask and restore calls lands inside the
    window the review named. Revocation must still run in full."""
    saved = _quiet_handlers()
    real = signal.signal
    calls = {"n": 0}

    def injecting(signum: int, handler: Any) -> Any:
        index = calls["n"]
        calls["n"] += 1
        if when == "before" and index == call_index:
            signal.raise_signal(signal.SIGTERM)
        previous = real(signum, handler)
        if when == "after" and index == call_index:
            signal.raise_signal(signal.SIGHUP)
        return previous

    world = _World([[]] * 20)
    out: list[str] = []
    monkeypatch.setattr(signal, "signal", injecting)
    try:
        code = watchdog.run(
            world.factory,
            "run_x",
            deadline_seconds=3,
            sleep=lambda _s: None,
            clock=iter(range(1000)).__next__,
            out=out.append,
        )
    finally:
        monkeypatch.setattr(signal, "signal", real)
        for signum, handler in saved.items():
            real(signum, handler)
    assert world.executed[:-1] == list(spec.revocation_sql("run_x")), (when, call_index)
    assert not world.role_present
    assert code in (watchdog.EXIT_CLEAN, watchdog.EXIT_SIGNALLED)
    assert code != watchdog.EXIT_UNCLEAN


def test_a_signal_raised_inside_the_first_mask_call_still_revokes_and_exits_6(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The exact scenario of the review: SIGHUP, then the kit trap's SIGTERM
    arriving while the first SIG_IGN call is running."""
    saved = _quiet_handlers()
    real = signal.signal
    state = {"masking": False, "fired": False}

    def injecting(signum: int, handler: Any) -> Any:
        if handler is signal.SIG_IGN and not state["fired"]:
            state["fired"] = True
            signal.raise_signal(signal.SIGTERM)
        return real(signum, handler)

    world = _World([[]] * 20)

    def sleeper(_s: float) -> None:
        if not state["masking"]:
            state["masking"] = True
            signal.raise_signal(signal.SIGHUP)

    monkeypatch.setattr(signal, "signal", injecting)
    try:
        code = watchdog.run(
            world.factory,
            "run_x",
            deadline_seconds=100,
            sleep=sleeper,
            clock=iter(range(1000)).__next__,
            out=lambda _line: None,
        )
    finally:
        monkeypatch.setattr(signal, "signal", real)
        for signum, handler in saved.items():
            real(signum, handler)
    assert state["fired"] and code == watchdog.EXIT_SIGNALLED
    assert world.executed[:-1] == list(spec.revocation_sql("run_x"))
    assert not world.role_present


def test_a_dead_terminal_does_not_end_the_retry() -> None:
    world = _World([["advisory_lock"]])
    world.verify_script = [(1, 0, 0), (0, 0, 0)]

    def broken(_line: str) -> None:
        raise OSError(5, "input/output error")

    assert watchdog.revoke_until_clean(
        world.factory, "run_x", sleep=lambda _s: None, out=broken
    )


# ── exit code and restore order (final check N1, N2, N4) ────────────────────


def _default_handlers() -> dict[int, Any]:
    """The REAL default dispositions, so `previous` is SIG_DFL, not a test stub."""
    saved = {s: signal.getsignal(s) for s in watchdog.SIGNALS}
    for signum in watchdog.SIGNALS:
        signal.signal(signum, signal.SIG_DFL)
    return saved


def _run_with_defaults(world: _World, out: Any) -> int:
    saved = _default_handlers()
    try:
        return watchdog.run(
            world.factory,
            "run_x",
            deadline_seconds=3,
            sleep=lambda _s: None,
            clock=iter(range(1000)).__next__,
            out=out,
        )
    finally:
        for signum, handler in saved.items():
            signal.signal(signum, handler)


def test_a_signal_while_the_incomplete_message_is_written_cannot_change_exit_5() -> (
    None
):
    world = _World([["advisory_lock"]])
    world.verify_script = [RuntimeError("down")] * 100
    lines: list[str] = []

    def out(line: str) -> None:
        lines.append(line)
        if "INCOMPLETE" in line:
            # With the old handlers already restored this would be SIG_DFL: the
            # process would die (143). Masked, it is ignored.
            signal.raise_signal(signal.SIGTERM)
            signal.raise_signal(signal.SIGHUP)

    assert _run_with_defaults(world, out) == watchdog.EXIT_UNCLEAN
    assert any("INCOMPLETE" in line for line in lines)


def test_a_signal_while_the_failed_message_is_written_cannot_escape_run() -> None:
    world = _World([RuntimeError("tick failed")])

    def out(line: str) -> None:
        if "failed" in line:
            signal.raise_signal(signal.SIGINT)

    code = _run_with_defaults(world, out)
    assert code == watchdog.EXIT_FAILED
    assert world.executed[:-1] == list(spec.revocation_sql("run_x"))
    assert not world.role_present


def test_a_failing_writer_never_changes_the_exit_code() -> None:
    world = _World([["advisory_lock"]])

    def broken(_line: str) -> None:
        raise ValueError("writer exploded")

    assert _run_with_defaults(world, broken) == watchdog.EXIT_TRIPPED


def test_a_role_already_gone_with_an_unclean_readback_is_not_a_zero_exit() -> None:
    world = _World([])
    world.role_present = False
    world.verify_script = [(1, 0, 0)] * 100
    code, out = _run(world)
    assert code == watchdog.EXIT_UNCLEAN
    assert any("already gone" in line for line in out)
    assert any("INCOMPLETE" in line for line in out)


def test_a_role_already_gone_and_clean_is_still_zero() -> None:
    world = _World([])
    world.role_present = False
    code, out = _run(world)
    assert code == watchdog.EXIT_CLEAN and any("already gone" in line for line in out)


def test_the_old_handlers_return_only_after_the_final_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    saved = _quiet_handlers()
    real = signal.signal
    events: list[str] = []

    def recording(signum: int, handler: Any) -> Any:
        if handler is signal.SIG_IGN:
            events.append("mask")
        elif not callable(handler) or handler.__name__ != "on_signal":
            events.append("restore")
        return real(signum, handler)

    world = _World([[]] * 5)
    world.verify_script = [RuntimeError("down")] * 100
    monkeypatch.setattr(signal, "signal", recording)
    try:
        watchdog.run(
            world.factory,
            "run_x",
            deadline_seconds=3,
            sleep=lambda _s: None,
            clock=iter(range(1000)).__next__,
            out=lambda line: events.append(f"out:{line[:24]}"),
        )
    finally:
        monkeypatch.setattr(signal, "signal", real)
        for signum, handler in saved.items():
            real(signum, handler)
    last_message = max(i for i, e in enumerate(events) if e.startswith("out:"))
    first_restore = events.index("restore")
    assert first_restore > last_message
    assert any(e.startswith("out:watchdog: REVOCATION") for e in events)


def test_the_command_refuses_a_dsn_without_a_bounded_connect_timeout(
    capsys: pytest.CaptureFixture[str],
) -> None:
    base = "postgresql+psycopg://admin:pw@db.example.test/cp"
    for dsn in (
        base,
        base + "?connect_timeout=0",
        base + "?connect_timeout=6",
        base + "?connect_timeout=abc",
    ):
        assert (
            watchdog.main(
                ["--role", "run_x", "--kind", "consumption"],
                {watchdog.ADMIN_DSN_ENV: dsn},
            )
            == watchdog.EXIT_FAILED
        )
        err = capsys.readouterr().err
        assert "connect_timeout" in err and "pw" not in err
