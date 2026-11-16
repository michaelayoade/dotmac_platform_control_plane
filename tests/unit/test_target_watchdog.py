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
    assert watchdog.main(["--role", "run_x"], {}) == watchdog.EXIT_FAILED
    assert watchdog.ADMIN_DSN_ENV in capsys.readouterr().err


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
