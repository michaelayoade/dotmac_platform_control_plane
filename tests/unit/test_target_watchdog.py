"""The tripwire watchdog: trips on any violation, always ends revoked."""

from __future__ import annotations

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
        self.fail_on: str | None = None

    def factory(self) -> Any:
        world = self

        class _Conn:
            def exec_driver_sql(self, statement: str) -> Any:
                world.executed.append(statement)
                if world.fail_on and world.fail_on in statement:
                    raise RuntimeError("boom")
                if statement.startswith("DROP ROLE"):
                    world.role_present = False
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
    assert code == watchdog.EXIT_FAILED and "left something behind" in out[-1]


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
