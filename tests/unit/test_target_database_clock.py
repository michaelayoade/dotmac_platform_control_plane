"""CP database time as the freshness clock, and the skew check."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from vendor_cp.deployment import database_clock as clock_module
from vendor_cp.deployment.database_clock import (
    DEFAULT_SKEW_LIMIT,
    MAX_SKEW_LIMIT,
    SKEW_LIMIT_ENV,
    DatabaseClock,
    measure_clock_skew,
    parse_skew_limit,
    require_clock_skew_within,
)
from vendor_cp.deployment.target_refusals import (
    FoundationBindingsUnavailable,
    TargetRefusal,
)

_DB_NOW = datetime(2026, 11, 14, 12, 0, 0, tzinfo=UTC)


class _Session:
    def __init__(self, value: Any, *, fail: bool = False) -> None:
        self.value, self.fail = value, fail
        self.statements: list[str] = []
        self.rolled_back = self.closed = False

    def execute(self, statement: Any) -> Any:
        self.statements.append(str(statement))
        if self.fail:
            raise RuntimeError("SECRET-MARKER")
        outer = self

        class _R:
            def scalar(self) -> Any:
                return outer.value

        return _R()

    def rollback(self) -> None:
        self.rolled_back = True

    def close(self) -> None:
        self.closed = True


def test_database_clock_reads_database_wall_clock_time_not_the_local_clock() -> None:
    session = _Session(_DB_NOW)
    clock = DatabaseClock(lambda: session)  # type: ignore[arg-type,return-value]
    observed = clock.now()
    assert observed == _DB_NOW and observed.tzinfo is UTC
    # The server's wall clock, not transaction start time, and nothing local.
    assert session.statements == ["SELECT clock_timestamp()"]
    assert session.rolled_back and session.closed
    assert clock() == _DB_NOW


def test_database_time_is_normalised_to_utc() -> None:
    plus_one = datetime(2026, 11, 14, 13, 0, 0, tzinfo=timezone_plus_one())
    assert DatabaseClock(lambda: _Session(plus_one)).now() == _DB_NOW  # type: ignore[arg-type,return-value]


def timezone_plus_one():  # noqa: ANN201
    from datetime import timezone

    return timezone(timedelta(hours=1))


def test_database_failure_refuses_and_never_falls_back_to_the_local_clock() -> None:
    session = _Session(None, fail=True)
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        DatabaseClock(lambda: session).now()  # type: ignore[arg-type,return-value]
    assert caught.value.code is TargetRefusal.CLOCK_UNAVAILABLE
    assert caught.value.__cause__ is None
    assert "SECRET-MARKER" not in str(caught.value)
    assert session.rolled_back and session.closed


def test_session_factory_failure_refuses() -> None:
    def boom() -> Any:
        raise RuntimeError("SECRET-MARKER")

    with pytest.raises(FoundationBindingsUnavailable) as caught:
        DatabaseClock(boom).now()
    assert caught.value.code is TargetRefusal.CLOCK_UNAVAILABLE


@pytest.mark.parametrize("value", [None, "2026-11-14", datetime(2026, 11, 14)])
def test_a_non_instant_or_naive_answer_refuses(value: object) -> None:
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        DatabaseClock(lambda: _Session(value)).now()  # type: ignore[arg-type,return-value]
    assert caught.value.code is TargetRefusal.CLOCK_UNAVAILABLE


# ── skew ────────────────────────────────────────────────────────────────────


def _local(*instants: datetime):  # noqa: ANN202
    iterator = iter(instants)
    return lambda: next(iterator)


def test_skew_is_local_midpoint_minus_database_time() -> None:
    local = _local(_DB_NOW + timedelta(seconds=2), _DB_NOW + timedelta(seconds=4))
    skew, round_trip = measure_clock_skew(lambda: _DB_NOW, local_now=local)
    assert skew == timedelta(seconds=3) and round_trip == timedelta(seconds=2)


def test_a_host_within_the_limit_passes_in_both_directions() -> None:
    for offset in (-3, 0, 3):
        local = _local(
            _DB_NOW + timedelta(seconds=offset), _DB_NOW + timedelta(seconds=offset)
        )
        skew = require_clock_skew_within(lambda: _DB_NOW, local_now=local)
        assert skew == timedelta(seconds=offset)


@pytest.mark.parametrize("offset", [-30, -6, 6, 3600])
def test_a_host_beyond_the_limit_refuses_ahead_or_behind(offset: int) -> None:
    local = _local(
        _DB_NOW + timedelta(seconds=offset), _DB_NOW + timedelta(seconds=offset)
    )
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        require_clock_skew_within(lambda: _DB_NOW, local_now=local)
    assert caught.value.code is TargetRefusal.CLOCK_SKEW_EXCEEDED


def test_the_default_limit_boundary_is_inclusive_of_the_limit_only() -> None:
    at_limit = _local(_DB_NOW + DEFAULT_SKEW_LIMIT, _DB_NOW + DEFAULT_SKEW_LIMIT)
    require_clock_skew_within(lambda: _DB_NOW, local_now=at_limit)
    over = _local(
        _DB_NOW + DEFAULT_SKEW_LIMIT + timedelta(milliseconds=1),
        _DB_NOW + DEFAULT_SKEW_LIMIT + timedelta(milliseconds=1),
    )
    with pytest.raises(FoundationBindingsUnavailable):
        require_clock_skew_within(lambda: _DB_NOW, local_now=over)


def test_a_slow_answer_counts_its_round_trip_against_the_limit() -> None:
    # Zero apparent skew, but a 8 s bracket: the true skew could be +-4 s of the
    # midpoint, plus the 4 s uncertainty is under 5 s only if |skew| is ~0, so
    # a 12 s bracket cannot be trusted.
    local = _local(_DB_NOW - timedelta(seconds=6), _DB_NOW + timedelta(seconds=6))
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        require_clock_skew_within(lambda: _DB_NOW, local_now=local)
    assert caught.value.code is TargetRefusal.CLOCK_SKEW_EXCEEDED


def test_a_backwards_local_clock_during_the_bracket_refuses() -> None:
    local = _local(_DB_NOW + timedelta(seconds=1), _DB_NOW)
    with pytest.raises(FoundationBindingsUnavailable):
        require_clock_skew_within(lambda: _DB_NOW, local_now=local)


def test_database_unavailability_propagates_as_its_own_refusal() -> None:
    def unavailable() -> datetime:
        raise FoundationBindingsUnavailable("x", code=TargetRefusal.CLOCK_UNAVAILABLE)

    with pytest.raises(FoundationBindingsUnavailable) as caught:
        require_clock_skew_within(unavailable)
    assert caught.value.code is TargetRefusal.CLOCK_UNAVAILABLE


# ── limit configuration ─────────────────────────────────────────────────────


def test_limit_defaults_when_unset_and_is_conservative() -> None:
    assert parse_skew_limit(None) == parse_skew_limit("  ") == DEFAULT_SKEW_LIMIT
    assert DEFAULT_SKEW_LIMIT == timedelta(seconds=5)
    assert MAX_SKEW_LIMIT == timedelta(seconds=60)


def test_a_valid_limit_is_taken_as_stated() -> None:
    assert parse_skew_limit("2.5") == timedelta(seconds=2.5)
    assert parse_skew_limit("60") == MAX_SKEW_LIMIT


@pytest.mark.parametrize("raw", ["0", "-1", "61", "abc", "nan", "inf", "1e9"])
def test_an_unusable_limit_refuses_and_is_never_clamped(raw: str) -> None:
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        parse_skew_limit(raw)
    assert caught.value.code is TargetRefusal.CLOCK_SKEW_LIMIT_INVALID
    assert SKEW_LIMIT_ENV in str(caught.value)


@pytest.mark.parametrize("limit", [timedelta(0), timedelta(seconds=61)])
def test_the_checker_itself_refuses_an_out_of_bounds_limit(limit: timedelta) -> None:
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        require_clock_skew_within(lambda: _DB_NOW, limit=limit)
    assert caught.value.code is TargetRefusal.CLOCK_SKEW_LIMIT_INVALID


# ── launcher entry ──────────────────────────────────────────────────────────


def test_main_reports_pass_and_refusal_with_codes_only(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from vendor_cp.deployment import consumption_scope

    dsn = "postgresql+psycopg://run_consume:SECRET-MARKER@db.example.test/cp"
    env = {consumption_scope.CONSUMPTION_DSN_ENV: dsn}
    monkeypatch.setattr(
        consumption_scope, "consumption_sessions", lambda _dsn: lambda: None
    )
    monkeypatch.setattr(
        clock_module,
        "require_clock_skew_within",
        lambda *_a, **_k: timedelta(0),
    )
    assert clock_module.main(env) == 0
    assert "passed" in capsys.readouterr().out

    def refuse(*_a: Any, **_k: Any) -> timedelta:
        raise FoundationBindingsUnavailable("x", code=TargetRefusal.CLOCK_SKEW_EXCEEDED)

    monkeypatch.setattr(clock_module, "require_clock_skew_within", refuse)
    assert clock_module.main(env) == 2
    err = capsys.readouterr().err
    assert "clock_skew_exceeded" in err and "SECRET-MARKER" not in err
    # A general DSN on the host refuses before any connection.
    assert clock_module.main({**env, "DATABASE_URL": dsn}) == 2
    assert "general_dsn_present_on_target" in capsys.readouterr().err
