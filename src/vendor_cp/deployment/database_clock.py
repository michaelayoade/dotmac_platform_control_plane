"""CP database time as the freshness clock, and the skew check (E3-Q2 ruling).

Grant liveness (`provider.now()`) and Control's presentation/standing expiry
must not be judged on the target's own clock: a backdated target could then
consume an expired dispatch (S2). The clock this assembly installs is the
database server's wall clock, read through the same scoped session factory the
consumption path uses. It never falls back to the local clock: if the database
cannot answer, the clock raises and the caller refuses.

`clock_timestamp()` is used, not `now()`: `now()` is the START of the current
transaction, so a session reused across a long step would read a stale time and
make a stale grant look fresh. `clock_timestamp()` is the server wall clock at
the call, which is what "freshness" means.

Skew check (`require_clock_skew_within`, `python -m
vendor_cp.deployment.database_clock`): the target's own clock still matters for
timestamps it writes (leases, evidence), so the launcher refuses a target whose
clock disagrees with database time by more than a limit. The reading is
bracketed by two local reads, so the uncertainty is the round trip; the check
refuses when `|skew| + round_trip/2` exceeds the limit rather than trusting a
slow answer.

Limit: 5 seconds by default, 60 seconds at most. Presentations live at most
five minutes and grant windows are minutes, so a limit of seconds costs a
healthy NTP/chrony-disciplined VM nothing (sub-second in practice) while still
catching an unsynchronised or deliberately backdated clock long before it could
matter to expiry. 60 s is the ceiling because above a fifth of the longest
presentation lifetime the check stops constraining anything it exists to
constrain. A value above the ceiling, non-numeric or non-positive refuses; it is
never clamped.
"""

from __future__ import annotations

import math
import os
import sys
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Final

from sqlalchemy import text

from vendor_cp.deployment.target_refusals import (
    FoundationBindingsUnavailable,
    TargetRefusal,
)

if TYPE_CHECKING:  # pragma: no cover
    from sqlalchemy.orm import Session

__all__ = [
    "DEFAULT_SKEW_LIMIT",
    "MAX_SKEW_LIMIT",
    "SKEW_LIMIT_ENV",
    "DatabaseClock",
    "measure_clock_skew",
    "parse_skew_limit",
    "require_clock_skew_within",
]

SKEW_LIMIT_ENV: Final = "DISPATCH_CLOCK_SKEW_LIMIT_SECONDS"
DEFAULT_SKEW_LIMIT: Final = timedelta(seconds=5)
MAX_SKEW_LIMIT: Final = timedelta(seconds=60)

_CLOCK_SQL: Final = "SELECT clock_timestamp()"


def _refuse(message: str, code: TargetRefusal) -> FoundationBindingsUnavailable:
    return FoundationBindingsUnavailable(message, code=code)


class DatabaseClock:
    """`datetime`-returning clock reading CP database server time."""

    def __init__(self, sessions: Callable[[], Session]) -> None:
        self._sessions = sessions

    def now(self) -> datetime:
        session: Session | None = None
        try:
            session = self._sessions()
            value = session.execute(text(_CLOCK_SQL)).scalar()
        except Exception:
            raise _refuse(
                "database time is unavailable; freshness is never judged on "
                "the local clock",
                TargetRefusal.CLOCK_UNAVAILABLE,
            ) from None
        finally:
            if session is not None:
                try:
                    session.rollback()
                finally:
                    session.close()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise _refuse(
                "database time was not a timezone-aware instant",
                TargetRefusal.CLOCK_UNAVAILABLE,
            )
        return value.astimezone(UTC)

    __call__ = now


def parse_skew_limit(raw: str | None) -> timedelta:
    """The configured skew limit; the default when unset; refuse the rest."""
    if raw is None or not raw.strip():
        return DEFAULT_SKEW_LIMIT
    try:
        seconds = float(raw.strip())
    except ValueError:
        seconds = float("nan")
    limit = (
        timedelta(seconds=seconds)
        if math.isfinite(seconds) and abs(seconds) < 1e6
        else None
    )
    if limit is None or limit <= timedelta(0) or limit > MAX_SKEW_LIMIT:
        raise _refuse(
            f"{SKEW_LIMIT_ENV} must be a positive number of seconds no greater "
            f"than {int(MAX_SKEW_LIMIT.total_seconds())}",
            TargetRefusal.CLOCK_SKEW_LIMIT_INVALID,
        )
    return limit


def measure_clock_skew(
    clock: Callable[[], datetime],
    *,
    local_now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> tuple[timedelta, timedelta]:
    """`(skew, round_trip)`: local midpoint minus database time, and the bracket."""
    before = local_now()
    database = clock()
    after = local_now()
    round_trip = after - before
    return (before + round_trip / 2) - database, round_trip


def require_clock_skew_within(
    clock: Callable[[], datetime],
    *,
    limit: timedelta = DEFAULT_SKEW_LIMIT,
    local_now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> timedelta:
    """Return the measured skew, or refuse when it can exceed `limit`."""
    if limit <= timedelta(0) or limit > MAX_SKEW_LIMIT:
        raise _refuse(
            "the skew limit is outside its bounds",
            TargetRefusal.CLOCK_SKEW_LIMIT_INVALID,
        )
    skew, round_trip = measure_clock_skew(clock, local_now=local_now)
    if round_trip < timedelta(0) or abs(skew) + round_trip / 2 > limit:
        raise _refuse(
            "this host's clock disagrees with CP database time by more than "
            "the permitted limit",
            TargetRefusal.CLOCK_SKEW_EXCEEDED,
        )
    return skew


def main(environ: Mapping[str, str] | None = None) -> int:
    """Launcher entry: exit 0 within limit, 2 on any refusal. Names only."""
    from vendor_cp.deployment.consumption_scope import (
        consumption_sessions,
        scoped_consumption_dsn,
    )

    env = os.environ if environ is None else environ
    try:
        limit = parse_skew_limit(env.get(SKEW_LIMIT_ENV))
        clock = DatabaseClock(consumption_sessions(scoped_consumption_dsn(env)))
        require_clock_skew_within(clock, limit=limit)
    except FoundationBindingsUnavailable as refusal:
        print(f"clock skew check refused: {refusal.code}", file=sys.stderr)
        return 2
    print("clock skew check passed")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
