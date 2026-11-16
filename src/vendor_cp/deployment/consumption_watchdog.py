"""Tripwire watchdog for the scoped consumption role (E6 design, section 2.3).

`statement_timeout`, `lock_timeout` and `idle_in_transaction_session_timeout` are
USERSET in PostgreSQL: `ALTER ROLE ... SET` sets only a default, so the role can
`SET ... = 0`, and `pg_advisory_lock` is executable by PUBLIC. There is no
per-role deny. The real bound on lock abuse is therefore this watchdog plus the
4 hour role lifetime.

Every second it asks the catalogue whether any backend of the role:

* holds an advisory lock (the legitimate path takes none);
* has been idle in a transaction for more than 30 s;
* has had a transaction open for more than 120 s;
* has run one statement for more than 10 s;
* is blocking another backend that has waited more than 5 s.

On ANY violation the ROLE is killed, not just the backend: `NOLOGIN CONNECTION
LIMIT 0`, terminate its sessions, drop its ledger policies, `DROP OWNED`, `DROP
ROLE`, then the read-back must show nothing remaining. Reconnecting does not
reopen the window, so abuse is bounded to about one tick, once. The legitimate
consumption holds millisecond transactions; a false trip costs one re-run
(budget B3).

Signals. SIGTERM, SIGINT, SIGHUP (an SSH drop, the ruled session model) and SIGQUIT
all take the one exit path, which revokes. Once revocation starts, further signals
are IGNORED, so a second signal cannot abort it. Revocation is retried with bounded
backoff until the read-back is clean; if it never is (a database that stays
unreachable), the watchdog exits LOUDLY with code 5 and the ceremony must revoke by
hand. What it cannot survive is SIGKILL (for example `docker stop` after its grace
period): run it so that cannot happen, with a stop timeout of 1200 s
(`--stop-timeout 1200`, or `systemd-run -p TimeoutStopSec=1200`, which also
survives SSH loss), and let the ceremony kit's trap run the revocation too. The
DSN must carry `connect_timeout` (at most 5 s): the command refuses one without.
Exit codes: 0 clean end, 3 tripped, 4 failed, 5 revocation NOT clean, 6 signalled.

Its own database access (documented, not new): it runs on the CEREMONY host, never
on a target, with the SAME administrative session credential that created the role
(`CONSUMPTION_WATCHDOG_DATABASE_URL`, a superuser or a role holding ALTER ROLE,
pg_terminate_backend, DROP OWNED and ownership of the ledger). It reads
`pg_stat_activity` and `pg_locks` across roles, which needs that privilege. It
opens a session per tick and commits nothing it does not mean to.

Residual: memory amplification (`SET work_mem` plus a large join) can grow server
memory within the one-tick window; PostgreSQL 16 has no per-role memory cap. The
bound is the tick, the small CP tables, and the one-rehearsal scope; removed at D3.

    CONSUMPTION_WATCHDOG_DATABASE_URL=... \\
        python -m vendor_cp.deployment.consumption_watchdog --role NAME
"""

from __future__ import annotations

import argparse
import contextlib
import os
import signal
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Final

from sqlalchemy import text
from sqlalchemy.engine import make_url

from vendor_cp.deployment.consumption_role_spec import (
    revocation_sql,
    verification_sql,
)
from vendor_cp.deployment.consumption_scope import MAX_ROLE_TTL
from vendor_cp.deployment.target_refusals import (
    FoundationBindingsUnavailable,
    TargetRefusal,
)

__all__ = [
    "ADMIN_DSN_ENV",
    "BLOCKING_SECONDS",
    "EXIT_CLEAN",
    "EXIT_FAILED",
    "EXIT_SIGNALLED",
    "EXIT_TRIPPED",
    "EXIT_UNCLEAN",
    "REVOKE_ATTEMPTS",
    "SIGNALS",
    "IDLE_IN_TRANSACTION_SECONDS",
    "STATEMENT_SECONDS",
    "TRANSACTION_SECONDS",
    "main",
    "revoke",
    "run",
    "tick",
]

ADMIN_DSN_ENV: Final = "CONSUMPTION_WATCHDOG_DATABASE_URL"
IDLE_IN_TRANSACTION_SECONDS: Final = 30
TRANSACTION_SECONDS: Final = 120
STATEMENT_SECONDS: Final = 10
BLOCKING_SECONDS: Final = 5
MAX_CONNECT_TIMEOUT_SECONDS: Final = 5
EXIT_CLEAN: Final = 0
EXIT_TRIPPED: Final = 3
EXIT_FAILED: Final = 4
EXIT_UNCLEAN: Final = 5
EXIT_SIGNALLED: Final = 6
#: Signals that take the revoke-and-exit path.
SIGNALS: Final = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT)
#: Revocation retries: bounded, so a dead database ends loudly, not never.
REVOKE_ATTEMPTS: Final = 12
REVOKE_BACKOFF_CAP_SECONDS: Final = 15.0

# One query, one row per violation, a fixed kind name and nothing else.
# The literal intervals equal the constants above; a test pins them together.
_VIOLATIONS_SQL: Final = (  # noqa: S608
    "SELECT 'advisory_lock' FROM pg_locks l JOIN pg_stat_activity a "
    "ON a.pid = l.pid WHERE a.usename = :role AND l.locktype = 'advisory' "
    "UNION ALL SELECT 'idle_in_transaction' FROM pg_stat_activity "
    "WHERE usename = :role AND state LIKE 'idle in transaction%' "
    "AND clock_timestamp() - state_change > interval '30 seconds' "
    "UNION ALL SELECT 'long_transaction' FROM pg_stat_activity "
    "WHERE usename = :role AND xact_start IS NOT NULL "
    "AND clock_timestamp() - xact_start > interval '120 seconds' "
    "UNION ALL SELECT 'long_statement' FROM pg_stat_activity "
    "WHERE usename = :role AND state = 'active' "
    "AND clock_timestamp() - query_start > interval '10 seconds' "
    "UNION ALL SELECT 'blocking' FROM pg_stat_activity w "
    "WHERE w.wait_event_type = 'Lock' "
    "AND clock_timestamp() - w.state_change > interval '5 seconds' "
    "AND EXISTS (SELECT 1 FROM pg_stat_activity b WHERE b.usename = :role "
    "AND b.pid = ANY (pg_blocking_pids(w.pid)))"
)
_EXISTS_SQL: Final = "SELECT count(*) FROM pg_roles WHERE rolname = :role"


def tick(session: Any, role: str) -> list[str]:
    """Violation kinds for the role right now (empty when none). Read-only."""
    rows = session.execute(text(_VIOLATIONS_SQL), {"role": role}).all()
    return [str(row[0]) for row in rows]


def role_exists(session: Any, role: str) -> bool:
    return bool(session.execute(text(_EXISTS_SQL), {"role": role}).scalar())


def revoke(session_factory: Callable[[], Any], role: str) -> tuple[int, int, int]:
    """The full ordered revocation, then the read-back counts.

    Every step is attempted even if an earlier one errors (the aim is that nothing
    remains), each in its own transaction. Returns `(roles, sessions, policies)`
    remaining; the caller treats anything but zeros as a failure.
    """
    for statement in revocation_sql(role):
        session = session_factory()
        try:
            connection = session.connection()
            # A blocked DDL must fail and let the next step run, never hang.
            connection.exec_driver_sql("SET lock_timeout = '5s'")
            connection.exec_driver_sql(statement)
            session.commit()
        except Exception:
            session.rollback()
        finally:
            session.close()
    session = session_factory()
    try:
        row = session.connection().exec_driver_sql(verification_sql(role)).one()
        session.rollback()
        return int(row[0]), int(row[1]), int(row[2])
    finally:
        session.close()


class _Interrupted(BaseException):
    """A signal arrived. BaseException so no `except Exception` can swallow it."""

    def __init__(self, signum: int) -> None:
        super().__init__(signum)
        self.signum = signum


def revoke_until_clean(
    session_factory: Callable[[], Any],
    role: str,
    *,
    sleep: Callable[[float], None] = time.sleep,
    out: Callable[[str], None] = print,
    attempts: int = REVOKE_ATTEMPTS,
) -> bool:
    """Revoke, read back, and retry with bounded backoff until nothing remains."""
    delay = 1.0
    for attempt in range(1, attempts + 1):
        try:
            counts: tuple[int, int, int] | None = revoke(session_factory, role)
        except Exception:
            counts = None
        if counts == (0, 0, 0):
            return True
        what = "not clean" if counts is not None else "could not read back"
        with contextlib.suppress(Exception):  # a dead terminal must not end the retry
            out(f"watchdog: revocation {what} (attempt {attempt} of {attempts})")
        if attempt < attempts:
            sleep(min(delay, REVOKE_BACKOFF_CAP_SECONDS))
            delay *= 2
    return False


def run(
    session_factory: Callable[[], Any],
    role: str,
    *,
    deadline_seconds: float = MAX_ROLE_TTL.total_seconds(),
    interval: float = 1.0,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    out: Callable[[str], None] = print,
    install_signals: bool = True,
) -> int:
    """Watch until the deadline, tripping on any violation. Always ends revoked.

    Any of `SIGNALS` takes the revoke path; once revocation starts, signals are
    ignored; revocation retries until the read-back is clean, else exit 5. A
    signal at ANY point (including inside the mask-and-revoke window) cannot
    skip it.
    """
    if not 0 < deadline_seconds <= MAX_ROLE_TTL.total_seconds():
        raise FoundationBindingsUnavailable(
            "the watchdog deadline must be within the 4 hour role window",
            code=TargetRefusal.CONSUMPTION_ROLE_OVERBROAD,
        )

    revoking = False

    def say(message: str) -> None:
        # A dead terminal or a failing writer must not change the exit code.
        with contextlib.suppress(Exception):
            out(message)

    def on_signal(signum: int, _frame: Any) -> None:
        nonlocal revoking
        if revoking:
            # Revocation is under way (or about to be): a signal must never
            # interrupt it, and `signal.signal` itself runs pending handlers.
            return
        revoking = True
        raise _Interrupted(signum)

    previous: dict[int, Any] = {}
    result = EXIT_CLEAN
    clean = False
    try:
        try:
            if install_signals:
                for signum in SIGNALS:
                    previous[signum] = signal.signal(signum, on_signal)
            stop = clock() + deadline_seconds
            while clock() < stop:
                session = session_factory()
                try:
                    if not role_exists(session, role):
                        say("watchdog: the role is already gone")
                        break  # still revoked and read back below, never a bare 0
                    kinds = tick(session, role)
                    session.rollback()
                finally:
                    session.close()
                if kinds:
                    say("watchdog tripped: " + ", ".join(sorted(set(kinds))))
                    result = EXIT_TRIPPED
                    break
                sleep(interval)
            else:
                say("watchdog: deadline reached")
        except _Interrupted as interrupted:
            say(f"watchdog: signal {interrupted.signum} received: revoking")
            result = EXIT_SIGNALLED
        except Exception:
            revoking = True  # from here a signal is a no-op, even for the message
            say("watchdog failed: revoking")
            result = EXIT_FAILED
    finally:
        # From the first statement here the handler is a no-op, so nothing can
        # skip or abort the revocation. The loop is belt and braces: if anything
        # still interrupted it, revocation is simply entered again, and it ends
        # only when the read-back is clean or the bounded retry is exhausted.
        revoking = True
        while True:
            try:
                for signum in SIGNALS if install_signals else ():
                    signal.signal(signum, signal.SIG_IGN)
                clean = revoke_until_clean(session_factory, role, sleep=sleep, out=out)
                break
            except _Interrupted:
                continue
    # Signals are still ignored here. The old handlers come back only AFTER the
    # final message is written and the exit code chosen, so a signal on this path
    # cannot turn exit 5 into 143, nor a failed message into a traceback.
    if clean:
        say("watchdog: role revoked and read back clean")
        code = result
    else:
        say(
            "watchdog: REVOCATION INCOMPLETE; the role may still be alive. "
            "Revoke it by hand NOW (consumption_role_spec revoke, then verify)"
        )
        code = EXIT_UNCLEAN
    for old_signum, handler in previous.items():
        signal.signal(old_signum, handler)
    return code


def main(
    argv: Sequence[str] | None = None, environ: Mapping[str, str] | None = None
) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", required=True)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument(
        "--deadline-seconds", type=float, default=MAX_ROLE_TTL.total_seconds()
    )
    args = parser.parse_args(argv)
    env = os.environ if environ is None else environ
    dsn = env.get(ADMIN_DSN_ENV, "").strip()
    if not dsn:
        print(f"{ADMIN_DSN_ENV} is not supplied", file=sys.stderr)
        return EXIT_FAILED
    try:
        # A blackholed database must not hang a connect for minutes.
        timeout = make_url(dsn).query.get("connect_timeout")
        if not isinstance(timeout, str) or not timeout.isdigit():
            raise ValueError("connect_timeout")
        if not 1 <= int(timeout) <= MAX_CONNECT_TIMEOUT_SECONDS:
            raise ValueError("connect_timeout")
    except ValueError:
        print(
            f"{ADMIN_DSN_ENV} must carry connect_timeout "
            f"(1 to {MAX_CONNECT_TIMEOUT_SECONDS} seconds)",
            file=sys.stderr,
        )
        return EXIT_FAILED
    try:
        from dotmac_kernel.session_runtime import DatabaseRuntime

        factory = DatabaseRuntime.from_urls(
            database_url=dsn, platform_database_url=dsn
        ).platform_session_factory
        return run(
            factory,
            args.role,
            deadline_seconds=args.deadline_seconds,
            interval=max(0.5, args.interval),
        )
    except FoundationBindingsUnavailable as refusal:
        print(f"watchdog refused: {refusal.code}", file=sys.stderr)
        return EXIT_FAILED
    except ValueError:
        print("watchdog refused: invalid role", file=sys.stderr)
        return EXIT_FAILED


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
