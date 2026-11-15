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
(budget B3). If the watchdog exits for ANY reason (deadline, signal, error, the
database becoming unreachable) it revokes first. There is no mode that leaves the
role alive and unwatched.

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
import os
import signal
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Final

from sqlalchemy import text

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
EXIT_CLEAN: Final = 0
EXIT_TRIPPED: Final = 3
EXIT_FAILED: Final = 4

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
            session.connection().exec_driver_sql(statement)
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


def run(
    session_factory: Callable[[], Any],
    role: str,
    *,
    deadline_seconds: float = MAX_ROLE_TTL.total_seconds(),
    interval: float = 1.0,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    out: Callable[[str], None] = print,
) -> int:
    """Watch until the deadline, tripping on any violation. Always ends revoked."""
    if not 0 < deadline_seconds <= MAX_ROLE_TTL.total_seconds():
        raise FoundationBindingsUnavailable(
            "the watchdog deadline must be within the 4 hour role window",
            code=TargetRefusal.CONSUMPTION_ROLE_OVERBROAD,
        )
    stop = clock() + deadline_seconds
    result = EXIT_CLEAN
    try:
        while clock() < stop:
            session = session_factory()
            try:
                if not role_exists(session, role):
                    out("watchdog: the role is already gone")
                    return EXIT_CLEAN
                kinds = tick(session, role)
                session.rollback()
            finally:
                session.close()
            if kinds:
                out("watchdog tripped: " + ", ".join(sorted(set(kinds))))
                result = EXIT_TRIPPED
                break
            sleep(interval)
        else:
            out("watchdog: deadline reached")
    except Exception:
        out("watchdog failed: revoking")
        result = EXIT_FAILED
    finally:
        counts = revoke(session_factory, role)
    if counts != (0, 0, 0):
        out("watchdog: revocation left something behind")
        return EXIT_FAILED
    out("watchdog: role revoked and read back clean")
    return result


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
        from dotmac_kernel.session_runtime import DatabaseRuntime

        factory = DatabaseRuntime.from_urls(
            database_url=dsn, platform_database_url=dsn
        ).platform_session_factory
        # SIGTERM must still revoke: turn it into the normal exit path.
        signal.signal(
            signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt())
        )
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
