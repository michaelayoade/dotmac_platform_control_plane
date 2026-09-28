"""The host-brokered wire, over `transition_fence`, that PR 2's commands use.

`transition_fence` is a pure library over a caller-supplied connection: no
process, no environment, no stdio. This module is the thin layer that gives
it those things, exactly along the boundary its own module docstring's "The
threat model" and "Known limits" sections describe as PR 2's to build. See
that module first; this one restates none of its reasoning, only the wiring.

## D1: one owner connection, AUTOCOMMIT, over the kernel runtime

`owner_runtime()` builds a `dotmac_kernel.session_runtime.DatabaseRuntime`
from `MIGRATION_DATABASE_URL` — the same `app_admin` DSN `admin migrate`
already reads from the environment — with both URLs pointed at it and a
pool of exactly one connection: this is a single sequential command, not a
request path, and `app_admin` is the database owner whose ACL work
`fence_writers`/`restore_writers` require (see that module's "D1: the owner
topology" section). `close_fence`/`fence_holding`/`restore_fence` all take
their connection from `runtime.platform_engine`, execution-optioned to
`isolation_level="AUTOCOMMIT"` BEFORE the connection is ever checked out —
`transition_fence` refuses `CONNECTION_NOT_AUTOCOMMIT` before any change
otherwise, and there is no other way to get that property from a plain
SQLAlchemy `Engine`. There is no new privilege and no owner-equivalent login
here: `app_admin` already is the owner.

## Backend termination happens on the HOST, never in this process

This module never opens a second, more-privileged connection to terminate
another role's backends — that privilege stays with the HOST orchestrator
(PR 4), over its own superuser `psql` invocation of the fixed, checked-in
`deploy/postgres/terminate_writers.sql`. `StdioBrokerTerminator` is the
`Terminator` this module hands to `fence_writers`/`restore_writers`: it never
touches the database itself. It writes one line asking the host to
terminate, and waits for the host's proof that it did. The host's own
`scripts/lib/fence_broker.sh` is the other end of this exact protocol.

## The digest/`fence_id` channel is this module's to build, per the ruling

Per the 2026-09-28 ruling: the HOST generates `fence_id` and passes it to
`close_fence`. On the document `close_fence` returns, the HOST — not this
module — checks `fence_id` against the value it generated BEFORE ever
recording `expected_digest`, and keeps both in host-only state (see
`transition_fence`'s "The threat model" section for why that order matters).
`fence_holding`/`restore_fence` take `expected_digest`/`expected_fence_id`
as arguments precisely because they must come from that host-only state,
never from the document being checked or restored — this module never reads
either value out of a document itself. An unkeyed digest alone
(`FenceProof.digest()`) is not authentication of anything; it is integrity
between capture and restore, and only the host-checked `fence_id` binds a
document to the run the host actually asked about.

## Argument validation happens before any connection

Every function here refuses, before `owner_runtime()` is ever called and so
before any connection is opened, if a required host-supplied value —
`database`, `fence_id`, `expected_digest`, `expected_fence_id` — is missing
or empty. `FenceCommandConfigError` is this module's own vocabulary for that
refusal, distinct from `transition_fence.FenceRefused`, because it is a
configuration fault this module caught, not a verdict the fence itself made.
"""

from __future__ import annotations

from typing import TextIO

from dotmac_kernel.session_runtime import DatabaseRuntime
from sqlalchemy.engine import Connection

from vendor_cp.deployment.transition_fence import (
    FenceProof,
    Terminator,
    fence_is_holding,
    fence_writers,
    restore_writers,
)

#: The protocol's two line shapes, exactly. `StdioBrokerTerminator` writes the
#: first and requires the second, verbatim, as its only proof that the host's
#: broker actually ran the fixed termination statement.
_TERMINATE_PREFIX = "DOTMAC-FENCE-TERMINATE v1 "
_TERMINATED_PREFIX = "DOTMAC-FENCE-TERMINATED v1 "


class FenceCommandConfigError(RuntimeError):
    """A required host-supplied value is missing, empty, or `MIGRATION_
    DATABASE_URL` is unset. Raised before any connection is opened."""


class BrokerProtocolError(RuntimeError):
    """The broker's reply on stdin was not the exact expected line: a wrong
    `fence_id`, a trailing token, or end of input before any reply arrived.

    Wrapped by `transition_fence` as a terminator failure — never mistaken
    for a refusal that library itself produced."""


def owner_runtime() -> DatabaseRuntime:
    """The `app_admin` runtime this module's three commands share.

    A pool of one: this is a single sequential command invocation, never a
    request path. Both URLs are the same `MIGRATION_DATABASE_URL` DSN — the
    identical variable `admin migrate` already reads — so exactly one
    credential is ever in play here.
    """
    import os

    url = os.environ.get("MIGRATION_DATABASE_URL", "").strip()
    if not url:
        raise FenceCommandConfigError(
            "set MIGRATION_DATABASE_URL (the app_admin DSN) before running an "
            "`admin transition-fence` command"
        )
    return DatabaseRuntime.from_urls(
        database_url=url,
        platform_database_url=url,
        pool_size=1,
        max_overflow=0,
        platform_pool_size=1,
        platform_max_overflow=0,
    )


def _autocommit_connection(runtime: DatabaseRuntime) -> Connection:
    """An AUTOCOMMIT connection over `runtime.platform_engine`.

    `execution_options` is applied to the ENGINE, not to a connection already
    checked out, so the driver's `autocommit` flag is already `True` the
    instant the connection is opened — before `transition_fence` ever reads
    it (see that module's "The connection must be AUTOCOMMIT" section)."""
    engine = runtime.platform_engine.execution_options(isolation_level="AUTOCOMMIT")
    return engine.connect()


def _require(value: str | None, name: str) -> str:
    if not value:
        raise FenceCommandConfigError(f"{name} must be given and must not be empty")
    return value


class StdioBrokerTerminator:
    """A `Terminator` that asks a host-side broker to terminate writers, over
    the direct stdout/stdin of the process the host spawned.

    Each call writes exactly one `DOTMAC-FENCE-TERMINATE v1 <fence_id>` line
    to `stdout` and flushes it, then reads exactly one line from `stdin` and
    requires it to be exactly `DOTMAC-FENCE-TERMINATED v1 <fence_id>` — the
    identical `fence_id` this instance was constructed with, never a value
    read back off the wire. Anything else — a different `fence_id`, a
    trailing token, or end of input — raises `BrokerProtocolError`, which
    `transition_fence` wraps as a terminator failure so it can never be
    mistaken for one of that module's own refusals.
    """

    def __init__(self, fence_id: str, *, stdin: TextIO, stdout: TextIO) -> None:
        self._fence_id = fence_id
        self._stdin = stdin
        self._stdout = stdout

    def __call__(self) -> None:
        self._stdout.write(f"{_TERMINATE_PREFIX}{self._fence_id}\n")
        self._stdout.flush()
        raw = self._stdin.readline()
        if raw == "":
            raise BrokerProtocolError(
                "the broker closed stdin before replying to a termination request"
            )
        line = raw.rstrip("\r\n")
        expected = f"{_TERMINATED_PREFIX}{self._fence_id}"
        if line != expected:
            raise BrokerProtocolError(
                f"the broker replied {line!r}, expected exactly {expected!r}"
            )


def close_fence(
    *,
    database: str,
    fence_id: str,
    session_wait_seconds: float,
    stdin: TextIO,
    stdout: TextIO,
    prior_document: dict[str, object] | None = None,
    prior_expected_digest: str | None = None,
    expected_prior_fence_id: str | None = None,
) -> dict[str, object]:
    """Fence every writer role, brokering termination over `stdin`/`stdout`.

    `prior_document` is built into a `FenceProof` ONLY via
    `FenceProof.from_document` — this module never accepts an in-process
    `FenceProof` across this boundary (see `transition_fence`'s "The trust
    boundary" section for why that matters). `prior_expected_digest` is
    required whenever `prior_document` is given, and is never read out of
    the document itself.
    """
    database = _require(database, "database")
    fence_id = _require(fence_id, "fence_id")

    prior: FenceProof | None = None
    if prior_document is not None:
        prior_expected_digest = _require(prior_expected_digest, "prior_expected_digest")
        expected_prior_fence_id = _require(
            expected_prior_fence_id, "expected_prior_fence_id"
        )
        prior = FenceProof.from_document(
            prior_document, expected_digest=prior_expected_digest
        )
    elif prior_expected_digest or expected_prior_fence_id:
        raise FenceCommandConfigError(
            "prior_expected_digest and expected_prior_fence_id both require a "
            "prior_document to bind against"
        )

    runtime = owner_runtime()
    terminator: Terminator = StdioBrokerTerminator(fence_id, stdin=stdin, stdout=stdout)
    with _autocommit_connection(runtime) as conn:
        proof = fence_writers(
            conn,
            database=database,
            fence_id=fence_id,
            session_wait_seconds=session_wait_seconds,
            prior=prior,
            expected_prior_fence_id=expected_prior_fence_id,
            terminator=terminator,
        )
    return {
        "proof": proof.to_document(),
        "digest": proof.digest(),
        "fence_id": fence_id,
    }


def fence_holding(
    *, proof_document: dict[str, object], expected_digest: str
) -> dict[str, object]:
    """Read-only: does the fence this document describes still hold?

    `expected_digest` is required and checked before anything else. Once
    that holds, any exception raised while checking — an invalid document, an
    unreachable database, a driver error — is reported as `holding: false`
    rather than propagated, because "cannot tell" and "does not hold" both
    mean the caller must not proceed as though the fence were up.
    """
    expected_digest = _require(expected_digest, "expected_digest")
    try:
        proof = FenceProof.from_document(
            proof_document, expected_digest=expected_digest
        )
        runtime = owner_runtime()
        with _autocommit_connection(runtime) as conn:
            holding = fence_is_holding(conn, proof)
    except Exception:  # noqa: BLE001 - "cannot tell" collapses to "not holding"
        holding = False
    return {"holding": holding}


def restore_fence(
    *,
    database: str,
    proof_document: dict[str, object],
    expected_digest: str,
    expected_fence_id: str,
    session_wait_seconds: float,
    stdin: TextIO,
    stdout: TextIO,
) -> dict[str, object]:
    """Restore the fenced ACL to exactly what `proof_document` recorded.

    `expected_digest` and `expected_fence_id` both come from the HOST's own
    state, never from `proof_document` — see this module's docstring for why.
    The same `StdioBrokerTerminator`, keyed on `expected_fence_id`, is handed
    to `restore_writers` for the re-fence-and-redrain compensation path a
    failed or partial restore can take.
    """
    database = _require(database, "database")
    expected_digest = _require(expected_digest, "expected_digest")
    expected_fence_id = _require(expected_fence_id, "expected_fence_id")

    proof = FenceProof.from_document(proof_document, expected_digest=expected_digest)
    runtime = owner_runtime()
    terminator: Terminator = StdioBrokerTerminator(
        expected_fence_id, stdin=stdin, stdout=stdout
    )
    with _autocommit_connection(runtime) as conn:
        result = restore_writers(
            conn,
            proof,
            database=database,
            expected_fence_id=expected_fence_id,
            session_wait_seconds=session_wait_seconds,
            terminator=terminator,
        )
    return {
        "database": result.database,
        "restored_at": result.restored_at.isoformat().replace("+00:00", "Z"),
        "roles_restored": list(result.roles_restored),
    }


__all__ = [
    "BrokerProtocolError",
    "FenceCommandConfigError",
    "StdioBrokerTerminator",
    "close_fence",
    "fence_holding",
    "owner_runtime",
    "restore_fence",
]
