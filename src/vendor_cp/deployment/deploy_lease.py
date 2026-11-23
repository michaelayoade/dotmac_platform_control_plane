"""The production (deploy) lease class: a thin typed client plus the plan bounds.

P-CP1 WP5c, DESIGN-rev3 2.6.2. Every decision (exclusivity across both lease
classes, the store clock, the persistent-host rule, the reconcile marker, the
release rules) is a `SECURITY DEFINER` function of `v024_deploy_lease`; this
module owns none of it. What it owns:

* `DeployLeaseStore`: calls the five functions on the CALLER'S session and maps a
  database refusal to a code of the closed `lease_store.REFUSAL_CODES` set. It
  never commits, never retries and never surfaces database text. A refusal
  aborts the caller's transaction: the caller rolls back (consume relies on this
  so a missing cover leaves nothing consumed).
* `lease_bounds`: the TTL window one signed plan allows. A plan carries
  `lease_ttl_seconds` (per grant, 120..900) and `lease_max_seconds` (the total,
  at most 10800); a job plan (`operation = "run_job"`) has ttl = max =
  `timeout_seconds + 120`. A serving plan is renewed up to its total.

Identity (W-i): the database does not identify the caller; the CP application
asserts `principal_ref` after it verified the target's PoP signature.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from vendor_cp.deployment.lease_store import REFUSAL_CODES

__all__ = [
    "JOB_LEASE_MARGIN_SECONDS",
    "MAX_GRANT_SECONDS",
    "MAX_JOB_LEASE_SECONDS",
    "MAX_LEASE_SECONDS",
    "MIN_GRANT_SECONDS",
    "RUN_JOB_OPERATION",
    "DeployLease",
    "DeployLeaseRefused",
    "DeployLeaseStore",
    "DeployRelease",
    "DeployRenewal",
    "DeployStanding",
    "LeaseBounds",
    "LeasePlanRefused",
    "dispatch_run",
    "lease_bounds",
]

#: The operation value a job plan carries (RULING-agent-contract, F1 shape).
RUN_JOB_OPERATION: Final = "run_job"
#: A job lease covers the job's timeout plus this much for fetch, mint and purge.
JOB_LEASE_MARGIN_SECONDS: Final = 120
#: Per-grant TTL bounds of a plan (Control: 120..900) and the total's maximum.
MIN_GRANT_SECONDS: Final = 120
MAX_GRANT_SECONDS: Final = 900
MAX_LEASE_SECONDS: Final = 10800
#: A run_job lease is granted once, ttl = total, and never renewed.
MAX_JOB_LEASE_SECONDS: Final = 3600
SERVING_CLASS: Final = "serving"
JOB_CLASS: Final = "run_job"

_REFUSAL_SQLSTATE: Final = "L3001"
STORE_UNREACHABLE: Final = "store-unreachable"
STORE_ERROR: Final = "store-error"
#: The standings `deploy_standing` answers.
STANDINGS: Final = frozenset({"held", "released", "expired_unreleased"})


class DeployLeaseRefused(Exception):  # noqa: N818 - a refusal is the vocabulary here
    """The store refused. `code` is a closed name, never a database value."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class LeasePlanRefused(Exception):  # noqa: N818
    """The signed plan does not describe a lease this API will grant."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class DeployLease:
    lease_id: UUID
    #: The TTL granted; a replayed acquire answers the REMAINING seconds.
    ttl_seconds: int
    acquired_at: datetime
    expires_at: datetime
    #: The store's own clock when it answered.
    store_now: datetime


@dataclass(frozen=True, slots=True)
class DeployRenewal:
    lease_id: UUID
    granted_seconds: int
    expires_at: datetime
    store_now: datetime


@dataclass(frozen=True, slots=True)
class DeployRelease:
    released_at: datetime
    #: True when this was a repeat of an earlier identical release.
    replay: bool


@dataclass(frozen=True, slots=True)
class DeployStanding:
    standing: str
    lease_id: UUID
    expires_at: datetime
    store_now: datetime
    #: The lease's run (`<target_ref>#<dispatch_id>`): names the dispatch that held
    #: it, which the agent needs when that lease expired unreleased.
    dispatch_run: str


@dataclass(frozen=True, slots=True)
class LeaseBounds:
    """What one signed plan allows: the grant window and the total, inclusive."""

    min_ttl: int
    max_ttl: int
    max_seconds: int
    lease_class: str = SERVING_CLASS

    def check(self, requested: object) -> int:
        """`requested` as an int inside the grant window, or `lease-ttl-invalid`."""
        if (
            isinstance(requested, bool)
            or not isinstance(requested, int)
            or not self.min_ttl <= requested <= self.max_ttl
        ):
            raise DeployLeaseRefused("lease-ttl-invalid")
        return requested


def dispatch_run(target_ref: str, dispatch_id: str) -> str:
    """The lease's run identity: `<target_ref>#<dispatch_id>`.

    Qualified by the AUTHENTICATED target, so a lease can only ever be covered or
    released by the target it was granted to: another target naming the same
    dispatch id builds a different run and is refused `lease-foreign-run`.
    """
    return f"{target_ref}#{dispatch_id}"


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def lease_bounds(
    *,
    operation: object,
    dispatched_job: object,
    lease_ttl_seconds: object,
    lease_max_seconds: object,
) -> LeaseBounds:
    """The class, grant window and total of one signed plan, or `LeasePlanRefused`.

    * `operation` and `dispatched_job` must agree: `run_job` requires an object,
      any other operation requires null.
    * Serving plan: `lease_ttl_seconds` 120..900 per grant, `lease_max_seconds` at
      least the ttl and at most 10800; granted 120 up to the ttl, renewed up to the
      total.
    * Job plan: `lease_ttl_seconds = lease_max_seconds`, at most 3600 and at least
      `timeout_seconds + 120`; granted exactly once and never renewed.
    """
    ttl = _int(lease_ttl_seconds)
    total = _int(lease_max_seconds)
    if operation != RUN_JOB_OPERATION:
        if dispatched_job is not None:
            raise LeasePlanRefused("dispatched-job-on-a-serving-plan")
        if ttl is None or not MIN_GRANT_SECONDS <= ttl <= MAX_GRANT_SECONDS:
            raise LeasePlanRefused("plan-lease-ttl-out-of-bounds")
        if total is None or not ttl <= total <= MAX_LEASE_SECONDS:
            raise LeasePlanRefused("plan-lease-max-out-of-bounds")
        return LeaseBounds(MIN_GRANT_SECONDS, ttl, total, SERVING_CLASS)
    if not isinstance(dispatched_job, Mapping):
        raise LeasePlanRefused("run-job-without-dispatched-job")
    timeout = _int(dispatched_job.get("timeout_seconds"))
    if timeout is None or timeout < 1:
        raise LeasePlanRefused("job-timeout-out-of-bounds")
    if ttl is None or not 1 <= ttl <= MAX_JOB_LEASE_SECONDS:
        raise LeasePlanRefused("plan-lease-ttl-out-of-bounds")
    if total != ttl or ttl < timeout + JOB_LEASE_MARGIN_SECONDS:
        raise LeasePlanRefused("job-lease-does-not-fit")
    return LeaseBounds(ttl, ttl, total, JOB_CLASS)


def _state(exc: BaseException) -> str | None:
    orig = getattr(exc, "orig", exc)
    state = getattr(orig, "sqlstate", None)
    if state is None:
        state = getattr(getattr(orig, "diag", None), "sqlstate", None)
    return state if isinstance(state, str) else None


def _map(exc: DBAPIError) -> DeployLeaseRefused:
    """A database error as a closed refusal code; no database text escapes."""
    state = _state(exc)
    if state == _REFUSAL_SQLSTATE:
        orig = getattr(exc, "orig", exc)
        message = getattr(getattr(orig, "diag", None), "message_primary", None)
        if message in REFUSAL_CODES:
            return DeployLeaseRefused(str(message))
        return DeployLeaseRefused(STORE_ERROR)
    if (
        getattr(exc, "connection_invalidated", False)
        or state is None
        or state.startswith("08")
    ):
        return DeployLeaseRefused(STORE_UNREACHABLE)
    return DeployLeaseRefused(STORE_ERROR)


class DeployLeaseStore:
    """The five `cp_deploy_lease` functions over the caller's session.

    `session` is a SQLAlchemy `Session` or `Connection` connected as the CP
    runtime role. Nothing is committed here: the caller owns the transaction.
    """

    def __init__(self, session: Any) -> None:
        self._session = session

    def _one(self, statement: str, params: Mapping[str, Any]) -> Any:
        try:
            return self._session.execute(text(statement), dict(params)).one()
        except DBAPIError as exc:
            raise _map(exc) from None

    def acquire(
        self,
        *,
        target_ref: str,
        host_id: str,
        dispatch_run: str,
        ttl_seconds: int,
        max_seconds: int,
        lease_class: str,
        principal_ref: str,
        reconcile_marker: str | None = None,
    ) -> DeployLease:
        """Take the host's lease on the shared row lock, or raise a refusal."""
        row = self._one(
            "SELECT o_lease_id, o_ttl, o_acquired_at, o_expires_at, o_store_now "
            "FROM cp_deploy_lease.deploy_acquire(:target_ref, :host, :run, "
            "CAST(:ttl AS integer), CAST(:max AS integer), :class, :principal, "
            ":marker)",
            {
                "target_ref": target_ref,
                "host": host_id,
                "run": dispatch_run,
                "ttl": ttl_seconds,
                "max": max_seconds,
                "class": lease_class,
                "principal": principal_ref,
                "marker": reconcile_marker,
            },
        )
        return DeployLease(row[0], row[1], row[2], row[3], row[4])

    def covers(self, *, lease_id: UUID | str, dispatch_run: str) -> datetime:
        """Judge the lease on store time for THIS run; return the instant judged."""
        row = self._one(
            "SELECT cp_deploy_lease.deploy_covers(CAST(:lease AS uuid), :run)",
            {"lease": str(lease_id), "run": dispatch_run},
        )
        return row[0]  # type: ignore[no-any-return]

    def renew(self, *, lease_id: UUID | str, dispatch_run: str) -> DeployRenewal:
        """Grant `min(ttl, max - time held)` more, or raise a refusal."""
        row = self._one(
            "SELECT o_lease_id, o_granted, o_expires_at, o_store_now "
            "FROM cp_deploy_lease.deploy_renew(CAST(:lease AS uuid), :run)",
            {"lease": str(lease_id), "run": dispatch_run},
        )
        return DeployRenewal(row[0], row[1], row[2], row[3])

    def release(
        self,
        *,
        lease_id: UUID | str,
        target_ref: str,
        principal_ref: str,
        host_mutated: bool,
    ) -> DeployRelease:
        """Release once, on store time; a repeat of the same release is a replay."""
        row = self._one(
            "SELECT o_released_at, o_replay FROM cp_deploy_lease.deploy_release("
            "CAST(:lease AS uuid), :target, :principal, :mutated)",
            {
                "lease": str(lease_id),
                "target": target_ref,
                "principal": principal_ref,
                "mutated": host_mutated,
            },
        )
        return DeployRelease(row[0], bool(row[1]))

    def standing(self, host_id: str) -> DeployStanding:
        """The host's standing on store time (`held`, `released`, ...)."""
        row = self._one(
            "SELECT o_standing, o_lease_id, o_expires_at, o_store_now, o_dispatch_run "
            "FROM cp_deploy_lease.deploy_standing(:host)",
            {"host": host_id},
        )
        if row[0] not in STANDINGS:
            raise DeployLeaseRefused(STORE_ERROR)
        return DeployStanding(row[0], row[1], row[2], row[3], row[4])
