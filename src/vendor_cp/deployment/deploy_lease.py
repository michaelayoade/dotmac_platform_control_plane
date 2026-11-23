"""The production (deploy) lease class: a thin typed client plus the plan bounds.

P-CP1 WP5c, DESIGN-rev3 2.6.2. Every decision (exclusivity across both lease
classes, the store clock, the persistent-host rule, the reconcile marker, the
release rules) is a `SECURITY DEFINER` function of `v024_deploy_lease`; this
module owns none of it. What it owns:

* `DeployLeaseStore`: calls the four functions on the CALLER'S session and maps a
  database refusal to a code of the closed `lease_store.REFUSAL_CODES` set. It
  never commits, never retries and never surfaces database text. A refusal
  aborts the caller's transaction: the caller rolls back (consume relies on this
  so a missing cover leaves nothing consumed).
* `lease_bounds`: the TTL window one signed plan allows. A role job
  (`operation = "run_job"`) is leased for `timeout_seconds + 120` at least and
  for no more than Control's per-target `role_job_lease_ceiling_seconds`
  (default 900, at most 3600). A serving plan has no 900 s cap, only the lease
  store's 3600 s.

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
    "DEFAULT_ROLE_JOB_LEASE_CEILING_SECONDS",
    "JOB_LEASE_MARGIN_SECONDS",
    "MAX_LEASE_SECONDS",
    "MAX_ROLE_JOB_LEASE_CEILING_SECONDS",
    "RUN_JOB_OPERATION",
    "DeployLease",
    "DeployLeaseRefused",
    "DeployLeaseStore",
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
#: The lease store's own cap (`deploy_acquire` refuses more).
MAX_LEASE_SECONDS: Final = 3600
#: Control's per-target `role_job_lease_ceiling_seconds`: default and maximum.
DEFAULT_ROLE_JOB_LEASE_CEILING_SECONDS: Final = 900
MAX_ROLE_JOB_LEASE_CEILING_SECONDS: Final = 3600

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
    acquired_at: datetime
    expires_at: datetime
    #: The store's own clock when it answered.
    store_now: datetime


@dataclass(frozen=True, slots=True)
class DeployStanding:
    standing: str
    lease_id: UUID
    expires_at: datetime
    store_now: datetime


@dataclass(frozen=True, slots=True)
class LeaseBounds:
    """The TTL window a plan allows, inclusive on both ends."""

    min_ttl: int
    max_ttl: int

    def check(self, requested: object) -> int:
        """`requested` as an int inside the window, or `lease-ttl-invalid`."""
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
    plan_lease_ttl_seconds: object,
    role_job_lease_ceiling_seconds: object = DEFAULT_ROLE_JOB_LEASE_CEILING_SECONDS,
) -> LeaseBounds:
    """The TTL window of one signed plan, or `LeasePlanRefused`.

    * `operation` and `dispatched_job` must agree: `run_job` requires an object,
      any other operation requires null.
    * Job plan: `timeout_seconds + 120 <= ttl <= min(plan ttl, ceiling)`, with the
      ceiling 1..3600 (Control's per-target setting, default 900). The signed
      `timeout_seconds` is at least 1 and at most `ceiling - 120`.
    * Serving plan: `1 <= ttl <= min(plan ttl, 3600)`. No 900 s cap.
    """
    plan_ttl = _int(plan_lease_ttl_seconds)
    if plan_ttl is None or not 1 <= plan_ttl <= MAX_LEASE_SECONDS:
        raise LeasePlanRefused("plan-lease-ttl-out-of-bounds")
    if operation != RUN_JOB_OPERATION:
        if dispatched_job is not None:
            raise LeasePlanRefused("dispatched-job-on-a-serving-plan")
        return LeaseBounds(1, plan_ttl)
    if not isinstance(dispatched_job, Mapping):
        raise LeasePlanRefused("run-job-without-dispatched-job")
    cap = _int(role_job_lease_ceiling_seconds)
    if cap is None or not 1 <= cap <= MAX_ROLE_JOB_LEASE_CEILING_SECONDS:
        raise LeasePlanRefused("role-job-lease-ceiling-out-of-bounds")
    timeout = _int(dispatched_job.get("timeout_seconds"))
    if timeout is None or not 1 <= timeout <= cap - JOB_LEASE_MARGIN_SECONDS:
        raise LeasePlanRefused("job-timeout-out-of-bounds")
    low = timeout + JOB_LEASE_MARGIN_SECONDS
    high = min(plan_ttl, cap)
    if low > high:
        raise LeasePlanRefused("job-lease-does-not-fit")
    return LeaseBounds(low, high)


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
    """The four `cp_deploy_lease` functions over the caller's session.

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
        principal_ref: str,
        reconcile_marker: str | None = None,
    ) -> DeployLease:
        """Take the host's lease on the shared row lock, or raise a refusal."""
        row = self._one(
            "SELECT o_lease_id, o_acquired_at, o_expires_at, o_store_now "
            "FROM cp_deploy_lease.deploy_acquire("
            ":target_ref, :host, :run, CAST(:ttl AS integer), :principal, "
            ":marker)",
            {
                "target_ref": target_ref,
                "host": host_id,
                "run": dispatch_run,
                "ttl": ttl_seconds,
                "principal": principal_ref,
                "marker": reconcile_marker,
            },
        )
        return DeployLease(row[0], row[1], row[2], row[3])

    def covers(self, *, lease_id: UUID | str, dispatch_run: str) -> datetime:
        """Judge the lease on store time for THIS run; return the instant judged."""
        row = self._one(
            "SELECT cp_deploy_lease.deploy_covers(CAST(:lease AS uuid), :run)",
            {"lease": str(lease_id), "run": dispatch_run},
        )
        return row[0]  # type: ignore[no-any-return]

    def release(
        self,
        *,
        lease_id: UUID | str,
        dispatch_run: str,
        principal_ref: str,
        host_mutated: bool,
    ) -> datetime:
        """Release once, on store time; return the store's release instant."""
        row = self._one(
            "SELECT cp_deploy_lease.deploy_release("
            "CAST(:lease AS uuid), :run, :principal, :mutated)",
            {
                "lease": str(lease_id),
                "run": dispatch_run,
                "principal": principal_ref,
                "mutated": host_mutated,
            },
        )
        return row[0]  # type: ignore[no-any-return]

    def standing(self, host_id: str) -> DeployStanding:
        """The host's standing on store time (`held`, `released`, ...)."""
        row = self._one(
            "SELECT o_standing, o_lease_id, o_expires_at, o_store_now "
            "FROM cp_deploy_lease.deploy_standing(:host)",
            {"host": host_id},
        )
        if row[0] not in STANDINGS:
            raise DeployLeaseRefused(STORE_ERROR)
        return DeployStanding(row[0], row[1], row[2], row[3])
