"""The lease endpoints of the target API (WP5c, DESIGN 2.6.2).

`LeaseHandlers` is a `TargetHandlers` (lane 5b's seam) that serves the four lease
routes and delegates every other route to the handlers it wraps (5b's
`TargetApiHandlers`, whose lease routes answer 501 until this is composed in):

    POST lease/acquire   {"dispatch_id", "ttl_seconds"}
    POST lease/covers    {"lease_id", "dispatch_id"}
    POST lease/release   {"lease_id", "dispatch_id", "host_mutated"}
    GET  lease/standing

Covers-in-consume is NOT a route here: 5b's consume calls
`ConsumptionBackend.covers_lease` at step 4 of the atomic consume, in the same
transaction as the nonce and the effect, and `deploy_lease_consume.LeaseCoveringBackend`
fills that port with `cp_deploy_lease.deploy_covers`.

## What the handler decides and what it does not

* The caller is the authenticated target principal; the host is the third segment
  of ITS target ref (never a request field), the lease's `principal_ref` is the
  principal's own reference, and the lease's run is `<target_ref>#<dispatch_id>`
  (`dispatch_run`), so another target cannot cover or release this one's lease.
  Requests carry no host, no principal, no marker and no time.
* The TTL window comes from the signed plan (`lease_bounds`): a job plan
  (`operation = "run_job"`) is `timeout_seconds + 120` up to Control's per-target
  `role_job_lease_ceiling_seconds` (default 900, at most 3600); a serving plan has
  no 900 s cap. The plan is read through the `LeasePort`, at acquire only, for THIS
  target's pending dispatch.
* The reconcile marker is NEVER read from the request. After an expired-unreleased
  lease the agent posts a signed read-only reconcile observation; Control issues the
  marker when the observed release matches, and the `LeasePort` hands the handler
  that issued, unspent marker. A caller cannot supply its own.
* Every database refusal aborts only a SAVEPOINT: the request's nonce still
  commits and the caller gets a typed, signed answer. A store fault (unreachable,
  error) is raised, so the whole request rolls back and the caller retries.

`LeasePort` is the one seam left for Control (the plan of a pending dispatch and
its issued marker); `UnconfiguredLeasePort` fails closed until it is composed.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, Protocol

from vendor_cp.deployment.deploy_lease import (
    DeployLease,
    DeployLeaseRefused,
    DeployLeaseStore,
    LeasePlanRefused,
    dispatch_run,
    lease_bounds,
)
from vendor_cp.deployment.target_api.auth import AuthenticatedCall
from vendor_cp.deployment.target_api.handlers import HandlerResult, TargetHandlers

__all__ = [
    "LeaseHandlers",
    "LeasePlan",
    "LeasePort",
    "UnconfiguredLeasePort",
    "refusal_http_status",
]

_LEASE_ROUTES: Final = frozenset(
    {"lease/acquire", "lease/covers", "lease/release", "lease/standing"}
)
#: The contract's dispatch id grammar (`target_api.contract`): the lease's run.
_DISPATCH_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_UUID: Final = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)

#: HTTP status of each closed store refusal. State conflicts are 409; a malformed
#: request is 400; an unknown lease or host is 404; a lease that is not this
#: caller's to release is 403. Anything else is a store fault and is raised.
_STATUS: Final = {
    "lease-held-by-another-run": 409,
    "lease-host-mutated": 409,
    "lease-expired": 409,
    "lease-foreign-run": 409,
    "lease-already-released": 409,
    "reprovision-receipt-spent": 409,
    "lease-ttl-invalid": 400,
    "host-mutated-required": 400,
    "reprovision-receipt-mismatch": 400,
    "lease-role-unbound": 404,
    "lease-host-unknown": 404,
    "release-not-this-lease": 403,
}


def refusal_http_status(code: str) -> int | None:
    """The status for a closed refusal code, or None for a store fault."""
    return _STATUS.get(code)


@dataclass(frozen=True, slots=True)
class LeasePlan:
    """What the lease API needs from one signed plan."""

    operation: str
    dispatched_job: Mapping[str, object] | None
    lease_ttl_seconds: int
    role_job_lease_ceiling_seconds: int


class LeasePort(Protocol):
    """Lane 5b's Control-backed facts, for ONE target."""

    def plan_for(
        self, db: Any, *, target_ref: str, dispatch_id: str, at: datetime
    ) -> LeasePlan | None:
        """The signed plan of a dispatch that is PENDING for `target_ref`, or None
        for an unknown, consumed or other-target dispatch. Read at acquire only."""

    def reconcile_marker_for(
        self, db: Any, *, target_ref: str, at: datetime
    ) -> str | None:
        """Control's ISSUED, unspent reconcile marker digest for the target's host
        (`sha256:<64 hex>`), or None when Control has not issued one."""


class UnconfiguredLeasePort:
    """Fails closed: no dispatch is known and no marker exists."""

    def plan_for(
        self, db: Any, *, target_ref: str, dispatch_id: str, at: datetime
    ) -> LeasePlan | None:
        return None

    def reconcile_marker_for(
        self, db: Any, *, target_ref: str, at: datetime
    ) -> str | None:
        return None


def _stamp(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _refusal(code: str, status: int, **extra: object) -> HandlerResult:
    return HandlerResult(status, {"error": code, **extra})


def _body(payload: object, keys: frozenset[str]) -> Mapping[str, Any] | None:
    """The body as a mapping with exactly `keys`, or None."""
    if not isinstance(payload, dict) or set(payload) != keys:
        return None
    return payload


def _is_dispatch_id(value: object) -> bool:
    return isinstance(value, str) and _DISPATCH_ID.fullmatch(value) is not None


def _is_lease_id(value: object) -> bool:
    return isinstance(value, str) and _UUID.fullmatch(value) is not None


class LeaseHandlers:
    def __init__(
        self,
        *,
        inner: TargetHandlers,
        port: LeasePort | None = None,
        store_factory: Callable[[Any], Any] = DeployLeaseStore,
        savepoint: Callable[[Any], AbstractContextManager[Any]] = lambda db: (
            db.begin_nested()
        ),
    ) -> None:
        self._inner = inner
        self._port: LeasePort = port or UnconfiguredLeasePort()
        self._store_factory = store_factory
        self._savepoint = savepoint

    # ── routing ─────────────────────────────────────────────────────────────

    def handle(
        self, call: AuthenticatedCall, db: Any, payload: object
    ) -> HandlerResult:
        route = call.coordinates.route
        if route in _LEASE_ROUTES:
            return {
                "lease/acquire": self._acquire,
                "lease/covers": self._covers,
                "lease/release": self._release,
                "lease/standing": self._standing,
            }[route](call, db, payload)
        return self._inner.handle(call, db, payload)

    # ── plumbing ────────────────────────────────────────────────────────────

    @staticmethod
    def _host(call: AuthenticatedCall) -> str:
        return call.principal.target_ref.split("/")[2]

    def _guarded(
        self, db: Any, operation: Callable[[Any], Any]
    ) -> tuple[Any, HandlerResult | None]:
        """Run one store call in a savepoint. A typed refusal rolls back only the
        savepoint and is answered; a store fault propagates (full rollback)."""
        try:
            with self._savepoint(db):
                return operation(self._store_factory(db)), None
        except DeployLeaseRefused as refusal:
            status = refusal_http_status(refusal.code)
            if status is None:
                raise
            return None, _refusal(refusal.code, status)

    # ── lease/acquire ───────────────────────────────────────────────────────

    def _acquire(
        self, call: AuthenticatedCall, db: Any, payload: object
    ) -> HandlerResult:
        body = _body(payload, frozenset({"dispatch_id", "ttl_seconds"}))
        if body is None or not _is_dispatch_id(body["dispatch_id"]):
            return _refusal("bad_body", 400)
        dispatch_id = str(body["dispatch_id"])
        plan = self._port.plan_for(
            db,
            target_ref=call.principal.target_ref,
            dispatch_id=dispatch_id,
            at=call.store_now,
        )
        if plan is None:
            return _refusal("unknown_dispatch", 404)
        try:
            bounds = lease_bounds(
                operation=plan.operation,
                dispatched_job=plan.dispatched_job,
                plan_lease_ttl_seconds=plan.lease_ttl_seconds,
                role_job_lease_ceiling_seconds=plan.role_job_lease_ceiling_seconds,
            )
        except LeasePlanRefused as refused:
            return _refusal("plan_not_leasable", 422, reason=refused.reason)
        try:
            ttl = bounds.check(body["ttl_seconds"])
        except DeployLeaseRefused as refused:
            return _refusal(
                refused.code, 400, min_ttl=bounds.min_ttl, max_ttl=bounds.max_ttl
            )
        marker = self._port.reconcile_marker_for(
            db, target_ref=call.principal.target_ref, at=call.store_now
        )
        lease, refusal = self._guarded(
            db,
            lambda store: store.acquire(
                target_ref=call.principal.target_ref,
                host_id=self._host(call),
                dispatch_run=dispatch_run(call.principal.target_ref, dispatch_id),
                ttl_seconds=ttl,
                principal_ref=call.principal.principal_ref,
                reconcile_marker=marker,
            ),
        )
        if refusal is not None:
            return refusal
        assert isinstance(lease, DeployLease)  # noqa: S101 - typing narrow
        return HandlerResult(
            200,
            {
                "lease_id": str(lease.lease_id),
                "acquired_at": _stamp(lease.acquired_at),
                "expires_at": _stamp(lease.expires_at),
                "lease_store_now": _stamp(lease.store_now),
            },
        )

    # ── lease/covers ────────────────────────────────────────────────────────

    def _covers(
        self, call: AuthenticatedCall, db: Any, payload: object
    ) -> HandlerResult:
        body = _body(payload, frozenset({"lease_id", "dispatch_id"}))
        if (
            body is None
            or not _is_dispatch_id(body["dispatch_id"])
            or not _is_lease_id(body["lease_id"])
        ):
            return _refusal("bad_body", 400)
        judged, refusal = self._guarded(
            db,
            lambda store: store.covers(
                lease_id=body["lease_id"],
                dispatch_run=dispatch_run(
                    call.principal.target_ref, body["dispatch_id"]
                ),
            ),
        )
        if refusal is not None:
            return refusal
        return HandlerResult(
            200,
            {
                "covered": True,
                "lease_id": body["lease_id"],
                "lease_store_now": _stamp(judged),
            },
        )

    # ── lease/release ───────────────────────────────────────────────────────

    def _release(
        self, call: AuthenticatedCall, db: Any, payload: object
    ) -> HandlerResult:
        body = _body(payload, frozenset({"lease_id", "dispatch_id", "host_mutated"}))
        if (
            body is None
            or not _is_dispatch_id(body["dispatch_id"])
            or not _is_lease_id(body["lease_id"])
            or not isinstance(body["host_mutated"], bool)
        ):
            return _refusal("bad_body", 400)
        released, refusal = self._guarded(
            db,
            lambda store: store.release(
                lease_id=body["lease_id"],
                dispatch_run=dispatch_run(
                    call.principal.target_ref, body["dispatch_id"]
                ),
                principal_ref=call.principal.principal_ref,
                host_mutated=body["host_mutated"],
            ),
        )
        if refusal is not None:
            return refusal
        return HandlerResult(
            200, {"lease_id": body["lease_id"], "released_at": _stamp(released)}
        )

    # ── lease/standing ──────────────────────────────────────────────────────

    def _standing(
        self, call: AuthenticatedCall, db: Any, payload: object
    ) -> HandlerResult:
        standing, refusal = self._guarded(
            db, lambda store: store.standing(self._host(call))
        )
        if refusal is not None:
            if refusal.body.get("error") == "lease-host-unknown":
                return HandlerResult(200, {"standing": "none"})
            return refusal
        return HandlerResult(
            200,
            {
                "standing": standing.standing,
                "lease_id": str(standing.lease_id),
                "expires_at": _stamp(standing.expires_at),
                "lease_store_now": _stamp(standing.store_now),
            },
        )
