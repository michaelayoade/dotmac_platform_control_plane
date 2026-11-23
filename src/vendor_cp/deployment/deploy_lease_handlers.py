"""The lease endpoints of the target API (WP5c, DESIGN 2.6.2).

`LeaseHandlers` is a `TargetHandlers` (lane 5b's seam) that serves the five lease
routes and delegates every other route to the handlers it wraps (5b's
`TargetApiHandlers`, whose lease routes answer 501 until this is composed in):

    POST lease/acquire   {"dispatch_run", "ttl_seconds"}  -> {"lease_id", "ttl_seconds"}
    POST lease/covers    {"lease_id", "dispatch_run"}     -> {"covers"}
    POST lease/renew     {"lease_id", "dispatch_run"}     -> {"lease_id", "ttl_seconds"}
    POST lease/release   {"lease_id", "host_mutated"}     -> {"released", "replay"}
    GET  lease/standing                                    -> {"standing"}

(architect ruling Q-c/4; Control's `target_api_v2` is the authority once it lands.
`lease/renew` is not a route of the pinned v1 mirror in `target_api.contract`, so it
becomes reachable through the router when the v2 mirror is vendored.)

Covers-in-consume is NOT a route here: 5b's consume calls
`ConsumptionBackend.covers_lease` at step 4 of the atomic consume, and
`deploy_lease_consume.LeaseCoveringBackend` fills that port with
`cp_deploy_lease.deploy_covers`.

## What the handler decides and what it does not

* The caller is the authenticated target principal; the host is the third segment
  of ITS target ref (never a request field), the lease's `principal_ref` is the
  principal's own reference, and the lease's run is `<target_ref>#<dispatch_id>`
  (`dispatch_run`), so another target cannot cover or release this one's lease.
  Requests carry no host, no principal, no marker and no time.
* The TTL window comes from the signed plan (`lease_bounds`): `lease_ttl_seconds`
  per grant (120..900) and `lease_max_seconds` for the total (at most 10800); a job
  plan has ttl = max = `timeout_seconds + 120`. The plan is read through the
  `LeasePort`, at acquire only, for THIS target's pending dispatch; renewal reads
  the ttl and total the lease was stored with, so it works after consume.
* Release names only the lease: the holder is the authenticated target and its
  credential principal, checked in the database.
* The reconcile marker is NEVER read from the request and never derived by CP:
  only Control's `reconcile_marker` decision, through the `LeasePort`, supplies it.
* Every lease call runs on the DEDICATED lease role's own transaction
  (`deploy_lease_engine`), never the request's: a refusal rolls that transaction
  back and is answered typed and signed while the request's nonce still commits; a
  store fault (unreachable, error) is raised, so the request rolls back and the
  caller retries (the functions are idempotent under retry).
* The reconcile marker is read inside the acquire's own transaction, under the host
  row lock: `deploy_acquire` ANSWERS "marker required" with the expired dispatch's
  run (it does not raise), CP asks Control's `reconcile_marker` port for exactly
  that dispatch, and calls again in the same transaction.

`LeasePort` is the one seam left for Control (the plan of a pending dispatch and
its issued marker); `UnconfiguredLeasePort` fails closed until it is composed.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final, Protocol

from vendor_cp.deployment.deploy_lease import (
    DeployLease,
    DeployLeaseRefused,
    LeasePlanRefused,
    MarkerRequired,
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
    "LEASE_ERRORS",
    "refusal_http_status",
]

_LEASE_ROUTES: Final = frozenset(
    {
        "lease/acquire",
        "lease/covers",
        "lease/renew",
        "lease/release",
        "lease/standing",
    }
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
    "lease-max-reached": 409,
    "lease-not-renewable": 409,
    "lease-superseded": 409,
    "reconcile-marker-required": 409,
    "reprovision-receipt-spent": 409,
    "lease-ttl-invalid": 400,
    "host-mutated-required": 400,
    "reprovision-receipt-mismatch": 400,
    "lease-role-unbound": 404,
    "lease-host-unknown": 404,
    "release-not-this-lease": 403,
}
#: Control's signed lease errors (`target_api_v2` `lease_errors`), all HTTP 409.
LEASE_ERRORS: Final = frozenset(
    {
        "lease_not_held",
        "lease_expired",
        "lease_max_reached",
        "lease_held",
        "lease_not_renewable",
        "lease_superseded",
        "reconcile_marker_required",
    }
)
#: Store refusal -> contract error name, per route. Anything not named here is its
#: own name with `_` (a request-level refusal, not a lease state).
_ACQUIRE_NAMES: Final = {
    "lease-held-by-another-run": "lease_held",
    # held by the rehearsal class, or a host a rehearsal released: not leasable
    "lease-host-mutated": "lease_held",
    "reconcile-marker-required": "reconcile_marker_required",
    # a marker Control issued but that cannot be used is still "no usable marker"
    "reprovision-receipt-spent": "reconcile_marker_required",
    "reprovision-receipt-mismatch": "reconcile_marker_required",
}
_RENEW_NAMES: Final = {
    "lease-role-unbound": "lease_not_held",
    "lease-foreign-run": "lease_not_held",
    "lease-already-released": "lease_not_held",
    "lease-expired": "lease_expired",
    "lease-max-reached": "lease_max_reached",
    "lease-not-renewable": "lease_not_renewable",
}
_RELEASE_NAMES: Final = {
    "lease-role-unbound": "lease_not_held",
    "release-not-this-lease": "lease_not_held",
    "lease-already-released": "lease_not_held",
    "lease-expired": "lease_expired",
}
#: Refusals that mean "this lease does not cover this run" (a `covers` answer).
_NOT_COVERED: Final = frozenset(
    {"lease-expired", "lease-foreign-run", "lease-role-unbound"}
)


def refusal_http_status(code: str) -> int | None:
    """The status for a closed refusal code, or None for a store fault."""
    return _STATUS.get(code)


@dataclass(frozen=True, slots=True)
class LeasePlan:
    """What the lease API needs from one signed plan."""

    operation: str
    dispatched_job: Mapping[str, object] | None
    lease_ttl_seconds: int
    lease_max_seconds: int


class LeasePort(Protocol):
    """Lane 5b's Control-backed facts, for ONE target."""

    def plan_for(
        self, db: Any, *, target_ref: str, dispatch_id: str, at: datetime
    ) -> LeasePlan | None:
        """The signed plan of a dispatch that is PENDING for `target_ref`, or None
        for an unknown, consumed or other-target dispatch. Read at acquire only."""

    def dispatch_consumed(self, db: Any, *, target_ref: str, dispatch_id: str) -> bool:
        """Whether `dispatch_id` has a committed consumption marker (5b's consume
        ledger). Control cannot see this; CP supplies it."""

    def reconcile_marker(
        self,
        db: Any,
        *,
        target_ref: str,
        dispatch_id: str,
        expired_dispatch_consumed: bool,
    ) -> str | None:
        """Control's `reconcile_marker` decision over the verified v2 reconcile
        observation of the EXPIRED dispatch: the issued, unspent marker digest
        (`sha256:<64 hex>`), or None. CP derives nothing here."""


class UnconfiguredLeasePort:
    """Fails closed: no dispatch is known and no marker exists."""

    def plan_for(
        self, db: Any, *, target_ref: str, dispatch_id: str, at: datetime
    ) -> LeasePlan | None:
        return None

    def dispatch_consumed(self, db: Any, *, target_ref: str, dispatch_id: str) -> bool:
        return False

    def reconcile_marker(
        self,
        db: Any,
        *,
        target_ref: str,
        dispatch_id: str,
        expired_dispatch_consumed: bool,
    ) -> str | None:
        return None


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
        stores: Callable[[Any], AbstractContextManager[Any]],
        port: LeasePort | None = None,
    ) -> None:
        """`stores(request_db)` yields a lease store on the DEDICATED lease role's own
        transaction (commit on success, rollback on a refusal or fault); see
        `deploy_lease_engine`. The request's session is never used for a lease."""
        self._inner = inner
        self._port: LeasePort = port or UnconfiguredLeasePort()
        self._stores = stores

    # ── routing ─────────────────────────────────────────────────────────────

    def handle(
        self, call: AuthenticatedCall, db: Any, payload: object
    ) -> HandlerResult:
        route = call.coordinates.route
        if route in _LEASE_ROUTES:
            return {
                "lease/acquire": self._acquire,
                "lease/covers": self._covers,
                "lease/renew": self._renew,
                "lease/release": self._release,
                "lease/standing": self._standing,
            }[route](call, db, payload)
        return self._inner.handle(call, db, payload)

    # ── plumbing ────────────────────────────────────────────────────────────

    @staticmethod
    def _host(call: AuthenticatedCall) -> str:
        return call.principal.target_ref.split("/")[2]

    def _guarded(
        self,
        db: Any,
        operation: Callable[[Any], Any],
        names: Mapping[str, str] | None = None,
    ) -> tuple[Any, HandlerResult | None, str | None]:
        """Run one lease operation in its own transaction on the lease role. A typed
        refusal rolls it back and is answered (the request's nonce still commits); a
        store fault propagates. Returns `(result, refusal answer, refusal code)`."""
        try:
            with self._stores(db) as store:
                return operation(store), None, None
        except DeployLeaseRefused as refusal:
            status = refusal_http_status(refusal.code)
            if status is None:
                raise
            name = (names or {}).get(refusal.code) or refusal.code.replace("-", "_")
            if name in LEASE_ERRORS:
                status = 409
            return None, _refusal(name, status), refusal.code

    # ── lease/acquire ───────────────────────────────────────────────────────

    def _acquire(
        self, call: AuthenticatedCall, db: Any, payload: object
    ) -> HandlerResult:
        body = _body(payload, frozenset({"dispatch_run", "ttl_seconds"}))
        if body is None or not _is_dispatch_id(body["dispatch_run"]):
            return _refusal("bad_body", 400)
        dispatch_id = str(body["dispatch_run"])
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
                lease_ttl_seconds=plan.lease_ttl_seconds,
                lease_max_seconds=plan.lease_max_seconds,
            )
        except LeasePlanRefused as refused:
            return _refusal("plan_not_leasable", 422, reason=refused.reason)
        try:
            ttl = bounds.check(body["ttl_seconds"])
        except DeployLeaseRefused as refused:
            return _refusal(
                refused.code.replace("-", "_"),
                400,
                min_ttl=bounds.min_ttl,
                max_ttl=bounds.max_ttl,
            )

        def acquire(store: Any, marker: str | None) -> Any:
            return store.acquire(
                target_ref=call.principal.target_ref,
                host_id=self._host(call),
                dispatch_run=dispatch_run(call.principal.target_ref, dispatch_id),
                ttl_seconds=ttl,
                max_seconds=bounds.max_seconds,
                lease_class=bounds.lease_class,
                principal_ref=call.principal.principal_ref,
                reconcile_marker=marker,
            )

        def take(store: Any) -> Any:
            try:
                return acquire(store, None)
            except MarkerRequired as needed:
                # The host's last lease expired unreleased, and the function still
                # holds the host row lock in THIS transaction. Control decides the
                # marker over the verified reconcile observation of the EXPIRED
                # dispatch; CP names that dispatch (from the lease row) and says
                # whether it was consumed. CP derives nothing.
                expired = needed.expired_dispatch_run.rsplit("#", 1)[-1]
                marker = self._port.reconcile_marker(
                    db,
                    target_ref=call.principal.target_ref,
                    dispatch_id=expired,
                    expired_dispatch_consumed=self._port.dispatch_consumed(
                        db, target_ref=call.principal.target_ref, dispatch_id=expired
                    ),
                )
                if marker is None:
                    raise
                return acquire(store, marker)

        lease, refusal, _ = self._guarded(db, take, _ACQUIRE_NAMES)
        if refusal is not None:
            return refusal
        assert isinstance(lease, DeployLease)  # noqa: S101 - typing narrow
        return HandlerResult(
            200, {"lease_id": str(lease.lease_id), "ttl_seconds": lease.ttl_seconds}
        )

    # ── lease/covers ────────────────────────────────────────────────────────

    def _lease_and_run(
        self, call: AuthenticatedCall, payload: object
    ) -> tuple[str, str] | None:
        """`(lease_id, run)`, or None for a body of the wrong shape or types. A
        lease id that is a string but not a UUID is a lease nobody holds: it is
        answered by the caller as `lease_not_held`, never sent to the database."""
        body = _body(payload, frozenset({"lease_id", "dispatch_run"}))
        if (
            body is None
            or not _is_dispatch_id(body["dispatch_run"])
            or not isinstance(body["lease_id"], str)
        ):
            return None
        return body["lease_id"], dispatch_run(
            call.principal.target_ref, body["dispatch_run"]
        )

    def _covers(
        self, call: AuthenticatedCall, db: Any, payload: object
    ) -> HandlerResult:
        named = self._lease_and_run(call, payload)
        if named is None:
            return _refusal("bad_body", 400)
        lease_id, run = named
        if not _is_lease_id(lease_id):
            return HandlerResult(200, {"covers": False})
        _, refusal, code = self._guarded(
            db, lambda store: store.covers(lease_id=lease_id, dispatch_run=run)
        )
        if refusal is not None:
            if code in _NOT_COVERED:
                return HandlerResult(200, {"covers": False})
            return refusal
        return HandlerResult(200, {"covers": True})

    # ── lease/renew ─────────────────────────────────────────────────────────

    def _renew(
        self, call: AuthenticatedCall, db: Any, payload: object
    ) -> HandlerResult:
        named = self._lease_and_run(call, payload)
        if named is None:
            return _refusal("bad_body", 400)
        lease_id, run = named
        if not _is_lease_id(lease_id):
            return _refusal("lease_not_held", 409)
        renewal, refusal, _ = self._guarded(
            db,
            lambda store: store.renew(lease_id=lease_id, dispatch_run=run),
            _RENEW_NAMES,
        )
        if refusal is not None:
            return refusal
        return HandlerResult(
            200, {"lease_id": lease_id, "ttl_seconds": renewal.granted_seconds}
        )

    # ── lease/release ───────────────────────────────────────────────────────

    def _release(
        self, call: AuthenticatedCall, db: Any, payload: object
    ) -> HandlerResult:
        body = _body(payload, frozenset({"lease_id", "host_mutated"}))
        if (
            body is None
            or not isinstance(body["lease_id"], str)
            or not isinstance(body["host_mutated"], bool)
        ):
            return _refusal("bad_body", 400)
        if not _is_lease_id(body["lease_id"]):
            return _refusal("lease_not_held", 409)
        released, refusal, _ = self._guarded(
            db,
            lambda store: store.release(
                lease_id=body["lease_id"],
                target_ref=call.principal.target_ref,
                principal_ref=call.principal.principal_ref,
                host_mutated=body["host_mutated"],
            ),
            _RELEASE_NAMES,
        )
        if refusal is not None:
            return refusal
        return HandlerResult(200, {"released": True, "replay": released.replay})

    # ── lease/standing ──────────────────────────────────────────────────────

    def _standing(
        self, call: AuthenticatedCall, db: Any, payload: object
    ) -> HandlerResult:
        standing, refusal, code = self._guarded(
            db, lambda store: store.standing(self._host(call))
        )
        if refusal is not None:
            if code == "lease-host-unknown":
                return HandlerResult(200, {"standing": "free", "dispatch_run": None})
            return refusal
        # the contract's three: a released lease leaves the host `free`
        value = "free" if standing.standing == "released" else standing.standing
        # the dispatch whose lease expired (the run is `<target>#<id>`), else null
        expired = (
            str(standing.dispatch_run).rsplit("#", 1)[-1]
            if value == "expired_unreleased"
            else None
        )
        body: dict[str, object] = {"standing": value, "dispatch_run": expired}
        return HandlerResult(200, body)
