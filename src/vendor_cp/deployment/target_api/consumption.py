"""The consumption endpoints (DESIGN-rev3 section 2.6.1), as a service over ports.

`resolve`, `consume`, `committed`, plus `materials` and `observations`. The
router authenticates; this decides. Each endpoint authorises on the
`TargetPrincipal` and on nothing the body claims: a dispatch is served to the
target it belongs to and to no other.

## Atomic consume

One request, one fresh server session (the resolve ran in a different request,
so a different session), one transaction that also holds the spent nonce:

1. a committed marker already exists for the dispatch -> `409 already_consumed`
   with that marker (the client takes its `lookup_committed` path);
2. RE-RESOLVE, and refuse if the result differs from the `resolution_id` the
   caller holds (`resolution_changed`);
3. RE-VERIFY the attestation pair (`ConsumptionBackend.reverify_attestation`);
4. the lease: `covers(lease_id, dispatch run)` on store time, or
   `no_covering_lease`. Consumption is impossible without a live lease held by
   this run;
5. the approval-guarded composer (the held finalizer, barrier #261) runs inside
   `execute_once_platform`, which inserts `control-dispatch:<dispatch_id>` in the
   SAME transaction;
6. the committed marker is returned. Two concurrent consumes converge on one
   effect: the loser's effect rolls back with its savepoint and it is answered as
   a replay.

## What is a port, and why

`ConsumptionBackend` is Control's side: resolve, the attestation re-verification,
the lease check and the finalizer. The production adapters are NOT in this
commit. Re-verifying the pair server-side needs Foundation's verifier, and
Foundation is deliberately not a dependency of this assembly (pyproject); the
lease check is lane 5c (`deploy_covers`); and the finalizer rides the approval
barrier. Until a composition supplies them the default backend refuses closed
(`consumption_not_composed`, 503): nothing can be consumed by an unwired API.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final, Protocol

from dotmac_kernel.idempotency import execute_once_platform
from dotmac_kernel.idempotency_models import PlatformIdempotencyRecord
from sqlalchemy import select
from sqlalchemy.orm import Session

from vendor_cp.deployment.target_api import contract as c
from vendor_cp.deployment.target_api.auth import AuthenticatedCall
from vendor_cp.deployment.target_api.handlers import HandlerResult

__all__ = [
    "CONSUME_LEDGER_SCOPE",
    "ConsumptionBackend",
    "ConsumptionRefused",
    "ConsumptionService",
    "MaterialsHandler",
    "MaterialsSource",
    "ObservationHandler",
    "ObservationSink",
    "Resolution",
    "TargetApiHandlers",
    "UnwiredBackend",
]

#: The CP-side exactly-once ledger for consumption. The key is the design's
#: literal `control-dispatch:<dispatch_id>`; Control's own finalizer keeps its
#: own ledger entry, in its own scope.
CONSUME_LEDGER_SCOPE: Final = "deployment.target_consume.v1"
_CONSUME_OPERATION: Final = "vendor.deploy_target_api.consume"


class ConsumptionRefused(Exception):
    """A closed refusal. `code` never carries a value."""

    def __init__(self, code: str, status: int = 409) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


@dataclass(frozen=True, slots=True)
class Resolution:
    """Control's resolved context for one dispatch, as the target is shown it."""

    dispatch_id: str
    target_ref: str
    #: Identifies the resolved context; a re-resolve must reproduce it.
    resolution_id: str
    context: Mapping[str, object]


class ConsumptionBackend(Protocol):
    def resolve(
        self, db: Session, *, request: Mapping[str, object], store_now: datetime
    ) -> Resolution: ...

    def reverify_attestation(
        self, db: Session, *, resolution: Resolution, request: Mapping[str, object]
    ) -> None: ...

    def covers_lease(
        self,
        db: Session,
        *,
        target_ref: str,
        dispatch_id: str,
        lease_id: str,
        store_now: datetime,
    ) -> bool: ...

    def finalize(
        self,
        db: Session,
        *,
        resolution: Resolution,
        request: Mapping[str, object],
        store_now: datetime,
    ) -> Mapping[str, object]: ...


class UnwiredBackend:
    """Refuses closed: an API with no composed backend consumes nothing."""

    def _refuse(self) -> ConsumptionRefused:
        return ConsumptionRefused("consumption_not_composed", 503)

    def resolve(
        self, db: Session, *, request: Mapping[str, object], store_now: datetime
    ) -> Resolution:
        raise self._refuse()

    def reverify_attestation(
        self, db: Session, *, resolution: Resolution, request: Mapping[str, object]
    ) -> None:
        raise self._refuse()

    def covers_lease(
        self,
        db: Session,
        *,
        target_ref: str,
        dispatch_id: str,
        lease_id: str,
        store_now: datetime,
    ) -> bool:
        raise self._refuse()

    def finalize(
        self,
        db: Session,
        *,
        resolution: Resolution,
        request: Mapping[str, object],
        store_now: datetime,
    ) -> Mapping[str, object]:
        raise self._refuse()


def _refusal(refusal: ConsumptionRefused) -> HandlerResult:
    return HandlerResult(refusal.status, {"error": refusal.code})


def _request(payload: object) -> Mapping[str, object]:
    if not isinstance(payload, dict):
        raise ConsumptionRefused("bad_request", 400)
    return payload


def _text(request: Mapping[str, object], name: str) -> str:
    value = request.get(name)
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ConsumptionRefused("bad_request", 400)
    return value


def _dispatch_id(call: AuthenticatedCall, request: Mapping[str, object]) -> str:
    value = _text(request, "dispatch_id")
    try:
        # The contract's own dispatch-id grammar, through its path builder.
        c.target_path(call.principal.target_ref, "committed", dispatch_id=value)
    except c.TargetApiError:
        raise ConsumptionRefused("bad_request", 400) from None
    return value


def _own(call: AuthenticatedCall, target_ref: str) -> None:
    """Another target's dispatch is refused, whatever the body says."""
    if target_ref != call.principal.target_ref:
        raise ConsumptionRefused("dispatch_not_for_target", 403)


def _ledger_key(dispatch_id: str) -> str:
    return f"control-dispatch:{dispatch_id}"


def _committed(db: Session, dispatch_id: str) -> Mapping[str, Any] | None:
    row = db.execute(
        select(PlatformIdempotencyRecord).where(
            PlatformIdempotencyRecord.scope == CONSUME_LEDGER_SCOPE,
            PlatformIdempotencyRecord.key == _ledger_key(dispatch_id),
        )
    ).scalar_one_or_none()
    return None if row is None else dict(row.result or {})


class ConsumptionService:
    def __init__(self, backend: ConsumptionBackend) -> None:
        self._backend = backend

    def resolve(
        self, call: AuthenticatedCall, db: Session, payload: object
    ) -> HandlerResult:
        try:
            request = _request(payload)
            resolution = self._backend.resolve(
                db, request=request, store_now=call.store_now
            )
            _own(call, resolution.target_ref)
        except ConsumptionRefused as refusal:
            return _refusal(refusal)
        return HandlerResult(
            200,
            {
                "dispatch_id": resolution.dispatch_id,
                "resolution_id": resolution.resolution_id,
                "context": dict(resolution.context),
            },
        )

    def consume(
        self, call: AuthenticatedCall, db: Session, payload: object
    ) -> HandlerResult:
        try:
            return self._consume(call, db, payload)
        except ConsumptionRefused as refusal:
            return _refusal(refusal)

    def _consume(
        self, call: AuthenticatedCall, db: Session, payload: object
    ) -> HandlerResult:
        request = _request(payload)
        dispatch_id = _dispatch_id(call, request)
        resolution_id = _text(request, "resolution_id")
        lease_id = _text(request, "lease_id")

        existing = _committed(db, dispatch_id)
        if existing is not None:
            return self._replay(call, existing)

        resolution = self._backend.resolve(
            db, request=request, store_now=call.store_now
        )
        _own(call, resolution.target_ref)
        if resolution.dispatch_id != dispatch_id:
            raise ConsumptionRefused("dispatch_mismatch")
        if resolution.resolution_id != resolution_id:
            raise ConsumptionRefused("resolution_changed")
        self._backend.reverify_attestation(db, resolution=resolution, request=request)
        if not self._backend.covers_lease(
            db,
            target_ref=resolution.target_ref,
            dispatch_id=dispatch_id,
            lease_id=lease_id,
            store_now=call.store_now,
        ):
            raise ConsumptionRefused("no_covering_lease")

        def effect(session: Session) -> Mapping[str, object]:
            marker = dict(
                self._backend.finalize(
                    session,
                    resolution=resolution,
                    request=request,
                    store_now=call.store_now,
                )
            )
            return {"target_ref": resolution.target_ref, "marker": marker}

        outcome = execute_once_platform(
            db,
            scope=CONSUME_LEDGER_SCOPE,
            key=_ledger_key(dispatch_id),
            operation=effect,
            operation_name=_CONSUME_OPERATION,
        )
        if outcome.replayed:
            return self._replay(call, outcome.result)
        return HandlerResult(200, {"committed": outcome.result["marker"]})

    def _replay(
        self, call: AuthenticatedCall, stored: Mapping[str, Any]
    ) -> HandlerResult:
        _own(call, str(stored.get("target_ref")))
        return HandlerResult(
            409, {"error": "already_consumed", "committed": stored.get("marker")}
        )

    def committed(self, call: AuthenticatedCall, db: Session) -> HandlerResult:
        dispatch_id = call.coordinates.dispatch_id
        if dispatch_id is None:
            return HandlerResult(400, {"error": "bad_request"})
        stored = _committed(db, dispatch_id)
        if stored is None:
            return HandlerResult(404, {"error": "not_committed"})
        try:
            _own(call, str(stored.get("target_ref")))
        except ConsumptionRefused as refusal:
            return _refusal(refusal)
        return HandlerResult(200, {"committed": stored.get("marker")})


class MaterialsSource(Protocol):
    def pending(
        self, db: Session, *, target_ref: str, store_now: datetime
    ) -> Mapping[str, object] | None:
        """The pending-dispatch fields for this target, or None when idle.

        Exactly `contract.MATERIALS_PENDING`: `dispatch_id`, `params`,
        `app_image`, `dispatch_envelope` (Control's signed envelope) and
        `plan_snapshot`. Never a field the plan binds (those are READ from the
        snapshot by the agent).
        """


class MaterialsHandler:
    def __init__(self, source: MaterialsSource | None) -> None:
        self._source = source

    def get(self, call: AuthenticatedCall, db: Session) -> HandlerResult:
        if self._source is None:
            return HandlerResult(503, {"error": "materials_not_composed"})
        pending = self._source.pending(
            db, target_ref=call.principal.target_ref, store_now=call.store_now
        )
        document: dict[str, object] = {
            "schema": c.MATERIALS_SCHEMA,
            "pending": pending is not None,
            "store_now": call.store_now_stamp,
            "target_ref": call.principal.target_ref,
        }
        if pending is not None:
            document.update(pending)
        try:
            # What the agent will check is checked before it is sent: a
            # producer fault is OURS, and is a 500 the agent retries.
            c.check_materials_shape(document)
        except c.TargetApiError:
            return HandlerResult(500, {"error": "materials_invalid"})
        return HandlerResult(200, document)


class ObservationSink(Protocol):
    def record(
        self, db: Session, *, call: AuthenticatedCall, body: bytes
    ) -> Mapping[str, object]: ...


class ObservationHandler:
    def __init__(self, sink: ObservationSink | None) -> None:
        self._sink = sink

    def post(self, call: AuthenticatedCall, db: Session) -> HandlerResult:
        if self._sink is None:
            return HandlerResult(503, {"error": "observations_not_composed"})
        return HandlerResult(
            200, dict(self._sink.record(db, call=call, body=call.body))
        )


class TargetApiHandlers:
    """Route -> service. The lease routes are lane 5c's and refuse until it lands."""

    def __init__(
        self,
        *,
        consumption: ConsumptionService,
        materials: MaterialsHandler,
        observations: ObservationHandler,
    ) -> None:
        self._consumption = consumption
        self._materials = materials
        self._observations = observations

    def handle(
        self, call: AuthenticatedCall, db: Session, payload: object
    ) -> HandlerResult:
        route = call.coordinates.route
        if route == "materials":
            return self._materials.get(call, db)
        if route == "observations":
            return self._observations.post(call, db)
        if route == "resolve":
            return self._consumption.resolve(call, db, payload)
        if route == "consume":
            return self._consumption.consume(call, db, payload)
        if route == "committed/<dispatch_id>":
            return self._consumption.committed(call, db)
        if route.startswith("lease/"):
            return HandlerResult(501, {"error": "lease_not_composed"})
        return HandlerResult(404, {"error": "unknown_route"})
