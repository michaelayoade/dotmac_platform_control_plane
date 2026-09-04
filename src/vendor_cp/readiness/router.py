"""`GET /health/ready` — the dependency-aware probe, as a thin adapter.

## The path is the kernel's, not a choice

`/health/ready` is a member of `dotmac_kernel.middleware.tenant._HEALTH_PATHS`,
and that is why it is this path and not a nicer-looking one. The tenant resolver
runs before every route and QUERIES THE DATABASE to resolve a host; the two
health paths short-circuit before it, with the kernel's own comment saying
liveness and readiness probes "run before a DB may even be reachable".

An earlier draft of this route answered on `/readyz`. It went through tenant
resolution, so with the database unreachable the middleware raised first and the
probe returned 500 — the exact opposite of a readiness answer, and precisely
when readiness matters most. The kernel had already reserved the right path and
left it for the assembly to implement.

Note what the exemption does and does not say. The middleware must not touch the
database on this path; the ROUTE deliberately does, because asking the
dependency is the whole point. The two are compatible: the exemption exists so a
probe can answer at all when the database is gone, which is what lets this one
answer 503 instead of 500.

No prefix: `mount_features` calls `include_router` without one, so this router
owns its own path. A readiness probe under `/platform/vendor/...` would sit
behind the authentication that prefix carries, and an orchestrator holds no
credential.

## Unguarded, and the reasons that makes it acceptable here

This is the one vendor route with no `require_*` guard, which is a governance
exception and is stated as one rather than left to be noticed. Three properties
make it a probe rather than a hole, and each is a real constraint rather than a
reassurance:

* It reveals nothing an operator's adversary can act on. The response is a
  boolean and one member of a closed enum
  (`vendor_cp.readiness.service.ReadinessDetail`) — no driver message, no host,
  no role, no timing, and deliberately no COUNT. The relay verdict published
  here says a drain is stalled; it never says how much is queued. The depths,
  ages and dead-letter totals are on `vendor_cp.relay.health.RelayHealth` and
  are rendered only by `dotmac-platform relay health`, which needs a shell on
  the host.
* It costs nothing an attacker could not already cause. `SELECT 1` plus five
  counts restricted by `status` against the kernel's own index on a pooled
  session is cheaper than any authenticated route, so it is not the lever
  anyone would reach for.
* It is not published. `docker-compose.production.yml` binds the application
  port to `127.0.0.1` and the vhost proxies only what it names, so reaching
  this route means already being on the host.

The kernel's `/health` is unguarded for the same reason and by the same owner's
decision; this route is its dependency-aware counterpart, not a second liveness.

`503` rather than `200` with a false body: an orchestrator reads the STATUS, and
a probe that returned 200 saying "not ready" would be ready as far as every
tool that matters is concerned.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from dotmac_kernel.db import get_platform_db
from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.orm import Session

from vendor_cp.config import vendor_settings
from vendor_cp.readiness.schemas import ReadinessResponse
from vendor_cp.readiness.service import check_readiness

router = APIRouter(tags=["readiness"])

Db = Annotated[Session, Depends(get_platform_db)]


@router.get(
    "/health/ready",
    response_model=ReadinessResponse,
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ReadinessResponse}},
    summary="Whether this process can reach the dependencies it needs to serve",
)
def health_ready(db: Db, response: Response) -> ReadinessResponse:
    """Ask the service, set the status, return the two fields. Nothing else.

    Reading the clock and the configured windows here is the adapter's job, not
    a decision: the service is handed `now` and every window so its answer is
    reproducible and the thresholds stay the deployment's configuration.
    """
    report = check_readiness(
        db,
        now=datetime.now(UTC),
        overdue_after=timedelta(seconds=vendor_settings.relay_overdue_seconds),
        stale_lease_after=timedelta(seconds=vendor_settings.relay_stale_lease_seconds),
        heartbeat_stale_after=timedelta(
            seconds=vendor_settings.relay_heartbeat_stale_seconds
        ),
        settled_within=timedelta(seconds=vendor_settings.relay_settled_within_seconds),
    )
    if not report.ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return ReadinessResponse(ready=report.ready, detail=report.detail.value)
