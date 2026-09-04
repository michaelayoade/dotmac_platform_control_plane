"""Composes the drain: the kernel's platform relay worker + Vendor's consumer.

This module owns no decision. The kernel owns leasing, backoff, dead-lettering
and the two connection identities; `dotmac-entitlement-allocation` owns what a
valid allocation is; `dotmac-commercial-agreements` owns whether an agreement is
active. All that was missing was something to construct
`ContractEventConsumer` and hand it to `dotmac_kernel.messaging.platform_worker`,
and that is the whole of this file.

## Two connections, THREE ROLES, ONE DATABASE

Read this before reporting a rule-8 or deny-case-D1 violation, because the shape
is easy to misread as a second database:

* the **dispatcher** connection is the `platform_outbox_dispatcher` role, which
  holds EXECUTE on `claim_platform_outbox_batch` and
  `settle_platform_outbox_event` and NO table privilege of any kind — it can
  lease and settle, and it can never read a business table;
* the **delivery** connection is the ordinary `platform_api` role, taken from
  the assembly's existing runtime, and is where the consumer stages.

That is a third ROLE on the one control-plane database, not a third session
factory and not a second database. `AGENTS.md` rule 2 forbids vendor code
building an engine; `dotmac_starter_mt` hard rule 8 states the sanctioned path
for a product that needs its own credential: construct your own
`dotmac_kernel.session_runtime.DatabaseRuntime` rather than growing another
session factory. That is exactly what `dispatcher_runtime` does — the kernel's
own instantiable runtime, its public surface, with a DSN this deployment
resolved. No `create_engine`, `sessionmaker` or `psycopg.connect` appears in
vendor code, so deny case D1's connection allowlist stays empty.

## An unconfigured relay REFUSES

`RelayNotConfiguredError` rather than a run that claims nothing and reports
success. "Drained 0 events" from a relay that never had a credential is
indistinguishable from "drained 0 events" from a healthy idle relay, and the
whole subject of this package is that those two must never look alike.

## Delivery failure is the kernel's business

A refusal from `stage_allocation` — a superseded agreement, a content hash that
no longer matches — raises out of `deliver`, and the kernel worker backs it off
and eventually dead-letters it. That is deliberate and is not caught here: a
dead letter is VISIBLE and `vendor_cp.relay.health` reports it, where swallowing
the refusal would settle the event as sent and restore exactly the silence this
package removes.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from dotmac_kernel.messaging import RelayPolicy
from dotmac_kernel.messaging.platform_worker import (
    PlatformDeliveryTransport,
    SessionFactory,
    run_once,
)
from dotmac_kernel.session_runtime import DatabaseRuntime

from vendor_cp.allocations.consumer import ContractEventConsumer
from vendor_cp.config import VendorSettings, vendor_settings
from vendor_cp.relay import heartbeat

logger = logging.getLogger("vendor_cp.relay.runner")

#: The kernel's own prod-safe tuning, bound once. A module-level singleton
#: rather than a call in a default argument: `RelayPolicy` is frozen so the
#: shared instance cannot be mutated by a caller, and one bound object keeps the
#: default stable for the life of the process.
DEFAULT_POLICY: Final[RelayPolicy] = RelayPolicy()


class RelayNotConfiguredError(RuntimeError):
    """No dispatcher credential, so there is nothing to drain WITH.

    Distinct from "nothing to drain": one is a deployment that cannot run the
    relay, the other is a relay with an empty queue, and they are the two states
    this package exists to keep apart.
    """


@dataclass(frozen=True, slots=True)
class DrainReport:
    """What one drain pass did. `claimed` is events LEASED, not events staged.

    The two differ whenever a delivery fails, and reporting the second as the
    first would let a pass in which every event dead-lettered read as a
    successful drain. Which events succeeded is
    `vendor_cp.relay.health`'s question, asked of the durable table rather than
    of this process's memory.
    """

    worker_id: str
    claimed: int


@dataclass(frozen=True, slots=True)
class RelayComposition:
    """The three things a drain needs, named once so a caller cannot half-build one.

    `composed()` builds the production arrangement from configuration. A caller
    that passes its own is a rehearsal against a scratch database — the
    Postgres drain proof substitutes the two DSNs and NOTHING else, so the
    kernel's real claim/settle functions and the real consumer are what run.
    """

    dispatcher_sessions: SessionFactory
    delivery_sessions: SessionFactory
    transport: PlatformDeliveryTransport


def dispatcher_runtime(dsn: str) -> DatabaseRuntime:
    """The dispatcher role's runtime — the kernel's, constructed by the product.

    Both URLs are the dispatcher DSN so exactly one credential is in play; only
    the platform half is ever used, because the dispatcher has no tenant work
    and no tenant privilege. The pool is one connection: the relay is a single
    sequential poller, and sizing it like a request pool would hold idle
    connections open for a role that must be able to do nothing else.
    """
    return DatabaseRuntime.from_urls(
        database_url=dsn,
        platform_database_url=dsn,
        pool_size=1,
        max_overflow=0,
        platform_pool_size=1,
        platform_max_overflow=0,
    )


def require_dispatcher_dsn(settings: VendorSettings = vendor_settings) -> str:
    """The configured dispatcher DSN, or a refusal naming what is missing."""
    dsn = settings.relay_dispatcher_database_url.strip()
    if not dsn:
        raise RelayNotConfiguredError(
            "VENDOR_RELAY_DISPATCHER_DATABASE_URL is unset, so the platform "
            "outbox relay has no dispatcher credential and cannot claim a "
            "batch. Set it to the `platform_outbox_dispatcher` role's DSN "
            "against the one control-plane database."
        )
    return dsn


def composed(settings: VendorSettings = vendor_settings) -> RelayComposition:
    """The production arrangement: dispatcher credential, delivery credential, consumer.

    The delivery factory is the ASSEMBLY'S EXISTING runtime, reached through its
    public name. A relay that built its own platform engine would be the second
    session factory hard rule 8 forbids — the dispatcher needs its own because
    its CREDENTIAL differs, and this one does not.

    The transport is returned as the kernel's Protocol rather than the concrete
    class, because what the worker needs is a `deliver`, and naming the protocol
    here is what keeps a second transport from being bolted onto the consumer.
    """
    from dotmac_kernel.db import runtime

    dispatcher = dispatcher_runtime(require_dispatcher_dsn(settings))
    return RelayComposition(
        dispatcher_sessions=dispatcher.platform_session_factory,
        delivery_sessions=runtime.platform_session_factory,
        transport=ContractEventConsumer(),
    )


def drain_once(
    *,
    worker_id: str,
    composition: RelayComposition | None = None,
    settings: VendorSettings = vendor_settings,
    policy: RelayPolicy = DEFAULT_POLICY,
    now: datetime | None = None,
) -> DrainReport:
    """Claim one batch and deliver it. Returns how many were LEASED.

    One pass, then return — this is the shape an operator invokes and the shape
    a timer invokes. `run` is the long-lived peer.
    """
    arrangement = composition or composed(settings)
    dispatcher_db = arrangement.dispatcher_sessions()
    try:
        claimed = run_once(
            dispatcher_db=dispatcher_db,
            platform_session_factory=arrangement.delivery_sessions,
            transport=arrangement.transport,
            worker_id=worker_id,
            policy=policy,
        )
    finally:
        dispatcher_db.close()
    _stamp(arrangement, worker_id=worker_id, claimed=claimed > 0, now=now)
    return DrainReport(worker_id=worker_id, claimed=claimed)


def _stamp(
    arrangement: RelayComposition,
    *,
    worker_id: str,
    claimed: bool,
    now: datetime | None,
) -> None:
    """Record this poll, on its OWN transaction, and never fail the drain.

    Its own session and its own commit, deliberately: the heartbeat must be
    durable even on a cycle where every delivery failed, and sharing the
    delivery transaction would roll the liveness fact back with the work. A
    relay that is alive and failing every delivery is exactly the WEDGED state
    `vendor_cp.relay.health` exists to name, and it can only name it if the
    heartbeat survives the failure.

    A heartbeat that cannot be written is LOGGED and swallowed. It is an
    observation, not the job: refusing to drain because the liveness table is
    unwritable would turn a reporting fault into an outage. Health notices
    anyway — the heartbeat ages, and a stale heartbeat is `RELAY_NOT_RUNNING`,
    which is the correct thing to say about a relay whose liveness cannot be
    established.
    """
    session = arrangement.delivery_sessions()
    try:
        heartbeat.stamp(
            session,
            worker_id=worker_id,
            now=now or datetime.now(UTC),
            claimed=claimed,
        )
        session.commit()
    except Exception as error:  # noqa: BLE001 - reported, never fatal
        session.rollback()
        logger.warning("relay heartbeat could not be recorded: %r", error)
    finally:
        session.close()


def run(
    *,
    worker_id: str,
    stop: threading.Event,
    composition: RelayComposition | None = None,
    settings: VendorSettings = vendor_settings,
    policy: RelayPolicy = DEFAULT_POLICY,
    poll_interval: float = 1.0,
) -> None:
    """Poll until `stop` is set. The long-lived process the deployment runs.

    ## Why this loop is here and not `dotmac_kernel.messaging.platform_worker
    .run_forever`

    The kernel's `run_forever` is a loop over its own `run_once` with an
    interruptible idle sleep, and it has no seam for a per-cycle side effect.
    The heartbeat has to be stamped on EVERY cycle including the idle ones —
    that is the entire reason it exists — so the cadence is owned here.

    What is NOT re-implemented is the part that matters: `run_once` is the
    kernel's, unchanged, and it still owns claiming, delivery, settling, backoff
    and dead-lettering. What this file owns is when to call it and what to
    record afterwards. A fresh dispatcher session per iteration and an
    interruptible sleep on an idle poll are the kernel loop's own discipline,
    kept deliberately identical.

    `stop` is supplied by the caller rather than created here so the process
    that installs the signal handlers owns the shutdown.
    """
    arrangement = composition or composed(settings)
    logger.info("platform relay worker %s starting", worker_id)
    while not stop.is_set():
        report = drain_once(
            worker_id=worker_id,
            composition=arrangement,
            policy=policy,
        )
        if report.claimed == 0:
            # Interruptible, so a stop during an idle window is immediate rather
            # than waiting out the interval.
            stop.wait(poll_interval)
    logger.info("platform relay worker %s stopped", worker_id)


__all__ = [
    "DEFAULT_POLICY",
    "DrainReport",
    "RelayComposition",
    "RelayNotConfiguredError",
    "composed",
    "dispatcher_runtime",
    "drain_once",
    "require_dispatcher_dsn",
    "run",
]
