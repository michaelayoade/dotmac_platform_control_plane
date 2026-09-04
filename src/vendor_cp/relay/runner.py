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

import threading
from dataclasses import dataclass
from typing import Final

from dotmac_kernel.messaging import RelayPolicy
from dotmac_kernel.messaging.platform_worker import (
    PlatformDeliveryTransport,
    SessionFactory,
    run_forever,
    run_once,
)
from dotmac_kernel.session_runtime import DatabaseRuntime

from vendor_cp.allocations.consumer import ContractEventConsumer
from vendor_cp.config import VendorSettings, vendor_settings

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
    return DrainReport(worker_id=worker_id, claimed=claimed)


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

    `stop` is supplied by the caller rather than created here so the process
    that installs the signal handlers owns the shutdown, which is the kernel
    worker's own contract.
    """
    arrangement = composition or composed(settings)
    run_forever(
        dispatcher_session_factory=arrangement.dispatcher_sessions,
        platform_session_factory=arrangement.delivery_sessions,
        transport=arrangement.transport,
        worker_id=worker_id,
        stop=stop,
        policy=policy,
        poll_interval=poll_interval,
    )


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
