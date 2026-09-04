"""The platform outbox relay — the missing middle of activation -> allocation.

Commercial Agreements enqueues `agreement.activated.v1` into
`public.platform_outbox_events` atomically with the transition. Entitlement
Allocation stages an allocation when `vendor_cp.allocations.consumer
.ContractEventConsumer` is handed that event. Between those two halves sits a
drain, and until this package there was none: the class implementing the
kernel's `PlatformDeliveryTransport` was constructed nowhere under `src/`, no
process claimed a batch, and an activated agreement therefore looked complete
while producing no allocation. The 2026-08-30 composition census measured that
directly (s 6.3).

Two modules, and the split is the point:

- `runner` composes the drain. It owns no decision — the kernel owns leasing,
  backoff and dead-lettering; Entitlement Allocation owns what a valid
  allocation is; this only introduces them to each other.
- `health` reports whether the drain is happening. It writes nothing.

Neither is a SURFACE, either: this package bears no route and carries no
manifest, so ADR-0019's derived `route_bearing_codes` cannot see it and no
profile's `surface_inventory` names it. The operator detail lives on
`dotmac-platform relay health`; the verdict rides on `readiness`, which is the
sole member of `NEVER_WITHHELD_SURFACES`. A relay-stall report a deployment
could switch off would be the same defect as a readiness probe with an off
switch.

Neither is a second allocation authority. `ContractEventConsumer` remains an
adapter over `vendor_cp.allocations.adapter.stage_allocation`, and no name from
the allocation module's AUTHORITY surface appears in this package
(`tests/architecture/test_allocations_authority.py`).
"""
