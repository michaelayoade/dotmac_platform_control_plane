"""The platform-outbox consumer that stages allocations on contract activation.

`ContractEventConsumer` is a `PlatformDeliveryTransport` (kernel a6): the platform
relay worker claims `contract.*` events and calls `deliver` on a `platform_api`
session. This consumer dispatches `contract.activated` to the allocation adapter
and ignores every other event type.

This is the seam that keeps ContractService and the allocation authority
decoupled: they never call each other. ContractService emits an event, the relay
delivers it, and the allocation is staged in reaction. At-least-once delivery is
safe because staging is idempotent on the source event id — at both layers, since
the module keys its own staging on it too.

The catalogue reader is resolved per delivery rather than held, because it is
built from configured release pins and held catalogue evidence that an operator
can change between deliveries; caching it here would pin a decision this
consumer has no authority over.
"""

from __future__ import annotations

from uuid import UUID

from dotmac_entitlement_allocation import CapabilityCatalogueReader
from dotmac_kernel.messaging import ClaimedPlatformEvent
from sqlalchemy.orm import Session

from vendor_cp.allocations import adapter
from vendor_cp.offers.catalog import configured_product_capability_catalogues

_ACTIVATED = "contract.activated"


class ContractEventConsumer:
    """Stages an allocation when a contract activates; ignores other events."""

    def deliver(self, event: ClaimedPlatformEvent, platform_db: Session) -> None:
        if event.event_type != _ACTIVATED:
            return  # not ours — a no-op delivery (the relay settles it as sent)
        payload = event.payload
        adapter.stage_allocation(
            platform_db,
            adapter.StageAllocationCommand(
                source_event_id=str(event.id),
                contract_id=UUID(str(payload["contract_id"])),
                content_hash=str(payload["content_hash"]),
                customer_ref=str(payload["customer_ref"]),
            ),
            catalogues=self._catalogues(platform_db),
        )

    def _catalogues(self, platform_db: Session) -> CapabilityCatalogueReader:
        return configured_product_capability_catalogues(platform_db)


__all__ = ["ContractEventConsumer"]
