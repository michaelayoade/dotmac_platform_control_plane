"""Stage allocations from Commercial Agreements activation facts.

`ContractEventConsumer` is a `PlatformDeliveryTransport`: the platform relay
dispatches the module's versioned activation fact and ignores other event types.

This is the seam that keeps both authorities decoupled: Commercial Agreements
emits a fact, the relay delivers it, and the allocation is staged in reaction.
At-least-once delivery is
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
from vendor_cp.contracts.adapter import ACTIVATED_EVENT_TYPE
from vendor_cp.offers.catalog import configured_product_capability_catalogues


class ContractEventConsumer:
    """Stages an allocation when a contract activates; ignores other events."""

    def deliver(self, event: ClaimedPlatformEvent, platform_db: Session) -> None:
        if event.event_type != ACTIVATED_EVENT_TYPE:
            return  # not ours — a no-op delivery (the relay settles it as sent)
        payload = event.payload
        adapter.stage_allocation(
            platform_db,
            adapter.StageAllocationCommand(
                source_event_id=str(event.id),
                contract_id=UUID(str(payload["agreement_id"])),
                content_hash=str(payload["content_hash"]),
            ),
            catalogues=self._catalogues(platform_db),
        )

    def _catalogues(self, platform_db: Session) -> CapabilityCatalogueReader:
        return configured_product_capability_catalogues(platform_db)


__all__ = ["ACTIVATED_EVENT_TYPE", "ContractEventConsumer"]
