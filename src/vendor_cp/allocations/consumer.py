"""The platform-outbox consumer that drives AllocationService.

`ContractEventConsumer` is a `PlatformDeliveryTransport` (kernel a6): the platform
relay worker claims `contract.*` events and calls `deliver` on a `platform_api`
session. This consumer dispatches `contract.activated` to `stage_allocation`
(idempotent via `process_once_platform`) and ignores every other event type.

This is the seam that keeps ContractService and AllocationService decoupled: they
never call each other; ContractService emits an event, the relay delivers it, and
AllocationService reacts. At-least-once delivery is safe because staging is
idempotent on the source event id.
"""

from __future__ import annotations

from uuid import UUID

from dotmac_kernel.messaging import ClaimedPlatformEvent
from sqlalchemy.orm import Session

from vendor_cp.allocations import service

_ACTIVATED = "contract.activated"


class ContractEventConsumer:
    """Stages an allocation when a contract activates; ignores other events."""

    def deliver(self, event: ClaimedPlatformEvent, platform_db: Session) -> None:
        if event.event_type != _ACTIVATED:
            return  # not ours — a no-op delivery (the relay settles it as sent)
        payload = event.payload
        service.stage_allocation(
            platform_db,
            service.StageAllocationCommand(
                source_event_id=str(event.id),
                contract_id=UUID(str(payload["contract_id"])),
                content_hash=str(payload["content_hash"]),
                customer_ref=str(payload["customer_ref"]),
            ),
        )


__all__ = ["ContractEventConsumer"]
