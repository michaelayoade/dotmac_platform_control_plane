"""`AllocationService` — stages an IMMUTABLE allocation from `contract.activated`.

A SEPARATE owner from `ContractService`. It reacts to the `contract.activated`
platform event and projects the activated contract's lines into an immutable
`Allocation` (what the customer is entitled to). Its boundary is explicit and
narrow:

- It **reads** authoritative contract state; it does not make commercial decisions.
- It stages an immutable allocation, keyed uniquely on `(contract_id,
  content_hash)` — one allocation per activated version; re-delivery is a no-op.
- It **NEVER writes `tenant_entitlement_grants`** and never touches a product data
  plane. Delivery of the allocation as a signed/versioned envelope, and the
  product-local WS2 grant + ack, are the WS8/C4 slice (design-only).

Idempotent via `process_once_platform` keyed on the source event id — the platform
relay guarantees at-least-once, so a redelivered event stages nothing new.

Transaction-authority contract: receives a `Session` and only add/flush.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from uuid import UUID

from dotmac_kernel import NotFoundError, write_platform_audit_event
from dotmac_kernel.messaging import process_once_platform
from sqlalchemy import select
from sqlalchemy.orm import Session

from vendor_cp.allocations.models import Allocation, AllocationEntry, AllocationStatus
from vendor_cp.contracts.models import Contract, ContractStatus

_CMD_STAGE = "vendor.allocation.stage"


@dataclass(frozen=True, slots=True)
class StageAllocationCommand:
    """Stage an allocation from an activation event. `source_event_id` is the
    platform outbox event id — the idempotency key."""

    source_event_id: str
    contract_id: UUID
    content_hash: str
    customer_ref: str
    actor_admin_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class AllocationEntryView:
    capability_code: str
    quantity: int


@dataclass(frozen=True, slots=True)
class AllocationView:
    id: UUID
    contract_id: UUID
    customer_ref: str
    content_hash: str
    status: str
    entries: tuple[AllocationEntryView, ...] = field(default_factory=tuple)


def _view(row: Allocation) -> AllocationView:
    return AllocationView(
        id=row.id,
        contract_id=row.contract_id,
        customer_ref=row.customer_ref,
        content_hash=row.content_hash,
        status=row.status,
        entries=tuple(
            AllocationEntryView(capability_code=e.capability_code, quantity=e.quantity)
            for e in row.entries
        ),
    )


def _find(session: Session, contract_id: UUID, content_hash: str) -> Allocation | None:
    return session.execute(
        select(Allocation).where(
            Allocation.contract_id == contract_id,
            Allocation.content_hash == content_hash,
        )
    ).scalar_one_or_none()


def stage_allocation(db: Session, command: StageAllocationCommand) -> AllocationView:
    """Stage the immutable allocation for an activated contract version. Idempotent:
    a redelivered event (same `source_event_id`) or an already-staged
    `(contract_id, content_hash)` is a no-op. Reads the authoritative contract's
    lines; writes NO product grant."""

    def handler(session: Session) -> Mapping[str, object]:
        existing = _find(session, command.contract_id, command.content_hash)
        if existing is not None:
            return {"id": str(existing.id)}

        contract = session.get(Contract, command.contract_id)
        if contract is None:
            raise NotFoundError(f"contract {command.contract_id} not found")
        # Defensive: only project an ACTIVE contract whose current version matches
        # the activated one. (Contracts are immutable once submitted, so this holds
        # unless the event is stale.)
        if contract.status != ContractStatus.ACTIVE.value:
            raise NotFoundError(
                f"contract {command.contract_id} is {contract.status!r}, "
                "not active — nothing to allocate"
            )
        if contract.content_hash != command.content_hash:
            raise NotFoundError(
                "activation event content_hash does not match the contract's "
                "current version — stale event, skipping"
            )

        allocation = Allocation(
            contract_id=contract.id,
            customer_ref=contract.customer_ref,
            content_hash=command.content_hash,
            status=AllocationStatus.STAGED.value,
            source_event_id=command.source_event_id,
        )
        session.add(allocation)
        session.flush()
        for line in contract.lines:
            session.add(
                AllocationEntry(
                    allocation_id=allocation.id,
                    capability_code=line.capability_code,
                    quantity=line.quantity,
                )
            )
        session.flush()
        write_platform_audit_event(
            session,
            actor_admin_id=command.actor_admin_id,
            action="vendor.allocation.staged",
            entity_type="allocation",
            entity_id=str(allocation.id),
            details={
                "contract_id": str(contract.id),
                "customer_ref": contract.customer_ref,
                "content_hash": command.content_hash,
                "entries": len(contract.lines),
            },
        )
        return {"id": str(allocation.id)}

    process_once_platform(
        db,
        command_id=command.source_event_id,
        command_type=_CMD_STAGE,
        handler=handler,
    )
    row = _find(db, command.contract_id, command.content_hash)
    if row is None:  # unreachable: staged above or already present
        raise RuntimeError("allocation missing after stage_allocation")
    return _view(row)


def list_for_contract(db: Session, contract_id: UUID) -> list[AllocationView]:
    rows = db.execute(
        select(Allocation)
        .where(Allocation.contract_id == contract_id)
        .order_by(Allocation.created_at)
    ).scalars()
    return [_view(r) for r in rows]


__all__ = [
    "StageAllocationCommand",
    "AllocationEntryView",
    "AllocationView",
    "stage_allocation",
    "list_for_contract",
]
