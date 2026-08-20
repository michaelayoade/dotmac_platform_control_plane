"""The typed seam between Vendor and `dotmac-entitlement-allocation`.

The module is the allocation authority now. This is the only place Vendor speaks
to it, so the mapping from Vendor's contract vocabulary to the module's
`ContractSnapshot` lives in one reviewable file.

Typed all the way through — no `Any` at the seam. Commands and views are frozen
dataclasses, the session is a real `Session`, and the module's own value types
are used rather than dictionaries.

## Where the domain rules live, and why they stay here

The module validates ALLOCATION rules: capabilities are declared by the product's
catalogue, entries are non-empty, duplicates are refused, staging is idempotent
on the source event. It knows nothing about Vendor contracts, and should not.

Commercial Agreements now answers whether an agreement is ACTIVE and whether an
activation fact still matches its frozen digest. This adapter receives that
typed snapshot; it does not read another owner's tables or reconstruct its
lifecycle.

## Reading

`read_allocation` and `list_for_contract` load the module's own ORM types — which
are public surface (`dotmac_entitlement_allocation.__all__`) — and return Vendor
views. Licensing therefore never sees a module row, only a typed view, and
`allocation_product()` is the module's own accessor for the product a staged
allocation belongs to.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID

from dotmac_entitlement_allocation import (
    STAGED,
    Allocation,
    CapabilityCatalogueReader,
    ContractEntitlement,
    ContractSnapshot,
)
from dotmac_entitlement_allocation import (
    allocation_product as module_allocation_product,
)
from dotmac_entitlement_allocation import stage_allocation as module_stage_allocation
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from vendor_cp.contracts import adapter as agreements

#: Re-exported so callers test against the module's own constant rather than a
#: second copy of the string.
STAGED_STATUS = STAGED


@dataclass(frozen=True, slots=True)
class StageAllocationCommand:
    """Stage an allocation from an activation event.

    `source_event_id` is the platform outbox event id, and it is the idempotency
    key at both layers — the module keys its own staging on it too, so a
    redelivered event is a no-op rather than a second allocation.
    """

    source_event_id: str
    contract_id: UUID
    content_hash: str
    actor_admin_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class AllocationEntryView:
    capability_code: str
    quantity: int


@dataclass(frozen=True, slots=True)
class AllocationView:
    """One staged allocation, in Vendor's terms."""

    id: UUID
    contract_id: UUID
    product_code: str
    customer_ref: str
    content_hash: str
    status: str
    entries: tuple[AllocationEntryView, ...] = field(default_factory=tuple)
    replayed: bool = False


def _snapshot(
    agreement: agreements.ActiveAgreementSnapshot,
    command: StageAllocationCommand,
) -> ContractSnapshot:
    """Translate the agreement owner's accepted snapshot to allocation input."""
    return ContractSnapshot(
        contract_ref=agreement.agreement_id,
        product_code=agreement.product_code,
        customer_ref=agreement.counterparty_ref,
        content_hash=command.content_hash,
        source_event_id=command.source_event_id,
        entries=tuple(
            ContractEntitlement(capability_code=capability_code, quantity=quantity)
            for capability_code, quantity in agreement.capabilities
        ),
    )


def stage_allocation(
    db: Session,
    command: StageAllocationCommand,
    *,
    catalogues: CapabilityCatalogueReader,
) -> AllocationView:
    """Project an activated contract into the module's immutable allocation.

    Commercial Agreements owns and checks agreement state. Everything about
    what a valid allocation IS belongs to Entitlement Allocation.
    """
    agreement = agreements.active_snapshot(
        db,
        command.contract_id,
        expected_content_hash=command.content_hash,
    )

    view = module_stage_allocation(
        db,
        _snapshot(agreement, command),
        catalogues=catalogues,
        actor_admin_id=command.actor_admin_id,
    )
    return AllocationView(
        id=view.id,
        contract_id=view.contract_ref,
        product_code=view.product_code,
        customer_ref=view.customer_ref,
        content_hash=view.content_hash,
        status=str(view.status),
        entries=tuple(
            AllocationEntryView(
                capability_code=entry.capability_code, quantity=entry.quantity
            )
            for entry in view.entries
        ),
        replayed=view.replayed,
    )


def _of_row(row: Allocation) -> AllocationView:
    return AllocationView(
        id=row.id,
        contract_id=row.contract_ref,
        product_code=row.product_code,
        customer_ref=row.customer_ref,
        content_hash=row.content_hash,
        status=str(row.status),
        entries=tuple(
            AllocationEntryView(
                capability_code=entry.capability_code, quantity=entry.quantity
            )
            for entry in row.entries
        ),
    )


def read_allocation(db: Session, allocation_id: UUID) -> AllocationView | None:
    """One staged allocation by id, or `None`."""
    row = db.get(Allocation, allocation_id)
    return None if row is None else _of_row(row)


def allocation_product(db: Session, allocation_id: UUID) -> str:
    """The product a staged allocation belongs to — the module's own accessor.

    Licensing binds a licence to a product, and this is where that product comes
    from: the allocation, not the caller. A caller-supplied product was the
    defect ADR-0003 removed.
    """
    return module_allocation_product(db, allocation_id)


def list_for_contract(db: Session, contract_id: UUID) -> list[AllocationView]:
    rows = db.scalars(
        select(Allocation)
        .where(Allocation.contract_ref == contract_id)
        .options(selectinload(Allocation.entries))
        .order_by(Allocation.created_at)
    ).all()
    return [_of_row(row) for row in rows]


__all__ = [
    "STAGED_STATUS",
    "AllocationEntryView",
    "AllocationView",
    "StageAllocationCommand",
    "allocation_product",
    "list_for_contract",
    "read_allocation",
    "stage_allocation",
]
