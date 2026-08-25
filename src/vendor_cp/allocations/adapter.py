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

The checks that stay on this side are the ones about VENDOR'S contract — that it
is ACTIVE, and that the activation event's digest still matches the contract's
current version. A stale event must not project an allocation, and only Vendor
can say what "stale" means about its own aggregate. Pushing those into the module
would give it an opinion about a domain it deliberately has no model of.

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
from dotmac_kernel import NotFoundError
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from vendor_cp.contracts.models import Contract, ContractStatus

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
    customer_ref: str
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


def _snapshot(contract: Contract, command: StageAllocationCommand) -> ContractSnapshot:
    """Vendor's activated contract as the module's `ContractSnapshot`.

    `product_code` is required by the module and is never invented: v011 made
    commercial identity product-qualified precisely so this could be read rather
    than guessed, and a contract without one cannot be allocated.
    """
    product_code = contract.product_code
    if not product_code:
        raise NotFoundError(
            f"contract {contract.id} carries no product_code; an allocation "
            "cannot be attributed to a product that was never recorded"
        )
    return ContractSnapshot(
        contract_ref=contract.id,
        product_code=product_code,
        customer_ref=contract.customer_ref,
        content_hash=command.content_hash,
        source_event_id=command.source_event_id,
        entries=tuple(
            ContractEntitlement(
                capability_code=line.capability_code, quantity=line.quantity
            )
            for line in contract.lines
        ),
    )


def stage_allocation(
    db: Session,
    command: StageAllocationCommand,
    *,
    catalogues: CapabilityCatalogueReader,
) -> AllocationView:
    """Project an activated contract into the module's immutable allocation.

    The staleness checks are Vendor's, about Vendor's contract; everything about
    what a valid allocation IS belongs to the module.
    """
    contract = db.get(Contract, command.contract_id)
    if contract is None:
        raise NotFoundError(f"contract {command.contract_id} not found")
    if contract.status != ContractStatus.ACTIVE.value:
        raise NotFoundError(
            f"contract {command.contract_id} is {contract.status!r}, not active "
            "— nothing to allocate"
        )
    if contract.content_hash != command.content_hash:
        raise NotFoundError(
            "activation event content_hash does not match the contract's current "
            "version — stale event, skipping"
        )

    view = module_stage_allocation(
        db,
        _snapshot(contract, command),
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
