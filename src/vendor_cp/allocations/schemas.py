"""Typed response models for the allocations read API (no bare dicts)."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel

from vendor_cp.allocations.adapter import AllocationView


class AllocationEntryResponse(BaseModel):
    capability_code: str
    quantity: int


class AllocationResponse(BaseModel):
    id: UUID
    contract_id: UUID
    customer_ref: str
    content_hash: str
    status: str
    entries: list[AllocationEntryResponse]

    @classmethod
    def of(cls, v: AllocationView) -> AllocationResponse:
        return cls(
            id=v.id,
            contract_id=v.contract_id,
            customer_ref=v.customer_ref,
            content_hash=v.content_hash,
            status=v.status,
            entries=[
                AllocationEntryResponse(
                    capability_code=e.capability_code, quantity=e.quantity
                )
                for e in v.entries
            ],
        )


__all__ = ["AllocationEntryResponse", "AllocationResponse"]
