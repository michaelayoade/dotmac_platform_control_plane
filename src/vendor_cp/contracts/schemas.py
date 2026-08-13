"""Typed request/response models for the contracts API (no bare dicts)."""

from __future__ import annotations

from datetime import date
from uuid import UUID

from pydantic import BaseModel, Field

from vendor_cp.contracts.service import ContractView


class LineRequest(BaseModel):
    offer_code: str = Field(min_length=1, max_length=120)
    offer_version: int = Field(ge=1)
    capability_code: str = Field(min_length=1, max_length=120)
    quantity: int = Field(ge=1, default=1)


class CreateDraftRequest(BaseModel):
    command_id: str = Field(min_length=1, max_length=200)
    product_code: str = Field(min_length=1, max_length=120)
    customer_ref: str = Field(min_length=1, max_length=200)
    legal_entity: str = Field(min_length=1, max_length=200)
    currency: str = Field(min_length=3, max_length=3)
    term_start: date
    term_end: date
    activation_rule: str = Field(default="manual_confirmation", max_length=60)
    lines: list[LineRequest] = Field(min_length=1)


class SubmitRequest(BaseModel):
    command_id: str = Field(min_length=1, max_length=200)
    approval_policy_code: str = Field(min_length=1, max_length=120)
    approval_policy_version: int = Field(ge=1)
    submitter_id: UUID


class TransitionRequest(BaseModel):
    command_id: str = Field(min_length=1, max_length=200)
    reason: str | None = Field(default=None, max_length=500)
    activation_evidence: str | None = Field(default=None, max_length=500)
    effective_date: date | None = None
    impact_acknowledged: bool = False


class LineResponse(BaseModel):
    offer_code: str
    offer_version: int
    capability_code: str
    quantity: int
    unit_amount: str | None
    unit_currency_code: str | None


class ContractResponse(BaseModel):
    id: UUID
    product_code: str
    customer_ref: str
    status: str
    content_hash: str | None
    activation_rule: str
    lines: list[LineResponse]

    @classmethod
    def of(cls, v: ContractView) -> ContractResponse:
        return cls(
            id=v.id,
            product_code=v.product_code,
            customer_ref=v.customer_ref,
            status=v.status,
            content_hash=v.content_hash,
            activation_rule=v.activation_rule,
            lines=[
                LineResponse(
                    offer_code=ln.offer_code,
                    offer_version=ln.offer_version,
                    capability_code=ln.capability_code,
                    quantity=ln.quantity,
                    unit_amount=ln.unit_amount,
                    unit_currency_code=ln.unit_currency_code,
                )
                for ln in v.lines
            ],
        )


__all__ = [
    "LineRequest",
    "CreateDraftRequest",
    "SubmitRequest",
    "TransitionRequest",
    "LineResponse",
    "ContractResponse",
]
