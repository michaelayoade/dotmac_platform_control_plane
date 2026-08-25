"""Typed HTTP values for Vendor's Commercial Agreements adapter."""

from __future__ import annotations

from datetime import date, datetime
from uuid import UUID

from pydantic import BaseModel, Field

from vendor_cp.contracts.adapter import ContractView


class LineRequest(BaseModel):
    offer_code: str = Field(min_length=1, max_length=120)
    offer_version: int = Field(ge=1)
    capability_code: str = Field(min_length=1, max_length=120)
    quantity: int = Field(ge=1, default=1)


class CreateDraftRequest(BaseModel):
    command_id: str = Field(min_length=1, max_length=200)
    reference: str = Field(min_length=1, max_length=120)
    product_code: str = Field(min_length=1, max_length=120)
    counterparty_ref: str = Field(min_length=1, max_length=200)
    agreement_type: str = Field(min_length=1, max_length=120)
    term_start: date
    term_end: date
    lines: list[LineRequest] = Field(min_length=1)


class ProposeRequest(BaseModel):
    command_id: str = Field(min_length=1, max_length=200)
    approval_policy_code: str = Field(min_length=1, max_length=120)
    approval_policy_version: int = Field(ge=1)
    requested_by: UUID
    expected_version: int | None = Field(default=None, ge=1)


class ApprovalRequest(BaseModel):
    command_id: str = Field(min_length=1, max_length=200)
    approval_request_id: UUID
    expected_version: int | None = Field(default=None, ge=1)


class ActivateRequest(ApprovalRequest):
    activation_rule: str = Field(min_length=1, max_length=120)
    activation_reference: str = Field(min_length=1, max_length=200)
    activation_satisfied_at: datetime


class TransitionRequest(BaseModel):
    command_id: str = Field(min_length=1, max_length=200)
    expected_status: str | None = Field(default=None, max_length=24)
    expected_version: int | None = Field(default=None, ge=1)
    reason: str | None = Field(default=None, max_length=500)


class TerminateRequest(TransitionRequest):
    effective_date: date
    impact_acknowledged: bool
    reason: str = Field(min_length=1, max_length=500)


class LineResponse(BaseModel):
    product_code: str
    capability_code: str
    quantity: int
    unit_amount: str
    unit_currency_code: str
    offer_ref: str | None
    release_ref: str | None


class ContractResponse(BaseModel):
    id: UUID
    reference: str
    agreement_family_id: UUID
    agreement_version: int
    product_code: str
    counterparty_ref: str
    agreement_type: str
    term_start: date
    term_end_exclusive: date
    status: str
    content_hash: str | None
    record_version: int
    activation_rule: str | None
    approval_request_id: UUID | None
    lines: list[LineResponse]

    @classmethod
    def of(cls, value: ContractView) -> ContractResponse:
        return cls(
            id=value.id,
            reference=value.reference,
            agreement_family_id=value.agreement_family_id,
            agreement_version=value.agreement_version,
            product_code=value.product_code,
            counterparty_ref=value.counterparty_ref,
            agreement_type=value.agreement_type,
            term_start=value.term_start,
            term_end_exclusive=value.term_end_exclusive,
            status=value.status,
            content_hash=value.content_hash,
            record_version=value.record_version,
            activation_rule=value.activation_rule,
            approval_request_id=value.approval_request_id,
            lines=[
                LineResponse(
                    product_code=line.product_code,
                    capability_code=line.capability_code,
                    quantity=line.quantity,
                    unit_amount=line.unit_amount,
                    unit_currency_code=line.unit_currency_code,
                    offer_ref=line.offer_ref,
                    release_ref=line.release_ref,
                )
                for line in value.lines
            ],
        )


__all__ = [
    "ActivateRequest",
    "ApprovalRequest",
    "ContractResponse",
    "CreateDraftRequest",
    "LineRequest",
    "LineResponse",
    "ProposeRequest",
    "TerminateRequest",
    "TransitionRequest",
]
