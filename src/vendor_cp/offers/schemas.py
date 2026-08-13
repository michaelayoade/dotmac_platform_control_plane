"""Typed request/response models for the offer-versions API (no bare dicts)."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, Field

from vendor_cp.offers.service import OfferVersionView


class PublishOfferVersionRequest(BaseModel):
    command_id: str = Field(min_length=1, max_length=200)
    product_code: str = Field(min_length=1, max_length=120)
    offer_code: str = Field(min_length=1, max_length=120)
    version: int = Field(ge=1)
    # Exact price as a decimal STRING (never a float) + ISO-4217 code.
    amount: str = Field(min_length=1, max_length=40)
    currency: str = Field(min_length=3, max_length=3)
    capability_codes: list[str] = Field(default_factory=list)


class OfferVersionResponse(BaseModel):
    id: UUID
    product_code: str
    offer_code: str
    version: int
    amount: str
    currency: str
    capability_codes: list[str]

    @classmethod
    def of(cls, view: OfferVersionView) -> OfferVersionResponse:
        return cls(
            id=view.id,
            product_code=view.product_code,
            offer_code=view.offer_code,
            version=view.version,
            amount=str(view.price.amount),
            currency=view.price.currency.code,
            capability_codes=list(view.capability_codes),
        )


__all__ = ["PublishOfferVersionRequest", "OfferVersionResponse"]
