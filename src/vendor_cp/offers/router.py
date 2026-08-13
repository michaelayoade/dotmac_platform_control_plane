"""Offer-versions JSON API — a thin, platform-admin-only adapter.

Builds the typed `Money` price + resolves the capability catalogue, then delegates
to `OfferVersionService`. `ConflictError` (immutable version / duplicate) → 409;
`UndeclaredCapabilityError` (undeclared code) → the kernel maps it; a bad
amount/currency → 400.
"""

from __future__ import annotations

from typing import Annotated

from dotmac_kernel import (
    BadRequestError,
    Money,
    MoneyError,
    NotFoundError,
    PlatformAdmin,
    currency,
)
from dotmac_kernel.db import get_platform_db
from dotmac_kernel.platform_auth import require_platform_admin
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from vendor_cp.offers import service
from vendor_cp.offers.catalog import configured_product_capability_catalogues
from vendor_cp.offers.schemas import OfferVersionResponse, PublishOfferVersionRequest

router = APIRouter(prefix="/platform/vendor/offer-versions", tags=["offer-versions"])

Admin = Annotated[PlatformAdmin, Depends(require_platform_admin)]
Db = Annotated[Session, Depends(get_platform_db)]


def _price(amount: str, code: str) -> Money:
    try:
        return Money.of(amount, currency(code))
    except (MoneyError, KeyError) as exc:
        raise BadRequestError(f"invalid price: {exc}") from exc


@router.post(
    "", response_model=OfferVersionResponse, status_code=status.HTTP_201_CREATED
)
def publish(
    body: PublishOfferVersionRequest, admin: Admin, db: Db
) -> OfferVersionResponse:
    result = service.publish_offer_version(
        db,
        service.PublishOfferVersionCommand(
            command_id=body.command_id,
            product_code=body.product_code,
            offer_code=body.offer_code,
            version=body.version,
            price=_price(body.amount, body.currency),
            capability_codes=tuple(body.capability_codes),
            actor_admin_id=admin.id,
        ),
        catalogues=configured_product_capability_catalogues(),
    )
    return OfferVersionResponse.of(result.offer_version)


@router.get("/{product_code}/{offer_code}", response_model=list[OfferVersionResponse])
def list_versions(
    product_code: str, offer_code: str, _admin: Admin, db: Db
) -> list[OfferVersionResponse]:
    return [
        OfferVersionResponse.of(v)
        for v in service.list_offer_versions(
            db, product_code=product_code, offer_code=offer_code
        )
    ]


@router.get(
    "/{product_code}/{offer_code}/{version}", response_model=OfferVersionResponse
)
def get_version(
    product_code: str, offer_code: str, version: int, _admin: Admin, db: Db
) -> OfferVersionResponse:
    view = service.get_offer_version(
        db, product_code=product_code, offer_code=offer_code, version=version
    )
    if view is None:
        raise NotFoundError(
            f"offer version {product_code!r}/{offer_code!r} v{version} not found"
        )
    return OfferVersionResponse.of(view)


__all__ = ["router"]
