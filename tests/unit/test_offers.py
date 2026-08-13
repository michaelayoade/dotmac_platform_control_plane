"""Unit tests for the OfferVersionService (immutable priced offer versions).

Uses the kernel testing kit (SQLite). Proves: exact-Money round-trip, declared-
capability enforcement (WS1), immutability (a published version can't be
republished), and idempotent publish.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from dotmac_entitlement_allocation import (
    UndeclaredCapabilityError,
    UnknownProductError,
)
from dotmac_kernel import BadRequestError, ConflictError, Money, NotFoundError, currency
from dotmac_kernel.testing import create_test_engine, isolated_session
from sqlalchemy.orm import Session

from vendor_cp.offers import service
from vendor_cp.offers.catalog import (
    ProductCapabilityCatalogues,
    catalogue_domain_error,
)


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as s:
            yield s
    finally:
        engine.dispose()


_CATALOGUES = ProductCapabilityCatalogues.from_capabilities(
    {"dotmac-sub": ("inventory.use", "billing.use")}
)


def _cmd(**over: object) -> service.PublishOfferVersionCommand:
    base: dict[str, object] = {
        "command_id": "cmd-1",
        "product_code": "dotmac-sub",
        "offer_code": "pro",
        "version": 1,
        "price": Money.of("19.99", currency("USD")),
        "capability_codes": ("inventory.use",),
    }
    base.update(over)
    return service.PublishOfferVersionCommand(**base)  # type: ignore[arg-type]


def test_publish_persists_exact_money_and_capabilities(db: Session) -> None:
    result = service.publish_offer_version(db, _cmd(), catalogues=_CATALOGUES)
    assert not result.was_duplicate
    v = result.offer_version
    assert v.price == Money.of("19.99", currency("USD"))  # exact round-trip
    assert v.product_code == "dotmac-sub"
    assert v.capability_codes == ("inventory.use",)
    fetched = service.get_offer_version(
        db, product_code="dotmac-sub", offer_code="pro", version=1
    )
    assert fetched is not None and fetched.price == v.price


def test_undeclared_capability_is_rejected(db: Session) -> None:
    with pytest.raises(UndeclaredCapabilityError):
        service.publish_offer_version(
            db, _cmd(capability_codes=("inventory.export",)), catalogues=_CATALOGUES
        )


def test_capability_is_validated_against_the_named_product(db: Session) -> None:
    catalogues = ProductCapabilityCatalogues.from_capabilities(
        {
            "dotmac-sub": ("inventory.use",),
            "dotmac-erp": ("billing.use",),
        }
    )
    with pytest.raises(UndeclaredCapabilityError):
        service.publish_offer_version(
            db,
            _cmd(product_code="dotmac-erp", capability_codes=("inventory.use",)),
            catalogues=catalogues,
        )


def test_unknown_product_fails_closed(db: Session) -> None:
    with pytest.raises(UnknownProductError):
        service.publish_offer_version(
            db,
            _cmd(product_code="dotmac-unknown"),
            catalogues=_CATALOGUES,
        )


def test_catalogue_errors_keep_the_http_contract() -> None:
    unknown = catalogue_domain_error(UnknownProductError("dotmac-unknown"))
    undeclared = catalogue_domain_error(
        UndeclaredCapabilityError("dotmac-sub", ("cap.unknown",))
    )
    assert isinstance(unknown, NotFoundError)
    assert isinstance(undeclared, BadRequestError)


def test_versions_are_immutable(db: Session) -> None:
    service.publish_offer_version(db, _cmd(command_id="c1"), catalogues=_CATALOGUES)
    # A DIFFERENT command republishing the same (offer_code, version) is a conflict.
    with pytest.raises(ConflictError):
        service.publish_offer_version(
            db,
            _cmd(command_id="c2", price=Money.of("29.99", currency("USD"))),
            catalogues=_CATALOGUES,
        )


def test_publish_is_idempotent_on_command_id(db: Session) -> None:
    first = service.publish_offer_version(db, _cmd(), catalogues=_CATALOGUES)
    second = service.publish_offer_version(db, _cmd(), catalogues=_CATALOGUES)
    assert not first.was_duplicate and second.was_duplicate
    assert second.offer_version.id == first.offer_version.id
    assert (
        len(
            service.list_offer_versions(db, product_code="dotmac-sub", offer_code="pro")
        )
        == 1
    )


def test_offer_identity_is_product_qualified(db: Session) -> None:
    catalogues = ProductCapabilityCatalogues.from_capabilities(
        {
            "dotmac-sub": ("inventory.use",),
            "dotmac-erp": ("inventory.use",),
        }
    )
    sub = service.publish_offer_version(
        db, _cmd(command_id="sub", product_code="dotmac-sub"), catalogues=catalogues
    )
    erp = service.publish_offer_version(
        db, _cmd(command_id="erp", product_code="dotmac-erp"), catalogues=catalogues
    )
    assert sub.offer_version.id != erp.offer_version.id
