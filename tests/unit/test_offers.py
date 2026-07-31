"""Unit tests for the OfferVersionService (immutable priced offer versions).

Uses the kernel testing kit (SQLite). Proves: exact-Money round-trip, declared-
capability enforcement (WS1), immutability (a published version can't be
republished), and idempotent publish.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from dotmac_kernel import (
    CapabilityCatalogue,
    ConflictError,
    FeatureManifest,
    Money,
    currency,
)
from dotmac_kernel.capabilities import UndeclaredCapabilityError
from dotmac_kernel.testing import create_test_engine, isolated_session
from sqlalchemy.orm import Session

from vendor_cp.offers import service


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as s:
            yield s
    finally:
        engine.dispose()


_CATALOGUE = CapabilityCatalogue.from_manifests(
    [FeatureManifest(name="p", capabilities=("inventory.use", "billing.use"))]
)


def _cmd(**over: object) -> service.PublishOfferVersionCommand:
    base: dict[str, object] = {
        "command_id": "cmd-1",
        "offer_code": "pro",
        "version": 1,
        "price": Money.of("19.99", currency("USD")),
        "capability_codes": ("inventory.use",),
    }
    base.update(over)
    return service.PublishOfferVersionCommand(**base)  # type: ignore[arg-type]


def test_publish_persists_exact_money_and_capabilities(db: Session) -> None:
    result = service.publish_offer_version(db, _cmd(), catalogue=_CATALOGUE)
    assert not result.was_duplicate
    v = result.offer_version
    assert v.price == Money.of("19.99", currency("USD"))  # exact round-trip
    assert v.capability_codes == ("inventory.use",)
    fetched = service.get_offer_version(db, offer_code="pro", version=1)
    assert fetched is not None and fetched.price == v.price


def test_undeclared_capability_is_rejected(db: Session) -> None:
    with pytest.raises(UndeclaredCapabilityError):
        service.publish_offer_version(
            db, _cmd(capability_codes=("inventory.export",)), catalogue=_CATALOGUE
        )


def test_versions_are_immutable(db: Session) -> None:
    service.publish_offer_version(db, _cmd(command_id="c1"), catalogue=_CATALOGUE)
    # A DIFFERENT command republishing the same (offer_code, version) is a conflict.
    with pytest.raises(ConflictError):
        service.publish_offer_version(
            db,
            _cmd(command_id="c2", price=Money.of("29.99", currency("USD"))),
            catalogue=_CATALOGUE,
        )


def test_publish_is_idempotent_on_command_id(db: Session) -> None:
    first = service.publish_offer_version(db, _cmd(), catalogue=_CATALOGUE)
    second = service.publish_offer_version(db, _cmd(), catalogue=_CATALOGUE)
    assert not first.was_duplicate and second.was_duplicate
    assert second.offer_version.id == first.offer_version.id
    assert len(service.list_offer_versions(db, offer_code="pro")) == 1
