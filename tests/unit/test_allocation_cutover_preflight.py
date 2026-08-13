"""Canaries for the read-only Entitlement Allocation cutover preflight."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from dataclasses import FrozenInstanceError
from datetime import date

import pytest
from dotmac_entitlement_allocation import UndeclaredCapabilityError
from dotmac_kernel.testing import create_test_engine, isolated_session
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vendor_cp.allocations.models import Allocation, AllocationEntry
from vendor_cp.allocations.preflight import (
    CutoverIssueCode,
    MappingEntity,
    ProductIdentityMapping,
    preflight_allocation_cutover,
)
from vendor_cp.contracts.models import Contract, ContractLine, ContractStatus
from vendor_cp.offers.catalog import ProductCapabilityCatalogues
from vendor_cp.offers.models import OfferVersion


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as session:
            yield session
    finally:
        engine.dispose()


def _catalogues(**products: tuple[str, ...]) -> ProductCapabilityCatalogues:
    return ProductCapabilityCatalogues.from_capabilities(products)


def _legacy_graph(
    db: Session,
    *,
    product_code: str | None,
    offer_product_code: str | None,
    contract_codes: tuple[tuple[str, int], ...] = (("cap.a", 1),),
    allocation_codes: tuple[tuple[str, int], ...] = (("cap.a", 1),),
) -> tuple[OfferVersion, Contract, Allocation]:
    offer = OfferVersion(
        product_code=offer_product_code,
        offer_code=f"offer-{uuid.uuid4()}",
        version=1,
        amount="10.00",
        currency_code="USD",
        capability_codes=sorted({code for code, _ in contract_codes}),
    )
    db.add(offer)
    db.flush()
    contract = Contract(
        product_code=product_code,
        customer_ref=f"cust-{uuid.uuid4()}",
        legal_entity="Dotmac Ltd",
        currency_code="USD",
        term_start=date(2026, 1, 1),
        term_end=date(2026, 12, 31),
        status=ContractStatus.ACTIVE.value,
        content_hash=f"hash-{uuid.uuid4()}",
    )
    db.add(contract)
    db.flush()
    for code, quantity in contract_codes:
        db.add(
            ContractLine(
                contract_id=contract.id,
                offer_version_id=offer.id,
                offer_code=offer.offer_code,
                offer_version=offer.version,
                capability_code=code,
                quantity=quantity,
                unit_amount=offer.amount,
                unit_currency_code=offer.currency_code,
            )
        )
    allocation = Allocation(
        contract_id=contract.id,
        customer_ref=contract.customer_ref,
        content_hash=contract.content_hash or "",
        status="staged",
        source_event_id=f"event-{uuid.uuid4()}",
    )
    db.add(allocation)
    db.flush()
    for code, quantity in allocation_codes:
        db.add(
            AllocationEntry(
                allocation_id=allocation.id,
                capability_code=code,
                quantity=quantity,
            )
        )
    db.flush()
    return offer, contract, allocation


def test_a_fully_classified_graph_is_ready(db: Session) -> None:
    _legacy_graph(db, product_code="dotmac-sub", offer_product_code="dotmac-sub")
    report = preflight_allocation_cutover(
        db,
        mappings=(),
        catalogues=_catalogues(**{"dotmac-sub": ("cap.a",)}),
    )
    assert report.ready
    assert report.issues == ()
    assert report.offers_checked == 1
    assert report.contracts_checked == 1
    assert report.allocations_checked == 1
    assert report.allocations_ready == 1


def test_mapping_proposals_classify_legacy_rows_without_writing(db: Session) -> None:
    offer, contract, _allocation = _legacy_graph(
        db, product_code=None, offer_product_code=None
    )
    mappings = (
        ProductIdentityMapping(
            entity=MappingEntity.OFFER_VERSION,
            entity_id=offer.id,
            product_code="dotmac-sub",
            evidence_ref="contract-scan:2026-08-13:offer-1",
        ),
        ProductIdentityMapping(
            entity=MappingEntity.CONTRACT,
            entity_id=contract.id,
            product_code="dotmac-sub",
            evidence_ref="signed-order:2026-08-13:contract-1",
        ),
    )
    before = db.scalar(select(func.count()).select_from(Allocation))
    report = preflight_allocation_cutover(
        db,
        mappings=mappings,
        catalogues=_catalogues(**{"dotmac-sub": ("cap.a",)}),
    )
    assert report.ready
    assert report.mapping_digest.startswith("sha256:")
    assert report.observation_digest.startswith("sha256:")
    assert db.get(OfferVersion, offer.id).product_code is None  # type: ignore[union-attr]
    assert db.get(Contract, contract.id).product_code is None  # type: ignore[union-attr]
    assert db.scalar(select(func.count()).select_from(Allocation)) == before
    assert not db.new and not db.dirty and not db.deleted


def test_preflight_reports_every_known_blocker_in_one_pass(db: Session) -> None:
    offer, contract, allocation = _legacy_graph(
        db,
        product_code=None,
        offer_product_code=None,
        contract_codes=(("cap.a", 1), ("cap.a", 2)),
        allocation_codes=(("cap.a", 1), ("cap.a", 2), ("cap.bad", 0)),
    )
    allocation.content_hash = "different"
    db.flush()
    report = preflight_allocation_cutover(
        db,
        mappings=(),
        catalogues=_catalogues(**{"dotmac-sub": ("cap.a",)}),
    )
    assert not report.ready
    assert report.allocations_ready == 0
    codes = {issue.code for issue in report.issues}
    assert {
        CutoverIssueCode.UNCLASSIFIED_OFFER,
        CutoverIssueCode.UNCLASSIFIED_CONTRACT,
        CutoverIssueCode.DUPLICATE_CAPABILITY,
        CutoverIssueCode.NON_POSITIVE_QUANTITY,
        CutoverIssueCode.ALLOCATION_CONTRACT_MISMATCH,
        CutoverIssueCode.ALLOCATION_ENTRY_DRIFT,
    } <= codes
    assert any(issue.entity_id == offer.id for issue in report.issues)
    assert any(issue.entity_id == contract.id for issue in report.issues)
    assert any(issue.entity_id == allocation.id for issue in report.issues)


def test_catalogue_validation_is_product_scoped_and_exhaustive(db: Session) -> None:
    _legacy_graph(
        db,
        product_code="dotmac-erp",
        offer_product_code="dotmac-erp",
        contract_codes=(("cap.sub", 1),),
        allocation_codes=(("cap.sub", 1),),
    )
    report = preflight_allocation_cutover(
        db,
        mappings=(),
        catalogues=_catalogues(
            **{"dotmac-sub": ("cap.sub",), "dotmac-erp": ("cap.erp",)}
        ),
    )
    assert not report.ready
    undeclared = [
        issue
        for issue in report.issues
        if issue.code is CutoverIssueCode.UNDECLARED_CAPABILITY
    ]
    assert undeclared
    assert all("dotmac-erp" in issue.detail for issue in undeclared)


def test_mapping_conflicts_and_missing_targets_are_reported(db: Session) -> None:
    offer, _contract, _allocation = _legacy_graph(
        db, product_code="dotmac-sub", offer_product_code="dotmac-sub"
    )
    mappings = (
        ProductIdentityMapping(
            entity=MappingEntity.OFFER_VERSION,
            entity_id=offer.id,
            product_code="dotmac-erp",
            evidence_ref="operator-ticket:conflict",
        ),
        ProductIdentityMapping(
            entity=MappingEntity.CONTRACT,
            entity_id=uuid.uuid4(),
            product_code="dotmac-sub",
            evidence_ref="operator-ticket:missing",
        ),
    )
    report = preflight_allocation_cutover(
        db,
        mappings=mappings,
        catalogues=_catalogues(**{"dotmac-sub": ("cap.a",), "dotmac-erp": ("cap.a",)}),
    )
    assert {issue.code for issue in report.issues} >= {
        CutoverIssueCode.MAPPING_CONFLICT,
        CutoverIssueCode.MAPPING_TARGET_MISSING,
    }


def test_mapping_shape_refuses_ambiguous_or_unattributed_evidence(db: Session) -> None:
    with pytest.raises(ValueError, match="evidence_ref"):
        ProductIdentityMapping(
            entity=MappingEntity.CONTRACT,
            entity_id=uuid.uuid4(),
            product_code="dotmac-sub",
            evidence_ref=" ",
        )
    mapping = ProductIdentityMapping(
        entity=MappingEntity.CONTRACT,
        entity_id=uuid.uuid4(),
        product_code="dotmac-sub",
        evidence_ref="operator-ticket:one",
    )
    with pytest.raises(ValueError, match="duplicate mapping"):
        preflight_allocation_cutover(
            db,
            mappings=(mapping, mapping),
            catalogues=_catalogues(**{"dotmac-sub": ("cap.a",)}),
        )


def test_mapping_is_immutable_and_digest_is_order_independent(db: Session) -> None:
    first = ProductIdentityMapping(
        entity=MappingEntity.CONTRACT,
        entity_id=uuid.UUID("00000000-0000-0000-0000-000000000002"),
        product_code="dotmac-sub",
        evidence_ref="operator-ticket:two",
    )
    second = ProductIdentityMapping(
        entity=MappingEntity.OFFER_VERSION,
        entity_id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
        product_code="dotmac-sub",
        evidence_ref="operator-ticket:one",
    )
    with pytest.raises(FrozenInstanceError):
        first.product_code = "dotmac-erp"  # type: ignore[misc]
    assert not hasattr(first, "__dict__")
    forward = preflight_allocation_cutover(
        db,
        mappings=(first, second),
        catalogues=_catalogues(**{"dotmac-sub": ("cap.a",)}),
    )
    reverse = preflight_allocation_cutover(
        db,
        mappings=(second, first),
        catalogues=_catalogues(**{"dotmac-sub": ("cap.a",)}),
    )
    assert forward.mapping_digest == reverse.mapping_digest
    assert forward.observation_digest == reverse.observation_digest
    assert forward.issues == reverse.issues


def test_observation_digest_binds_the_graph_that_was_checked(db: Session) -> None:
    _offer, _contract, allocation = _legacy_graph(
        db, product_code="dotmac-sub", offer_product_code="dotmac-sub"
    )
    catalogues = _catalogues(**{"dotmac-sub": ("cap.a",)})
    before = preflight_allocation_cutover(db, mappings=(), catalogues=catalogues)
    allocation.entries[0].quantity = 2
    db.flush()
    after = preflight_allocation_cutover(db, mappings=(), catalogues=catalogues)
    assert before.observation_digest != after.observation_digest
    assert CutoverIssueCode.ALLOCATION_ENTRY_DRIFT in {
        issue.code for issue in after.issues
    }


def test_preflight_refuses_to_attest_a_dirty_session(db: Session) -> None:
    offer, _contract, _allocation = _legacy_graph(
        db, product_code="dotmac-sub", offer_product_code="dotmac-sub"
    )
    offer.amount = "11.00"
    with pytest.raises(ValueError, match="clean session"):
        preflight_allocation_cutover(
            db,
            mappings=(),
            catalogues=_catalogues(**{"dotmac-sub": ("cap.a",)}),
        )


def test_unknown_product_is_a_blocker(db: Session) -> None:
    _legacy_graph(
        db,
        product_code="dotmac-unknown",
        offer_product_code="dotmac-unknown",
    )
    report = preflight_allocation_cutover(
        db,
        mappings=(),
        catalogues=_catalogues(**{"dotmac-sub": ("cap.a",)}),
    )
    assert CutoverIssueCode.UNKNOWN_PRODUCT in {issue.code for issue in report.issues}


def test_untranslated_catalogue_failure_surfaces(db: Session) -> None:
    class BrokenCatalogue:
        def require_declared(self, *, product_code: str, capability_code: str) -> None:
            raise RuntimeError("catalogue unavailable")

    _legacy_graph(db, product_code="dotmac-sub", offer_product_code="dotmac-sub")
    with pytest.raises(RuntimeError, match="catalogue unavailable"):
        preflight_allocation_cutover(
            db,
            mappings=(),
            catalogues=BrokenCatalogue(),
        )


def test_module_catalogue_errors_are_the_only_translated_failures(db: Session) -> None:
    class UndeclaredCatalogue:
        def require_declared(self, *, product_code: str, capability_code: str) -> None:
            raise UndeclaredCapabilityError(product_code, (capability_code,))

    _legacy_graph(db, product_code="dotmac-sub", offer_product_code="dotmac-sub")
    report = preflight_allocation_cutover(
        db,
        mappings=(),
        catalogues=UndeclaredCatalogue(),
    )
    assert report.issues
    assert {issue.code for issue in report.issues} == {
        CutoverIssueCode.UNDECLARED_CAPABILITY
    }
