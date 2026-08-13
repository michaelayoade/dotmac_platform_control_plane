"""Read-only gate for the Entitlement Allocation writer cutover.

This service audits the Vendor Control Plane's legacy commercial graph. It does
not stage an independent allocation, backfill a product code, normalize a line,
or decide what ambiguous history means. Those are operator/contract-owner acts
that require their own evidence and transaction.

The catalogue boundary is the published module's
``CapabilityCatalogueReader``. The temporary Vendor configuration adapter may
implement that port during shadow, but this service neither knows nor accepts a
raw capability list.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

from dotmac_entitlement_allocation import (
    CapabilityCatalogueReader,
    UndeclaredCapabilityError,
    UnknownProductError,
)
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from vendor_cp.allocations.models import Allocation
from vendor_cp.contracts.models import Contract
from vendor_cp.offers.models import OfferVersion

_PRODUCT_CODE_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,118}[a-z0-9])?$")


class MappingEntity(StrEnum):
    """Legacy rows for which an operator may propose product identity."""

    OFFER_VERSION = "offer_version"
    CONTRACT = "contract"


class CutoverEntity(StrEnum):
    """Entity kinds named by findings."""

    OFFER_VERSION = "offer_version"
    CONTRACT = "contract"
    ALLOCATION = "allocation"
    MAPPING = "mapping"


class CutoverIssueCode(StrEnum):
    """Stable, exhaustive blocker codes for operator automation."""

    UNCLASSIFIED_OFFER = "unclassified_offer"
    UNCLASSIFIED_CONTRACT = "unclassified_contract"
    MAPPING_CONFLICT = "mapping_conflict"
    MAPPING_TARGET_MISSING = "mapping_target_missing"
    UNKNOWN_PRODUCT = "unknown_product"
    UNDECLARED_CAPABILITY = "undeclared_capability"
    DUPLICATE_CAPABILITY = "duplicate_capability"
    NON_POSITIVE_QUANTITY = "non_positive_quantity"
    CONTRACT_OFFER_PRODUCT_MISMATCH = "contract_offer_product_mismatch"
    ALLOCATION_CONTRACT_MISMATCH = "allocation_contract_mismatch"
    ALLOCATION_ENTRY_DRIFT = "allocation_entry_drift"


@dataclass(frozen=True, slots=True)
class ProductIdentityMapping:
    """An operator's attributed proposal; never a write command."""

    entity: MappingEntity
    entity_id: UUID
    product_code: str
    evidence_ref: str

    def __post_init__(self) -> None:
        if not isinstance(self.entity, MappingEntity):
            raise ValueError("entity must be a MappingEntity")
        if not isinstance(self.entity_id, UUID):
            raise ValueError("entity_id must be a UUID")
        if (
            not isinstance(self.product_code, str)
            or _PRODUCT_CODE_RE.fullmatch(self.product_code) is None
        ):
            raise ValueError("product_code must be a stable lowercase product code")
        if (
            not isinstance(self.evidence_ref, str)
            or not self.evidence_ref
            or self.evidence_ref != self.evidence_ref.strip()
        ):
            raise ValueError("evidence_ref must be non-blank and trimmed")


@dataclass(frozen=True, slots=True)
class CutoverIssue:
    code: CutoverIssueCode
    entity: CutoverEntity
    entity_id: UUID
    detail: str


@dataclass(frozen=True, slots=True)
class CutoverPreflightReport:
    """One complete observation of the legacy graph."""

    mapping_digest: str
    observation_digest: str
    offers_checked: int
    contracts_checked: int
    allocations_checked: int
    allocations_ready: int
    issues: tuple[CutoverIssue, ...]

    @property
    def ready(self) -> bool:
        return not self.issues


def _canonical_digest(payload: object) -> str:
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _mapping_digest(mappings: tuple[ProductIdentityMapping, ...]) -> str:
    payload = [
        {
            "entity": mapping.entity.value,
            "entity_id": str(mapping.entity_id),
            "evidence_ref": mapping.evidence_ref,
            "product_code": mapping.product_code,
        }
        for mapping in sorted(
            mappings, key=lambda item: (item.entity.value, str(item.entity_id))
        )
    ]
    return _canonical_digest(payload)


def _observation_digest(
    offers: list[OfferVersion],
    contracts: list[Contract],
    allocations: list[Allocation],
) -> str:
    """Bind every persisted fact this report uses to reach its conclusion."""

    return _canonical_digest(
        {
            "offers": [
                {
                    "capability_codes": list(offer.capability_codes),
                    "id": str(offer.id),
                    "offer_code": offer.offer_code,
                    "product_code": offer.product_code,
                    "version": offer.version,
                }
                for offer in offers
            ],
            "contracts": [
                {
                    "content_hash": contract.content_hash,
                    "customer_ref": contract.customer_ref,
                    "id": str(contract.id),
                    "lines": [
                        {
                            "capability_code": line.capability_code,
                            "id": str(line.id),
                            "offer_version_id": str(line.offer_version_id),
                            "quantity": line.quantity,
                        }
                        for line in sorted(
                            contract.lines, key=lambda item: str(item.id)
                        )
                    ],
                    "product_code": contract.product_code,
                    "status": contract.status,
                }
                for contract in contracts
            ],
            "allocations": [
                {
                    "content_hash": allocation.content_hash,
                    "contract_id": str(allocation.contract_id),
                    "customer_ref": allocation.customer_ref,
                    "entries": [
                        {
                            "capability_code": entry.capability_code,
                            "id": str(entry.id),
                            "quantity": entry.quantity,
                        }
                        for entry in sorted(
                            allocation.entries, key=lambda item: str(item.id)
                        )
                    ],
                    "id": str(allocation.id),
                    "source_event_id": allocation.source_event_id,
                    "status": allocation.status,
                }
                for allocation in allocations
            ],
        }
    )


def _duplicates(codes: list[str]) -> tuple[str, ...]:
    counts = Counter(codes)
    return tuple(sorted(code for code, count in counts.items() if count > 1))


def _validate_capability(
    *,
    catalogues: CapabilityCatalogueReader,
    product_code: str,
    capability_code: str,
    entity: CutoverEntity,
    entity_id: UUID,
    issues: list[CutoverIssue],
) -> None:
    try:
        catalogues.require_declared(
            product_code=product_code,
            capability_code=capability_code,
        )
    except UnknownProductError:
        issues.append(
            CutoverIssue(
                code=CutoverIssueCode.UNKNOWN_PRODUCT,
                entity=entity,
                entity_id=entity_id,
                detail=f"product {product_code!r} has no verified catalogue",
            )
        )
    except UndeclaredCapabilityError:
        issues.append(
            CutoverIssue(
                code=CutoverIssueCode.UNDECLARED_CAPABILITY,
                entity=entity,
                entity_id=entity_id,
                detail=(
                    f"product {product_code!r} does not declare "
                    f"capability {capability_code!r}"
                ),
            )
        )


def _resolved_product(
    *,
    stored: str | None,
    mapping: ProductIdentityMapping | None,
    entity: CutoverEntity,
    entity_id: UUID,
    unclassified: CutoverIssueCode,
    issues: list[CutoverIssue],
) -> str | None:
    if stored is not None:
        if mapping is not None and mapping.product_code != stored:
            issues.append(
                CutoverIssue(
                    code=CutoverIssueCode.MAPPING_CONFLICT,
                    entity=entity,
                    entity_id=entity_id,
                    detail=(
                        f"stored product {stored!r} conflicts with mapped "
                        f"product {mapping.product_code!r} from "
                        f"{mapping.evidence_ref!r}"
                    ),
                )
            )
        return stored
    if mapping is not None:
        return mapping.product_code
    issues.append(
        CutoverIssue(
            code=unclassified,
            entity=entity,
            entity_id=entity_id,
            detail="historical row has no evidence-backed product identity",
        )
    )
    return None


def preflight_allocation_cutover(
    db: Session,
    *,
    mappings: tuple[ProductIdentityMapping, ...],
    catalogues: CapabilityCatalogueReader,
) -> CutoverPreflightReport:
    """Observe every known cutover divergence without mutating the session."""

    if db.new or db.dirty or db.deleted:
        raise ValueError(
            "cutover preflight requires a clean session; flush/commit or roll back "
            "pending changes before producing evidence"
        )

    mapping_by_key: dict[tuple[MappingEntity, UUID], ProductIdentityMapping] = {}
    for mapping in mappings:
        key = (mapping.entity, mapping.entity_id)
        if key in mapping_by_key:
            raise ValueError(
                f"duplicate mapping for {mapping.entity.value} {mapping.entity_id}"
            )
        mapping_by_key[key] = mapping

    with db.no_autoflush:
        offers = list(db.scalars(select(OfferVersion).order_by(OfferVersion.id)))
        contracts = list(
            db.scalars(
                select(Contract)
                .options(selectinload(Contract.lines))
                .order_by(Contract.id)
            )
        )
        allocations = list(
            db.scalars(
                select(Allocation)
                .options(selectinload(Allocation.entries))
                .order_by(Allocation.id)
            )
        )

    offers_by_id = {offer.id: offer for offer in offers}
    contracts_by_id = {contract.id: contract for contract in contracts}
    issues: list[CutoverIssue] = []

    known_keys = {(MappingEntity.OFFER_VERSION, offer.id) for offer in offers} | {
        (MappingEntity.CONTRACT, contract.id) for contract in contracts
    }
    for key, mapping in sorted(
        mapping_by_key.items(), key=lambda item: (item[0][0].value, str(item[0][1]))
    ):
        if key not in known_keys:
            issues.append(
                CutoverIssue(
                    code=CutoverIssueCode.MAPPING_TARGET_MISSING,
                    entity=CutoverEntity.MAPPING,
                    entity_id=mapping.entity_id,
                    detail=(
                        f"mapping targets missing {mapping.entity.value} row; "
                        f"evidence {mapping.evidence_ref!r} was not applied"
                    ),
                )
            )

    offer_products: dict[UUID, str | None] = {}
    for offer in offers:
        product_code = _resolved_product(
            stored=offer.product_code,
            mapping=mapping_by_key.get((MappingEntity.OFFER_VERSION, offer.id)),
            entity=CutoverEntity.OFFER_VERSION,
            entity_id=offer.id,
            unclassified=CutoverIssueCode.UNCLASSIFIED_OFFER,
            issues=issues,
        )
        offer_products[offer.id] = product_code
        duplicate_codes = _duplicates(list(offer.capability_codes))
        if duplicate_codes:
            issues.append(
                CutoverIssue(
                    code=CutoverIssueCode.DUPLICATE_CAPABILITY,
                    entity=CutoverEntity.OFFER_VERSION,
                    entity_id=offer.id,
                    detail=f"offer repeats capability codes {duplicate_codes!r}",
                )
            )
        if product_code is not None:
            for code in offer.capability_codes:
                _validate_capability(
                    catalogues=catalogues,
                    product_code=product_code,
                    capability_code=code,
                    entity=CutoverEntity.OFFER_VERSION,
                    entity_id=offer.id,
                    issues=issues,
                )

    contract_products: dict[UUID, str | None] = {}
    for contract in contracts:
        product_code = _resolved_product(
            stored=contract.product_code,
            mapping=mapping_by_key.get((MappingEntity.CONTRACT, contract.id)),
            entity=CutoverEntity.CONTRACT,
            entity_id=contract.id,
            unclassified=CutoverIssueCode.UNCLASSIFIED_CONTRACT,
            issues=issues,
        )
        contract_products[contract.id] = product_code
        codes = [line.capability_code for line in contract.lines]
        duplicate_codes = _duplicates(codes)
        if duplicate_codes:
            issues.append(
                CutoverIssue(
                    code=CutoverIssueCode.DUPLICATE_CAPABILITY,
                    entity=CutoverEntity.CONTRACT,
                    entity_id=contract.id,
                    detail=f"contract repeats capability codes {duplicate_codes!r}",
                )
            )
        for line in contract.lines:
            if line.quantity <= 0:
                issues.append(
                    CutoverIssue(
                        code=CutoverIssueCode.NON_POSITIVE_QUANTITY,
                        entity=CutoverEntity.CONTRACT,
                        entity_id=contract.id,
                        detail=(
                            f"contract capability {line.capability_code!r} has "
                            f"quantity {line.quantity}"
                        ),
                    )
                )
            pinned_offer = offers_by_id.get(line.offer_version_id)
            offer_product = offer_products.get(line.offer_version_id)
            if pinned_offer is None or (
                product_code is not None
                and offer_product is not None
                and offer_product != product_code
            ):
                issues.append(
                    CutoverIssue(
                        code=CutoverIssueCode.CONTRACT_OFFER_PRODUCT_MISMATCH,
                        entity=CutoverEntity.CONTRACT,
                        entity_id=contract.id,
                        detail=(
                            f"line {line.id} does not pin an offer for contract "
                            f"product {product_code!r}"
                        ),
                    )
                )
            if product_code is not None:
                _validate_capability(
                    catalogues=catalogues,
                    product_code=product_code,
                    capability_code=line.capability_code,
                    entity=CutoverEntity.CONTRACT,
                    entity_id=contract.id,
                    issues=issues,
                )

    allocations_ready = 0
    for allocation in allocations:
        issue_count_before = len(issues)
        authoritative_contract = contracts_by_id.get(allocation.contract_id)
        if authoritative_contract is None:
            issues.append(
                CutoverIssue(
                    code=CutoverIssueCode.ALLOCATION_CONTRACT_MISMATCH,
                    entity=CutoverEntity.ALLOCATION,
                    entity_id=allocation.id,
                    detail="allocation references a contract that does not exist",
                )
            )
            continue
        product_code = contract_products[authoritative_contract.id]
        if (
            allocation.customer_ref != authoritative_contract.customer_ref
            or allocation.content_hash != authoritative_contract.content_hash
        ):
            issues.append(
                CutoverIssue(
                    code=CutoverIssueCode.ALLOCATION_CONTRACT_MISMATCH,
                    entity=CutoverEntity.ALLOCATION,
                    entity_id=allocation.id,
                    detail=(
                        "allocation customer/content identity differs from its "
                        "authoritative contract"
                    ),
                )
            )

        allocation_codes = [entry.capability_code for entry in allocation.entries]
        duplicate_codes = _duplicates(allocation_codes)
        if duplicate_codes:
            issues.append(
                CutoverIssue(
                    code=CutoverIssueCode.DUPLICATE_CAPABILITY,
                    entity=CutoverEntity.ALLOCATION,
                    entity_id=allocation.id,
                    detail=f"allocation repeats capability codes {duplicate_codes!r}",
                )
            )
        for entry in allocation.entries:
            if entry.quantity <= 0:
                issues.append(
                    CutoverIssue(
                        code=CutoverIssueCode.NON_POSITIVE_QUANTITY,
                        entity=CutoverEntity.ALLOCATION,
                        entity_id=allocation.id,
                        detail=(
                            f"allocation capability {entry.capability_code!r} has "
                            f"quantity {entry.quantity}"
                        ),
                    )
                )
            if product_code is not None:
                _validate_capability(
                    catalogues=catalogues,
                    product_code=product_code,
                    capability_code=entry.capability_code,
                    entity=CutoverEntity.ALLOCATION,
                    entity_id=allocation.id,
                    issues=issues,
                )

        contract_entries = sorted(
            (line.capability_code, line.quantity)
            for line in authoritative_contract.lines
        )
        allocation_entries = sorted(
            (entry.capability_code, entry.quantity) for entry in allocation.entries
        )
        if allocation_entries != contract_entries:
            issues.append(
                CutoverIssue(
                    code=CutoverIssueCode.ALLOCATION_ENTRY_DRIFT,
                    entity=CutoverEntity.ALLOCATION,
                    entity_id=allocation.id,
                    detail=(
                        f"allocation entries {allocation_entries!r} differ from "
                        f"contract entries {contract_entries!r}"
                    ),
                )
            )

        related_entities = {
            (CutoverEntity.CONTRACT, authoritative_contract.id),
            (CutoverEntity.ALLOCATION, allocation.id),
            *(
                (CutoverEntity.OFFER_VERSION, line.offer_version_id)
                for line in authoritative_contract.lines
            ),
        }
        prior_related_issue = any(
            (issue.entity, issue.entity_id) in related_entities
            for issue in issues[:issue_count_before]
        )
        if not prior_related_issue and len(issues) == issue_count_before:
            allocations_ready += 1

    return CutoverPreflightReport(
        mapping_digest=_mapping_digest(mappings),
        observation_digest=_observation_digest(offers, contracts, allocations),
        offers_checked=len(offers),
        contracts_checked=len(contracts),
        allocations_checked=len(allocations),
        allocations_ready=allocations_ready,
        issues=tuple(issues),
    )


__all__ = [
    "CutoverEntity",
    "CutoverIssue",
    "CutoverIssueCode",
    "CutoverPreflightReport",
    "MappingEntity",
    "ProductIdentityMapping",
    "preflight_allocation_cutover",
]
