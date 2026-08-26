"""Catalogue-backed product-owned cross-capability composition evidence."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, Self
from uuid import UUID

from dotmac_kernel import (
    CapabilityCompositionError,
    CapabilityCompositionSnapshot,
    CapabilityContractSnapshot,
    CapabilitySchemaDocument,
    ConflictError,
    ProductManifestError,
    ProductManifestSnapshot,
)
from dotmac_release_catalog import (
    ArtifactAttestation,
    ArtifactOrigin,
    AttestationKind,
    ReleaseArtifact,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from vendor_cp.config import ProductReleasePin
from vendor_cp.managed_profiles.capability_contracts import (
    CapabilityContractDocumentReader,
    CapabilityContractRegistry,
)


class CapabilityCompositionEvidenceError(ConflictError):
    """An immutable cross-capability composition is absent or invalid."""


@dataclass(frozen=True, slots=True)
class CapabilityCompositionEvidence:
    artifact_id: UUID
    artifact_digest: str
    product_manifest_attestation_id: UUID
    product_manifest_digest: str
    contract_ref: str
    contract_digest: str
    contract_attestation_id: UUID
    snapshot: CapabilityCompositionSnapshot


class CapabilityCompositionRegistry(Protocol):
    """Resolve admitted composition evidence; never accepts request documents."""

    def require(
        self,
        *,
        commercial_product_code: str,
        capability_ids: tuple[str, ...],
    ) -> tuple[CapabilityCompositionEvidence, ...]: ...


@dataclass(frozen=True, slots=True)
class UnavailableCapabilityCompositionRegistry:
    """Fail-closed boundary for a Release Catalog without the attestation kind."""

    def require(
        self,
        *,
        commercial_product_code: str,
        capability_ids: tuple[str, ...],
    ) -> tuple[CapabilityCompositionEvidence, ...]:
        del commercial_product_code, capability_ids
        raise CapabilityCompositionEvidenceError(
            "dependent managed profiles require a catalogue-backed "
            "capability-composition attestation"
        )


@dataclass(frozen=True, slots=True)
class CataloguedCapabilityCompositionRegistry:
    """Held canonical compositions admitted for exact Dotmac artifacts."""

    _evidence: tuple[CapabilityCompositionEvidence, ...]

    def require(
        self,
        *,
        commercial_product_code: str,
        capability_ids: tuple[str, ...],
    ) -> tuple[CapabilityCompositionEvidence, ...]:
        if not commercial_product_code or commercial_product_code != (
            commercial_product_code.strip()
        ):
            raise CapabilityCompositionEvidenceError(
                "commercial product code must be non-blank and trimmed"
            )
        selected = set(capability_ids)
        matching = tuple(
            item
            for item in self._evidence
            if any(
                _capability_id(
                    binding.source_capability_code,
                    binding.source_capability_schema_version,
                )
                in selected
                and _capability_id(
                    binding.target_capability_code,
                    binding.target_capability_schema_version,
                )
                in selected
                for binding in item.snapshot.evidence_bindings
            )
        )
        if not matching:
            raise CapabilityCompositionEvidenceError(
                f"no admitted capability composition covers {commercial_product_code!r}"
            )
        return matching

    @classmethod
    def from_catalogue(
        cls,
        db: Session,
        *,
        pins: Mapping[str, ProductReleasePin],
        document_reader: CapabilityContractDocumentReader,
        capability_registry: CapabilityContractRegistry,
    ) -> Self:
        composition_kind = getattr(AttestationKind, "CAPABILITY_COMPOSITION", None)
        if composition_kind is None:
            raise CapabilityCompositionEvidenceError(
                "Release Catalog lacks capability_composition admission"
            )
        evidence: list[CapabilityCompositionEvidence] = []
        identities: set[tuple[str, str, int]] = set()
        for product_code, pin in sorted(pins.items()):
            artifact = db.scalar(
                select(ReleaseArtifact).where(
                    ReleaseArtifact.product_code == product_code,
                    ReleaseArtifact.artifact_kind == pin.artifact_kind.value,
                    ReleaseArtifact.digest == pin.artifact_digest,
                )
            )
            if artifact is None or artifact.origin_class != (
                ArtifactOrigin.DOTMAC_PRODUCT.value
            ):
                raise CapabilityCompositionEvidenceError(
                    f"product {product_code!r} lacks its exact Dotmac artifact"
                )
            manifest_row = db.scalar(
                select(ArtifactAttestation).where(
                    ArtifactAttestation.artifact_id == artifact.id,
                    ArtifactAttestation.attestation_kind
                    == AttestationKind.PRODUCT_MANIFEST.value,
                    ArtifactAttestation.digest == pin.product_manifest_digest,
                )
            )
            if manifest_row is None:
                raise CapabilityCompositionEvidenceError(
                    f"product {product_code!r} lacks its exact Product Manifest"
                )
            manifest = _manifest(
                document_reader.read(manifest_row.uri),
                expected_digest=manifest_row.digest,
            )
            if (
                manifest.product_code != artifact.product_code
                or manifest.product_version != artifact.version
            ):
                raise CapabilityCompositionEvidenceError(
                    "composition Product Manifest differs from its artifact"
                )
            rows = tuple(
                db.scalars(
                    select(ArtifactAttestation).where(
                        ArtifactAttestation.artifact_id == artifact.id,
                        ArtifactAttestation.attestation_kind == composition_kind.value,
                    )
                )
            )
            for row in rows:
                snapshot = _composition(
                    document_reader.read(row.uri), expected_digest=row.digest
                )
                try:
                    snapshot.require_owned_by(manifest)
                    contracts, schemas = _required_owner_documents(
                        snapshot=snapshot, capability_registry=capability_registry
                    )
                    snapshot.require_compatible_with(
                        contracts=contracts, schemas=schemas
                    )
                except CapabilityCompositionError as exc:
                    raise CapabilityCompositionEvidenceError(
                        "held capability composition is incompatible with exact "
                        "owner contracts or schemas"
                    ) from exc
                if snapshot.identity in identities:
                    raise CapabilityCompositionEvidenceError(
                        f"composition {snapshot.identity!r} has ambiguous evidence"
                    )
                identities.add(snapshot.identity)
                evidence.append(
                    CapabilityCompositionEvidence(
                        artifact_id=artifact.id,
                        artifact_digest=artifact.digest,
                        product_manifest_attestation_id=manifest_row.id,
                        product_manifest_digest=manifest_row.digest,
                        contract_ref=row.uri,
                        contract_digest=row.digest,
                        contract_attestation_id=row.id,
                        snapshot=snapshot,
                    )
                )
        return cls(tuple(sorted(evidence, key=lambda item: item.snapshot.identity)))


def _required_owner_documents(
    *,
    snapshot: CapabilityCompositionSnapshot,
    capability_registry: CapabilityContractRegistry,
) -> tuple[
    tuple[CapabilityContractSnapshot, ...], tuple[CapabilitySchemaDocument, ...]
]:
    contract_by_identity: dict[tuple[str, str, int], CapabilityContractSnapshot] = {}
    schema_by_identity: dict[tuple[str, str], CapabilitySchemaDocument] = {}
    for binding in snapshot.evidence_bindings:
        for owner, code, version in (
            (
                binding.source_owner_code,
                binding.source_capability_code,
                binding.source_capability_schema_version,
            ),
            (
                binding.target_owner_code,
                binding.target_capability_code,
                binding.target_capability_schema_version,
            ),
        ):
            item = capability_registry.require(_capability_id(code, version))
            if item.snapshot.owner_code != owner:
                raise CapabilityCompositionEvidenceError(
                    "composition capability owner differs from held contract"
                )
            prior_contract = contract_by_identity.get(item.snapshot.identity)
            if prior_contract is not None and prior_contract != item.snapshot:
                raise CapabilityCompositionEvidenceError(
                    "composition capability has conflicting held contracts"
                )
            contract_by_identity[item.snapshot.identity] = item.snapshot
            for schema in item.schemas:
                schema_identity = (schema.schema_ref, schema.schema_digest)
                prior_schema = schema_by_identity.get(schema_identity)
                if prior_schema is not None and prior_schema != schema.document:
                    raise CapabilityCompositionEvidenceError(
                        "composition schema has conflicting held documents"
                    )
                schema_by_identity[schema_identity] = schema.document
    return tuple(contract_by_identity.values()), tuple(schema_by_identity.values())


def _manifest(payload: bytes, *, expected_digest: str) -> ProductManifestSnapshot:
    try:
        return ProductManifestSnapshot.from_json_bytes(
            payload, expected_digest=expected_digest
        )
    except ProductManifestError as exc:
        raise CapabilityCompositionEvidenceError(
            "held composition Product Manifest is invalid"
        ) from exc


def _composition(
    payload: bytes, *, expected_digest: str
) -> CapabilityCompositionSnapshot:
    try:
        return CapabilityCompositionSnapshot.from_json_bytes(
            payload, expected_digest=expected_digest
        )
    except CapabilityCompositionError as exc:
        raise CapabilityCompositionEvidenceError(
            "held capability composition is invalid"
        ) from exc


def _capability_id(capability_code: str, schema_version: int) -> str:
    return f"{capability_code}.v{schema_version}"


__all__ = [
    "CapabilityCompositionEvidence",
    "CapabilityCompositionEvidenceError",
    "CapabilityCompositionRegistry",
    "CataloguedCapabilityCompositionRegistry",
    "UnavailableCapabilityCompositionRegistry",
]
