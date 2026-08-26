"""Release-bound, product-owned capability contract evidence.

Vendor composes commercial profiles but owns none of a product capability's
semantics.  This adapter selects immutable Release Catalog rows, reads already
held bytes through an injected local port and delegates the document grammar,
digest and Product Manifest cross-check to kernel a69.

There is no global/default registry and no request can supply a contract URI,
document or owner label. Missing Release Catalog a5/kernel a69 surfaces fail
closed.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Protocol, Self
from urllib.parse import unquote, urlparse
from uuid import UUID

from dotmac_kernel import (
    CapabilityContractError,
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


class CapabilityContractEvidenceError(ConflictError):
    """Catalogue or held bytes cannot prove one exact owner contract."""


class CapabilityContractDocumentReader(Protocol):
    """Read already-held bytes; implementations perform no network I/O."""

    def read(self, uri: str) -> bytes: ...


@dataclass(frozen=True, slots=True)
class DirectoryCapabilityContractDocumentReader:
    """Read content-addressed documents beneath one configured held root."""

    root: Path
    max_bytes: int = 1_048_576

    def read(self, uri: str) -> bytes:
        parsed = urlparse(uri)
        if parsed.scheme != "file" or parsed.netloc not in {"", "localhost"}:
            raise CapabilityContractEvidenceError(
                "capability contract URI must be a held local file URI"
            )
        root = self.root.resolve()
        path = Path(unquote(parsed.path)).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise CapabilityContractEvidenceError(
                "capability contract URI resolves outside the held document directory"
            ) from exc
        try:
            with path.open("rb") as document:
                payload = document.read(self.max_bytes + 1)
        except OSError as exc:
            raise CapabilityContractEvidenceError(
                f"cannot read held capability contract {path.name!r}"
            ) from exc
        if len(payload) > self.max_bytes:
            raise CapabilityContractEvidenceError(
                f"capability contract exceeds {self.max_bytes} bytes"
            )
        return payload


@dataclass(frozen=True, slots=True)
class CapabilityContractEvidence:
    """Canonical owner snapshot plus the exact catalogue rows that admit it."""

    capability_id: str
    artifact_id: UUID
    artifact_digest: str
    product_manifest_attestation_id: UUID
    product_manifest_digest: str
    contract_attestation_id: UUID
    contract_attestation_digest: str
    contract_ref: str
    snapshot: CapabilityContractSnapshot
    schemas: tuple[CapabilitySchemaEvidence, ...]


@dataclass(frozen=True, slots=True)
class CapabilitySchemaEvidence:
    """One held operation schema and the exact catalogue row attesting it."""

    schema_ref: str
    schema_digest: str
    attestation_id: UUID
    document_ref: str
    document: CapabilitySchemaDocument


class CapabilityContractRegistry(Protocol):
    """Read-only immutable evidence assembled from owner publications."""

    def require(self, capability_id: str) -> CapabilityContractEvidence: ...


@dataclass(frozen=True, slots=True)
class CataloguedCapabilityContractRegistry:
    """Immutable in-process view built only from exact catalogued evidence."""

    _evidence: Mapping[str, CapabilityContractEvidence]

    def require(self, capability_id: str) -> CapabilityContractEvidence:
        try:
            return self._evidence[capability_id]
        except KeyError:
            raise CapabilityContractEvidenceError(
                f"no product owner published capability contract {capability_id!r}"
            ) from None

    @classmethod
    def from_catalogue(
        cls,
        db: Session,
        *,
        pins: Mapping[str, ProductReleasePin],
        document_reader: CapabilityContractDocumentReader,
    ) -> Self:
        evidence: dict[str, CapabilityContractEvidence] = {}
        for product_code, pin in sorted(pins.items()):
            artifact = db.scalar(
                select(ReleaseArtifact).where(
                    ReleaseArtifact.product_code == product_code,
                    ReleaseArtifact.artifact_kind == pin.artifact_kind.value,
                    ReleaseArtifact.digest == pin.artifact_digest,
                )
            )
            if artifact is None:
                raise CapabilityContractEvidenceError(
                    f"product {product_code!r} has no exact catalogued artifact"
                )
            if (
                getattr(artifact, "origin_class", None)
                != ArtifactOrigin.DOTMAC_PRODUCT.value
            ):
                raise CapabilityContractEvidenceError(
                    "capability contracts require a Dotmac product artifact origin"
                )
            manifest_attestation = db.scalar(
                select(ArtifactAttestation).where(
                    ArtifactAttestation.artifact_id == artifact.id,
                    ArtifactAttestation.attestation_kind
                    == AttestationKind.PRODUCT_MANIFEST.value,
                    ArtifactAttestation.digest == pin.product_manifest_digest,
                )
            )
            if manifest_attestation is None:
                raise CapabilityContractEvidenceError(
                    f"product {product_code!r} lacks its exact Product Manifest"
                )
            manifest = _parse_manifest(
                document_reader.read(manifest_attestation.uri),
                expected_digest=manifest_attestation.digest,
            )
            if (
                manifest.product_code != artifact.product_code
                or manifest.product_version != artifact.version
            ):
                raise CapabilityContractEvidenceError(
                    "Product Manifest identity differs from its catalogued artifact"
                )
            contract_attestations = tuple(
                db.scalars(
                    select(ArtifactAttestation).where(
                        ArtifactAttestation.artifact_id == artifact.id,
                        ArtifactAttestation.attestation_kind
                        == AttestationKind.CAPABILITY_CONTRACT.value,
                    )
                )
            )
            parsed_contracts: list[
                tuple[ArtifactAttestation, CapabilityContractSnapshot]
            ] = []
            required_schemas: set[tuple[str, str]] = set()
            for attestation in contract_attestations:
                snapshot = _parse_contract(
                    document_reader.read(attestation.uri),
                    expected_digest=attestation.digest,
                    manifest=manifest,
                )
                parsed_contracts.append((attestation, snapshot))
                required_schemas.update(_operation_schema_pins(snapshot))

            schema_rows = tuple(
                db.scalars(
                    select(ArtifactAttestation).where(
                        ArtifactAttestation.artifact_id == artifact.id,
                        ArtifactAttestation.attestation_kind
                        == AttestationKind.CAPABILITY_SCHEMA.value,
                    )
                )
            )
            schemas_by_pin: dict[tuple[str, str], CapabilitySchemaEvidence] = {}
            schemas_by_ref: dict[str, str] = {}
            for schema_row in schema_rows:
                schema = _parse_schema(
                    document_reader.read(schema_row.uri),
                    expected_digest=schema_row.digest,
                )
                prior_digest = schemas_by_ref.get(schema.schema_ref)
                if prior_digest is not None and prior_digest != schema.digest:
                    raise CapabilityContractEvidenceError(
                        f"schema {schema.schema_ref!r} has ambiguous catalogue evidence"
                    )
                schemas_by_ref[schema.schema_ref] = schema.digest
                schema_identity = (schema.schema_ref, schema.digest)
                if schema_identity in schemas_by_pin:
                    raise CapabilityContractEvidenceError(
                        f"schema {schema.schema_ref!r} has duplicate catalogue evidence"
                    )
                schemas_by_pin[schema_identity] = CapabilitySchemaEvidence(
                    schema_ref=schema.schema_ref,
                    schema_digest=schema.digest,
                    attestation_id=schema_row.id,
                    document_ref=schema_row.uri,
                    document=schema,
                )
            if set(schemas_by_pin) != required_schemas:
                missing = sorted(required_schemas - set(schemas_by_pin))
                extra = sorted(set(schemas_by_pin) - required_schemas)
                raise CapabilityContractEvidenceError(
                    "capability schema attestations do not exactly cover operation "
                    f"schemas: missing={missing}, extra={extra}"
                )

            for attestation, snapshot in parsed_contracts:
                capability_id = f"{snapshot.capability_code}.v{snapshot.schema_version}"
                if capability_id in evidence:
                    raise CapabilityContractEvidenceError(
                        f"capability {capability_id!r} has ambiguous catalogue evidence"
                    )
                evidence[capability_id] = CapabilityContractEvidence(
                    capability_id=capability_id,
                    artifact_id=artifact.id,
                    artifact_digest=artifact.digest,
                    product_manifest_attestation_id=manifest_attestation.id,
                    product_manifest_digest=manifest_attestation.digest,
                    contract_attestation_id=attestation.id,
                    contract_attestation_digest=attestation.digest,
                    contract_ref=attestation.uri,
                    snapshot=snapshot,
                    schemas=tuple(
                        schemas_by_pin[schema_pin]
                        for schema_pin in sorted(_operation_schema_pins(snapshot))
                    ),
                )
        return cls(MappingProxyType(evidence))


def _parse_manifest(payload: bytes, *, expected_digest: str) -> ProductManifestSnapshot:
    try:
        return ProductManifestSnapshot.from_json_bytes(
            payload, expected_digest=expected_digest
        )
    except ProductManifestError as exc:
        raise CapabilityContractEvidenceError(
            "held Product Manifest digest or canonical document is invalid"
        ) from exc


def _parse_contract(
    payload: bytes,
    *,
    expected_digest: str,
    manifest: ProductManifestSnapshot,
) -> CapabilityContractSnapshot:
    try:
        snapshot = CapabilityContractSnapshot.from_json_bytes(
            payload, expected_digest=expected_digest
        )
        snapshot.require_declared_by(manifest)
        return snapshot
    except CapabilityContractError as exc:
        raise CapabilityContractEvidenceError(
            "held capability contract is invalid or not declared by its product"
        ) from exc


def _parse_schema(payload: bytes, *, expected_digest: str) -> CapabilitySchemaDocument:
    try:
        return CapabilitySchemaDocument.from_json_bytes(
            payload, expected_digest=expected_digest
        )
    except CapabilityContractError as exc:
        raise CapabilityContractEvidenceError(
            "held capability schema digest or canonical document is invalid"
        ) from exc


def _operation_schema_pins(
    snapshot: CapabilityContractSnapshot,
) -> set[tuple[str, str]]:
    return {
        pin
        for operation in snapshot.operations
        for pin in (
            (operation.input_schema_ref, operation.input_schema_digest),
            (operation.output_schema_ref, operation.output_schema_digest),
        )
    }


__all__ = [
    "CapabilityContractDocumentReader",
    "CapabilityContractEvidence",
    "CapabilityContractEvidenceError",
    "CapabilityContractRegistry",
    "CapabilitySchemaEvidence",
    "CataloguedCapabilityContractRegistry",
    "DirectoryCapabilityContractDocumentReader",
]
