"""Product-scoped access to target applications' capability catalogues.

The vendor control plane does not own capability codes. It receives a
manifest-derived snapshot for each named product and exposes only a fail-closed
``require_declared`` port to commercial services. A code declared by one product
is not evidence that another product declares it.

The assembly pins exact artifact and manifest digests. This adapter proves that
Release Catalog associates those identities, reads held document bytes through
an explicit port, and delegates canonical parsing and digest checking to the
kernel. Vendor never reconstructs a product capability vocabulary.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Protocol, Self
from urllib.parse import unquote, urlparse

from dotmac_entitlement_allocation import (
    AllocationError,
    UndeclaredCapabilityError,
    UnknownProductError,
)
from dotmac_kernel import (
    BadRequestError,
    CapabilityCatalogue,
    DomainError,
    FeatureManifest,
    NotFoundError,
    ProductManifestError,
    ProductManifestSnapshot,
)
from dotmac_kernel import UndeclaredCapabilityError as KernelUndeclaredCapabilityError
from dotmac_release_catalog import (
    ArtifactAttestation,
    ArtifactKind,
    AttestationKind,
    ReleaseArtifact,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from vendor_cp.config import ProductReleasePin, vendor_settings


class CatalogueEvidenceError(RuntimeError):
    """Pinned release evidence is absent, ambiguous, or inconsistent."""


class ProductManifestDocumentReader(Protocol):
    """Read held attestation bytes without making Release Catalog a fetcher."""

    def read(self, uri: str) -> bytes: ...


@dataclass(frozen=True, slots=True)
class DirectoryProductManifestDocumentReader:
    """Read ``file://`` documents held beneath one configured directory."""

    root: Path
    max_bytes: int = 1_048_576

    def read(self, uri: str) -> bytes:
        parsed = urlparse(uri)
        if parsed.scheme != "file" or parsed.netloc not in {"", "localhost"}:
            raise CatalogueEvidenceError(
                "product-manifest URI must be a local file URI"
            )
        root = self.root.resolve()
        path = Path(unquote(parsed.path)).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise CatalogueEvidenceError(
                "product-manifest URI resolves outside the held document directory"
            ) from exc
        try:
            with path.open("rb") as document:
                payload = document.read(self.max_bytes + 1)
            if len(payload) > self.max_bytes:
                raise CatalogueEvidenceError(
                    f"product-manifest document exceeds {self.max_bytes} bytes"
                )
            return payload
        except OSError as exc:
            raise CatalogueEvidenceError(
                f"cannot read held product-manifest document {path.name!r}"
            ) from exc


@dataclass(frozen=True, slots=True)
class ProductCapabilityCatalogues:
    """Immutable in-process adapter over product-qualified kernel catalogues."""

    _catalogues: Mapping[str, CapabilityCatalogue]

    @classmethod
    def from_capabilities(
        cls, capabilities_by_product: Mapping[str, Iterable[str]]
    ) -> Self:
        catalogues: dict[str, CapabilityCatalogue] = {}
        for product_code, codes in capabilities_by_product.items():
            if not product_code or product_code != product_code.strip():
                raise ValueError("product catalogue keys must be non-blank and trimmed")
            catalogues[product_code] = CapabilityCatalogue.from_manifests(
                [
                    FeatureManifest(
                        name=f"product:{product_code}", capabilities=tuple(codes)
                    )
                ]
            )
        return cls(MappingProxyType(catalogues))

    def require_declared(self, *, product_code: str, capability_code: str) -> None:
        catalogue = self._catalogues.get(product_code)
        if catalogue is None:
            raise UnknownProductError(
                f"product {product_code!r} has no supplied manifest catalogue"
            )
        try:
            catalogue.require(capability_code)
        except KernelUndeclaredCapabilityError as exc:
            # The published module owns this port and its stable error
            # vocabulary. The kernel catalogue is the backing mechanism; its
            # KeyError-shaped exception must not leak across the module seam.
            raise UndeclaredCapabilityError(product_code, (capability_code,)) from exc


def catalogued_product_capability_catalogues(
    db: Session,
    *,
    pins: Mapping[str, ProductReleasePin],
    document_reader: ProductManifestDocumentReader,
) -> ProductCapabilityCatalogues:
    """Build catalogues only from documents attested for exact pinned artifacts."""

    capabilities: dict[str, tuple[str, ...]] = {}
    for product_code, pin in pins.items():
        artifact = db.scalar(
            select(ReleaseArtifact).where(
                ReleaseArtifact.product_code == product_code,
                ReleaseArtifact.artifact_kind == ArtifactKind.CONTAINER_IMAGE.value,
                ReleaseArtifact.digest == pin.artifact_digest,
            )
        )
        if artifact is None:
            raise CatalogueEvidenceError(
                f"product {product_code!r} has no catalogued artifact matching "
                "its exact artifact digest pin"
            )
        attestation = db.scalar(
            select(ArtifactAttestation).where(
                ArtifactAttestation.artifact_id == artifact.id,
                ArtifactAttestation.attestation_kind
                == AttestationKind.PRODUCT_MANIFEST.value,
                ArtifactAttestation.digest == pin.product_manifest_digest,
            )
        )
        if attestation is None:
            raise CatalogueEvidenceError(
                f"product {product_code!r} artifact has no product-manifest "
                "attestation matching its exact digest pin"
            )
        payload = document_reader.read(attestation.uri)
        try:
            snapshot = ProductManifestSnapshot.from_json_bytes(
                payload,
                expected_digest=pin.product_manifest_digest,
            )
        except ProductManifestError as exc:
            raise CatalogueEvidenceError(
                f"product {product_code!r} manifest digest or document is invalid"
            ) from exc
        if (
            snapshot.product_code != artifact.product_code
            or snapshot.product_version != artifact.version
        ):
            raise CatalogueEvidenceError(
                f"product {product_code!r} manifest identity does not match the "
                "catalogued artifact"
            )
        capabilities[product_code] = snapshot.capability_codes
    return ProductCapabilityCatalogues.from_capabilities(capabilities)


def catalogue_domain_error(error: AllocationError) -> DomainError:
    """Translate the module-owned validation vocabulary at the HTTP boundary."""

    if isinstance(error, UnknownProductError):
        return NotFoundError(str(error))
    return BadRequestError(str(error))


def configured_product_capability_catalogues(
    db: Session,
) -> ProductCapabilityCatalogues:
    """Resolve configured exact release pins against held catalogue evidence."""

    return catalogued_product_capability_catalogues(
        db,
        pins=dict(vendor_settings.product_release_pins),
        document_reader=DirectoryProductManifestDocumentReader(
            vendor_settings.product_manifest_directory
        ),
    )


__all__ = [
    "CatalogueEvidenceError",
    "DirectoryProductManifestDocumentReader",
    "ProductCapabilityCatalogues",
    "ProductManifestDocumentReader",
    "catalogue_domain_error",
    "catalogued_product_capability_catalogues",
    "configured_product_capability_catalogues",
]
