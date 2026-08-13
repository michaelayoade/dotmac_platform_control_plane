"""Canaries for the digest-verified Release Catalog consumer adapter."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from dotmac_entitlement_allocation import (
    UndeclaredCapabilityError,
    UnknownProductError,
)
from dotmac_kernel import ProductManifestSnapshot
from dotmac_kernel.testing import create_test_engine, isolated_session
from dotmac_release_catalog import (
    ArtifactKind,
    AttestationKind,
    attest_artifact,
    publish_artifact,
)
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from vendor_cp.config import ProductReleasePin
from vendor_cp.offers.catalog import (
    CatalogueEvidenceError,
    DirectoryProductManifestDocumentReader,
    ProductManifestDocumentReader,
    catalogued_product_capability_catalogues,
)

_PRODUCT = "dotmac-sub"
_VERSION = "7.173.6"
_ARTIFACT_DIGEST = f"sha256:{'a' * 64}"
_ARTIFACT_REF = f"ghcr.io/dotmac/sub@{_ARTIFACT_DIGEST}"


class MemoryDocumentReader(ProductManifestDocumentReader):
    def __init__(self, documents: dict[str, bytes]) -> None:
        self.documents = documents
        self.read_uris: list[str] = []

    def read(self, uri: str) -> bytes:
        self.read_uris.append(uri)
        return self.documents[uri]


@pytest.fixture
def engine() -> Iterator[Engine]:
    engine = create_test_engine()
    try:
        yield engine
    finally:
        engine.dispose()


def _snapshot(
    *,
    product_code: str = _PRODUCT,
    product_version: str = _VERSION,
    capabilities: tuple[str, ...] = ("billing_export.erp_billing",),
) -> ProductManifestSnapshot:
    return ProductManifestSnapshot(
        product_code=product_code,
        product_version=product_version,
        capability_codes=capabilities,
    )


def _catalogue_rows(
    db: Session,
    snapshot: ProductManifestSnapshot,
    *,
    uri: str = "file:///run/dotmac/product-manifests/dotmac-sub.json",
) -> ProductReleasePin:
    artifact = publish_artifact(
        db,
        product_code=_PRODUCT,
        version=_VERSION,
        artifact_kind=ArtifactKind.CONTAINER_IMAGE,
        digest=_ARTIFACT_DIGEST,
        artifact_ref=_ARTIFACT_REF,
    )
    attest_artifact(
        db,
        artifact_id=artifact.id,
        attestation_kind=AttestationKind.PRODUCT_MANIFEST,
        uri=uri,
        digest=snapshot.digest,
    )
    return ProductReleasePin(
        artifact_digest=_ARTIFACT_DIGEST,
        product_manifest_digest=snapshot.digest,
    )


def test_catalogue_requires_the_document_attested_for_the_exact_artifact(
    engine: Engine,
) -> None:
    snapshot = _snapshot()
    uri = "file:///run/dotmac/product-manifests/dotmac-sub.json"
    reader = MemoryDocumentReader({uri: snapshot.to_json_bytes()})
    with isolated_session(engine) as db:
        pin = _catalogue_rows(db, snapshot, uri=uri)
        catalogues = catalogued_product_capability_catalogues(
            db,
            pins={_PRODUCT: pin},
            document_reader=reader,
        )

    catalogues.require_declared(
        product_code=_PRODUCT,
        capability_code="billing_export.erp_billing",
    )
    assert reader.read_uris == [uri]


def test_unknown_product_and_undeclared_capability_fail_closed(engine: Engine) -> None:
    snapshot = _snapshot()
    uri = "file:///run/dotmac/product-manifests/dotmac-sub.json"
    with isolated_session(engine) as db:
        pin = _catalogue_rows(db, snapshot, uri=uri)
        catalogues = catalogued_product_capability_catalogues(
            db,
            pins={_PRODUCT: pin},
            document_reader=MemoryDocumentReader({uri: snapshot.to_json_bytes()}),
        )

    with pytest.raises(UnknownProductError):
        catalogues.require_declared(
            product_code="dotmac-erp",
            capability_code="billing_export.erp_billing",
        )
    with pytest.raises(UndeclaredCapabilityError):
        catalogues.require_declared(
            product_code=_PRODUCT,
            capability_code="capability.not_declared",
        )


@pytest.mark.parametrize(
    ("changed", "message"),
    (
        ({"artifact_digest": f"sha256:{'c' * 64}"}, "catalogued artifact"),
        ({"product_manifest_digest": f"sha256:{'d' * 64}"}, "attestation"),
    ),
)
def test_a_pin_cannot_fall_through_to_different_catalogue_evidence(
    engine: Engine,
    changed: dict[str, str],
    message: str,
) -> None:
    snapshot = _snapshot()
    uri = "file:///run/dotmac/product-manifests/dotmac-sub.json"
    with isolated_session(engine) as db:
        pin = _catalogue_rows(db, snapshot, uri=uri)
        values = {
            "artifact_digest": pin.artifact_digest,
            "product_manifest_digest": pin.product_manifest_digest,
        }
        values.update(changed)
        with pytest.raises(CatalogueEvidenceError, match=message):
            catalogued_product_capability_catalogues(
                db,
                pins={_PRODUCT: ProductReleasePin(**values)},
                document_reader=MemoryDocumentReader({uri: snapshot.to_json_bytes()}),
            )


def test_document_bytes_must_match_the_attested_digest(engine: Engine) -> None:
    snapshot = _snapshot()
    different = _snapshot(capabilities=("network_projection.radius",))
    uri = "file:///run/dotmac/product-manifests/dotmac-sub.json"
    with isolated_session(engine) as db:
        pin = _catalogue_rows(db, snapshot, uri=uri)
        with pytest.raises(CatalogueEvidenceError, match="digest"):
            catalogued_product_capability_catalogues(
                db,
                pins={_PRODUCT: pin},
                document_reader=MemoryDocumentReader({uri: different.to_json_bytes()}),
            )


@pytest.mark.parametrize(
    "snapshot",
    (
        _snapshot(product_code="dotmac-erp"),
        _snapshot(product_version="7.173.7"),
    ),
)
def test_document_identity_must_match_the_catalogued_artifact(
    engine: Engine,
    snapshot: ProductManifestSnapshot,
) -> None:
    uri = "file:///run/dotmac/product-manifests/product.json"
    with isolated_session(engine) as db:
        pin = _catalogue_rows(db, snapshot, uri=uri)
        with pytest.raises(CatalogueEvidenceError, match="identity"):
            catalogued_product_capability_catalogues(
                db,
                pins={_PRODUCT: pin},
                document_reader=MemoryDocumentReader({uri: snapshot.to_json_bytes()}),
            )


def test_directory_reader_refuses_paths_outside_its_held_root(tmp_path: Path) -> None:
    held_root = tmp_path / "held"
    held_root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_bytes(_snapshot().to_json_bytes())
    reader = DirectoryProductManifestDocumentReader(held_root)

    with pytest.raises(CatalogueEvidenceError, match="outside"):
        reader.read(outside.as_uri())


def test_directory_reader_reads_a_catalogued_file_uri(tmp_path: Path) -> None:
    held_root = tmp_path / "held"
    held_root.mkdir()
    document = held_root / "dotmac-sub.json"
    payload = _snapshot().to_json_bytes()
    document.write_bytes(payload)

    assert (
        DirectoryProductManifestDocumentReader(held_root).read(document.as_uri())
        == payload
    )
