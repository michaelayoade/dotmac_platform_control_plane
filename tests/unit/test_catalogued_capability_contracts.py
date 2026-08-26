"""Canaries for held, Release-Catalog-backed capability contracts and schemas."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from dotmac_kernel import (
    CAPABILITY_SCHEMA_DIALECT,
    CapabilityContractSnapshot,
    CapabilityOperation,
    CapabilitySchemaDocument,
    ProductManifestSnapshot,
)
from dotmac_kernel.testing import create_test_engine, isolated_session
from dotmac_release_catalog import (
    ArtifactKind,
    ArtifactOrigin,
    AttestationKind,
    attest_artifact,
    publish_artifact,
)
from sqlalchemy import Engine
from tests.capability_contract_registry import (
    build_capability_composition_registry,
    build_capability_contract_registry,
)

from vendor_cp.config import ProductReleasePin
from vendor_cp.managed_profiles.capability_contracts import (
    CapabilityContractDocumentReader,
    CapabilityContractEvidenceError,
    CataloguedCapabilityContractRegistry,
)
from vendor_cp.managed_profiles.composition_contracts import (
    CataloguedCapabilityCompositionRegistry,
)

PRODUCT = "dotmac-managed-contracts"
VERSION = "0.1.0a1"
ARTIFACT_DIGEST = "sha256:" + "9" * 64


class MemoryDocumentReader(CapabilityContractDocumentReader):
    def __init__(self, documents: dict[str, bytes]) -> None:
        self.documents = documents

    def read(self, uri: str) -> bytes:
        return self.documents[uri]


@pytest.fixture
def engine() -> Iterator[Engine]:
    engine = create_test_engine()
    try:
        yield engine
    finally:
        engine.dispose()


def _schema(schema_ref: str) -> CapabilitySchemaDocument:
    return CapabilitySchemaDocument.from_mapping(
        {
            "$id": schema_ref,
            "$schema": CAPABILITY_SCHEMA_DIALECT,
            "additionalProperties": False,
            "properties": {"value": {"type": "string"}},
            "type": "object",
        }
    )


def _publish_evidence(
    db,
    *,
    artifact_kind: ArtifactKind = ArtifactKind.PYTHON_WHEEL,
    include_output_schema: bool = True,
    include_extra_schema: bool = False,
) -> tuple[ProductReleasePin, MemoryDocumentReader]:
    input_ref = "schema:managed/contracts/apply/input@v1"
    output_ref = "schema:managed/contracts/apply/output@v1"
    input_schema = _schema(input_ref)
    output_schema = _schema(output_ref)
    contract = CapabilityContractSnapshot(
        owner_code="dotmac-managed-contracts",
        capability_code="managed.contract.lifecycle",
        schema_version=1,
        operations=(
            CapabilityOperation(
                operation_code="apply",
                input_schema_ref=input_ref,
                input_schema_digest=input_schema.digest,
                output_schema_ref=output_ref,
                output_schema_digest=output_schema.digest,
            ),
        ),
    )
    manifest = ProductManifestSnapshot(
        product_code=PRODUCT,
        product_version=VERSION,
        capability_codes=(contract.capability_id,),
    )
    artifact = publish_artifact(
        db,
        product_code=PRODUCT,
        version=VERSION,
        artifact_kind=artifact_kind,
        origin=ArtifactOrigin.DOTMAC_PRODUCT,
        digest=ARTIFACT_DIGEST,
        artifact_ref=f"registry.invalid/contracts@{ARTIFACT_DIGEST}",
    )
    documents = {
        "file:///held/manifest.json": manifest.to_json_bytes(),
        "file:///held/contract.json": contract.to_json_bytes(),
        "file:///held/input.json": input_schema.to_json_bytes(),
        "file:///held/output.json": output_schema.to_json_bytes(),
    }
    manifest_row = attest_artifact(
        db,
        artifact_id=artifact.id,
        attestation_kind=AttestationKind.PRODUCT_MANIFEST,
        uri="file:///held/manifest.json",
        digest=manifest.digest,
    )
    attest_artifact(
        db,
        artifact_id=artifact.id,
        attestation_kind=AttestationKind.CAPABILITY_CONTRACT,
        uri="file:///held/contract.json",
        digest=contract.digest,
    )
    attest_artifact(
        db,
        artifact_id=artifact.id,
        attestation_kind=AttestationKind.CAPABILITY_SCHEMA,
        uri="file:///held/input.json",
        digest=input_schema.digest,
    )
    if include_output_schema:
        attest_artifact(
            db,
            artifact_id=artifact.id,
            attestation_kind=AttestationKind.CAPABILITY_SCHEMA,
            uri="file:///held/output.json",
            digest=output_schema.digest,
        )
    if include_extra_schema:
        extra = _schema("schema:managed/contracts/unused@v1")
        documents["file:///held/extra.json"] = extra.to_json_bytes()
        attest_artifact(
            db,
            artifact_id=artifact.id,
            attestation_kind=AttestationKind.CAPABILITY_SCHEMA,
            uri="file:///held/extra.json",
            digest=extra.digest,
        )
    return (
        ProductReleasePin(
            artifact_kind=artifact_kind,
            artifact_digest=ARTIFACT_DIGEST,
            product_manifest_digest=manifest_row.digest,
        ),
        MemoryDocumentReader(documents),
    )


def test_registry_accepts_a_separate_python_wheel_contract_artifact(
    engine: Engine,
) -> None:
    with isolated_session(engine) as db:
        pin, reader = _publish_evidence(db)
        registry = CataloguedCapabilityContractRegistry.from_catalogue(
            db, pins={PRODUCT: pin}, document_reader=reader
        )
        evidence = registry.require("managed.contract.lifecycle.v1")

    assert evidence.artifact_digest == ARTIFACT_DIGEST
    assert {schema.schema_ref for schema in evidence.schemas} == {
        "schema:managed/contracts/apply/input@v1",
        "schema:managed/contracts/apply/output@v1",
    }
    assert all(
        schema.document.digest == schema.schema_digest for schema in evidence.schemas
    )


def test_registry_queries_the_explicit_artifact_kind(engine: Engine) -> None:
    with isolated_session(engine) as db:
        pin, reader = _publish_evidence(db)
        wrong_kind = ProductReleasePin(
            artifact_kind=ArtifactKind.CONTAINER_IMAGE,
            artifact_digest=pin.artifact_digest,
            product_manifest_digest=pin.product_manifest_digest,
        )
        with pytest.raises(
            CapabilityContractEvidenceError, match="catalogued artifact"
        ):
            CataloguedCapabilityContractRegistry.from_catalogue(
                db, pins={PRODUCT: wrong_kind}, document_reader=reader
            )


@pytest.mark.parametrize(
    ("include_output_schema", "include_extra_schema"),
    ((False, False), (True, True)),
)
def test_operation_schemas_must_have_exact_catalogue_coverage(
    engine: Engine,
    include_output_schema: bool,
    include_extra_schema: bool,
) -> None:
    with isolated_session(engine) as db:
        pin, reader = _publish_evidence(
            db,
            include_output_schema=include_output_schema,
            include_extra_schema=include_extra_schema,
        )
        with pytest.raises(CapabilityContractEvidenceError, match="exactly cover"):
            CataloguedCapabilityContractRegistry.from_catalogue(
                db, pins={PRODUCT: pin}, document_reader=reader
            )


def test_composition_registry_loads_only_held_catalogue_attested_bytes(
    engine: Engine,
) -> None:
    owner_contracts = build_capability_contract_registry()
    composition = build_capability_composition_registry().evidence.snapshot
    manifest = ProductManifestSnapshot(
        product_code=composition.owner_code,
        product_version="0.1.0a1",
        capability_codes=("managed-suite.composition",),
    )
    digest = "sha256:" + "8" * 64
    documents = {
        "file:///held/composition-manifest.json": manifest.to_json_bytes(),
        "file:///held/composition.json": composition.to_json_bytes(),
    }
    with isolated_session(engine) as db:
        artifact = publish_artifact(
            db,
            product_code=composition.owner_code,
            version=manifest.product_version,
            artifact_kind=ArtifactKind.PYTHON_WHEEL,
            origin=ArtifactOrigin.DOTMAC_PRODUCT,
            digest=digest,
            artifact_ref=f"registry.invalid/composition@{digest}",
        )
        manifest_row = attest_artifact(
            db,
            artifact_id=artifact.id,
            attestation_kind=AttestationKind.PRODUCT_MANIFEST,
            uri="file:///held/composition-manifest.json",
            digest=manifest.digest,
        )
        composition_row = attest_artifact(
            db,
            artifact_id=artifact.id,
            attestation_kind=AttestationKind.CAPABILITY_COMPOSITION,
            uri="file:///held/composition.json",
            digest=composition.digest,
        )
        registry = CataloguedCapabilityCompositionRegistry.from_catalogue(
            db,
            pins={
                composition.owner_code: ProductReleasePin(
                    artifact_kind=ArtifactKind.PYTHON_WHEEL,
                    artifact_digest=digest,
                    product_manifest_digest=manifest.digest,
                )
            },
            document_reader=MemoryDocumentReader(documents),
            capability_registry=owner_contracts,
        )
        evidence = registry.require(
            commercial_product_code="managed-email",
            capability_ids=(
                "email.lifecycle.v1",
                "identity.oidc-client.lifecycle.v1",
                "identity.realm.lifecycle.v1",
            ),
        )

    assert len(evidence) == 1
    assert evidence[0].contract_attestation_id == composition_row.id
    assert evidence[0].product_manifest_attestation_id == manifest_row.id
    assert evidence[0].snapshot.digest == composition.digest
