"""Canaries for idempotent product-release evidence ingestion."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from dotmac_kernel import PlatformAuditEvent, ProductManifestSnapshot
from dotmac_kernel.idempotency import IdempotencyConflict
from dotmac_kernel.idempotency_models import PlatformIdempotencyRecord
from dotmac_kernel.testing import create_test_engine, isolated_session
from dotmac_release_catalog import ArtifactAttestation, ReleaseArtifact
from sqlalchemy import Engine, func, select

from vendor_cp.release_evidence.service import (
    DirectoryProductManifestStore,
    ProductReleaseEvidenceCommand,
    ReleaseEvidenceError,
    ingest_product_release_evidence,
)

_PRODUCT = "dotmac-sub"
_VERSION = "7.173.6"
_ARTIFACT_DIGEST = f"sha256:{'a' * 64}"
_ARTIFACT_REF = f"ghcr.io/michaelayoade/dotmac_sub@{_ARTIFACT_DIGEST}"


@pytest.fixture
def engine() -> Iterator[Engine]:
    engine = create_test_engine()
    try:
        yield engine
    finally:
        engine.dispose()


def _manifest(
    *,
    product_code: str = _PRODUCT,
    product_version: str = _VERSION,
) -> ProductManifestSnapshot:
    return ProductManifestSnapshot(
        product_code=product_code,
        product_version=product_version,
        capability_codes=("billing_export.erp_billing",),
    )


def _command(
    *,
    command_id: str = "sub-build-31739879074",
    artifact_digest: str = _ARTIFACT_DIGEST,
    manifest: ProductManifestSnapshot | None = None,
    source_revision: str = "bde32103f114d63b8d3815d367f765a051770325",
    operator_ref: str = "github-actions:31739879074",
) -> ProductReleaseEvidenceCommand:
    snapshot = manifest or _manifest()
    return ProductReleaseEvidenceCommand(
        command_id=command_id,
        product_code=_PRODUCT,
        product_version=_VERSION,
        artifact_digest=artifact_digest,
        artifact_ref=(f"ghcr.io/michaelayoade/dotmac_sub@{artifact_digest}"),
        source_revision=source_revision,
        product_manifest_digest=snapshot.digest,
        product_manifest=snapshot.to_json_bytes(),
        actor_admin_id=None,
        operator_ref=operator_ref,
    )


def test_ingestion_holds_bytes_and_catalogues_one_audited_release(
    engine: Engine,
    tmp_path: Path,
) -> None:
    command = _command()
    with isolated_session(engine) as db:
        result = ingest_product_release_evidence(
            db,
            command,
            document_store=DirectoryProductManifestStore(tmp_path),
        )

        artifact = db.get(ReleaseArtifact, result.artifact_id)
        attestation = db.get(ArtifactAttestation, result.attestation_id)
        events = list(db.scalars(select(PlatformAuditEvent)))

    assert not result.replayed
    assert artifact is not None
    assert artifact.product_code == _PRODUCT
    assert artifact.version == _VERSION
    assert artifact.digest == _ARTIFACT_DIGEST
    assert artifact.artifact_ref == _ARTIFACT_REF
    assert artifact.source_revision == command.source_revision
    assert attestation is not None
    assert attestation.digest == command.product_manifest_digest
    assert attestation.uri == result.product_manifest_uri
    assert Path(result.product_manifest_uri.removeprefix("file://")).read_bytes() == (
        command.product_manifest
    )
    assert len(events) == 1
    assert events[0].action == "vendor.release_evidence.catalogued"
    assert events[0].details["operator_ref"] == command.operator_ref


def test_every_delivery_is_recorded_but_semantic_replay_does_not_reaudit(
    engine: Engine,
    tmp_path: Path,
) -> None:
    store = DirectoryProductManifestStore(tmp_path)
    with isolated_session(engine) as db:
        first = ingest_product_release_evidence(
            db,
            _command(command_id="delivery-one"),
            document_store=store,
        )
        same_delivery = ingest_product_release_evidence(
            db,
            _command(command_id="delivery-one"),
            document_store=store,
        )
        second_delivery = ingest_product_release_evidence(
            db,
            _command(command_id="delivery-two"),
            document_store=store,
        )

        assert db.scalar(select(func.count()).select_from(ReleaseArtifact)) == 1
        assert db.scalar(select(func.count()).select_from(ArtifactAttestation)) == 1
        assert (
            db.scalar(select(func.count()).select_from(PlatformIdempotencyRecord)) == 2
        )
        assert db.scalar(select(func.count()).select_from(PlatformAuditEvent)) == 1

    assert not first.replayed
    assert same_delivery.replayed
    assert second_delivery.replayed
    assert first.artifact_id == same_delivery.artifact_id == second_delivery.artifact_id


def test_reusing_a_delivery_key_for_different_artifact_is_a_conflict(
    engine: Engine,
    tmp_path: Path,
) -> None:
    store = DirectoryProductManifestStore(tmp_path)
    with isolated_session(engine) as db:
        ingest_product_release_evidence(db, _command(), document_store=store)
        with pytest.raises(IdempotencyConflict):
            ingest_product_release_evidence(
                db,
                _command(artifact_digest=f"sha256:{'b' * 64}"),
                document_store=store,
            )


def test_reusing_a_delivery_key_with_different_attribution_is_a_conflict(
    engine: Engine,
    tmp_path: Path,
) -> None:
    store = DirectoryProductManifestStore(tmp_path)
    with isolated_session(engine) as db:
        ingest_product_release_evidence(db, _command(), document_store=store)
        with pytest.raises(IdempotencyConflict):
            ingest_product_release_evidence(
                db,
                _command(operator_ref="manual-operator:different"),
                document_store=store,
            )


def test_same_artifact_digest_deduplicates_build_metadata(
    engine: Engine,
    tmp_path: Path,
) -> None:
    store = DirectoryProductManifestStore(tmp_path)
    with isolated_session(engine) as db:
        first = ingest_product_release_evidence(
            db,
            _command(command_id="first-source"),
            document_store=store,
        )
        replay = ingest_product_release_evidence(
            db,
            _command(command_id="rebuilt-source", source_revision="c" * 40),
            document_store=store,
        )

        artifact = db.get(ReleaseArtifact, first.artifact_id)
        assert artifact is not None
        assert artifact.source_revision == "bde32103f114d63b8d3815d367f765a051770325"
        assert replay.replayed
        assert db.scalar(select(func.count()).select_from(ReleaseArtifact)) == 1
        assert (
            db.scalar(select(func.count()).select_from(PlatformIdempotencyRecord)) == 2
        )


@pytest.mark.parametrize(
    "manifest",
    (
        _manifest(product_code="dotmac-erp"),
        _manifest(product_version="7.173.7"),
    ),
)
def test_manifest_identity_must_match_the_release_command(
    engine: Engine,
    tmp_path: Path,
    manifest: ProductManifestSnapshot,
) -> None:
    with isolated_session(engine) as db:
        with pytest.raises(ReleaseEvidenceError, match="identity"):
            ingest_product_release_evidence(
                db,
                _command(manifest=manifest),
                document_store=DirectoryProductManifestStore(tmp_path),
            )
        assert db.scalar(select(func.count()).select_from(ReleaseArtifact)) == 0


def test_document_store_never_rewrites_content_at_a_digest(tmp_path: Path) -> None:
    store = DirectoryProductManifestStore(tmp_path)
    snapshot = _manifest()
    uri = store.hold(snapshot.to_json_bytes(), digest=snapshot.digest)

    assert store.hold(snapshot.to_json_bytes(), digest=snapshot.digest) == uri
    with pytest.raises(ReleaseEvidenceError, match="digest"):
        store.hold(b"different", digest=snapshot.digest)


def test_oversized_manifest_is_refused_before_any_catalogue_write(
    engine: Engine,
    tmp_path: Path,
) -> None:
    command = _command()
    oversized = ProductReleaseEvidenceCommand(
        command_id=command.command_id,
        product_code=command.product_code,
        product_version=command.product_version,
        artifact_digest=command.artifact_digest,
        artifact_ref=command.artifact_ref,
        source_revision=command.source_revision,
        product_manifest_digest=command.product_manifest_digest,
        product_manifest=b"x" * (1_048_576 + 1),
        actor_admin_id=command.actor_admin_id,
        operator_ref=command.operator_ref,
    )
    with isolated_session(engine) as db:
        with pytest.raises(ReleaseEvidenceError, match="exceeds"):
            ingest_product_release_evidence(
                db,
                oversized,
                document_store=DirectoryProductManifestStore(tmp_path),
            )
        assert db.scalar(select(func.count()).select_from(ReleaseArtifact)) == 0
