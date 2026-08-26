"""PostgreSQL proof for concurrent release-evidence deliveries."""

from __future__ import annotations

import threading
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from dotmac_kernel import PlatformAuditEvent, ProductManifestSnapshot
from dotmac_kernel.audit_actions import (
    AuditActionRegistry,
    AuditActionsNotInstalledError,
    active_audit_actions,
    install_audit_actions,
)
from dotmac_kernel.idempotency_models import PlatformIdempotencyRecord
from dotmac_release_catalog import (
    ArtifactAttestation,
    ArtifactKind,
    ArtifactOrigin,
    ReleaseArtifact,
    publish_artifact,
)
from sqlalchemy import create_engine, func, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from vendor_cp.release_evidence.feature import feature
from vendor_cp.release_evidence.service import (
    DirectoryProductManifestStore,
    ProductManifestStore,
    ProductReleaseEvidenceCommand,
    ProductReleaseEvidenceResult,
    ReleaseEvidenceConflict,
    ingest_product_release_evidence,
)


@pytest.fixture(scope="module", autouse=True)
def _declared_audit_actions() -> Iterator[None]:
    """Mirror assembly wiring so this two-session canary is independent."""

    import dotmac_kernel.audit_actions as registry_module

    try:
        previous = active_audit_actions()
    except AuditActionsNotInstalledError:
        previous = None
    install_audit_actions(AuditActionRegistry.from_manifests((feature,)))
    try:
        yield
    finally:
        if previous is None:
            registry_module._active_registry = None
        else:
            install_audit_actions(previous)


class RendezvousStore(ProductManifestStore):
    """Hold both callers after their artifact read and before either INSERT."""

    def __init__(self, root: Path) -> None:
        self._store = DirectoryProductManifestStore(root)
        self._barrier = threading.Barrier(2, timeout=30)

    def hold(self, payload: bytes, *, digest: str) -> str:
        try:
            uri = self._store.hold(payload, digest=digest)
            self._barrier.wait()
            return uri
        except BaseException:
            self._barrier.abort()
            raise


def test_two_delivery_keys_converge_on_one_catalogue_write(
    postgres_url: str,
    tmp_path: Path,
) -> None:
    suffix = uuid.uuid4().hex
    product_code = f"canary-{suffix}"
    version = f"0.0.0-{suffix}"
    artifact_digest = f"sha256:{suffix * 2}"
    snapshot = ProductManifestSnapshot(
        product_code=product_code,
        product_version=version,
        capability_codes=("canary.capability",),
    )
    store = RendezvousStore(tmp_path)
    platform_url = make_url(postgres_url).set(
        username="platform_api",
        password=None,
    )
    engine = create_engine(platform_url)
    factory = sessionmaker(
        bind=engine,
        autocommit=False,
        autoflush=False,
    )
    results: list[ProductReleaseEvidenceResult] = []
    failures: list[BaseException] = []

    def ingest(delivery: str) -> None:
        db: Session = factory()
        try:
            result = ingest_product_release_evidence(
                db,
                ProductReleaseEvidenceCommand(
                    command_id=delivery,
                    product_code=product_code,
                    product_version=version,
                    artifact_digest=artifact_digest,
                    artifact_ref=f"ghcr.io/dotmac/canary@{artifact_digest}",
                    source_revision="a" * 40,
                    product_manifest_digest=snapshot.digest,
                    product_manifest=snapshot.to_json_bytes(),
                    actor_admin_id=None,
                    operator_ref=f"canary:{suffix}",
                ),
                document_store=store,
            )
            db.commit()
            results.append(result)
        except BaseException as exc:
            db.rollback()
            failures.append(exc)
        finally:
            db.close()

    threads = [
        threading.Thread(target=ingest, args=(f"{suffix}-one",), daemon=True),
        threading.Thread(target=ingest, args=(f"{suffix}-two",), daemon=True),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=40)

    assert all(not thread.is_alive() for thread in threads), "ingestion deadlocked"
    assert failures == []
    assert sorted(result.replayed for result in results) == [False, True]
    assert len({result.artifact_id for result in results}) == 1
    assert len({result.attestation_id for result in results}) == 1

    try:
        with factory() as db:
            assert (
                db.scalar(
                    select(func.count())
                    .select_from(ReleaseArtifact)
                    .where(ReleaseArtifact.digest == artifact_digest)
                )
                == 1
            )
            artifact_id = results[0].artifact_id
            assert (
                db.scalar(
                    select(func.count())
                    .select_from(ArtifactAttestation)
                    .where(ArtifactAttestation.artifact_id == artifact_id)
                )
                == 1
            )
            assert (
                db.scalar(
                    select(func.count())
                    .select_from(PlatformAuditEvent)
                    .where(
                        PlatformAuditEvent.entity_id == str(artifact_id),
                        PlatformAuditEvent.action
                        == "vendor.release_evidence.catalogued",
                    )
                )
                == 1
            )
            assert (
                db.scalar(
                    select(func.count())
                    .select_from(PlatformIdempotencyRecord)
                    .where(
                        PlatformIdempotencyRecord.key.in_(
                            (f"{suffix}-one", f"{suffix}-two")
                        )
                    )
                )
                == 2
            )
    finally:
        engine.dispose()


def test_competing_manifests_for_one_artifact_cannot_both_land(
    postgres_url: str,
    tmp_path: Path,
) -> None:
    suffix = uuid.uuid4().hex
    product_code = f"canary-{suffix}"
    version = f"0.0.0-{suffix}"
    artifact_digest = f"sha256:{suffix * 2}"
    artifact_ref = f"ghcr.io/dotmac/canary@{artifact_digest}"
    first_manifest = ProductManifestSnapshot(
        product_code=product_code,
        product_version=version,
        capability_codes=("canary.first",),
    )
    second_manifest = ProductManifestSnapshot(
        product_code=product_code,
        product_version=version,
        capability_codes=("canary.second",),
    )
    store = RendezvousStore(tmp_path)
    platform_url = make_url(postgres_url).set(
        username="platform_api",
        password=None,
    )
    engine = create_engine(platform_url)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory() as db:
        artifact = publish_artifact(
            db,
            product_code=product_code,
            version=version,
            artifact_kind=ArtifactKind.CONTAINER_IMAGE,
            origin=ArtifactOrigin.DOTMAC_PRODUCT,
            digest=artifact_digest,
            artifact_ref=artifact_ref,
            source_revision="a" * 40,
        )
        artifact_id = artifact.id
        db.commit()

    results: list[ProductReleaseEvidenceResult] = []
    failures: list[BaseException] = []

    def ingest(delivery: str, snapshot: ProductManifestSnapshot) -> None:
        db: Session = factory()
        try:
            result = ingest_product_release_evidence(
                db,
                ProductReleaseEvidenceCommand(
                    command_id=delivery,
                    product_code=product_code,
                    product_version=version,
                    artifact_digest=artifact_digest,
                    artifact_ref=artifact_ref,
                    source_revision="a" * 40,
                    product_manifest_digest=snapshot.digest,
                    product_manifest=snapshot.to_json_bytes(),
                    actor_admin_id=None,
                    operator_ref=f"canary:{suffix}",
                ),
                document_store=store,
            )
            db.commit()
            results.append(result)
        except BaseException as exc:
            db.rollback()
            failures.append(exc)
        finally:
            db.close()

    threads = [
        threading.Thread(
            target=ingest,
            args=(f"{suffix}-first", first_manifest),
            daemon=True,
        ),
        threading.Thread(
            target=ingest,
            args=(f"{suffix}-second", second_manifest),
            daemon=True,
        ),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=40)

    assert all(not thread.is_alive() for thread in threads), "ingestion deadlocked"
    assert len(results) == 1
    assert len(failures) == 1
    assert isinstance(failures[0], ReleaseEvidenceConflict)

    try:
        with factory() as db:
            assert (
                db.scalar(
                    select(func.count())
                    .select_from(ArtifactAttestation)
                    .where(ArtifactAttestation.artifact_id == artifact_id)
                )
                == 1
            )
            assert (
                db.scalar(
                    select(func.count())
                    .select_from(PlatformAuditEvent)
                    .where(
                        PlatformAuditEvent.entity_id == str(artifact_id),
                        PlatformAuditEvent.action
                        == "vendor.release_evidence.catalogued",
                    )
                )
                == 1
            )
            assert (
                db.scalar(
                    select(func.count())
                    .select_from(PlatformIdempotencyRecord)
                    .where(
                        PlatformIdempotencyRecord.key.in_(
                            (f"{suffix}-first", f"{suffix}-second")
                        )
                    )
                )
                == 1
            )
    finally:
        engine.dispose()
