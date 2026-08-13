"""Ingest one product's build-once evidence into Release Catalog.

The product release workflow owns the canonical manifest bytes and the OCI
digest that binds them. This Vendor adapter holds those exact bytes locally and
records their immutable artifact/attestation association. It never reconstructs
a capability list and never fetches a product database or network resource.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import UUID

from dotmac_kernel import (
    ConflictError,
    ProductManifestError,
    ProductManifestSnapshot,
    write_platform_audit_event,
)
from dotmac_kernel.db import conflict_savepoint
from dotmac_kernel.idempotency import (
    IdempotentOutcome,
    execute_once_platform,
    fingerprint_of,
)
from dotmac_release_catalog import (
    ArtifactAttestation,
    ArtifactKind,
    AttestationKind,
    Digest,
    ReleaseArtifact,
    attest_artifact,
    pinned_reference,
    publish_artifact,
)
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

_SOURCE_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
_MAX_MANIFEST_BYTES = 1_048_576
_SCOPE = "vendor.release_evidence.ingest"
_OPERATION = "vendor.release_evidence.catalogue"


class ReleaseEvidenceError(ValueError):
    """Product release evidence is malformed or internally inconsistent."""


class ReleaseEvidenceConflict(ConflictError):
    """Immutable catalogue evidence already says something different."""


class ProductManifestStore(Protocol):
    """Hold canonical bytes and return the immutable URI recorded for them."""

    def hold(self, payload: bytes, *, digest: str) -> str: ...


@dataclass(frozen=True, slots=True)
class DirectoryProductManifestStore:
    """Content-addressed local document holding with no overwrite path."""

    root: Path

    def hold(self, payload: bytes, *, digest: str) -> str:
        parsed = Digest.parse(digest)
        actual = f"sha256:{hashlib.sha256(payload).hexdigest()}"
        if actual != str(parsed):
            raise ReleaseEvidenceError(
                f"product-manifest bytes do not match digest {digest}"
            )

        root = self.root.resolve()
        root.mkdir(parents=True, exist_ok=True)
        target = root / f"{parsed.algorithm}-{parsed.hex_digest}.json"
        if target.exists():
            if target.is_symlink() or not target.is_file():
                raise ReleaseEvidenceError(
                    "held product-manifest path must be a regular file"
                )
            if target.read_bytes() != payload:
                raise ReleaseEvidenceError(
                    f"held product-manifest bytes at {digest} do not match the digest"
                )
            return target.as_uri()

        descriptor, temporary_name = tempfile.mkstemp(
            dir=root,
            prefix=f".{parsed.hex_digest}.",
            suffix=".tmp",
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as document:
                document.write(payload)
                document.flush()
                os.fsync(document.fileno())
            try:
                os.link(temporary, target)
            except FileExistsError:
                if target.is_symlink() or not target.is_file():
                    raise ReleaseEvidenceError(
                        "held product-manifest path must be a regular file"
                    ) from None
                if target.read_bytes() != payload:
                    raise ReleaseEvidenceError(
                        f"held product-manifest bytes at {digest} are inconsistent"
                    ) from None
        finally:
            temporary.unlink(missing_ok=True)
            directory = os.open(root, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        return target.as_uri()


@dataclass(frozen=True, slots=True)
class ProductReleaseEvidenceCommand:
    """Exact build and manifest evidence supplied by a product release run."""

    command_id: str
    product_code: str
    product_version: str
    artifact_digest: str
    artifact_ref: str
    source_revision: str
    product_manifest_digest: str
    product_manifest: bytes
    actor_admin_id: UUID | None
    operator_ref: str

    def __post_init__(self) -> None:
        if _SOURCE_REVISION_RE.fullmatch(self.source_revision) is None:
            raise ReleaseEvidenceError(
                "source_revision must be a full lowercase 40-character Git SHA"
            )
        if not self.operator_ref or self.operator_ref != self.operator_ref.strip():
            raise ReleaseEvidenceError("operator_ref must be non-blank and trimmed")


@dataclass(frozen=True, slots=True)
class ProductReleaseEvidenceResult:
    artifact_id: UUID
    attestation_id: UUID
    product_manifest_uri: str
    replayed: bool


def _fingerprint(command: ProductReleaseEvidenceCommand) -> str:
    return fingerprint_of(
        {
            "actor_admin_id": str(command.actor_admin_id)
            if command.actor_admin_id is not None
            else None,
            "artifact_digest": command.artifact_digest,
            "artifact_ref": command.artifact_ref,
            "operator_ref": command.operator_ref,
            "product_code": command.product_code,
            "product_manifest_digest": command.product_manifest_digest,
            "product_version": command.product_version,
            "source_revision": command.source_revision,
        }
    )


def _existing_artifact(
    db: Session, command: ProductReleaseEvidenceCommand
) -> ReleaseArtifact | None:
    by_digest = db.scalar(
        select(ReleaseArtifact).where(ReleaseArtifact.digest == command.artifact_digest)
    )
    by_release = db.scalar(
        select(ReleaseArtifact).where(
            ReleaseArtifact.product_code == command.product_code,
            ReleaseArtifact.version == command.product_version,
            ReleaseArtifact.artifact_kind == ArtifactKind.CONTAINER_IMAGE.value,
        )
    )
    if (
        by_digest is not None
        and by_release is not None
        and by_digest.id != by_release.id
    ):
        raise ReleaseEvidenceConflict(
            "artifact digest and product release resolve to different immutable rows"
        )
    artifact = by_digest or by_release
    if artifact is None:
        return None
    expected = (
        command.product_code,
        command.product_version,
        ArtifactKind.CONTAINER_IMAGE.value,
        command.artifact_digest,
        command.artifact_ref,
    )
    actual = (
        artifact.product_code,
        artifact.version,
        artifact.artifact_kind,
        artifact.digest,
        artifact.artifact_ref,
    )
    if actual != expected:
        raise ReleaseEvidenceConflict(
            "catalogued artifact conflicts with the supplied immutable release evidence"
        )
    return artifact


def _existing_attestation(
    db: Session,
    *,
    artifact: ReleaseArtifact,
    digest: str,
    uri: str,
) -> ArtifactAttestation | None:
    attestations = list(
        db.scalars(
            select(ArtifactAttestation).where(
                ArtifactAttestation.artifact_id == artifact.id,
                ArtifactAttestation.attestation_kind
                == AttestationKind.PRODUCT_MANIFEST.value,
            )
        )
    )
    if not attestations:
        return None
    if len(attestations) != 1:
        raise ReleaseEvidenceConflict(
            "catalogued artifact has ambiguous product-manifest attestations"
        )
    attestation = attestations[0]
    if attestation.digest != digest or attestation.uri != uri:
        raise ReleaseEvidenceConflict(
            "catalogued product-manifest attestation conflicts with supplied evidence"
        )
    return attestation


def _publish_or_replay(
    db: Session,
    command: ProductReleaseEvidenceCommand,
    *,
    artifact_digest: Digest,
    artifact_ref: str,
    existing: ReleaseArtifact | None,
) -> tuple[ReleaseArtifact, bool]:
    if existing is not None:
        return existing, True
    try:
        with conflict_savepoint(db):
            artifact = publish_artifact(
                db,
                product_code=command.product_code,
                version=command.product_version,
                artifact_kind=ArtifactKind.CONTAINER_IMAGE,
                digest=artifact_digest,
                artifact_ref=artifact_ref,
                source_revision=command.source_revision,
            )
    except IntegrityError:
        # A different delivery key may have published this immutable identity
        # concurrently. The nested savepoint contains the losing INSERT; prove
        # the winner is semantically identical before treating it as replay.
        winner = _existing_artifact(db, command)
        if winner is None:
            raise
        return winner, True
    return artifact, False


def _attest_or_replay(
    db: Session,
    *,
    artifact: ReleaseArtifact,
    digest: str,
    uri: str,
) -> tuple[ArtifactAttestation, bool]:
    # Serialize all product-manifest decisions for one artifact. A row lock is
    # deliberately unavailable: Release Catalog gives platform_api SELECT and
    # INSERT but no UPDATE, and PostgreSQL requires UPDATE privilege for
    # SELECT ... FOR UPDATE. An advisory transaction lock preserves that
    # immutability boundary while preventing two different manifest digests
    # from being admitted concurrently. SQLite unit tests are single-session;
    # the real-role PostgreSQL canary exercises this branch.
    bind = db.get_bind()
    if bind.dialect.name == "postgresql":
        db.execute(
            text(
                "SELECT pg_advisory_xact_lock("
                "hashtextextended(CAST(:identity AS text), 0))"
            ),
            {"identity": f"product_manifest:{artifact.id}"},
        )
    attestation = _existing_attestation(db, artifact=artifact, digest=digest, uri=uri)
    if attestation is not None:
        return attestation, True
    try:
        with conflict_savepoint(db):
            attestation = attest_artifact(
                db,
                artifact_id=artifact.id,
                attestation_kind=AttestationKind.PRODUCT_MANIFEST,
                uri=uri,
                digest=digest,
            )
    except IntegrityError:
        attestation = _existing_attestation(
            db,
            artifact=artifact,
            digest=digest,
            uri=uri,
        )
        if attestation is None:
            raise
        return attestation, True
    return attestation, False


def _result(
    outcome: Mapping[str, object], *, delivery_replayed: bool
) -> ProductReleaseEvidenceResult:
    return ProductReleaseEvidenceResult(
        artifact_id=UUID(str(outcome["artifact_id"])),
        attestation_id=UUID(str(outcome["attestation_id"])),
        product_manifest_uri=str(outcome["product_manifest_uri"]),
        replayed=delivery_replayed or bool(outcome["semantic_replay"]),
    )


def ingest_product_release_evidence(
    db: Session,
    command: ProductReleaseEvidenceCommand,
    *,
    document_store: ProductManifestStore,
) -> ProductReleaseEvidenceResult:
    """Hold and catalogue evidence once; every delivery still spends its key."""

    if len(command.product_manifest) > _MAX_MANIFEST_BYTES:
        raise ReleaseEvidenceError(
            f"product-manifest document exceeds {_MAX_MANIFEST_BYTES} bytes"
        )
    try:
        snapshot = ProductManifestSnapshot.from_json_bytes(
            command.product_manifest,
            expected_digest=command.product_manifest_digest,
        )
    except ProductManifestError as exc:
        raise ReleaseEvidenceError(
            "product-manifest bytes or digest are invalid"
        ) from exc
    if (
        snapshot.product_code != command.product_code
        or snapshot.product_version != command.product_version
    ):
        raise ReleaseEvidenceError(
            "product-manifest identity does not match the release command"
        )
    artifact_digest = Digest.parse(command.artifact_digest)
    artifact_ref = pinned_reference(command.artifact_ref, expected=artifact_digest)

    def operation(session: Session) -> Mapping[str, object]:
        # The observation deliberately happens before document holding. Besides
        # making the read-before-insert ordering explicit, this gives real
        # document-store adapters a public coordination seam for the PostgreSQL
        # race canary without patching a private function.
        existing = _existing_artifact(session, command)
        product_manifest_uri = document_store.hold(
            command.product_manifest,
            digest=command.product_manifest_digest,
        )
        artifact, artifact_replayed = _publish_or_replay(
            session,
            command,
            artifact_digest=artifact_digest,
            artifact_ref=artifact_ref,
            existing=existing,
        )
        attestation, attestation_replayed = _attest_or_replay(
            session,
            artifact=artifact,
            digest=command.product_manifest_digest,
            uri=product_manifest_uri,
        )
        semantic_replay = artifact_replayed and attestation_replayed
        if not semantic_replay:
            write_platform_audit_event(
                session,
                actor_admin_id=command.actor_admin_id,
                action="vendor.release_evidence.catalogued",
                entity_type="release_artifact",
                entity_id=str(artifact.id),
                details={
                    "artifact_digest": command.artifact_digest,
                    "operator_ref": command.operator_ref,
                    "product_code": command.product_code,
                    "product_manifest_digest": command.product_manifest_digest,
                    "product_version": command.product_version,
                    "source_revision": command.source_revision,
                },
            )
        return {
            "artifact_id": str(artifact.id),
            "attestation_id": str(attestation.id),
            "product_manifest_uri": product_manifest_uri,
            "semantic_replay": semantic_replay,
        }

    outcome: IdempotentOutcome = execute_once_platform(
        db,
        scope=_SCOPE,
        key=command.command_id,
        operation=operation,
        operation_name=_OPERATION,
        fingerprint=_fingerprint(command),
    )
    return _result(outcome.result, delivery_replayed=outcome.replayed)


__all__ = [
    "DirectoryProductManifestStore",
    "ProductManifestStore",
    "ProductReleaseEvidenceCommand",
    "ProductReleaseEvidenceResult",
    "ReleaseEvidenceConflict",
    "ReleaseEvidenceError",
    "ingest_product_release_evidence",
]
