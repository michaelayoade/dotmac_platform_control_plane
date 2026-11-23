"""Record a release's `deploy-unit.toml` as a catalogue attestation.

Release record ruling (2026-11-22): the release record is the Release Catalogue's
one container-image artifact per product version, plus an attestation of kind
`deploy_unit` over the exact `deploy-unit.toml` bytes at `source_revision`
(catalogue 0.1.0a6). CP holds the bytes content-addressed, as it does for the
product manifest, and hands them to Deployment Control through the
`ReleaseDescriptorSource` port (`vendor_cp.deployment.release_descriptor_source`).
Control recomputes the digest from those bytes and refuses a difference, so
nothing here is trusted by Control; this module only has to be faithful.

Unlike `ingest_product_release_evidence` it does NOT require a kernel product
manifest, because ERP v2 and Integrator emit none. Publication and replay of the
artifact share the product-manifest command's helpers and semantics: an existing
identical artifact replays, a differing one is a conflict, and a second
different `deploy_unit` attestation on one artifact is refused. There is no HTTP
publish route; this is an operator command.

The attestation's `uri` is the held document's `file:` URI with the descriptor's
repository-relative path as its fragment, so the catalogue row alone says WHICH
descriptor (primary or `deploy/companion/`) was attested.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol
from urllib.parse import urldefrag
from uuid import UUID

from dotmac_kernel import write_platform_audit_event
from dotmac_kernel.idempotency import (
    IdempotentOutcome,
    execute_once_platform,
    fingerprint_of,
)
from dotmac_release_catalog import (
    AttestationKind,
    Digest,
    pinned_reference,
)
from sqlalchemy.orm import Session

from vendor_cp.release_evidence.service import (
    ReleaseEvidenceError,
    _attest_or_replay,
    _existing_artifact,
    _publish_or_replay,
)

DESCRIPTOR_SCHEMA: Final = "dotmac.deploy_unit/1"
PRIMARY_DESCRIPTOR_PATH: Final = "deploy/deploy-unit.toml"
COMPANION_DESCRIPTOR_PATH: Final = "deploy/companion/deploy-unit.toml"
DESCRIPTOR_PATHS: Final = (PRIMARY_DESCRIPTOR_PATH, COMPANION_DESCRIPTOR_PATH)
MAX_DEPLOY_UNIT_BYTES: Final = 262_144
_REVISION: Final = re.compile(r"[0-9a-f]{40}")
_SCOPE: Final = "vendor.release_evidence.deploy_unit"
_OPERATION: Final = "vendor.release_evidence.attest_deploy_unit"
AUDIT_ACTION: Final = "vendor.release_evidence.deploy_unit_attested"


class DeployUnitStore(Protocol):
    """Hold the exact descriptor bytes; read them back by digest."""

    def hold(self, payload: bytes, *, digest: str) -> str: ...

    def read(self, *, digest: str) -> bytes: ...


@dataclass(frozen=True, slots=True)
class DirectoryDeployUnitStore:
    """Content-addressed local holding with no overwrite and no delete path."""

    root: Path

    def _target(self, digest: str) -> Path:
        parsed = Digest.parse(digest)
        return self.root.resolve() / f"{parsed.algorithm}-{parsed.hex_digest}.toml"

    def hold(self, payload: bytes, *, digest: str) -> str:
        if f"sha256:{hashlib.sha256(payload).hexdigest()}" != str(Digest.parse(digest)):
            raise ReleaseEvidenceError(f"deploy-unit bytes do not match {digest}")
        target = self._target(digest)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() or target.is_symlink():
            if self._read_checked(target, digest) != payload:
                raise ReleaseEvidenceError("held deploy-unit bytes are inconsistent")
            return target.as_uri()
        descriptor, temporary_name = tempfile.mkstemp(
            dir=target.parent, prefix=".deploy-unit.", suffix=".tmp"
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
                if self._read_checked(target, digest) != payload:
                    raise ReleaseEvidenceError(
                        "held deploy-unit bytes are inconsistent"
                    ) from None
        finally:
            temporary.unlink(missing_ok=True)
        return target.as_uri()

    def read(self, *, digest: str) -> bytes:
        return self._read_checked(self._target(digest), digest)

    @staticmethod
    def _read_checked(target: Path, digest: str) -> bytes:
        if target.is_symlink() or not target.is_file():
            raise ReleaseEvidenceError("held deploy-unit path must be a regular file")
        data = target.read_bytes()
        if f"sha256:{hashlib.sha256(data).hexdigest()}" != str(Digest.parse(digest)):
            raise ReleaseEvidenceError("held deploy-unit bytes do not match the digest")
        return data


@dataclass(frozen=True, slots=True)
class DeployUnitEvidenceCommand:
    """Exact build and descriptor evidence supplied by a product release run."""

    command_id: str
    product_code: str
    product_version: str
    artifact_digest: str
    artifact_ref: str
    source_revision: str
    descriptor_path: str
    deploy_unit_digest: str
    deploy_unit: bytes
    actor_admin_id: UUID | None
    operator_ref: str

    def __post_init__(self) -> None:
        if _REVISION.fullmatch(self.source_revision) is None:
            raise ReleaseEvidenceError(
                "source_revision must be a full lowercase 40-character Git SHA"
            )
        if not self.operator_ref or self.operator_ref != self.operator_ref.strip():
            raise ReleaseEvidenceError("operator_ref must be non-blank and trimmed")
        if self.descriptor_path not in DESCRIPTOR_PATHS:
            raise ReleaseEvidenceError(
                "descriptor_path must be deploy/deploy-unit.toml or "
                "deploy/companion/deploy-unit.toml"
            )


@dataclass(frozen=True, slots=True)
class DeployUnitEvidenceResult:
    artifact_id: UUID
    attestation_id: UUID
    deploy_unit_uri: str
    replayed: bool


def attestation_uri(held_uri: str, descriptor_path: str) -> str:
    return f"{held_uri}#{descriptor_path}"


def split_attestation_uri(uri: str) -> tuple[str, str]:
    held, fragment = urldefrag(uri)
    return held, fragment


def _fingerprint(command: DeployUnitEvidenceCommand) -> str:
    return fingerprint_of(
        {
            "actor_admin_id": str(command.actor_admin_id)
            if command.actor_admin_id is not None
            else None,
            "artifact_digest": command.artifact_digest,
            "artifact_ref": command.artifact_ref,
            "deploy_unit_digest": command.deploy_unit_digest,
            "descriptor_path": command.descriptor_path,
            "operator_ref": command.operator_ref,
            "product_code": command.product_code,
            "product_version": command.product_version,
            "source_revision": command.source_revision,
        }
    )


def _check_descriptor(command: DeployUnitEvidenceCommand) -> None:
    payload = command.deploy_unit
    if not payload or len(payload) > MAX_DEPLOY_UNIT_BYTES:
        raise ReleaseEvidenceError(
            f"deploy-unit document must be 1..{MAX_DEPLOY_UNIT_BYTES} bytes"
        )
    try:
        expected = Digest.parse(command.deploy_unit_digest)
    except ValueError as exc:
        raise ReleaseEvidenceError("deploy_unit_digest is not a valid digest") from exc
    if f"sha256:{hashlib.sha256(payload).hexdigest()}" != str(expected):
        raise ReleaseEvidenceError("deploy-unit bytes do not match deploy_unit_digest")
    try:
        document = tomllib.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ReleaseEvidenceError("deploy-unit document is not UTF-8 TOML") from exc
    if document.get("schema") != DESCRIPTOR_SCHEMA:
        raise ReleaseEvidenceError(f"deploy-unit schema must be {DESCRIPTOR_SCHEMA}")


def record_deploy_unit_evidence(
    db: Session,
    command: DeployUnitEvidenceCommand,
    *,
    document_store: DeployUnitStore,
) -> DeployUnitEvidenceResult:
    """Hold and attest once; every delivery still spends its key."""
    _check_descriptor(command)
    artifact_digest = Digest.parse(command.artifact_digest)
    artifact_ref = pinned_reference(command.artifact_ref, expected=artifact_digest)

    def operation(session: Session) -> Mapping[str, object]:
        existing = _existing_artifact(session, command)
        held_uri = document_store.hold(
            command.deploy_unit, digest=command.deploy_unit_digest
        )
        uri = attestation_uri(held_uri, command.descriptor_path)
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
            digest=command.deploy_unit_digest,
            uri=uri,
            kind=AttestationKind.DEPLOY_UNIT,
        )
        semantic_replay = artifact_replayed and attestation_replayed
        if not semantic_replay:
            write_platform_audit_event(
                session,
                actor_admin_id=command.actor_admin_id,
                action="vendor.release_evidence.deploy_unit_attested",
                entity_type="release_artifact",
                entity_id=str(artifact.id),
                details={
                    "artifact_digest": command.artifact_digest,
                    "deploy_unit_digest": command.deploy_unit_digest,
                    "descriptor_path": command.descriptor_path,
                    "operator_ref": command.operator_ref,
                    "product_code": command.product_code,
                    "product_version": command.product_version,
                    "source_revision": command.source_revision,
                },
            )
        return {
            "artifact_id": str(artifact.id),
            "attestation_id": str(attestation.id),
            "deploy_unit_uri": uri,
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
    result = outcome.result
    return DeployUnitEvidenceResult(
        artifact_id=UUID(str(result["artifact_id"])),
        attestation_id=UUID(str(result["attestation_id"])),
        deploy_unit_uri=str(result["deploy_unit_uri"]),
        replayed=outcome.replayed or bool(result["semantic_replay"]),
    )


__all__ = [
    "AUDIT_ACTION",
    "COMPANION_DESCRIPTOR_PATH",
    "DESCRIPTOR_PATHS",
    "DESCRIPTOR_SCHEMA",
    "PRIMARY_DESCRIPTOR_PATH",
    "DeployUnitEvidenceCommand",
    "DeployUnitEvidenceResult",
    "DeployUnitStore",
    "DirectoryDeployUnitStore",
    "attestation_uri",
    "record_deploy_unit_evidence",
    "split_attestation_uri",
]
