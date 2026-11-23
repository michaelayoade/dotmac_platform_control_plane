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

The attestation's `uri` is the held document's `file:` URI with the document's
repository-relative path as its fragment, so the catalogue row alone says WHICH
document (primary or `deploy/companion/` descriptor, or the `product.toml` at the
descriptor's `spec` path) was attested.

Architect ruling (REVIEW-cp-5a-PR270, 2026-11-23): the descriptor's `product.toml`
is attested too, as `product_spec` (catalogue a6, added in Starter #1145), in the
SAME transaction, because nothing else attests it and Control refuses a primary
plan without its path and sha. Both documents are held on the CP's DURABLE volume
(`VENDOR_HELD_DOCUMENTS_DIRECTORY`, never `/run`), write-once, content-addressed,
dirs 0700 and files 0600, and join the CP backup set; `verify_held_documents` is
the restore read-back that every attestation still resolves to matching bytes.
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
    ArtifactAttestation,
    AttestationKind,
    Digest,
    pinned_reference,
)
from sqlalchemy import select
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
    """Hold the exact document bytes; read them back by digest."""

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
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.parent.chmod(0o700)
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
            os.chmod(temporary, 0o600)
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
    #: The `product.toml` the descriptor's `spec` names, and its sha256. Required
    #: for a primary descriptor; a companion's may be absent while it is pending
    #: (Control accepts that for a companion path only, and refuses every plan).
    product_spec: bytes | None = None
    product_spec_digest: str | None = None

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
    product_spec_attestation_id: UUID | None = None
    product_spec_uri: str | None = None


@dataclass(frozen=True, slots=True)
class HeldDocuments:
    """The two durable, content-addressed stores under one configured base."""

    deploy_units: DeployUnitStore
    product_specs: DeployUnitStore

    @classmethod
    def under(cls, base: Path) -> HeldDocuments:
        return cls(
            deploy_units=DirectoryDeployUnitStore(root=base / "deploy-units"),
            product_specs=DirectoryDeployUnitStore(root=base / "product-specs"),
        )


def product_spec_kind() -> AttestationKind:
    """`AttestationKind.PRODUCT_SPEC`, which catalogue a6 adds (Starter #1145).

    Looked up by value so the repository imports on a catalogue that predates
    it, and REFUSES, rather than recording a primary release it cannot attest.
    """
    try:
        return AttestationKind("product_spec")
    except ValueError:
        raise ReleaseEvidenceError(
            "the pinned release catalogue has no product_spec attestation kind; "
            "pin catalogue 0.1.0a6 with PRODUCT_SPEC"
        ) from None


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
            "product_spec_digest": command.product_spec_digest,
            "operator_ref": command.operator_ref,
            "product_code": command.product_code,
            "product_version": command.product_version,
            "source_revision": command.source_revision,
        }
    )


SPEC_PATHS: Final = {
    PRIMARY_DESCRIPTOR_PATH: "deploy/product.toml",
    COMPANION_DESCRIPTOR_PATH: "deploy/companion/product.toml",
}
MAX_PRODUCT_SPEC_BYTES: Final = 1_048_576


def _checked_digest(payload: bytes, digest: str, *, what: str) -> None:
    try:
        expected = Digest.parse(digest)
    except ValueError as exc:
        raise ReleaseEvidenceError(f"{what} digest is not a valid digest") from exc
    if f"sha256:{hashlib.sha256(payload).hexdigest()}" != str(expected):
        raise ReleaseEvidenceError(f"{what} bytes do not match their digest")


def _toml(payload: bytes, *, what: str) -> dict[str, object]:
    try:
        return tomllib.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ReleaseEvidenceError(f"{what} is not UTF-8 TOML") from exc


def _check_documents(command: DeployUnitEvidenceCommand) -> str | None:
    """Validate both documents; return the `product.toml` path to attest, if any."""
    payload = command.deploy_unit
    if not payload or len(payload) > MAX_DEPLOY_UNIT_BYTES:
        raise ReleaseEvidenceError(
            f"deploy-unit document must be 1..{MAX_DEPLOY_UNIT_BYTES} bytes"
        )
    _checked_digest(payload, command.deploy_unit_digest, what="deploy-unit")
    document = _toml(payload, what="deploy-unit document")
    if document.get("schema") != DESCRIPTOR_SCHEMA:
        raise ReleaseEvidenceError(f"deploy-unit schema must be {DESCRIPTOR_SCHEMA}")
    spec_path = SPEC_PATHS[command.descriptor_path]
    if document.get("spec") != spec_path:
        raise ReleaseEvidenceError(
            f"the descriptor's spec must be {spec_path} for {command.descriptor_path}"
        )
    spec, spec_digest = command.product_spec, command.product_spec_digest
    if (spec is None) != (spec_digest is None):
        raise ReleaseEvidenceError("product.toml bytes and digest come together")
    if spec is None:
        if command.descriptor_path == PRIMARY_DESCRIPTOR_PATH:
            raise ReleaseEvidenceError(
                "a primary release needs the product.toml its descriptor names"
            )
        return None  # a companion whose product.toml is still pending (I3)
    if spec_digest is None:  # unreachable: the pair check above; narrows for mypy
        raise ReleaseEvidenceError("product.toml bytes and digest come together")
    if not spec or len(spec) > MAX_PRODUCT_SPEC_BYTES:
        raise ReleaseEvidenceError(
            f"product.toml must be 1..{MAX_PRODUCT_SPEC_BYTES} bytes"
        )
    _checked_digest(spec, spec_digest, what="product.toml")
    _toml(spec, what="product.toml")
    product_spec_kind()  # refuse now, before anything is held, on an old catalogue
    return spec_path


def record_deploy_unit_evidence(
    db: Session,
    command: DeployUnitEvidenceCommand,
    *,
    held: HeldDocuments,
) -> DeployUnitEvidenceResult:
    """Hold both documents and attest them in ONE transaction, once."""
    spec_path = _check_documents(command)
    artifact_digest = Digest.parse(command.artifact_digest)
    artifact_ref = pinned_reference(command.artifact_ref, expected=artifact_digest)

    def operation(session: Session) -> Mapping[str, object]:
        existing = _existing_artifact(session, command)
        unit_uri = attestation_uri(
            held.deploy_units.hold(
                command.deploy_unit, digest=command.deploy_unit_digest
            ),
            command.descriptor_path,
        )
        spec_uri: str | None = None
        spec_bytes, spec_digest = command.product_spec, command.product_spec_digest
        if spec_path is not None and spec_bytes is not None and spec_digest:
            spec_uri = attestation_uri(
                held.product_specs.hold(spec_bytes, digest=spec_digest), spec_path
            )
        artifact, artifact_replayed = _publish_or_replay(
            session,
            command,
            artifact_digest=artifact_digest,
            artifact_ref=artifact_ref,
            existing=existing,
        )
        attestation, unit_replayed = _attest_or_replay(
            session,
            artifact=artifact,
            digest=command.deploy_unit_digest,
            uri=unit_uri,
            kind=AttestationKind.DEPLOY_UNIT,
        )
        replays = [artifact_replayed, unit_replayed]
        spec_attestation_id: str | None = None
        if spec_uri is not None and spec_digest:
            spec_attestation, spec_replayed = _attest_or_replay(
                session,
                artifact=artifact,
                digest=spec_digest,
                uri=spec_uri,
                kind=product_spec_kind(),
            )
            replays.append(spec_replayed)
            spec_attestation_id = str(spec_attestation.id)
        semantic_replay = all(replays)
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
                    "product_spec_digest": command.product_spec_digest,
                    "product_version": command.product_version,
                    "source_revision": command.source_revision,
                },
            )
        return {
            "artifact_id": str(artifact.id),
            "attestation_id": str(attestation.id),
            "deploy_unit_uri": unit_uri,
            "product_spec_attestation_id": spec_attestation_id,
            "product_spec_uri": spec_uri,
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
    spec_id = result.get("product_spec_attestation_id")
    spec_uri_out = result.get("product_spec_uri")
    return DeployUnitEvidenceResult(
        artifact_id=UUID(str(result["artifact_id"])),
        attestation_id=UUID(str(result["attestation_id"])),
        deploy_unit_uri=str(result["deploy_unit_uri"]),
        replayed=outcome.replayed or bool(result["semantic_replay"]),
        product_spec_attestation_id=None if spec_id is None else UUID(str(spec_id)),
        product_spec_uri=None if spec_uri_out is None else str(spec_uri_out),
    )


def verify_held_documents(db: Session, held: HeldDocuments) -> tuple[str, ...]:
    """Restore read-back: every document attestation resolves to matching bytes.

    Read-only. Returns one value-free line per problem (attestation id and a
    reason, never a path or digest); an empty tuple means the held store and the
    catalogue rows agree. Run after a restore, and as part of the CP backup
    verification, because the catalogue rows and these bytes must restore
    together.
    """
    kinds = {AttestationKind.DEPLOY_UNIT.value: held.deploy_units}
    try:
        kinds[product_spec_kind().value] = held.product_specs
    except ReleaseEvidenceError:
        pass  # a catalogue without the kind cannot hold such rows
    problems: list[str] = []
    rows = db.scalars(
        select(ArtifactAttestation)
        .where(ArtifactAttestation.attestation_kind.in_(sorted(kinds)))
        .order_by(ArtifactAttestation.id)
    )
    for row in rows:
        store = kinds[row.attestation_kind]
        _held, fragment = split_attestation_uri(row.uri)
        if not fragment:
            problems.append(f"{row.id}: the attestation names no document path")
            continue
        try:
            store.read(digest=row.digest)
        except (ReleaseEvidenceError, OSError):
            problems.append(f"{row.id}: the held bytes are missing or do not match")
    return tuple(problems)


__all__ = [
    "AUDIT_ACTION",
    "COMPANION_DESCRIPTOR_PATH",
    "DESCRIPTOR_PATHS",
    "DESCRIPTOR_SCHEMA",
    "PRIMARY_DESCRIPTOR_PATH",
    "SPEC_PATHS",
    "DeployUnitEvidenceCommand",
    "DeployUnitEvidenceResult",
    "DeployUnitStore",
    "DirectoryDeployUnitStore",
    "HeldDocuments",
    "attestation_uri",
    "product_spec_kind",
    "record_deploy_unit_evidence",
    "split_attestation_uri",
    "verify_held_documents",
]
