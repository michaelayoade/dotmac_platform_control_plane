"""Deployment Control's `ReleaseDescriptorSource`, over the Release Catalogue.

Release record ruling (2026-11-22): Control never imports the catalogue and
`release_ref` stays opaque to it. THIS module, in the assembly, interprets the
ref, reads the catalogue's `deploy_unit` attestation, reads the bytes CP held at
`release record-deploy-unit`, and hands Control `ReleaseDescriptorEvidence`.
Control then recomputes the digest over those bytes and refuses a difference, so
a wrong answer here is caught there; this module's job is to be faithful and to
refuse to guess.

`release_ref` is `<catalogue_product_code>@<version>`. It names the catalogue's
one container-image artifact for that product version, so a companion release
(the Integrator image) is addressed by its own product and version, and the
descriptor it carries is the companion one.

What is refused as `ReleaseDescriptorUnavailableError` (Control plans nothing
from a descriptor nobody could show): a ref that is not `<product>@<version>`; a
descriptor path other than the two the contract allows; no artifact; no
`deploy_unit` attestation; MORE than one (ambiguous); an attestation recorded for
a different descriptor path than the one asked for; held bytes that are missing
or do not match the attested digest.

`product_toml_*` are left absent. The catalogue has no attestation for the
released `product.toml` (only `deploy_unit` was added), so Control accepts that
only for a companion path and refuses every plan otherwise. Where a primary
descriptor's `product.toml` sha comes from is an OPEN QUESTION for the release
record design, recorded in the draft PR rather than invented here.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import Final

from dotmac_deployment_control import (
    ReleaseDescriptorEvidence,
    ReleaseDescriptorUnavailableError,
)
from dotmac_release_catalog import (
    ArtifactAttestation,
    ArtifactKind,
    AttestationKind,
    ReleaseArtifact,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from vendor_cp.release_evidence.deploy_unit import (
    DESCRIPTOR_PATHS,
    DeployUnitStore,
    split_attestation_uri,
)
from vendor_cp.release_evidence.service import ReleaseEvidenceError

__all__ = ["CatalogueReleaseDescriptorSource", "parse_release_ref"]

_RELEASE_REF: Final = re.compile(
    r"(?P<product>[a-z0-9][a-z0-9._-]{0,127})@(?P<version>[0-9A-Za-z][0-9A-Za-z._+-]{0,127})"
)

SessionScope = Callable[[], AbstractContextManager[Session]]


def parse_release_ref(release_ref: str) -> tuple[str, str]:
    match = _RELEASE_REF.fullmatch(release_ref)
    if match is None:
        raise ReleaseDescriptorUnavailableError(
            "the release_ref is not <catalogue product>@<version>"
        )
    return match.group("product"), match.group("version")


def _default_session_scope() -> AbstractContextManager[Session]:
    from dotmac_kernel.db import platform_session

    return platform_session()


def _default_store() -> DeployUnitStore:
    from vendor_cp.config import vendor_settings
    from vendor_cp.release_evidence.deploy_unit import DirectoryDeployUnitStore

    return DirectoryDeployUnitStore(
        root=vendor_settings.product_manifest_directory / "deploy-units"
    )


class CatalogueReleaseDescriptorSource:
    """Read-only: it never publishes, attests, fetches a URL or writes a file."""

    def __init__(
        self,
        *,
        session_scope: SessionScope = _default_session_scope,
        store: Callable[[], DeployUnitStore] = _default_store,
    ) -> None:
        self._session_scope = session_scope
        self._store = store

    def resolve(
        self, release_ref: str, *, product_code: str, descriptor_path: str
    ) -> ReleaseDescriptorEvidence:
        catalogue_product, version = parse_release_ref(release_ref)
        if descriptor_path not in DESCRIPTOR_PATHS:
            raise ReleaseDescriptorUnavailableError(
                "the descriptor path is not one the deploy contract allows"
            )
        with self._session_scope() as db:
            artifact = db.scalar(
                select(ReleaseArtifact).where(
                    ReleaseArtifact.product_code == catalogue_product,
                    ReleaseArtifact.version == version,
                    ReleaseArtifact.artifact_kind == ArtifactKind.CONTAINER_IMAGE.value,
                )
            )
            if artifact is None:
                raise ReleaseDescriptorUnavailableError(
                    "the catalogue has no container image for that release"
                )
            attestations = list(
                db.scalars(
                    select(ArtifactAttestation).where(
                        ArtifactAttestation.artifact_id == artifact.id,
                        ArtifactAttestation.attestation_kind
                        == AttestationKind.DEPLOY_UNIT.value,
                    )
                )
            )
            if not attestations:
                raise ReleaseDescriptorUnavailableError(
                    "the release has no deploy_unit attestation"
                )
            if len(attestations) != 1:
                raise ReleaseDescriptorUnavailableError(
                    "the release has ambiguous deploy_unit attestations"
                )
            attestation = attestations[0]
            _held, attested_path = split_attestation_uri(attestation.uri)
            if attested_path != descriptor_path:
                raise ReleaseDescriptorUnavailableError(
                    "the attested descriptor is for a different path"
                )
            ref, _, digest = artifact.artifact_ref.rpartition("@")
            if not ref or digest != artifact.digest:
                raise ReleaseDescriptorUnavailableError(
                    "the artifact reference does not pin the artifact digest"
                )
            attested_digest = attestation.digest
            source_revision = artifact.source_revision
            image_digest = artifact.digest
        try:
            payload = self._store().read(digest=attested_digest)
        except (ReleaseEvidenceError, OSError):
            raise ReleaseDescriptorUnavailableError(
                "the attested descriptor bytes are not held, or do not match"
            ) from None
        return ReleaseDescriptorEvidence(
            release_ref=release_ref,
            product_code=product_code,
            descriptor_path=descriptor_path,
            source_revision=source_revision,
            image_repository=ref,
            image_digest=image_digest,
            deploy_unit_bytes=payload,
            attested_digest=attested_digest,
        )
