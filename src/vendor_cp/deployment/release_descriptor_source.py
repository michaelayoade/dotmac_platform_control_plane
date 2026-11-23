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

A PRIMARY descriptor resolves only from the artifact whose catalogue product
equals the descriptor's own `product`; a companion descriptor resolves only via
the `deploy_unit` attestation whose fragment is its path, on whichever artifact
carries it. Exactly one container-image artifact must exist for the ref.

`product_toml_path` / `product_toml_sha256` come from the `product_spec`
attestation whose fragment is the descriptor's `spec` path (catalogue a6), with
the sha recomputed over the held bytes. A primary with none is refused; two
attestations for one path with different digests are `ambiguous`. A companion
whose product.toml is pending (I3) leaves both absent, and Control then refuses
every plan for it.
"""

from __future__ import annotations

import re
import tomllib
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
    PRIMARY_DESCRIPTOR_PATH,
    SPEC_PATHS,
    HeldDocuments,
    product_spec_kind,
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
    # The one existing platform-session borrower (`dotmac_kernel.db` importers
    # are a ratcheted inventory that is being retired, so no new one is added).
    # Its refusals are CLI-shaped; here any failure means "cannot answer".
    from vendor_cp.cli.runtime import platform_db

    return _Guarded(platform_db())


class _Guarded:
    def __init__(self, inner: AbstractContextManager[Session]) -> None:
        self._inner = inner

    def __enter__(self) -> Session:
        try:
            return self._inner.__enter__()
        except Exception:
            raise ReleaseDescriptorUnavailableError(
                "the catalogue database is unavailable"
            ) from None

    def __exit__(self, *exc: object) -> bool | None:
        return self._inner.__exit__(*exc)  # type: ignore[arg-type]


def _default_store() -> HeldDocuments:
    from vendor_cp.config import vendor_settings

    return HeldDocuments.under(vendor_settings.held_documents_directory)


def _distinct(
    rows: list[ArtifactAttestation], *, path: str, what: str
) -> ArtifactAttestation | None:
    """The one attestation for `path`; two with different digests are ambiguous."""
    matching = [r for r in rows if split_attestation_uri(r.uri)[1] == path]
    if len({r.digest for r in matching}) > 1:
        raise ReleaseDescriptorUnavailableError(
            f"the release has ambiguous {what} attestations for that path"
        )
    return matching[0] if matching else None


class CatalogueReleaseDescriptorSource:
    """Read-only: it never publishes, attests, fetches a URL or writes a file."""

    def __init__(
        self,
        *,
        session_scope: SessionScope = _default_session_scope,
        store: Callable[[], HeldDocuments] = _default_store,
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
        spec_kind: str | None
        try:
            spec_kind = product_spec_kind().value
        except ReleaseEvidenceError:
            spec_kind = None
        with self._session_scope() as db:
            artifacts = list(
                db.scalars(
                    select(ReleaseArtifact).where(
                        ReleaseArtifact.product_code == catalogue_product,
                        ReleaseArtifact.version == version,
                        ReleaseArtifact.artifact_kind
                        == ArtifactKind.CONTAINER_IMAGE.value,
                    )
                )
            )
            if len(artifacts) != 1:
                raise ReleaseDescriptorUnavailableError(
                    "the catalogue does not hold exactly one container image "
                    "for that release"
                )
            artifact = artifacts[0]
            rows = list(
                db.scalars(
                    select(ArtifactAttestation).where(
                        ArtifactAttestation.artifact_id == artifact.id,
                        ArtifactAttestation.attestation_kind.in_(
                            [AttestationKind.DEPLOY_UNIT.value, spec_kind or ""]
                        ),
                    )
                )
            )
            unit = _distinct(
                [r for r in rows if r.attestation_kind == "deploy_unit"],
                path=descriptor_path,
                what="deploy_unit",
            )
            if unit is None:
                raise ReleaseDescriptorUnavailableError(
                    "the release has no deploy_unit attestation for that path"
                )
            ref, _, digest = artifact.artifact_ref.rpartition("@")
            if not ref or digest != artifact.digest:
                raise ReleaseDescriptorUnavailableError(
                    "the artifact reference does not pin the artifact digest"
                )
            source_revision = artifact.source_revision
            if source_revision is None:
                raise ReleaseDescriptorUnavailableError(
                    "the catalogued artifact records no source revision"
                )
            image_digest = artifact.digest
            attested_digest = unit.digest
            spec_rows = [r for r in rows if r.attestation_kind == spec_kind]
        held = self._store()
        try:
            payload = held.deploy_units.read(digest=attested_digest)
            document = tomllib.loads(payload.decode("utf-8"))
        except (ReleaseEvidenceError, OSError, UnicodeDecodeError, ValueError):
            raise ReleaseDescriptorUnavailableError(
                "the attested descriptor bytes are not held, or do not match"
            ) from None
        if (
            descriptor_path == PRIMARY_DESCRIPTOR_PATH
            and document.get("product") != catalogue_product
        ):
            raise ReleaseDescriptorUnavailableError(
                "a primary descriptor resolves only from the artifact of its own "
                "product"
            )
        spec_path = document.get("spec")
        if spec_path != SPEC_PATHS[descriptor_path]:
            raise ReleaseDescriptorUnavailableError(
                "the descriptor's spec is not the path its location requires"
            )
        spec = _distinct(spec_rows, path=spec_path, what="product_spec")
        spec_sha: str | None = None
        if spec is None:
            if descriptor_path == PRIMARY_DESCRIPTOR_PATH:
                raise ReleaseDescriptorUnavailableError(
                    "a primary release has no product_spec attestation"
                )
        else:
            try:
                held.product_specs.read(digest=spec.digest)  # recomputes the sha
            except (ReleaseEvidenceError, OSError):
                raise ReleaseDescriptorUnavailableError(
                    "the attested product.toml bytes are not held, or do not match"
                ) from None
            spec_sha = spec.digest
        return ReleaseDescriptorEvidence(
            release_ref=release_ref,
            product_code=product_code,
            descriptor_path=descriptor_path,
            source_revision=source_revision,
            image_repository=ref,
            image_digest=image_digest,
            deploy_unit_bytes=payload,
            attested_digest=attested_digest,
            product_toml_path=None if spec_sha is None else spec_path,
            product_toml_sha256=spec_sha,
        )
