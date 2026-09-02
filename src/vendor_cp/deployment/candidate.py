"""The candidate deployment: DERIVED from the accepted descriptor, never edited into it.

## The circularity this removes

`deploy/product.toml` describes the image that is RUNNING. An execution plan
needs the image that will run. Those cannot be the same field, and the reason is
structural rather than procedural:

- the desired digest does not exist until the image is published;
- publishing happens from a commit, and `Dockerfile` bakes that commit into
  `org.opencontainers.image.revision`, which is inside the config blob;
- so a commit that names the digest of the image built from it changes that
  image's digest by existing.

Pre-editing `[image]` is therefore not merely forbidden by ADR-0017 s 2 — which
refuses a descriptor that claims a deployment nobody performed — it is not
expressible. The way out is not an edit but a DERIVATION:

    accepted descriptor + accepted release receipt
            -> candidate spec (two fields replaced, nothing else)
            -> canonical document
            -> FoundationExecutionPlanV1

The accepted descriptor is read and never written. The candidate exists only for
as long as the authorization does, and Git is updated AFTER a successful
deployment, as a projection of what happened rather than as permission for it.

## Two identities that were one, and the bug that came of it

The production workflow verified the deploying revision against `origin/main`'s
head. That conflated:

- the **image source revision** — fixed forever by the release receipt, and a
  property of the artifact; and
- the **deployment-adapter revision** — the protected revision the workflow
  itself runs from.

While they were one value the only deployable image was the one built from the
tip of `main`, which is why there is no reverse path: the running bytes are
never the tip. Separating them is what makes a rollback expressible without
weakening anything — the CI run must still be green FOR the revision being
deployed, and that revision must still be an ancestor of protected `main`.

## Why an operator cannot supply an image

`CandidateImage` carries a private witness that only :func:`admit_candidate_image`
holds, so it cannot be constructed from a string an operator typed. This is the
same device `dotmac_deployment_foundation.authorization.ExecutionGrant` uses,
and it is here for the same reason: "the override must come from a verified
receipt" has to be a shape rather than a rule somebody remembers. A raw
reference has nowhere to go.

## What this module does NOT do

It does not canonicalize and it does not digest. `build_canonical_document` and
`render_execution_plan` belong to the Foundation, and a second implementation of
either would be a second answer to what was authorized — the exact divergence
`ExecutionPlanDigestV1` exists to remove. The Foundation is imported INSIDE
:func:`render_candidate`, so its absence is a runtime answer
(`evidence.tool_absent`) rather than a collection error, exactly as
`vendor_cp.recovery.bundle` already treats it.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Protocol

__all__ = [
    "RECEIPT_CONTRACT",
    "CandidateImage",
    "CandidateRefused",
    "FoundationAbsent",
    "PlanRenderer",
    "RegistryObservation",
    "ReleaseReceiptV1",
    "RenderedCandidate",
    "admit_candidate_image",
    "render_candidate",
]

#: The receipt contract `production-image.yml` emits. A receipt in any other
#: shape may have been produced under rules this code cannot evaluate.
RECEIPT_CONTRACT: Final = "dotmac-candidate-release-receipt/1"

_SHA256: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
_REVISION: Final = re.compile(r"^[0-9a-f]{40}$")


class CandidateRefused(ValueError):
    """The candidate does not bind to the evidence offered for it.

    Deliberately not "the deployment is unauthorized": nothing has been asked of
    Deployment Control at this point. This assembly compared what it was handed
    against what the receipt and the registry say, and stopped first.
    """


class FoundationAbsent(RuntimeError):
    """`dotmac-deployment-foundation` is not installed in this interpreter.

    An ABSENCE, never a refusal. Nothing looked, so the same call may well
    succeed once the facility is installed — which is the distinction the CLI's
    `4` exists to preserve against `3`.
    """


def _text(document: Mapping[str, object], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value.strip():
        raise CandidateRefused(
            f"the release receipt has no usable {key!r}; a receipt that cannot "
            "state it is not a receipt for anything"
        )
    return value


@dataclass(frozen=True, slots=True)
class ReleaseReceiptV1:
    """What `production-image.yml` recorded about ONE accepted candidate.

    Parsed rather than trusted. `reference` and `registry_digest` are two
    spellings of one fact and are checked against each other here, because a
    receipt whose reference names a different image than its digest would
    otherwise deploy one and record the other.
    """

    source_revision: str
    registry_digest: str
    reference: str
    config_digest: str
    registry_config_digest: str
    rootfs_chain: str
    ci_run_id: str
    release_run_id: str

    @classmethod
    def from_document(cls, document: Mapping[str, object]) -> ReleaseReceiptV1:
        contract = document.get("contract")
        if contract != RECEIPT_CONTRACT:
            raise CandidateRefused(
                f"unknown release receipt contract {contract!r}; expected "
                f"{RECEIPT_CONTRACT!r}. A receipt this code cannot read is not "
                "a receipt it may act on"
            )
        source_revision = _text(document, "source_revision")
        if not _REVISION.match(source_revision):
            raise CandidateRefused(
                f"source_revision {source_revision!r} is not a 40-character "
                "commit; an abbreviated revision is ambiguous forever"
            )
        registry_digest = _text(document, "registry_digest")
        if not _SHA256.match(registry_digest):
            raise CandidateRefused(
                f"registry_digest {registry_digest!r} is not sha256:<64 hex>"
            )
        reference = _text(document, "reference")
        if not reference.endswith("@" + registry_digest):
            raise CandidateRefused(
                f"the receipt's reference {reference!r} does not name its own "
                f"digest {registry_digest}. One deployment would run the "
                "reference and the record would name the digest"
            )
        return cls(
            source_revision=source_revision,
            registry_digest=registry_digest,
            reference=reference,
            config_digest=_text(document, "config_digest"),
            registry_config_digest=_text(document, "registry_config_digest"),
            rootfs_chain=_text(document, "rootfs_chain"),
            ci_run_id=_text(document, "ci_run_id"),
            release_run_id=_text(document, "release_run_id"),
        )


@dataclass(frozen=True, slots=True)
class RegistryObservation:
    """What the registry says about the reference, read by the CALLER.

    Read-back rather than recollection. The receipt is what this repository
    wrote down; this is what the registry answers now, and the two agreeing is
    the only reason to believe the bytes were not replaced after acceptance.
    """

    manifest_digest: str
    revision_label: str


class _Witness:
    """Held only by this module. See :class:`CandidateImage`."""

    __slots__ = ()


_ADMITTED: Final = _Witness()


@dataclass(frozen=True, slots=True)
class CandidateImage:
    """The ONLY admissible image override, and it cannot be typed by hand.

    The witness is positional and required, and only :func:`admit_candidate_image`
    has one. A caller holding an image reference as a string has nothing to
    construct this with, so "the override must come from a verified receipt"
    stops being expressible any other way rather than merely being discouraged.
    """

    _witness: _Witness
    reference: str
    source_revision: str

    def __post_init__(self) -> None:
        if self._witness is not _ADMITTED:
            raise CandidateRefused(
                "a CandidateImage may only be produced by admit_candidate_image "
                "from a verified release receipt. An operator-supplied image "
                "reference is exactly what this type exists to refuse"
            )


def admit_candidate_image(
    receipt: ReleaseReceiptV1, observation: RegistryObservation
) -> CandidateImage:
    """Admit the receipt's image, or refuse. The only producer of a candidate image.

    Both comparisons are against the receipt, and neither is derived from the
    other. Reading the expected digest out of the observation would compare the
    registry with itself and pass for every input, which is the shape of a check
    that has stopped checking.
    """
    if observation.manifest_digest != receipt.registry_digest:
        raise CandidateRefused(
            f"the registry resolves this reference to "
            f"{observation.manifest_digest}, and the receipt accepted "
            f"{receipt.registry_digest}. These are different bytes"
        )
    if observation.revision_label != receipt.source_revision:
        raise CandidateRefused(
            f"the published image is labelled {observation.revision_label!r} and "
            f"the receipt names revision {receipt.source_revision!r}. The label "
            "is inside the config the digest covers, so a disagreement here "
            "means the receipt describes a different build"
        )
    return CandidateImage(_ADMITTED, receipt.reference, receipt.source_revision)


@dataclass(frozen=True, slots=True)
class RenderedCandidate:
    """The three values the packet carries, produced together or not at all."""

    descriptor_digest: str
    execution_plan_digest: str
    canonical_plan_bytes: bytes


class PlanRenderer(Protocol):
    """The Foundation's canonicalization, as a port this assembly does not own.

    A port rather than a direct call so a test can observe WHAT is handed
    across without this repository growing a second canonicalizer. The default
    implementation is the Foundation itself.
    """

    def __call__(
        self,
        *,
        descriptor_path: str,
        image: CandidateImage,
        target: str,
        operation: str,
    ) -> RenderedCandidate: ...


def _foundation_renderer(
    *,
    descriptor_path: str,
    image: CandidateImage,
    target: str,
    operation: str,
) -> RenderedCandidate:
    """Replace two fields, then let the Foundation say what that means.

    The import is late and its absence is an ABSENCE — see this module's
    docstring and `vendor_cp.recovery.bundle`, which draws the same line.
    """
    try:
        import dataclasses  # noqa: PLC0415 - local to the late import below

        from dotmac_deployment_foundation.document import (  # noqa: PLC0415
            build_canonical_document,
        )
        from dotmac_deployment_foundation.engine.plan import (  # noqa: PLC0415
            build_plan,
        )
        from dotmac_deployment_foundation.execution_plan import (  # noqa: PLC0415
            render_execution_plan,
        )
        from dotmac_deployment_foundation.spec import (  # noqa: PLC0415
            ProductDeploymentSpec,
        )
    except ImportError as error:  # pragma: no cover - exercised by absence
        raise FoundationAbsent(
            "dotmac-deployment-foundation is not installed, so no canonical "
            "document and no execution plan can be produced here. This "
            "assembly does not implement either: a second canonicalizer is a "
            "second answer to what was authorized"
        ) from error

    accepted = ProductDeploymentSpec.load(descriptor_path)
    # ONLY these two. Anything else changed here would be a descriptor edit
    # wearing a derivation's clothes, and the approver would be approving a
    # configuration that exists in no reviewed file.
    candidate = dataclasses.replace(
        accepted,
        image=image.reference,
        source_revision=image.source_revision,
    )
    document = build_canonical_document(candidate)
    plan = render_execution_plan(
        candidate,
        build_plan(candidate),
        target=target,
        operation=operation,
        descriptor_digest=document.sha256_digest(),
    )
    return RenderedCandidate(
        descriptor_digest=document.sha256_digest(),
        execution_plan_digest=plan.digest(),
        canonical_plan_bytes=plan.canonical_bytes(),
    )


def render_candidate(
    descriptor_path: str,
    image: CandidateImage,
    *,
    target: str,
    operation: str,
    renderer: PlanRenderer | None = None,
) -> RenderedCandidate:
    """Derive the candidate's canonical document and execution plan.

    `target` and `operation` are stated by the caller and never derived from the
    descriptor: a target read out of the thing being deployed would make every
    later comparison compare the descriptor with itself.

    Re-run at execution time from the SAME accepted descriptor and the SAME
    receipt, this returns the same digest — which is what makes recomputing
    before execution a check rather than a ceremony.
    """
    if not target.strip():
        raise CandidateRefused(
            "a candidate with no target is one that authorizes every host"
        )
    render = _foundation_renderer if renderer is None else renderer
    return render(
        descriptor_path=descriptor_path,
        image=image,
        target=target,
        operation=operation,
    )
