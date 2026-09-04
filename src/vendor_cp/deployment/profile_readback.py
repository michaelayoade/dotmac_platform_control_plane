"""Read the embedded `ApplicationFoundationProfile` back out of the ARTIFACT.

This lands BEFORE the document it verifies, deliberately, and that order is the
whole design.

## Why the verifier goes first

The programme reported "ten of thirteen concerns bound" for days. It was
measuring the wrong thing: ten IMPLEMENTATIONS existed in the source tree, while
no canonical profile document was embedded in the Platform artifact, discovery
returned nothing across the isolated tool boundary, and no runtime readback
proved composition. Ten implementations that exist and a profile that deploys
are different claims, and only the second one is about the artifact.

Embedding a document first and writing a reader afterwards cannot detect a
repeat of that: a verifier written against a document that is already there can
only ever confirm what is already there. So this module ships now, REFUSES
(`DOCUMENT_ABSENT`, which is the honest state of the artifact today), and the
document that follows turns the refusal into an admission. A refusal that
becomes an admission when the document lands is evidence the document is
CONSUMED. Presence is not consumption.

## Reads independently of the builder

Nothing here imports the profile builder, calls its serializer, or re-derives an
expectation from the code that produced the document. Three separate sources
have to agree:

* the **profile document** shipped in the artifact — the claim under test;
* `distributions.json` — per-file wheel and sdist digests, computed in the same
  builder stage that installed them and already carried into the image for
  exactly this purpose, and produced by a different mechanism than the profile;
* the **expected coordinates** the caller holds, which come from the release
  receipt rather than from anything inside the image.

An artifact that describes itself is not evidence about itself. The document is
never allowed to be the only witness to its own binding.

The canonical encoding below is a SPECIFICATION the builder must also
implement, not code for it to import. Sharing an encoder would make the digest
a statement that one function agrees with itself.

## Unreadable is not mismatched

Two verdicts, never one. A document that cannot be parsed and a document that
parses and disagrees have different repairs — a broken build versus an artifact
that is not the one authorized — and collapsing them would report a corrupt file
as a security refusal, or worse, the reverse. Same rule the table inventory
keeps per table: an unknown is a member of the type, never a zero.

## The cross-target case

An absence proof is well-formed, internally consistent, correctly signed for
what it is, and STILL inadmissible when it was produced for a different
artifact. A proof that concern X is absent from image A says nothing about image
B. A naive check — parse the proof, recompute its internal digest, accept —
passes this case, which is why the proof's own declared coordinates are checked
against the expected ones rather than against the proof itself.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final

__all__ = [
    "DEFAULT_DISTRIBUTIONS_PATH",
    "DEFAULT_PROFILE_PATH",
    "PROFILE_CONTRACT",
    "ExpectedArtifact",
    "ProfileReadback",
    "ProfileVerdict",
    "canonical_profile_digest",
    "verify_embedded_profile",
]

#: Where the document travels. Beside `distributions.json`, and for the same
#: stated reason: a claim about an artifact must be re-derivable from a pulled
#: image rather than trusted from the pipeline that made it.
DEFAULT_PROFILE_PATH: Final = Path("/app/application_foundation_profile.json")

#: Produced by the Dockerfile's builder stage, independently of the profile.
DEFAULT_DISTRIBUTIONS_PATH: Final = Path("/app/distributions.json")

PROFILE_CONTRACT: Final = "dotmac-application-foundation-profile/1"
DISTRIBUTIONS_CONTRACT: Final = "dotmac-distribution-digests/1"

#: The thirteen closed slots. A profile is complete or it is not; there is no
#: partial admission, because a concern with no owner is exactly what blocks a
#: candidate.
FOUNDATION_CONCERNS: Final[tuple[str, ...]] = (
    "identity_session",
    "authorization",
    "persistence_migrations",
    "settings_secrets",
    "audit_telemetry",
    "health_runtime_admission",
    "worker_execution",
    "edge_security",
    "api_web_interaction",
    "deployment_recovery",
    "request_evidence_context",
    "data_governance",
    "integration",
)


class ProfileVerdict(StrEnum):
    """Why the artifact was or was not admitted. Ordered by precedence below."""

    ADMITTED = "admitted"
    #: No document in the artifact at all — the state before it is embedded.
    DOCUMENT_ABSENT = "document_absent"
    #: Present and unusable. NEVER conflated with a document that disagrees.
    DOCUMENT_UNREADABLE = "document_unreadable"
    #: Parsed, but not a schema this verifier knows how to judge.
    CONTRACT_UNKNOWN = "contract_unknown"
    #: The document describes a different artifact than the one expected.
    ARTIFACT_COORDINATES_MISMATCHED = "artifact_coordinates_mismatched"
    #: The document's wheel digest is not the wheel this image carries.
    WHEEL_DIGEST_MISMATCHED = "wheel_digest_mismatched"
    #: The document's own digest does not cover its own content.
    PROFILE_DIGEST_MISMATCHED = "profile_digest_mismatched"
    #: A well-formed absence proof produced for a DIFFERENT artifact.
    ABSENCE_PROOF_FOREIGN = "absence_proof_foreign"
    #: Fewer than thirteen concerns are bound, or one is bound to nothing.
    CONCERNS_INCOMPLETE = "concerns_incomplete"


#: Checked in this order. Earlier verdicts describe a document that could not be
#: judged at all, so a later check would be reading fields it has no reason to
#: trust.
VERDICT_PRECEDENCE: Final[tuple[ProfileVerdict, ...]] = (
    ProfileVerdict.DOCUMENT_ABSENT,
    ProfileVerdict.DOCUMENT_UNREADABLE,
    ProfileVerdict.CONTRACT_UNKNOWN,
    ProfileVerdict.PROFILE_DIGEST_MISMATCHED,
    ProfileVerdict.ARTIFACT_COORDINATES_MISMATCHED,
    ProfileVerdict.WHEEL_DIGEST_MISMATCHED,
    ProfileVerdict.ABSENCE_PROOF_FOREIGN,
    ProfileVerdict.CONCERNS_INCOMPLETE,
    ProfileVerdict.ADMITTED,
)


@dataclass(frozen=True, slots=True)
class ExpectedArtifact:
    """What the caller independently knows the artifact to be.

    From the release receipt, never from the image. An expectation read out of
    the thing being checked is not an expectation.
    """

    source_revision: str
    wheel_sha256: str

    def __post_init__(self) -> None:
        if not self.source_revision:
            raise ValueError("source_revision is empty; there is nothing to bind to")
        if not self.wheel_sha256.startswith("sha256:"):
            raise ValueError("wheel_sha256 must be a `sha256:`-prefixed digest")


@dataclass(frozen=True, slots=True)
class ProfileReadback:
    """One verdict and what produced it. `detail` never carries file contents."""

    verdict: ProfileVerdict
    detail: str
    #: The concerns the document actually bound, for a reader that wants to see
    #: WHICH are missing rather than only that some are.
    bound_concerns: tuple[str, ...] = ()

    @property
    def admitted(self) -> bool:
        return self.verdict is ProfileVerdict.ADMITTED


def canonical_profile_digest(document: Mapping[str, object]) -> str:
    """The document's digest, over everything except the digest field itself.

    THE SPECIFICATION, which the builder implements separately: UTF-8 JSON, keys
    sorted, no insignificant whitespace, non-ASCII kept as itself, with
    `profile_digest` removed — a field cannot be an input to its own value.
    """
    body = {key: value for key, value in document.items() if key != "profile_digest"}
    encoded = json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _load(path: Path) -> tuple[Mapping[str, object] | None, ProfileReadback | None]:
    """Parse `path`, or say which of the two failures happened."""
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None, ProfileReadback(
            ProfileVerdict.DOCUMENT_ABSENT,
            f"no profile document at {path}: this artifact makes no profile "
            "claim, so there is nothing to admit",
        )
    except OSError as error:
        return None, ProfileReadback(
            ProfileVerdict.DOCUMENT_UNREADABLE,
            f"{path} could not be read ({error.__class__.__name__}). Unreadable "
            "is not mismatched: this says nothing about whether the artifact is "
            "the authorized one",
        )
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        return None, ProfileReadback(
            ProfileVerdict.DOCUMENT_UNREADABLE,
            f"{path} is not valid UTF-8 JSON ({error.__class__.__name__})",
        )
    if not isinstance(parsed, dict):
        return None, ProfileReadback(
            ProfileVerdict.DOCUMENT_UNREADABLE,
            f"{path} is a {type(parsed).__name__}, not a document",
        )
    return parsed, None


def _installed_wheel_digest(path: Path) -> str | None:
    """The wheel digest as the BUILDER STAGE recorded it, read independently.

    None when the record is missing or unusable — the caller turns that into
    `DOCUMENT_UNREADABLE` rather than into a mismatch, because a missing
    second witness is not a disagreement between two.
    """
    document, _failure = _load(path)
    if document is None or document.get("contract") != DISTRIBUTIONS_CONTRACT:
        return None
    files = document.get("files")
    if not isinstance(files, list):
        return None
    for entry in files:
        if not isinstance(entry, dict):
            continue
        name = entry.get("filename")
        digest = entry.get("sha256")
        if isinstance(name, str) and name.endswith(".whl") and isinstance(digest, str):
            return digest
    return None


def _absence_proofs(document: Mapping[str, object]) -> Sequence[Mapping[str, object]]:
    proofs = document.get("absence_proofs")
    if not isinstance(proofs, list):
        return ()
    return [entry for entry in proofs if isinstance(entry, dict)]


def verify_embedded_profile(
    expected: ExpectedArtifact,
    *,
    profile_path: Path = DEFAULT_PROFILE_PATH,
    distributions_path: Path = DEFAULT_DISTRIBUTIONS_PATH,
) -> ProfileReadback:
    """Judge the profile document this artifact carries against `expected`.

    Today this returns `DOCUMENT_ABSENT` against a real Platform image, which is
    the correct description of that image. When the canonical document is
    embedded, the same call admits — and that transition is the evidence the
    document is read rather than merely shipped.
    """
    document, failure = _load(profile_path)
    if failure is not None:
        return failure
    assert document is not None  # noqa: S101 - narrowing; `_load` returns one or other

    contract = document.get("contract")
    if contract != PROFILE_CONTRACT:
        return ProfileReadback(
            ProfileVerdict.CONTRACT_UNKNOWN,
            f"profile contract {contract!r} is not {PROFILE_CONTRACT!r}; this "
            "verifier will not guess at the meaning of a schema it does not know",
        )

    declared_digest = document.get("profile_digest")
    recomputed = canonical_profile_digest(document)
    if declared_digest != recomputed:
        return ProfileReadback(
            ProfileVerdict.PROFILE_DIGEST_MISMATCHED,
            "the document's own digest does not cover its own content "
            f"(declares {declared_digest!r}, content yields {recomputed!r})",
        )

    if document.get("source_revision") != expected.source_revision:
        return ProfileReadback(
            ProfileVerdict.ARTIFACT_COORDINATES_MISMATCHED,
            "the profile describes a different artifact: it names revision "
            f"{document.get('source_revision')!r}, expected "
            f"{expected.source_revision!r}",
        )

    carried = _installed_wheel_digest(distributions_path)
    if carried is None:
        return ProfileReadback(
            ProfileVerdict.DOCUMENT_UNREADABLE,
            f"the independent distribution record at {distributions_path} is "
            "missing or unusable, so the profile's wheel claim has no second "
            "witness. An artifact that describes itself is not evidence about "
            "itself",
        )
    claimed = document.get("wheel_sha256")
    if claimed != expected.wheel_sha256 or carried != expected.wheel_sha256:
        return ProfileReadback(
            ProfileVerdict.WHEEL_DIGEST_MISMATCHED,
            "the wheel this profile is bound to is not the expected wheel "
            f"(profile claims {claimed!r}, the image carries {carried!r}, "
            f"expected {expected.wheel_sha256!r})",
        )

    for proof in _absence_proofs(document):
        proof_revision = proof.get("source_revision")
        if proof_revision != expected.source_revision:
            return ProfileReadback(
                ProfileVerdict.ABSENCE_PROOF_FOREIGN,
                "an absence proof was produced for a different artifact "
                f"(concern {proof.get('concern')!r} carries revision "
                f"{proof_revision!r}, this artifact is "
                f"{expected.source_revision!r}). It may be perfectly well-formed "
                "and still say nothing about THIS image",
            )

    concerns = document.get("concerns")
    bound: tuple[str, ...] = ()
    if isinstance(concerns, dict):
        bound = tuple(
            name
            for name in FOUNDATION_CONCERNS
            if isinstance(concerns.get(name), dict) and concerns.get(name)
        )
    if len(bound) != len(FOUNDATION_CONCERNS):
        missing = [name for name in FOUNDATION_CONCERNS if name not in bound]
        return ProfileReadback(
            ProfileVerdict.CONCERNS_INCOMPLETE,
            f"{len(bound)} of {len(FOUNDATION_CONCERNS)} concerns are bound; "
            f"unbound: {', '.join(missing)}",
            bound,
        )

    return ProfileReadback(
        ProfileVerdict.ADMITTED,
        f"all {len(FOUNDATION_CONCERNS)} concerns bound, profile digest and "
        "wheel agree with the independent distribution record",
        bound,
    )
