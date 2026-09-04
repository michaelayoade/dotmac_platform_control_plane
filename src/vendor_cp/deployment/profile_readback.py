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

## An absence proof SATISFIES, and only when it ESTABLISHES

Ruled 2026-09-04: a proven absence may satisfy a concern, but **only** through
`IntegrationSurfaceAbsenceProofV1`, bound to the exact installed artifact and to
a closed surface inventory — *"this is not a general 'nothing applies' escape
hatch."*

Four things keep it from becoming one, and the fourth is the one people leave
out:

1. **A closed schema-to-concern map.** :data:`ABSENCE_PROOF_CONCERNS` has one
   entry. A document of this schema naming any other concern is refused by name
   rather than ignored, so a hand-written proof cannot certify
   `data_governance` — which an earlier ruling already refused an `inapplicable`
   for, and which an absence proof does not repair either.

2. **The unmanufacturable half.** ``observed_inventory_digest`` must equal a
   digest THIS module computes from ``distributions.json`` — the per-file record
   the builder stage produced independently of the profile. A caller may write
   any string into the proof; it cannot make that string equal one derived from
   the image without having examined that image.

3. **Coordinates that bind it to this artifact.** ``source_revision`` and the
   artifact digest, checked against what the caller holds from the release
   receipt rather than against the document.

4. **The producing type's own refusals, RE-CHECKED here.**
   `IntegrationSurfaceAbsenceProofV1.__post_init__` enforces complete
   enumeration, emptiness and a positive control — *in the producing process*.
   What arrives here is JSON. **The constructor's refusals did not travel with
   it.** A verifier that trusted the schema string would accept
   ``{"schema": "IntegrationSurfaceAbsenceProofV1", "state": "absent_proven"}``
   with no families at all, which is precisely the escape hatch. So the five
   families are re-enumerated, each must be present and empty, and the positive
   control must be non-empty — a proof whose instrument was never shown finding
   anything cannot distinguish "nothing is there" from "this scan finds nothing".

### What is NOT checked, and why it is named rather than skipped

The proof's ``image_digest`` is compared against the caller's
:attr:`ExpectedArtifact.wheel_sha256` — the INSTALLED ARTIFACT, which is what
Foundation's own docstring calls it. That reading is forced rather than
preferred: the proof travels INSIDE the profile document, the profile document is
baked into the container image, and a container digest computed over layers that
include the document cannot appear in the document. The two alternatives are
self-contradictory, so the artifact reading is the only one left.

If Foundation settles on a different meaning, this check fails LOUDLY rather than
admitting wrongly, which is the safe direction for an inference about another
repository's type. It is recorded here as an inference, not as a shared contract.

## The inventory digest is a SPECIFICATION, like the profile digest

:func:`canonical_inventory_digest` is what a producer must implement separately,
never import. Sharing an encoder would make the comparison a statement that one
function agrees with itself — the same reason `canonical_profile_digest` is a
spec rather than a shared helper.
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
    "ABSENCE_PROOF_CONCERNS",
    "DEFAULT_DISTRIBUTIONS_PATH",
    "DEFAULT_PROFILE_PATH",
    "INTEGRATION_ABSENCE_SCHEMA",
    "INTEGRATION_SURFACE_FAMILIES",
    "PROFILE_CONTRACT",
    "ExpectedArtifact",
    "ProfileReadback",
    "ProfileVerdict",
    "canonical_inventory_digest",
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

#: Foundation's discriminated proof schema. Spelled out rather than imported:
#: nothing in this module imports the builder or the type it verifies, and a
#: string read out of the document is what actually arrives.
INTEGRATION_ABSENCE_SCHEMA: Final = "IntegrationSurfaceAbsenceProofV1"

#: The closed surface inventory the proof must have enumerated COMPLETELY.
#: Restated here, not imported, because the check is against what the DOCUMENT
#: says — and a verifier that took the list from the same place the producer did
#: would agree with the producer by construction.
INTEGRATION_SURFACE_FAMILIES: Final[frozenset[str]] = frozenset(
    {
        "outbound_connector",
        "inbound_webhook",
        "scheduled_sync",
        "message_consumer",
        "external_api_client",
    }
)

#: Which concern each absence-proof schema may satisfy. ONE entry, and the point
#: of the mapping is everything that is not in it.
#:
#: Ruled 2026-09-04: absence is approved only through
#: `IntegrationSurfaceAbsenceProofV1`, and *"this is not a general 'nothing
#: applies' escape hatch."* `data_governance` in particular is not repairable
#: this way — an earlier ruling already refused an `inapplicable` for it, and it
#: needs a real implementation rather than a better proof of emptiness. A proof
#: naming a concern this map does not grant it is REFUSED, never ignored: ignoring
#: it would let a document carry a certification nobody rejected.
ABSENCE_PROOF_CONCERNS: Final[dict[str, str]] = {
    INTEGRATION_ABSENCE_SCHEMA: "integration",
}

#: The state a proven absence declares. A document that omits it is not making
#: this claim, whatever else it carries.
ABSENCE_PROVEN_STATE: Final = "absent_proven"


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
    #: A proof of a schema that may not certify the concern it names — or of a
    #: schema this verifier grants nothing at all. Refused, never ignored.
    ABSENCE_PROOF_INADMISSIBLE = "absence_proof_inadmissible"
    #: Well-formed, for this artifact, and it ESTABLISHES nothing: an inventory
    #: digest that is not the one derived from the image, an incomplete
    #: enumeration, a family that was not empty, or no positive control.
    ABSENCE_PROOF_UNESTABLISHED = "absence_proof_unestablished"
    #: Fewer than thirteen concerns are satisfied, or one is bound to nothing.
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
    ProfileVerdict.ABSENCE_PROOF_INADMISSIBLE,
    ProfileVerdict.ABSENCE_PROOF_UNESTABLISHED,
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
    #: The concerns the document actually satisfied — declared bound, or proven
    #: absent by an ESTABLISHED proof. For a reader that wants to see WHICH are
    #: missing rather than only that some are.
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


def canonical_inventory_digest(files: Sequence[tuple[str, str]]) -> str:
    """The digest of the artifact's own distribution inventory.

    THE SPECIFICATION, which a proof's producer implements separately: the
    `(filename, sha256)` pairs of every distribution the builder stage recorded,
    sorted by filename, as UTF-8 JSON with no insignificant whitespace.

    Filename and digest only. A size is redundant beside a content digest, and a
    field that adds nothing to the identity adds a way for two correct
    implementations to disagree.

    This is what makes ``observed_inventory_digest`` unmanufacturable: a caller
    can write any string into a proof, and cannot make that string equal this
    value without having read the same inventory.
    """
    body = sorted((str(name), str(digest)) for name, digest in files)
    encoded = json.dumps(
        [list(pair) for pair in body], separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _distribution_inventory(path: Path) -> tuple[tuple[str, str], ...] | None:
    """The builder stage's per-file record, read independently of the profile.

    None when the record is missing or unusable — the caller turns that into
    `DOCUMENT_UNREADABLE` rather than into a mismatch, because a missing
    second witness is not a disagreement between two.

    An entry missing either half makes the WHOLE inventory unusable rather than
    being skipped. A silently narrowed inventory still produces a digest, and a
    digest over the wrong set is the failure this second witness exists to
    prevent.
    """
    document, _failure = _load(path)
    if document is None or document.get("contract") != DISTRIBUTIONS_CONTRACT:
        return None
    files = document.get("files")
    if not isinstance(files, list) or not files:
        return None
    entries: list[tuple[str, str]] = []
    for entry in files:
        if not isinstance(entry, dict):
            return None
        name = entry.get("filename")
        digest = entry.get("sha256")
        if not isinstance(name, str) or not isinstance(digest, str):
            return None
        entries.append((name, digest))
    return tuple(entries)


def _wheel_digest(inventory: Sequence[tuple[str, str]]) -> str | None:
    """The one `.whl` entry's digest, or None when there is not exactly one."""
    wheels = [digest for name, digest in inventory if name.endswith(".whl")]
    if len(wheels) != 1:
        return None
    return wheels[0]


def _absence_proofs(document: Mapping[str, object]) -> Sequence[Mapping[str, object]]:
    proofs = document.get("absence_proofs")
    if not isinstance(proofs, list):
        return ()
    return [entry for entry in proofs if isinstance(entry, dict)]


def _establishes(
    proof: Mapping[str, object], *, artifact_digest: str, inventory_digest: str
) -> str:
    """Empty when the proof establishes its concern's absence; else the reason.

    The producing type's `__post_init__` already refused an incomplete
    enumeration, an occupied family and a missing positive control — **in the
    producing process.** What arrives here is JSON, and a constructor's refusals
    do not travel in a document. So they are re-checked, against what this
    document actually says, or a hand-written object with the right `schema`
    string would satisfy a concern nothing ever scanned.
    """
    if proof.get("state") != ABSENCE_PROVEN_STATE:
        return (
            f"the proof declares state {proof.get('state')!r}, not "
            f"{ABSENCE_PROVEN_STATE!r}; it is not making this claim"
        )
    if proof.get("observed_inventory_digest") != inventory_digest:
        return (
            "the proof's observed inventory digest "
            f"{proof.get('observed_inventory_digest')!r} is not the one derived "
            f"from this image's own distribution record ({inventory_digest}). "
            "This is the half a caller cannot manufacture: writing a string is "
            "free, making it equal a digest an independent reader computed is "
            "not"
        )
    if proof.get("image_digest") != artifact_digest:
        return (
            f"the proof binds to artifact {proof.get('image_digest')!r} and this "
            f"one is {artifact_digest!r}"
        )
    families = proof.get("families")
    if not isinstance(families, dict):
        return (
            "the proof reports no family mapping, so no family was visited and "
            "nothing was enumerated"
        )
    missing = sorted(INTEGRATION_SURFACE_FAMILIES - set(families))
    if missing:
        return (
            f"the proof did not visit {missing}. A family never looked at is not "
            "a family found empty, and a subset is the shape complete "
            "enumeration exists to refuse"
        )
    unregistered = sorted(set(families) - INTEGRATION_SURFACE_FAMILIES)
    if unregistered:
        return (
            f"the proof reports families {unregistered}, which are outside the "
            "closed inventory. A surface nobody registered silently satisfies "
            "'none present', which is the failure mode absence proofs actually "
            "have"
        )
    occupied = sorted(name for name, found in families.items() if found)
    if occupied:
        return (
            f"the scan found integration surfaces in {occupied}. The concern is "
            "not absent; it is UNBOUND, and needs a provider rather than a proof"
        )
    control = proof.get("positive_control")
    if not isinstance(control, list) or not control:
        return (
            "the proof carries no positive control. Without the instrument shown "
            "finding something known to exist, a scan that never finds anything "
            "and an artifact that has nothing are the same colour"
        )
    return ""


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

    inventory = _distribution_inventory(distributions_path)
    if inventory is None:
        return ProfileReadback(
            ProfileVerdict.DOCUMENT_UNREADABLE,
            f"the independent distribution record at {distributions_path} is "
            "missing or unusable, so the profile's wheel claim has no second "
            "witness. An artifact that describes itself is not evidence about "
            "itself",
        )
    carried = _wheel_digest(inventory)
    if carried is None:
        return ProfileReadback(
            ProfileVerdict.DOCUMENT_UNREADABLE,
            f"the distribution record at {distributions_path} does not name "
            "exactly one wheel, so there is no single second witness to compare "
            "against. Picking one of several would be choosing which witness to "
            "believe",
        )
    claimed = document.get("wheel_sha256")
    if claimed != expected.wheel_sha256 or carried != expected.wheel_sha256:
        return ProfileReadback(
            ProfileVerdict.WHEEL_DIGEST_MISMATCHED,
            "the wheel this profile is bound to is not the expected wheel "
            f"(profile claims {claimed!r}, the image carries {carried!r}, "
            f"expected {expected.wheel_sha256!r})",
        )

    inventory_digest = canonical_inventory_digest(inventory)
    proven_absent: set[str] = set()
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
        schema = proof.get("schema")
        concern = proof.get("concern")
        granted = ABSENCE_PROOF_CONCERNS.get(str(schema))
        if granted is None:
            return ProfileReadback(
                ProfileVerdict.ABSENCE_PROOF_INADMISSIBLE,
                f"absence proof schema {schema!r} certifies nothing here. "
                f"Exactly {sorted(ABSENCE_PROOF_CONCERNS)} may satisfy a concern "
                "by proving it absent, and an unknown schema is refused rather "
                "than ignored — ignoring it would let a document carry a "
                "certification nobody rejected",
            )
        if concern != granted:
            return ProfileReadback(
                ProfileVerdict.ABSENCE_PROOF_INADMISSIBLE,
                f"a {schema} names concern {concern!r}, and that schema may only "
                f"prove {granted!r} absent. Absence is not a general 'nothing "
                "applies' route: a concern outside this map needs an "
                "implementation, not a better proof of emptiness",
            )
        unestablished = _establishes(
            proof,
            artifact_digest=expected.wheel_sha256,
            inventory_digest=inventory_digest,
        )
        if unestablished:
            return ProfileReadback(
                ProfileVerdict.ABSENCE_PROOF_UNESTABLISHED,
                f"the {granted!r} absence proof is well-formed and establishes "
                f"nothing: {unestablished}",
            )
        proven_absent.add(granted)

    concerns = document.get("concerns")
    declared: set[str] = set()
    if isinstance(concerns, dict):
        declared = {
            name
            for name in FOUNDATION_CONCERNS
            if isinstance(concerns.get(name), dict) and concerns.get(name)
        }
    both = sorted(declared & proven_absent)
    if both:
        return ProfileReadback(
            ProfileVerdict.ABSENCE_PROOF_INADMISSIBLE,
            f"{both} are declared bound AND proven absent. Those are two of the "
            "four states a concern may be in, and a concern is in exactly one — "
            "a document asserting both has not decided which is true, and "
            "accepting either would be this verifier deciding for it",
        )
    satisfied = declared | proven_absent
    bound = tuple(name for name in FOUNDATION_CONCERNS if name in satisfied)
    if len(bound) != len(FOUNDATION_CONCERNS):
        missing = [name for name in FOUNDATION_CONCERNS if name not in bound]
        return ProfileReadback(
            ProfileVerdict.CONCERNS_INCOMPLETE,
            f"{len(bound)} of {len(FOUNDATION_CONCERNS)} concerns are "
            f"satisfied; unsatisfied: {', '.join(missing)}",
            bound,
        )

    return ProfileReadback(
        ProfileVerdict.ADMITTED,
        f"all {len(FOUNDATION_CONCERNS)} concerns satisfied "
        f"({len(declared)} bound, {len(proven_absent)} proven absent against "
        "this image's own inventory), profile digest and wheel agree with the "
        "independent distribution record",
        bound,
    )
