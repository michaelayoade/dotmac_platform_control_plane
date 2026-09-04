"""Two signers, because they answer two different questions.

The **authorization** signer answers *may this happen* — it signs the Control
envelope that permits a deployment. The **observation** signer answers *this is
what happened* — it signs what the target actually applied. One key answering
both would make the observation unable to contradict the authorization, and an
observation that cannot contradict is not evidence, it is an echo.

## What this module is, and is not

It is the SEAM: two pointer-holding descriptors and the refusals that keep them
apart. It is not a signer. No key material is read, held, derived or logged
here; a descriptor carries an OpenBao path and nothing else, and the product
installs real signing material at startup under the kernel's held-not-
dereferenced rule (ADR-0009). The identities themselves are minted by Michael.

## The separation is Control's, and it is structural on both sides

Read out of the published `dotmac-deployment-control 0.1.0a10` rather than
described:

* `authorization.AUTHORIZATION_PURPOSE == "deployment_authorization"`, and
  `AuthorizationSignerIdentity` refuses any other purpose with
  `PURPOSE_MISMATCH`;
* `execution_observation.EXECUTION_OBSERVATION_PURPOSE ==
  "target_execution_observation"`, refused the same way;
* the two `Protocol`s share no member name — `identity` / `sign` against
  `execution_observation_identity` / `sign_execution_observation` — so one
  cannot be passed where the other is expected even by accident. Control does
  not rely on a caller's discipline, and neither does this.

This module adds the half Control cannot see: which OpenBao pointer each
purpose is allowed to name, and that neither may name the licensing key.

## Why the licensing pointer is refused by value

`secret/dotmac/licensing/signing-key` signs customer licence envelopes. Reusing
it here would make one compromise cover licence issuance, deployment permission
and deployment evidence at once, and would let a party able to mint a licence
also mint a deployment authorization. The refusal compares the pointer, not a
name or a comment, so it cannot be defeated by aliasing the constant.

**And the order of the two checks is part of that rule, not a detail.** Every
forbidden pointer today also lives outside this product's own namespace, so a
`_validate` that asks *is this foreign?* before *is this forbidden?* answers
every forbidden pointer with the foreign refusal and never executes the by-value
comparison at all — present in the source, unreachable in the process. That is
exactly what shipped first, and it made the property this module exists for look
tested while it was not: three tests refused the licensing pointer and passed,
none of them for the reason claimed. By-value is checked FIRST, and
`test_the_by_value_refusal_is_not_shadowed_by_the_namespace_check` keeps it
there.

## Refusals carry a code, not a sentence

A caller distinguishing *forbidden key* from *foreign namespace* by matching
prose is one rewording away from a guard that silently stops discriminating —
which is the failure above, in the test rather than the code. Every refusal here
names a `SignerRefusal` member. `PURPOSE_MISMATCH` deliberately reuses the name
Control gives the same condition, so the two sides read as one vocabulary.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar, Final, Protocol

__all__ = [
    "AUTHORIZATION_PURPOSE",
    "EXECUTION_OBSERVATION_PURPOSE",
    "FORBIDDEN_SIGNING_POINTERS",
    "POINTER_MATERIAL",
    "POINTER_PREFIX",
    "RELEASE_EVIDENCE_PURPOSE",
    "AuthorizationSignerPointer",
    "MaterialKind",
    "ObservationSignerPointer",
    "ReleaseEvidenceSignerPointer",
    "SignerPointerRefused",
    "SignerPointerLike",
    "SignerRefusal",
    "require_distinct_signers",
]

#: Control's own purpose strings, restated here so a mismatch fails in this
#: repository rather than at the far end of a signature. `test_signer_purposes
#: _match_control` compares them against the installed distribution, so these
#: cannot silently drift from the authority that enforces them.
AUTHORIZATION_PURPOSE: Final = "deployment_authorization"
EXECUTION_OBSERVATION_PURPOSE: Final = "target_execution_observation"
#: Platform CP's own release-evidence purpose. Unlike the two above it is not
#: Control's — this product signs its own release evidence — but it is declared
#: here with them so every purpose in `POINTER_MATERIAL` resolves to a symbol
#: rather than to a string typed twice.
RELEASE_EVIDENCE_PURPOSE: Final = "platform_release_evidence"

#: Pointers no deployment signer may name, whatever it is called.
FORBIDDEN_SIGNING_POINTERS: Final[frozenset[str]] = frozenset(
    {"secret/dotmac/licensing/signing-key"}
)

#: This product's own OpenBao space. Public because it is half the contract:
#: which pointers a signer may name is not an implementation detail of the
#: check that enforces it.
POINTER_PREFIX: Final = "secret/dotmac/platform-cp/"


class MaterialKind(StrEnum):
    """What kind of material a pointer names — declared, never inferred.

    Four of the five signing pointers name PRIVATE signing material this
    product may hold. `target_execution_observation` does not: Michael's
    custody ruling of 2026-09-04 keeps that private key on the target, so the
    path in this namespace holds the target's PUBLIC verification identity and
    nothing else.

    The verdict is decided by one question rather than by a list: IS THIS
    PRODUCT THE PARTY MAKING THE STATEMENT? It issues authorizations, dispatches
    and recovery grants, and it produces release evidence, so it holds those
    four. It does not apply deployments, so it does not hold the fifth.

    The asymmetry is DECLARED rather than left for a reader to notice, and the
    type was not split to express it. A split would say the observation pointer
    is a different KIND of thing, which it is not — it is the same thing (a
    purpose-bound pointer) naming a different kind of material. What a reader
    actually needs is not a second class but an answer to one question before
    they write a policy against the path: *may private material live here?* So
    that question is answered on the type.
    """

    #: Signing material. A read policy against this path is legitimate.
    PRIVATE = "PRIVATE"
    #: A verification identity only. A read policy is unnecessary, and writing
    #: private material here would defeat the custody it exists to express.
    PUBLIC = "PUBLIC"


class SignerRefusal(StrEnum):
    """Why a signer pointer was refused, as a value rather than a sentence."""

    #: The pointer is one this product forbids outright, by value.
    FORBIDDEN_POINTER = "FORBIDDEN_POINTER"
    #: The pointer lives outside this product's own OpenBao space.
    FOREIGN_NAMESPACE = "FOREIGN_NAMESPACE"
    #: The declared purpose is not the one this descriptor signs for. Named as
    #: Control names the same condition.
    PURPOSE_MISMATCH = "PURPOSE_MISMATCH"
    #: Two or more signers named one pointer, collapsing distinct questions
    #: into one key.
    SHARED_POINTER = "SHARED_POINTER"
    #: Two or more signers named DIFFERENT pointers holding the SAME key. Only
    #: detectable when public fingerprints are supplied; see the note on
    #: `require_distinct_signers`.
    SHARED_KEY_MATERIAL = "SHARED_KEY_MATERIAL"
    #: Fewer than two signers were offered, so nothing could have been compared.
    NOTHING_TO_COMPARE = "NOTHING_TO_COMPARE"


class SignerPointerRefused(ValueError):
    """A signer pointer that would collapse two purposes into one key.

    Carries the machine-readable `refusal`; the message explains it to a human
    and is not the thing to assert on.
    """

    refusal: SignerRefusal

    def __init__(self, refusal: SignerRefusal, message: str) -> None:
        super().__init__(message)
        self.refusal = refusal


def _validate(pointer: str, *, purpose: str) -> str:
    # BY VALUE FIRST. See the module docstring: reversing these two makes the
    # forbidden-pointer branch unreachable for every pointer it currently names.
    if pointer in FORBIDDEN_SIGNING_POINTERS:
        raise SignerPointerRefused(
            SignerRefusal.FORBIDDEN_POINTER,
            f"{pointer!r} is refused for {purpose}: it signs customer licence "
            "envelopes. One key covering licence issuance and deployment "
            "permission means a party able to mint a licence can mint a "
            "deployment authorization",
        )
    if not pointer.startswith(POINTER_PREFIX):
        raise SignerPointerRefused(
            SignerRefusal.FOREIGN_NAMESPACE,
            f"an {purpose} signer pointer must live under {POINTER_PREFIX!r}; "
            f"{pointer!r} does not. A pointer outside this product's own space "
            "is another owner's key being borrowed",
        )
    return pointer


@dataclass(frozen=True, slots=True)
class AuthorizationSignerPointer:
    """Where the authorization key lives. Never the key."""

    material: ClassVar[MaterialKind] = MaterialKind.PRIVATE

    pointer: str
    purpose: str = AUTHORIZATION_PURPOSE

    def __post_init__(self) -> None:
        if self.purpose != AUTHORIZATION_PURPOSE:
            raise SignerPointerRefused(
                SignerRefusal.PURPOSE_MISMATCH,
                f"an authorization signer must declare {AUTHORIZATION_PURPOSE!r}",
            )
        _validate(self.pointer, purpose="authorization")


@dataclass(frozen=True, slots=True)
class ObservationSignerPointer:
    """Where the target-observation key lives. Never the key."""

    #: PUBLIC, and the one asymmetry in the set. See `MaterialKind`.
    material: ClassVar[MaterialKind] = MaterialKind.PUBLIC

    pointer: str
    purpose: str = EXECUTION_OBSERVATION_PURPOSE

    def __post_init__(self) -> None:
        if self.purpose != EXECUTION_OBSERVATION_PURPOSE:
            raise SignerPointerRefused(
                SignerRefusal.PURPOSE_MISMATCH,
                "an observation signer must declare "
                f"{EXECUTION_OBSERVATION_PURPOSE!r}",
            )
        _validate(self.pointer, purpose="observation")


@dataclass(frozen=True, slots=True)
class ReleaseEvidenceSignerPointer:
    """Where the release-evidence key lives, and which key id it is. Never the key.

    The third typed pointer, and the one that closes a gap the other two never
    had. `platform_release_evidence` was a dict entry and a JSON field — DATA,
    which cannot refuse a wrong purpose — so the full matrix accepted four
    diagonals and refused sixteen off-diagonals rather than five and twenty.
    This module's own comment said as much: *"do not exist as types yet, so they
    are named here as literals until they do."*

    ## Why this one carries a `key_id` and the others do not

    The producer must name the key that signed an envelope, and its gap was that
    `key_id` and the signing callable arrived as unrelated arguments — nothing
    structurally stopped the authorization key being handed a release-evidence
    key id. Binding the two into one identity moves that from a review to a call
    site.

    It is still not the whole coupling: this type cannot hold the signing
    callable, because a pointer that could reach material would be the thing it
    exists not to be. What it does is make the PURPOSE and the KEY ID
    inseparable, so the remaining pairing is the custody adapter's single job
    rather than every caller's.
    """

    material: ClassVar[MaterialKind] = MaterialKind.PRIVATE

    pointer: str
    key_id: str
    purpose: str = RELEASE_EVIDENCE_PURPOSE

    def __post_init__(self) -> None:
        if self.purpose != RELEASE_EVIDENCE_PURPOSE:
            raise SignerPointerRefused(
                SignerRefusal.PURPOSE_MISMATCH,
                "a release-evidence signer must declare "
                f"{RELEASE_EVIDENCE_PURPOSE!r}",
            )
        if not self.key_id.strip():
            raise SignerPointerRefused(
                SignerRefusal.PURPOSE_MISMATCH,
                "a release-evidence signer must name its key id, or no policy "
                "can select a key to check its signature against",
            )
        _validate(self.pointer, purpose="release evidence")


#: Every signing purpose and the kind of material its pointer names. THREE now
#: have descriptor classes and carry it as a `ClassVar`, and two are still
#: literals for DIFFERENT reasons:
#:
#:   `deployment_dispatch`  has no type anywhere yet.
#:   `deployment_recovery`  is CONTROL's purpose, not this product's, so its
#:                          type is Control's to publish and this entry reads
#:                          the name out of their source rather than owning it.
#:
#: A literal is exactly the second statement that drifts from the thing it
#: describes, which is why each one that gains a type stops being one.
#:
#: This mapping is what binds the mint dossier's
#: custody table to code — `tests/architecture/test_dossier_ceremony.py` refuses
#: a document whose table disagrees with it.
POINTER_MATERIAL: Final[dict[str, MaterialKind]] = {
    AUTHORIZATION_PURPOSE: AuthorizationSignerPointer.material,
    EXECUTION_OBSERVATION_PURPOSE: ObservationSignerPointer.material,
    "deployment_dispatch": MaterialKind.PRIVATE,
    RELEASE_EVIDENCE_PURPOSE: ReleaseEvidenceSignerPointer.material,
    #: Control's `RECOVERY_PURPOSE`, read from `recovery_grant.py:77`. PRIVATE
    #: by the rule the whole table now follows: THE SIGNER IS THE PARTY MAKING
    #: THE STATEMENT. The target signs observations because the target asserts
    #: what it applied; the control plane signs a recovery grant because the
    #: control plane asserts that a recovery is authorized. The opposite verdict
    #: to `target_execution_observation`, for the same reason.
    "deployment_recovery": MaterialKind.PRIVATE,
}


class SignerPointerLike(Protocol):
    """Any purpose-bound pointer descriptor, whatever its concrete class.

    A Protocol rather than a base class because the descriptors are deliberately
    unrelated types that share no member with each other's Control-side
    counterparts. Structural typing lets this function see all of them without
    giving them a common ancestor that would suggest they are interchangeable.
    """

    @property
    def pointer(self) -> str: ...

    @property
    def purpose(self) -> str: ...


def require_distinct_signers(
    *signers: SignerPointerLike,
    fingerprints: Mapping[str, str] | None = None,
) -> None:
    """Refuse a set of signers that is fewer keys than it is purposes.

    Written for a PAIR and widened when Control a11 made the count four. Two
    identities admit one collision; four admit six, and the shapes are not just
    "both the same": three sharing one pointer, two disjoint pairs, or two
    pointers holding one key. A function that compares two arguments cannot see
    any of those, and silently checked one sixth of the question.

    ## What this catches, and what belongs to Control

    **Ours, always:** two or more purposes naming the same POINTER. Every
    colliding purpose is named, not the first pair found, because an operator
    repairing one collision at a time re-runs the ceremony once per pair.

    **Ours, only when told:** two purposes at DIFFERENT pointers holding the
    same key. `fingerprints` maps pointer to public-key fingerprint. A
    fingerprint is public — deriving it needs no private material and this
    module still holds none — but it must be SUPPLIED, because a seam that
    fetched it would be dereferencing a pointer, which is the one thing this
    module may never do (ADR-0009).

    **Control's, and not ours:** the same collision observed at signing time.
    Control a11 raises `dispatch_signer_purpose_reused` when the dispatch
    identity's `public_key_fingerprint` equals the authorization's. That covers
    ONE ordered pair, at the moment of use, on material Control can see.

    **Nobody's, and say so rather than imply otherwise:** when `fingerprints` is
    omitted, distinct pointers sharing one key are unmonitored here. That is not
    a gap this function can close on its own, and a caller that omits the
    argument should know it is choosing the weaker check rather than the
    complete one.
    """
    if len(signers) < 2:
        raise SignerPointerRefused(
            SignerRefusal.NOTHING_TO_COMPARE,
            f"{len(signers)} signer(s) offered; distinctness is a property of a "
            "SET, and a call with fewer than two can only ever pass",
        )

    _refuse_collisions(
        {signer.purpose: signer.pointer for signer in signers},
        refusal=SignerRefusal.SHARED_POINTER,
        subject="pointer",
        why=(
            "Separate purposes need separate keys, or one compromise covers "
            "questions that were meant to be answered independently"
        ),
    )
    if fingerprints is None:
        return
    _refuse_collisions(
        {
            signer.purpose: fingerprints[signer.pointer]
            for signer in signers
            if signer.pointer in fingerprints
        },
        refusal=SignerRefusal.SHARED_KEY_MATERIAL,
        subject="key",
        why=(
            "Distinct pointers holding one key is the same collision wearing "
            "two names: a pointer is a spelling, and the key is the thing"
        ),
    )


def _refuse_collisions(
    by_purpose: Mapping[str, str], *, refusal: SignerRefusal, subject: str, why: str
) -> None:
    """Name every colliding group, never the first one found."""
    grouped: dict[str, list[str]] = {}
    for purpose, value in by_purpose.items():
        grouped.setdefault(value, []).append(purpose)
    collisions = {
        value: sorted(purposes)
        for value, purposes in grouped.items()
        if len(purposes) > 1
    }
    if not collisions:
        return
    detail = "; ".join(
        f"{', '.join(purposes)} share {subject} {value!r}"
        for value, purposes in sorted(collisions.items())
    )
    raise SignerPointerRefused(refusal, f"{detail}. {why}")
