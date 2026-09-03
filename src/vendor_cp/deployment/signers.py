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

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

__all__ = [
    "AUTHORIZATION_PURPOSE",
    "EXECUTION_OBSERVATION_PURPOSE",
    "FORBIDDEN_SIGNING_POINTERS",
    "POINTER_PREFIX",
    "AuthorizationSignerPointer",
    "ObservationSignerPointer",
    "SignerPointerRefused",
    "SignerRefusal",
    "require_distinct_signers",
]

#: Control's own purpose strings, restated here so a mismatch fails in this
#: repository rather than at the far end of a signature. `test_signer_purposes
#: _match_control` compares them against the installed distribution, so these
#: cannot silently drift from the authority that enforces them.
AUTHORIZATION_PURPOSE: Final = "deployment_authorization"
EXECUTION_OBSERVATION_PURPOSE: Final = "target_execution_observation"

#: Pointers no deployment signer may name, whatever it is called.
FORBIDDEN_SIGNING_POINTERS: Final[frozenset[str]] = frozenset(
    {"secret/dotmac/licensing/signing-key"}
)

#: This product's own OpenBao space. Public because it is half the contract:
#: which pointers a signer may name is not an implementation detail of the
#: check that enforces it.
POINTER_PREFIX: Final = "secret/dotmac/platform-cp/"


class SignerRefusal(StrEnum):
    """Why a signer pointer was refused, as a value rather than a sentence."""

    #: The pointer is one this product forbids outright, by value.
    FORBIDDEN_POINTER = "FORBIDDEN_POINTER"
    #: The pointer lives outside this product's own OpenBao space.
    FOREIGN_NAMESPACE = "FOREIGN_NAMESPACE"
    #: The declared purpose is not the one this descriptor signs for. Named as
    #: Control names the same condition.
    PURPOSE_MISMATCH = "PURPOSE_MISMATCH"
    #: Both signers named one pointer, collapsing two questions into one key.
    SHARED_POINTER = "SHARED_POINTER"


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


def require_distinct_signers(
    authorization: AuthorizationSignerPointer,
    observation: ObservationSignerPointer,
) -> None:
    """Refuse a pair that is one key wearing two purposes.

    Neither dataclass can see the other, so the rule that actually matters —
    that the two pointers are different — has to be checked where both are in
    hand. A pair naming one pointer twice would satisfy every per-class refusal
    above and still collapse *may this happen* into *this is what happened*.
    """
    if authorization.pointer == observation.pointer:
        raise SignerPointerRefused(
            SignerRefusal.SHARED_POINTER,
            f"both signers name {authorization.pointer!r}. Separate purposes need "
            "separate keys, or the observation cannot contradict the "
            "authorization and is an echo rather than evidence",
        )
