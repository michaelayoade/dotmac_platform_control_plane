"""The terms that must exist before a deployment window is named.

Michael's rule is that no window is named until the packet's terms already
exist. This module is the machine-readable half of that rule: a vocabulary of
terms, and a validator that refuses a packet which does not carry all of them
and **says which are missing**.

## Why the refusal is the part that was built first

Two terms cannot exist yet. `signed_authorization_envelope` and
`verified_target_signer` both depend on signing identities that have not been
minted (see `docs/design/signing-identity-mint-dossier.md`), so today every real
packet refuses. That is the correct answer, not a defect to work around, and it
is the reason the refusal is worth more than the happy path right now.

A validator that refuses without naming which of fourteen terms is absent sends
an operator round the loop once per missing term, which is the operator-surface
defect this repository has already paid for once. So `PacketRefused` carries the
terms, **all** of them, not the first one found.

## Present-but-empty is absent

A term whose value is `null`, `""`, `{}` or `[]` is absent wearing a costume. It
is refused as `EMPTY_TERM` rather than accepted, because the failure mode being
guarded is a packet assembled by a script that filled in every key and could not
find every value.

## One term is value-checked; the rest are presence-checked, and that is visible

`foundation_artifact_coordinate` is compared field by field against the pinned
candidate record (`vendor_cp.deployment.foundation_candidate`), so a wrong
digest or a wrong artifact id is refused by name. Every other term is checked
for presence and non-emptiness only.

That asymmetry is deliberate and is NOT a claim that the other terms are
verified. A term that accepts anything present is the same defect as a refusal
that fires for any reason — it looks like a check and discriminates nothing —
so the remaining twelve are known outstanding work rather than a finished
surface. They are value-checked as each one's oracle becomes available.

## The rollback term states a residual risk rather than implying one

There is no authorized restore executor and no deadman — that gap is open by
Michael's explicit decision, not by oversight. So the packet is required to SAY
so: `rollback_and_abort` must declare `restoration_executable` exactly `false`
and an `abort_procedure` of `"stop_and_report"`.

A packet claiming restoration is executable by this path is refused. That is not
pessimism about a future capability; it is refusing to let an accepted residual
risk be quietly overwritten by a packet that asserts otherwise. When an
authorized restore executor exists, relaxing this is a deliberate change in its
own right, made where the reasoning is visible.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from vendor_cp.deployment.foundation_candidate import (
    FOUNDATION_CANDIDATE,
    coordinate_fields,
)

__all__ = [
    "ABORT_PROCEDURE",
    "HELD_PENDING_MINT",
    "PacketRefusal",
    "PacketRefused",
    "PacketTerm",
    "ReadinessPacket",
    "validate_readiness_packet",
]


class PacketTerm(StrEnum):
    """Every term a packet must carry, as a machine name rather than a phrase.

    The three artifact coordinates are enumerated SEPARATELY. Collapsing them
    into one term would let a packet look complete while naming only one of the
    three, and would make the refusal say "artifact coordinates missing" when
    what an operator needs to hear is which artifact.
    """

    PROTECTED_MAIN_SOURCE = "protected_main_source"
    ACCEPTED_CANDIDATE_RECEIPT = "accepted_candidate_receipt"
    IMAGE_DIGEST = "image_digest"
    KERNEL_ARTIFACT_COORDINATE = "kernel_artifact_coordinate"
    CONTROL_ARTIFACT_COORDINATE = "control_artifact_coordinate"
    FOUNDATION_ARTIFACT_COORDINATE = "foundation_artifact_coordinate"
    DESCRIPTOR_DIGEST = "descriptor_digest"
    CONTROL_PLAN_DIGEST = "control_plan_digest"
    EXECUTION_PLAN_DIGEST = "execution_plan_digest"
    SIGNED_AUTHORIZATION_ENVELOPE = "signed_authorization_envelope"
    VERIFIED_TARGET_SIGNER = "verified_target_signer"
    RECOVERY_BUNDLE_PRECONDITIONS = "recovery_bundle_preconditions"
    APPROVAL_STANDING = "approval_standing"
    ROLLBACK_AND_ABORT = "rollback_and_abort"


#: The two terms that cannot exist until the signing identities are minted.
#: Naming them is not an exemption — a packet missing them is still refused —
#: it lets the refusal say WHY they are absent instead of leaving an operator
#: to discover it.
HELD_PENDING_MINT: Final[frozenset[PacketTerm]] = frozenset(
    {
        PacketTerm.SIGNED_AUTHORIZATION_ENVELOPE,
        PacketTerm.VERIFIED_TARGET_SIGNER,
    }
)

#: The only abort procedure this path can honestly offer while there is no
#: authorized restore executor.
ABORT_PROCEDURE: Final = "stop_and_report"


class PacketRefusal(StrEnum):
    """Why a packet was refused, as a value rather than a sentence."""

    #: One or more terms are absent. `PacketRefused.terms` names them.
    MISSING_TERMS = "MISSING_TERMS"
    #: A key that is not a term. Refused rather than ignored: a misspelled term
    #: is otherwise indistinguishable from a missing one plus a typo.
    UNKNOWN_TERMS = "UNKNOWN_TERMS"
    #: Present, but with a value that carries nothing.
    EMPTY_TERMS = "EMPTY_TERMS"
    #: The rollback term is not a structured statement.
    ROLLBACK_NOT_STATED = "ROLLBACK_NOT_STATED"
    #: The packet claims restoration is executable by this path. It is not.
    RESTORATION_CLAIMED_EXECUTABLE = "RESTORATION_CLAIMED_EXECUTABLE"
    #: The abort procedure is not stop-and-report.
    ABORT_PROCEDURE_UNSUPPORTED = "ABORT_PROCEDURE_UNSUPPORTED"
    #: An artifact coordinate does not identify the pinned build.
    ARTIFACT_COORDINATE_MISMATCH = "ARTIFACT_COORDINATE_MISMATCH"


class PacketRefused(ValueError):
    """A readiness packet that does not yet permit a window to be named.

    Carries the machine-readable `refusal` and, where the refusal is about
    particular terms, every term it is about — never just the first.
    """

    refusal: PacketRefusal
    terms: tuple[PacketTerm, ...]

    def __init__(
        self,
        refusal: PacketRefusal,
        message: str,
        *,
        terms: Sequence[PacketTerm] = (),
    ) -> None:
        super().__init__(message)
        self.refusal = refusal
        self.terms = tuple(terms)


@dataclass(frozen=True, slots=True)
class ReadinessPacket:
    """A packet whose every term is present, non-empty and self-consistent."""

    terms: Mapping[PacketTerm, object]


def _is_empty(value: object) -> bool:
    if value is None:
        return True
    if isinstance(value, str | Mapping | Sequence):
        return len(value) == 0
    return False


def _refuse_missing(absent: Sequence[PacketTerm]) -> PacketRefused:
    held = sorted(term for term in absent if term in HELD_PENDING_MINT)
    detail = ", ".join(sorted(absent))
    message = f"the readiness packet is missing {len(absent)} term(s): {detail}"
    if held:
        message += (
            f". {', '.join(held)} cannot exist until the signing identities are "
            "minted (docs/design/signing-identity-mint-dossier.md); the packet "
            "is refused rather than waived"
        )
    return PacketRefused(PacketRefusal.MISSING_TERMS, message, terms=absent)


def _check_foundation_coordinate(value: object) -> None:
    """Compare the stated coordinate against the pinned candidate, field by field.

    Names every field that disagrees, not the first. An operator handed one
    mismatch at a time re-runs the whole assembly once per field, and the second
    mismatch is usually a consequence of the first being wrong for the same
    reason.
    """
    term = PacketTerm.FOUNDATION_ARTIFACT_COORDINATE
    if not isinstance(value, Mapping):
        raise PacketRefused(
            PacketRefusal.ARTIFACT_COORDINATE_MISMATCH,
            f"{term} must be an object stating {', '.join(coordinate_fields())}",
            terms=(term,),
        )
    disagreed = [
        name
        for name in coordinate_fields()
        if value.get(name) != getattr(FOUNDATION_CANDIDATE, name)
    ]
    if disagreed:
        raise PacketRefused(
            PacketRefusal.ARTIFACT_COORDINATE_MISMATCH,
            f"{term} does not identify the pinned Foundation candidate "
            f"{FOUNDATION_CANDIDATE.version}: {', '.join(disagreed)} "
            "disagree(s) with the record",
            terms=(term,),
        )


def _check_rollback(value: object) -> None:
    """The residual risk must be stated by the packet, not assumed by a reader."""
    if not isinstance(value, Mapping):
        raise PacketRefused(
            PacketRefusal.ROLLBACK_NOT_STATED,
            f"{PacketTerm.ROLLBACK_AND_ABORT} must be an object stating "
            "restoration_executable and abort_procedure",
            terms=(PacketTerm.ROLLBACK_AND_ABORT,),
        )
    if value.get("restoration_executable") is not False:
        raise PacketRefused(
            PacketRefusal.RESTORATION_CLAIMED_EXECUTABLE,
            "restoration is NOT executable by this path: there is no authorized "
            "restore executor and no deadman, which is an accepted residual "
            "risk. A packet must declare restoration_executable false",
            terms=(PacketTerm.ROLLBACK_AND_ABORT,),
        )
    if value.get("abort_procedure") != ABORT_PROCEDURE:
        raise PacketRefused(
            PacketRefusal.ABORT_PROCEDURE_UNSUPPORTED,
            f"the only abort procedure this path can offer is {ABORT_PROCEDURE!r}",
            terms=(PacketTerm.ROLLBACK_AND_ABORT,),
        )


def validate_readiness_packet(document: Mapping[str, object]) -> ReadinessPacket:
    """Refuse a packet that cannot yet justify naming a window, and say why.

    The order is deliberate: unknown keys first (a misspelled term would
    otherwise be reported as missing, sending the reader to look for a value
    they already supplied), then missing, then empty, then the rollback
    statement.
    """
    known = {term.value for term in PacketTerm}
    unknown = sorted(key for key in document if key not in known)
    if unknown:
        raise PacketRefused(
            PacketRefusal.UNKNOWN_TERMS,
            f"the packet carries {len(unknown)} key(s) that are not terms: "
            f"{', '.join(unknown)}",
        )

    absent = [term for term in PacketTerm if term.value not in document]
    if absent:
        raise _refuse_missing(absent)

    empty = [term for term in PacketTerm if _is_empty(document[term.value])]
    if empty:
        raise PacketRefused(
            PacketRefusal.EMPTY_TERMS,
            f"{len(empty)} term(s) are present but carry no value: "
            f"{', '.join(sorted(empty))}. A term filled in with nothing is "
            "absent, not satisfied",
            terms=empty,
        )

    _check_foundation_coordinate(
        document[PacketTerm.FOUNDATION_ARTIFACT_COORDINATE.value]
    )
    _check_rollback(document[PacketTerm.ROLLBACK_AND_ABORT.value])

    return ReadinessPacket(terms={term: document[term.value] for term in PacketTerm})
