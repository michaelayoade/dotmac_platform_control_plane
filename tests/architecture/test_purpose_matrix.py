"""The five-by-five purpose matrix, and the control that makes it mean anything.

`accept_release_evidence` must accept five correct-purpose diagonals and refuse
twenty ordered cross-purpose pairings, **from installed artifacts**. This is the
harness, and it is built control-first for a reason the numbers make obvious:

    a verifier that refuses everything scores 20/20 on the refusals and 0/5 on
    the diagonals.

Twenty passing refusals are worthless without evidence that the verifier could
have accepted something. So `MatrixResult.meaningful` is False whenever no
diagonal was accepted, and the harness reports UNKNOWN rather than a score.
That is the same rule as `vendor_cp.deployment.table_inventory`: a result you
could not establish is not a zero.

## Why the run against installed artifacts is separate from the harness proof

The harness is proved here with constructed identities, so its discrimination is
demonstrable today. The real run needs the installed artifacts, and two of the
five purposes have no reachable pointer type yet:

* `deployment_dispatch` — no descriptor exists anywhere;
* `deployment_recovery` — Control's, and the installed Control publishes no
  signer purposes at this pin.

`dotmac-deployment-foundation` is also deliberately not a dependency of this
assembly, so the verifying half is absent here too. Those are ORDERING facts,
not defects: the matrix becomes executable when the artifacts are installed, and
until then this module reports each missing purpose as UNKNOWN rather than
letting an absence read as a refusal.
"""

from __future__ import annotations

import importlib.metadata as metadata
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

from vendor_cp.deployment.signers import (
    AUTHORIZATION_PURPOSE,
    EXECUTION_OBSERVATION_PURPOSE,
    RELEASE_EVIDENCE_PURPOSE,
)

DISPATCH_PURPOSE: Final = "deployment_dispatch"
RECOVERY_PURPOSE: Final = "deployment_recovery"

#: The five, in a fixed order so a matrix is diffable between runs. Ordered
#: cross-purpose pairings means the (signer, expected) pairs are enumerated in
#: this order, not gathered into a set.
PURPOSES: Final[tuple[str, ...]] = (
    AUTHORIZATION_PURPOSE,
    EXECUTION_OBSERVATION_PURPOSE,
    RELEASE_EVIDENCE_PURPOSE,
    DISPATCH_PURPOSE,
    RECOVERY_PURPOSE,
)


class CellOutcome(StrEnum):
    """What one (signer purpose, expected purpose) cell established."""

    ACCEPTED = "accepted"
    REFUSED = "refused"
    #: No identity was available for this purpose, so the cell was never run.
    #: NEVER counted as a refusal — an absent artifact and a rejected pairing
    #: are different facts, and only one of them is evidence about a verifier.
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class MatrixResult:
    """The full five-by-five, and whether it may be believed."""

    accepted_diagonals: int
    refused_cross: int
    unknown_cells: int
    absent_purposes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def meaningful(self) -> bool:
        """False when no diagonal was accepted.

        A verifier broken shut refuses everything, scoring a perfect twenty on
        the refusals. Without this, that is indistinguishable from a verifier
        working exactly as intended.
        """
        return self.accepted_diagonals > 0

    @property
    def complete(self) -> bool:
        return self.unknown_cells == 0 and not self.absent_purposes


def run_matrix(
    verify: Callable[[str, str], bool],
    *,
    available: frozenset[str],
) -> MatrixResult:
    """Drive every ordered pair. `verify(signer_purpose, expected_purpose)`.

    A purpose with no available identity yields UNKNOWN for its whole row and
    column; the verifier is never asked, because asking with a substitute would
    measure the substitute.
    """
    accepted = refused = unknown = 0
    for signer in PURPOSES:
        for expected in PURPOSES:
            if signer not in available or expected not in available:
                unknown += 1
                continue
            outcome = verify(signer, expected)
            if signer == expected:
                accepted += 1 if outcome else 0
                refused += 0 if outcome else 0
                if not outcome:
                    # A refused diagonal is a failure, not a refusal to count.
                    unknown += 0
            elif not outcome:
                refused += 1
    return MatrixResult(
        accepted_diagonals=accepted,
        refused_cross=refused,
        unknown_cells=unknown,
        absent_purposes=tuple(p for p in PURPOSES if p not in available),
    )


def _correct(signer: str, expected: str) -> bool:
    """A verifier that works: accepts only the matching purpose."""
    return signer == expected


def _broken_shut(signer: str, expected: str) -> bool:
    """A verifier that refuses everything."""
    return False


def _broken_open(signer: str, expected: str) -> bool:
    """A verifier that accepts everything."""
    return True


ALL = frozenset(PURPOSES)


def _declared_purpose(pointer: type) -> str:
    """The purpose a pointer class declares, read from its dataclass field."""
    import dataclasses

    for field_ in dataclasses.fields(pointer):
        if field_.name == "purpose":
            return str(field_.default)
    raise AssertionError(f"{pointer.__name__} declares no purpose field")


# ── the control that makes the other twenty-five mean anything ──────────────


def test_a_broken_shut_verifier_scores_a_perfect_twenty_and_is_refused() -> None:
    """THE CONTROL, BUILT FIRST.

    A verifier refusing everything gets all twenty cross-purpose refusals right
    and every diagonal wrong. The refusal count alone cannot tell it from a
    working verifier, which is exactly why the count alone is never the result.
    """
    result = run_matrix(_broken_shut, available=ALL)
    assert result.refused_cross == 20
    assert result.accepted_diagonals == 0
    assert result.meaningful is False, (
        "a verifier that refuses everything scored twenty refusals and was " "believed"
    )


def test_a_working_verifier_is_meaningful_and_scores_five_and_twenty() -> None:
    """NON-VACUITY for the control: a harness that called everything
    meaningless would pass the test above while measuring nothing."""
    result = run_matrix(_correct, available=ALL)
    assert (result.accepted_diagonals, result.refused_cross) == (5, 20)
    assert result.meaningful is True
    assert result.complete is True


def test_a_broken_open_verifier_refuses_nothing_and_is_caught_by_the_count() -> None:
    """The other failure direction. It is meaningful — a diagonal was accepted —
    and it is still wrong, which is why the refusal count is asserted separately
    rather than folded into one verdict."""
    result = run_matrix(_broken_open, available=ALL)
    assert result.accepted_diagonals == 5
    assert result.meaningful is True
    assert result.refused_cross == 0


# ── an absent artifact is UNKNOWN, never a refusal ──────────────────────────


def test_an_absent_purpose_yields_unknown_rather_than_refusals() -> None:
    """The rule carried from the table inventory: a cell that was never run is
    not a cell that refused. Counting an absent artifact as a refusal would let
    a matrix reach twenty by having fewer identities."""
    available = ALL - {DISPATCH_PURPOSE, RECOVERY_PURPOSE}
    result = run_matrix(_correct, available=available)
    assert result.absent_purposes == (DISPATCH_PURPOSE, RECOVERY_PURPOSE)
    assert result.complete is False
    # Three of five diagonals, and the cross-pairings among those three only.
    assert result.accepted_diagonals == 3
    assert result.refused_cross == 6
    assert result.unknown_cells == 16


def test_absence_cannot_inflate_the_refusal_count() -> None:
    """Stated as its own assertion because it is the failure mode: a harness
    that scored absent cells as refusals would report a BETTER number the fewer
    artifacts it had."""
    full = run_matrix(_correct, available=ALL)
    partial = run_matrix(_correct, available=ALL - {RECOVERY_PURPOSE})
    assert partial.refused_cross < full.refused_cross


# ── what is reachable from installed artifacts today ────────────────────────


def _installed(distribution: str) -> str:
    try:
        return metadata.version(distribution)
    except metadata.PackageNotFoundError:
        return "absent"


def test_the_reachable_purposes_are_measured_not_assumed() -> None:
    """The ordering fact, measured and recorded rather than skipped.

    Two purposes have no reachable pointer type and the verifying artifact is
    not installed here, so the five-by-five cannot yet run against artifacts.
    This asserts what IS reachable, so the day it changes the number moves and
    somebody notices — rather than a skip that stays silent through the change
    it was waiting for.
    """
    import dataclasses

    from vendor_cp.deployment.signers import (
        AuthorizationSignerPointer,
        ObservationSignerPointer,
        ReleaseEvidenceSignerPointer,
    )

    # Read from the FIELD DEFAULT, not the class attribute: these are
    # `slots=True` dataclasses, so `Cls.purpose` is a slot descriptor and a set
    # built from those would compare descriptors while looking like it compared
    # purposes.
    typed = {
        _declared_purpose(t)
        for t in (
            AuthorizationSignerPointer,
            ObservationSignerPointer,
            ReleaseEvidenceSignerPointer,
        )
    }
    assert dataclasses.is_dataclass(AuthorizationSignerPointer)
    assert typed == {
        AUTHORIZATION_PURPOSE,
        EXECUTION_OBSERVATION_PURPOSE,
        RELEASE_EVIDENCE_PURPOSE,
    }
    # The two that are not: neither is this product's to type.
    assert DISPATCH_PURPOSE not in typed
    assert RECOVERY_PURPOSE not in typed

    # And the verifying half is absent by composition, not by accident.
    assert _installed("dotmac-deployment-foundation") == "absent", (
        "the Foundation artifact is installed now, so the five-by-five can run "
        "against artifacts and this placeholder must be replaced by it"
    )


def test_the_release_evidence_purpose_is_no_longer_untyped() -> None:
    """The one this lane moved, asserted so the ordering note above stays
    accurate about WHICH two are missing."""
    from vendor_cp.deployment.signers import ReleaseEvidenceSignerPointer

    assert _declared_purpose(ReleaseEvidenceSignerPointer) == RELEASE_EVIDENCE_PURPOSE


def test_the_purpose_reader_reads_a_value_and_not_a_descriptor() -> None:
    """SENSITIVITY for the reader itself.

    `slots=True` makes `Cls.purpose` a slot descriptor rather than the default,
    so a set built from class attributes would compare descriptors and pass a
    membership test against nothing. This asserts the reader returns a string.
    """
    from vendor_cp.deployment.signers import AuthorizationSignerPointer

    declared = _declared_purpose(AuthorizationSignerPointer)
    assert isinstance(declared, str)
    assert declared == AUTHORIZATION_PURPOSE
    assert not isinstance(AuthorizationSignerPointer.purpose, str)
