"""The read-only semantic comparator: two parity claims, kept apart.

Read-only is, again, a property of the signature. `compare()` takes a plan and a
target observation and returns a `Report`. No session, no connection, no
writable argument of any kind.

## Row-count parity is NOT target semantic parity

They are different claims and this module refuses to collapse them.

**Row-count parity** asks whether the target holds as many rows as the plan
intends to send. It is cheap, it is worth having, and on its own it is nearly
worthless: a cohort backfilled with every cadence wrong has perfect row-count
parity. Every row present, every meaning wrong, and the check reports success.

**Target semantic parity** asks, per dimension, whether the categories the plan
expects match the categories the target actually shows. It is the claim that
tells you the rows MEAN the same thing.

`ParitySubject` names them separately, `ParityLine` carries one verdict each,
and there is no combined verdict anywhere in this module — because the moment
one exists, someone reads it.

## The target never sends rows here

`TargetObservation` carries CARDINALITIES BY CATEGORY, obtained by an operator
from the target's own versioned read API and reduced there. Vendor never
receives target rows, never stores them, and holds no copy of the target's
state. That is what keeps this a description of a transformation rather than a
second, drifting copy of the target's data — and it is the same rule that stops
this work introducing shared persistence or a second writer.

## A dimension the observation does not cover is NOT_COMPARABLE

Never a quiet `MATCHED`. An unobserved dimension has not been compared, and a
comparator that reported its own blind spot as agreement would be the most
expensive kind of green.

The same is true of SOURCE coverage. A bounded walk that stopped before the
owner's final page may contain rows and even happen to match a target count;
both parity claims remain `NOT_COMPARABLE` until every source kind is complete.
"""

from __future__ import annotations

from dataclasses import dataclass

from vendor_cp.commercial_backfill.planner import PlanOutcome, is_complete_cohort
from vendor_cp.commercial_backfill.report import (
    Count,
    ParityLine,
    Report,
    Tally,
    counted,
    counted_tally,
    tally,
)
from vendor_cp.commercial_backfill.vocabulary import (
    DIMENSION_ORDER,
    DIMENSION_SUBJECT,
    Bucket,
    Dimension,
    ParitySubject,
    ParityVerdict,
    ReportEnum,
    TallySubject,
)


@dataclass(frozen=True, slots=True)
class TargetObservation:
    """What an operator read back from the target, already reduced to counts.

    Built through `observe()`, which validates every key against the dimension's
    declared enum. A dimension absent from `dimension_counts` is one that was
    not observed, and it stays absent — there is no default and no zero-filling,
    because a zero-filled dimension compares as `DIVERGED` and an unobserved one
    must compare as `NOT_COMPARABLE`.
    """

    row_count: Count
    dimension_tallies: tuple[Tally, ...] = ()

    def tally_for(self, dimension: Dimension) -> Tally | None:
        subject = DIMENSION_SUBJECT[dimension]
        for item in self.dimension_tallies:
            if item.subject is subject:
                return item
        return None


def observe(
    *,
    row_count: int,
    dimension_counts: dict[Dimension, dict[ReportEnum, int]],
) -> TargetObservation:
    """The one entry for a target observation, validated on the way in."""
    return TargetObservation(
        row_count=counted(row_count),
        dimension_tallies=tuple(
            counted_tally(DIMENSION_SUBJECT[dimension], counts)
            for dimension, counts in dimension_counts.items()
        ),
    )


def row_count_verdict(
    plan: PlanOutcome, observation: TargetObservation
) -> ParityVerdict:
    """Mapped rows against observed rows. Nothing else.

    Compared against MAPPED rather than against every classified row: excluded
    and blocked rows were never going to the target, and counting them would
    make a correct backfill look short by exactly the number of rows it was
    right to leave behind.
    """
    if not is_complete_cohort(plan.report):
        return ParityVerdict.NOT_COMPARABLE
    mapped = plan.report.tally_for(TallySubject.BUCKET).of(Bucket.MAPPED)
    if mapped == observation.row_count:
        return ParityVerdict.MATCHED
    return ParityVerdict.DIVERGED


def dimension_verdict(
    plan: PlanOutcome, observation: TargetObservation, dimension: Dimension
) -> ParityVerdict:
    """One dimension's semantic parity, or `NOT_COMPARABLE`."""
    if not is_complete_cohort(plan.report):
        return ParityVerdict.NOT_COMPARABLE
    observed = observation.tally_for(dimension)
    if observed is None:
        return ParityVerdict.NOT_COMPARABLE
    expected = plan.mapped_dimension_tally(dimension)
    if expected.nonzero() == observed.nonzero():
        return ParityVerdict.MATCHED
    return ParityVerdict.DIVERGED


def semantic_verdict(verdicts: tuple[ParityVerdict, ...]) -> ParityVerdict:
    """The overall semantic claim, which is the WEAKEST of its dimensions.

    Any divergence diverges. Otherwise, any dimension that could not be compared
    makes the whole claim `NOT_COMPARABLE` — a parity claim over four of five
    dimensions is not parity, and rounding it up to `MATCHED` is how a blind
    spot becomes a sign-off.
    """
    if ParityVerdict.DIVERGED in verdicts:
        return ParityVerdict.DIVERGED
    if ParityVerdict.NOT_COMPARABLE in verdicts or not verdicts:
        return ParityVerdict.NOT_COMPARABLE
    return ParityVerdict.MATCHED


def compare(plan: PlanOutcome, observation: TargetObservation) -> Report:
    """Both claims, side by side, in one value-free report.

    The report carries the per-dimension verdict tally as well as the two parity
    lines, so a reader can see WHICH dimensions diverged without the report ever
    naming a row.
    """
    per_dimension = tuple(
        dimension_verdict(plan, observation, dimension) for dimension in DIMENSION_ORDER
    )
    return Report(
        parity=(
            ParityLine(
                subject=ParitySubject.ROW_COUNT,
                verdict=row_count_verdict(plan, observation),
            ),
            ParityLine(
                subject=ParitySubject.TARGET_SEMANTIC,
                verdict=semantic_verdict(per_dimension),
            ),
        ),
        tallies=(tally(TallySubject.PARITY, list(per_dimension)),),
    )


__all__ = [
    "TargetObservation",
    "compare",
    "dimension_verdict",
    "observe",
    "row_count_verdict",
    "semantic_verdict",
]
