"""The dry-run backfill planner. It reads, classifies and counts. It writes nothing.

Dry-run is a property of the type signature here, not a flag: `plan()` takes a
sequence of already-projected source rows and returns a `Report`. It has no
session parameter, no connection, no clock and no output path, so there is
nothing it could write to even if a later edit wanted it to. The only way to
make this function write is to change its signature, which is a review.

## What a plan claims, and what it does not

It claims: of the rows I was GIVEN, this many map, this many are excluded for
these stated reasons, and this many are blocked in these dimensions. Those three
sum to the number of rows — asserted, not assumed.

It does not claim the rows it was given are the whole estate. `SourceCoverage`
carries that separately, and a source recorded as `NOT_ENUMERABLE` makes the
difference between "zero rows" and "an unknown number of rows" visible in the
report itself. Vendor's contracts adapter now exposes the owner's bounded
paginated reader, but coverage becomes `ENUMERATED` only for a run that actually
walked every page; the presence of a method is not evidence that a run used it.

## Deliberately absent

**No target values.** A dry-run that produced target rows in memory would be a
backfill that had already run, and its output could not honour the no-emission
constraint without stripping the values it had just computed.

**No writes, no staging table, no reserved identifiers.** Nothing is reserved
before the effect (`dotmac_starter_mt` ADR-0014's shape — at-most-once
execution, not this repository's ADR-0014 — applied to a planner): a plan that
had already claimed target identifiers would be a partial backfill wearing a
report's clothes.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from vendor_cp.commercial_backfill.cohort import (
    CohortRules,
    RowVerdict,
    SourceRow,
    classify,
)
from vendor_cp.commercial_backfill.report import Report, Tally, tally
from vendor_cp.commercial_backfill.vocabulary import (
    DIMENSION_ORDER,
    DIMENSION_SUBJECT,
    Bucket,
    Dimension,
    ReportEnum,
    SourceCoverage,
    SourceKind,
    TallySubject,
)

#: Which coverage member states that a source kind WAS enumerated, and which
#: states it could not be. Declared as a pair per kind so a plan can never
#: report both, or neither, for the same source.
COVERAGE_MEMBERS: Final[dict[SourceKind, tuple[SourceCoverage, SourceCoverage]]] = {
    SourceKind.OFFER_VERSION: (
        SourceCoverage.OFFER_VERSION_ENUMERATED,
        SourceCoverage.OFFER_VERSION_NOT_ENUMERABLE,
    ),
    SourceKind.AGREEMENT_LINE: (
        SourceCoverage.AGREEMENT_LINE_ENUMERATED,
        SourceCoverage.AGREEMENT_LINE_NOT_ENUMERABLE,
    ),
}


class PlanTotalityError(AssertionError):
    """The buckets did not account for every row.

    An `AssertionError` subclass on purpose: this is an internal invariant of
    the planner, not a condition a caller can provoke with bad data, and if it
    ever fires the report must not be returned. A plan that has lost a row is
    worse than no plan, because its counts still add up to something.
    """


@dataclass(frozen=True, slots=True)
class PlanOutcome:
    """A plan: the report, and the verdicts it was computed from.

    The verdicts are kept because the shadow reconciler needs them per row and
    the comparator needs the mapped-row dimension tallies. They are NOT part of
    the report and never travel with it — `Report` has no field that could hold
    a `RowVerdict`.
    """

    report: Report
    verdicts: tuple[tuple[SourceRow, RowVerdict], ...]

    def mapped_dimension_tally(self, dimension: Dimension) -> Tally:
        """The dimension's categories across MAPPED rows only.

        Mapped-only, because target semantic parity is a claim about the rows
        that are actually going. Including blocked rows would compare the target
        against rows nobody intends to send it.
        """
        members: list[ReportEnum] = [
            outcome
            for _, verdict in self.verdicts
            if verdict.bucket is Bucket.MAPPED
            for candidate, outcome in verdict.outcomes
            if candidate is dimension
        ]
        return tally(DIMENSION_SUBJECT[dimension], members)


def coverage_tally(
    enumerated: frozenset[SourceKind],
) -> Tally:
    """One coverage member per source kind: enumerated, or not enumerable.

    Every kind appears. A kind left out of a coverage report is exactly the
    silent gap this whole type exists to close.
    """
    members: list[ReportEnum] = []
    for kind, (yes, no) in COVERAGE_MEMBERS.items():
        members.append(yes if kind in enumerated else no)
    return tally(TallySubject.SOURCE_COVERAGE, members)


def plan(
    rows: Sequence[SourceRow],
    rules: CohortRules,
    *,
    enumerated: frozenset[SourceKind],
) -> PlanOutcome:
    """Classify every row exactly once, then count.

    One pass, one verdict appended per row, no filtering step. The totality
    check afterwards is the same claim from the other end, and it fails the run
    rather than returning a report that has quietly lost rows.
    """
    verdicts = tuple((row, classify(row, rules)) for row in rows)
    if len(verdicts) != len(rows):
        raise PlanTotalityError("a row was lost between input and classification")

    buckets = tally(TallySubject.BUCKET, [v.bucket for _, v in verdicts])
    exclusions = tally(
        TallySubject.EXCLUSION,
        [v.exclusion for _, v in verdicts if v.exclusion is not None],
    )
    blocking = tally(
        TallySubject.BLOCKING_DIMENSION,
        [v.blocking_dimension for _, v in verdicts if v.blocking_dimension is not None],
    )
    kinds = tally(TallySubject.SOURCE_KIND, [row.kind for row, _ in verdicts])

    if buckets.total().value != len(rows):
        raise PlanTotalityError("the buckets do not account for every row")
    if exclusions.total() != buckets.of(Bucket.EXCLUDED):
        raise PlanTotalityError("an excluded row carries no stated reason")
    if blocking.total() != buckets.of(Bucket.BLOCKED):
        raise PlanTotalityError("a blocked row names no dimension")

    # Dimension tallies count rows that REACHED the transformations — mapped and
    # blocked. Excluded rows never ran one, and giving them a category would
    # invent an outcome for a row nobody transformed. `PRODUCT_IDENTITY` applies
    # to both source kinds, so its total is exactly that population and is
    # checked; the other four apply to agreement lines only and cannot be
    # cross-checked the same way without re-deriving the classifier's own answer.
    transformed = buckets.of(Bucket.MAPPED) + buckets.of(Bucket.BLOCKED)

    dimension_tallies = [
        tally(
            DIMENSION_SUBJECT[dimension],
            [
                outcome
                for _, verdict in verdicts
                for candidate, outcome in verdict.outcomes
                if candidate is dimension
            ],
        )
        for dimension in DIMENSION_ORDER
    ]

    identity = dimension_tallies[DIMENSION_ORDER.index(Dimension.PRODUCT_IDENTITY)]
    if identity.total() != transformed:
        raise PlanTotalityError("a transformed row has no product-identity outcome")

    report = Report(
        parity=(),
        tallies=(
            coverage_tally(enumerated),
            kinds,
            buckets,
            exclusions,
            blocking,
            *dimension_tallies,
        ),
    )
    return PlanOutcome(report=report, verdicts=verdicts)


def is_complete_cohort(report: Report) -> bool:
    """Whether the plan covered every source kind.

    Read by the retirement gate. Kept here rather than in `gates.py` because the
    coverage vocabulary is the planner's, and a second reader of it would be a
    second opinion about what "complete" means.
    """
    coverage = report.tally_for(TallySubject.SOURCE_COVERAGE)
    return not any(coverage.of(no).value for _, no in COVERAGE_MEMBERS.values())


__all__ = [
    "COVERAGE_MEMBERS",
    "PlanOutcome",
    "PlanTotalityError",
    "coverage_tally",
    "is_complete_cohort",
    "plan",
]
