"""The cohort: which source rows the backfill is about, and what happens to each.

## The cohort, stated once

The commercial backfill cohort is every Vendor source row that could produce a
Subscriptions contract or price, or a Billing input, on the target side:

* **agreement lines** of an agreement in live commercial state — the price, the
  quantity, the capability and the term a target contract would be built from;
* **offer versions referenced by such a line** — the immutable priced catalogue
  row the line's terms were frozen from.

An offer version nothing references is CATALOGUE, not commercial state. It is
excluded with a reason rather than dropped, because "we did not backfill the
catalogue" is a decision a reviewer should be able to see and disagree with.

## Every row lands in exactly one bucket

`MAPPED`, `EXCLUDED` with a stated reason, or `BLOCKED` with the dimension that
blocked it. `classify` is a TOTAL function: every path returns a `RowVerdict`,
there is no `None` return, no `continue` and no filtering step anywhere between
the source rows and the tallies. `plan()` asserts the three buckets sum to the
number of rows it was given, which is the same claim from the other end.

The one thing the totality claim does NOT cover is a source that could not be
enumerated at all. That is not zero rows — it is an unknown number of rows, and
`SourceCoverage` reports it separately so a plan over half the estate can never
read as a plan over all of it.

## Exclusion is decided before any transformation

Deliberately. A draft agreement has no frozen content hash, so a
transformation-first order would report every draft as a `FROZEN_CONTENT`
blocker — a queue of work items that are not work, burying the rows that really
are blocked. Membership first, then the five dimensions in `DIMENSION_ORDER`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date
from typing import Final

from vendor_cp.commercial_backfill.transforms import (
    cadence_outcome,
    currency_outcome,
    frozen_content_outcome,
    product_identity_outcome,
    proration_outcome,
)
from vendor_cp.commercial_backfill.vocabulary import (
    BLOCKING_OUTCOMES,
    DIMENSIONS_BY_SOURCE_KIND,
    Bucket,
    Dimension,
    ExclusionReason,
    ReportEnum,
    SourceKind,
)

#: Agreement statuses that are not commercial state YET. Spelled as the module's
#: own `AgreementStatus` values, uppercased, because that is what
#: `vendor_cp.contracts.adapter.ContractView.status` carries through.
PRE_COMMERCIAL_STATUSES: Final[frozenset[str]] = frozenset(
    {"DRAFT", "PROPOSED", "APPROVED"}
)

#: Statuses that ended before the cohort. A terminated agreement's target rows
#: are the target's history to hold or not; backfilling them would create live
#: contracts for relationships that are over.
ENDED_STATUSES: Final[frozenset[str]] = frozenset(
    {"REJECTED", "CANCELLED", "TERMINATED", "EXPIRED"}
)

#: Live commercial state. `SUSPENDED` is IN: a suspended agreement is a contract
#: that exists and is not billing, which is a state the target has and must be
#: told about — leaving it out would silently drop paying relationships that
#: happen to be paused on cutover day.
LIVE_STATUSES: Final[frozenset[str]] = frozenset({"ACTIVE", "SUSPENDED"})

#: The three sets above must PARTITION the agreement-status vocabulary, and a
#: status outside them is refused at row construction rather than classified.
#:
#: This is the failure worth catching. If the agreements module gains a status
#: this assembly has never seen, a classifier that fell through would put those
#: rows in `MAPPED` — silently changing who is in the cohort, in the direction
#: that backfills them. A broken projection contract is an integration bug, and
#: it is reported as one.
KNOWN_AGREEMENT_STATUSES: Final[frozenset[str]] = (
    PRE_COMMERCIAL_STATUSES | ENDED_STATUSES | LIVE_STATUSES
)

_FINGERPRINT = re.compile(r"[0-9a-f]{64}")


class SourceRowError(ValueError):
    """A source row that does not satisfy the projection contract.

    Raised at construction, not at classification. A malformed row is a broken
    export rather than a blocked business record, and reporting it as the latter
    would put an integration bug into a cohort report as if it were a commercial
    fact.
    """


@dataclass(frozen=True, slots=True)
class SourceRow:
    """One projected Vendor source row — the planner's whole input.

    `fingerprint` is a digest of the row's natural key, computed by whatever
    projected the row. It exists so the rehearsal shadow can be repaired
    idempotently, and it NEVER reaches a report: `report.py` has no field that
    could hold it.

    Everything else is read straight from what this assembly already has —
    `OfferVersion` for a catalogue row, `ContractView`/`LineView` for an
    agreement line. `docs/commercial-backfill-dossier.md` § "Source projection"
    maps each field to the attribute it comes from, and
    `tests/architecture/test_commercial_backfill.py` proves those attributes
    exist rather than trusting the prose.
    """

    kind: SourceKind
    fingerprint: str
    amount: str
    currency_code: str
    product_code: str | None = None
    sibling_product_codes: tuple[str, ...] = ()
    sibling_currency_codes: tuple[str, ...] = ()
    quantity: int = 1
    referenced_by_cohort_line: bool = True
    agreement_status: str | None = None
    is_superseded: bool = False
    content_hash: str | None = None
    activation_content_hash: str | None = None
    term_start: date | None = None
    term_end_exclusive: date | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, SourceKind):
            raise SourceRowError("kind is a SourceKind member")
        if not _FINGERPRINT.fullmatch(self.fingerprint):
            raise SourceRowError("fingerprint is 64 lowercase hex characters")
        if isinstance(self.quantity, bool) or not isinstance(self.quantity, int):
            raise SourceRowError("quantity is an int")
        if self.quantity < 0:
            raise SourceRowError("quantity is never negative")
        if self.kind is SourceKind.AGREEMENT_LINE and self.agreement_status is None:
            raise SourceRowError("an agreement line carries its agreement's status")
        if self.kind is SourceKind.OFFER_VERSION and self.agreement_status is not None:
            raise SourceRowError("a catalogue row has no agreement status")
        if (
            self.agreement_status is not None
            and self.agreement_status not in KNOWN_AGREEMENT_STATUSES
        ):
            raise SourceRowError("agreement status is outside the declared vocabulary")


@dataclass(frozen=True, slots=True)
class RowVerdict:
    """Exactly one bucket, and exactly the evidence that bucket takes.

    Validated rather than trusted: a `BLOCKED` verdict with no dimension, or a
    `MAPPED` verdict carrying an exclusion reason, is refused at construction.
    The invariant is what makes the three buckets genuinely exclusive instead of
    three fields that usually agree.
    """

    bucket: Bucket
    exclusion: ExclusionReason | None = None
    blocking_dimension: Dimension | None = None
    outcomes: tuple[tuple[Dimension, ReportEnum], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.bucket is Bucket.EXCLUDED:
            if self.exclusion is None or self.blocking_dimension is not None:
                raise SourceRowError("an excluded row states a reason and nothing else")
        elif self.bucket is Bucket.BLOCKED:
            if self.blocking_dimension is None or self.exclusion is not None:
                raise SourceRowError(
                    "a blocked row states a dimension and nothing else"
                )
        elif self.exclusion is not None or self.blocking_dimension is not None:
            raise SourceRowError("a mapped row states neither")


@dataclass(frozen=True, slots=True)
class CohortRules:
    """The declared inputs a classification depends on.

    Passed in rather than read from configuration inside the classifier, so the
    same rules produce the same verdicts on a workstation, in CI and in a
    rehearsal — which is what makes a plan comparable across runs at all.
    """

    declared_product_codes: frozenset[str]


def exclusion_of(row: SourceRow) -> ExclusionReason | None:
    """Cohort membership, decided before any transformation runs.

    Order is declared and fixed. A superseded, terminated agreement is reported
    as terminated, because that is the fact a reviewer acts on.
    """
    if row.kind is SourceKind.OFFER_VERSION and not row.referenced_by_cohort_line:
        return ExclusionReason.OFFER_VERSION_NEVER_REFERENCED
    status = row.agreement_status
    if status is not None and status in PRE_COMMERCIAL_STATUSES:
        return ExclusionReason.NOT_COMMERCIAL_STATE_YET
    if status is not None and status in ENDED_STATUSES:
        return ExclusionReason.TERMINATED_BEFORE_COHORT_START
    if row.is_superseded:
        return ExclusionReason.SUPERSEDED_AGREEMENT_VERSION
    if row.kind is SourceKind.AGREEMENT_LINE and row.quantity == 0:
        return ExclusionReason.ZERO_QUANTITY_LINE
    return None


def dimension_outcomes(
    row: SourceRow, rules: CohortRules
) -> tuple[tuple[Dimension, ReportEnum], ...]:
    """Every dimension that applies to this source kind, in declared order."""
    cadence = cadence_outcome(row.term_start, row.term_end_exclusive)
    by_dimension: dict[Dimension, ReportEnum] = {
        Dimension.PRODUCT_IDENTITY: product_identity_outcome(
            row.product_code,
            sibling_product_codes=row.sibling_product_codes,
            declared_product_codes=rules.declared_product_codes,
        ),
        Dimension.CURRENCY: currency_outcome(
            row.amount,
            row.currency_code,
            sibling_currency_codes=row.sibling_currency_codes,
        ),
        Dimension.CADENCE: cadence,
        Dimension.PRORATION: proration_outcome(row.term_start, cadence),
        Dimension.FROZEN_CONTENT: frozen_content_outcome(
            row.content_hash, row.activation_content_hash
        ),
    }
    return tuple(
        (dimension, by_dimension[dimension])
        for dimension in DIMENSIONS_BY_SOURCE_KIND[row.kind]
    )


def classify(row: SourceRow, rules: CohortRules) -> RowVerdict:
    """TOTAL: every row gets a verdict, and every path returns one.

    There is no early `return None`, no `continue`, and no branch that leaves a
    row unaccounted for. `tests/architecture/test_commercial_backfill.py` walks
    this function's AST to hold that shape, because "no row is silently dropped"
    is a property of the control flow rather than of the assertion at the end.
    """
    excluded = exclusion_of(row)
    if excluded is not None:
        return RowVerdict(bucket=Bucket.EXCLUDED, exclusion=excluded)
    outcomes = dimension_outcomes(row, rules)
    for dimension, outcome in outcomes:
        if outcome in BLOCKING_OUTCOMES:
            return RowVerdict(
                bucket=Bucket.BLOCKED,
                blocking_dimension=dimension,
                outcomes=outcomes,
            )
    return RowVerdict(bucket=Bucket.MAPPED, outcomes=outcomes)


__all__ = [
    "ENDED_STATUSES",
    "KNOWN_AGREEMENT_STATUSES",
    "LIVE_STATUSES",
    "PRE_COMMERCIAL_STATUSES",
    "CohortRules",
    "RowVerdict",
    "SourceRow",
    "SourceRowError",
    "classify",
    "dimension_outcomes",
    "exclusion_of",
]
