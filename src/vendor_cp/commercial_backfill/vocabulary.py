"""The closed vocabulary every commercial-backfill report is written in.

A backfill report leaves this assembly and is read by people who are not
entitled to the underlying commercial records. So the reports carry COUNTS,
CATEGORIES and BLOCKER REASONS only — never an identifier, an amount, a label
or a timestamp.

That is not a convention here. Every category a report may name is a member of
one of the enums below, every enum below derives from `ReportEnum`, and every
member carries `auto()` rather than a string value **on purpose**: a member with
a string value would be a second, unreviewed place for text to enter a report.
`report.py` builds reports out of these members and cardinalities and nothing
else, and refuses at render time anything outside the vocabulary this module
declares.

## Categories are not verdicts about the target

Every outcome named here is a statement about a SOURCE row read in this
assembly. Nothing here decides what the target system stores, which cadence it
bills on, or who owns billing. The planner classifies; it does not convert. That
is why no transformation in `transforms.py` returns a converted VALUE — it
returns a member of the dimension's enum, and a member of a closed enum cannot
carry a price.

## Why blockers are per-dimension rather than one flat list

A flat `BlockerReason` enum reads well until two dimensions block the same row,
at which point the report has to pick one and the reason it picks is invisible.
Here the blocking member lives inside its own dimension's enum, the dimension
that blocked is tallied separately (`Dimension`), and `DIMENSION_ORDER` fixes
which dimension is reported when several block — deterministically, so two runs
over the same rows produce the same report.
"""

from __future__ import annotations

from enum import Enum, auto
from typing import Final


class ReportEnum(Enum):
    """Base for every category a report may name.

    Subclasses declare members with `auto()`. Reports render member NAMES, so a
    member value is never read and never needs to be text.
    """


# ── What is being classified ───────────────────────────────────────────────


class SourceKind(ReportEnum):
    """The two shapes of Vendor commercial source row."""

    OFFER_VERSION = auto()
    AGREEMENT_LINE = auto()


class SourceCoverage(ReportEnum):
    """Whether a source kind could be enumerated at all.

    A plan over a source that could not be enumerated is not a plan with zero
    rows — it is a plan with an unknown number of rows, and the two must never
    render the same. `AGREEMENT_LINE_NOT_ENUMERABLE` is the state this assembly
    is in today: `vendor_cp.contracts.adapter` exposes `get` and no listing
    surface, so nothing here can walk the agreement estate.
    """

    OFFER_VERSION_ENUMERATED = auto()
    OFFER_VERSION_NOT_ENUMERABLE = auto()
    AGREEMENT_LINE_ENUMERATED = auto()
    AGREEMENT_LINE_NOT_ENUMERABLE = auto()


class Bucket(ReportEnum):
    """The three, and only three, fates of an enumerated source row."""

    MAPPED = auto()
    EXCLUDED = auto()
    BLOCKED = auto()


class ExclusionReason(ReportEnum):
    """Why an enumerated row is outside the cohort.

    Excluded is not blocked. A blocker says "this row belongs in the backfill
    and cannot go"; an exclusion says "this row was never part of the backfill",
    and the reason is what makes that reviewable instead of assumed.
    """

    OFFER_VERSION_NEVER_REFERENCED = auto()
    NOT_COMMERCIAL_STATE_YET = auto()
    TERMINATED_BEFORE_COHORT_START = auto()
    SUPERSEDED_AGREEMENT_VERSION = auto()
    ZERO_QUANTITY_LINE = auto()


class Dimension(ReportEnum):
    """The five transformations a mapped row must survive."""

    PRODUCT_IDENTITY = auto()
    CURRENCY = auto()
    CADENCE = auto()
    PRORATION = auto()
    FROZEN_CONTENT = auto()


#: Fixed evaluation order, so a row that fails two dimensions is always reported
#: against the same one. Product identity first because a row with no product
#: has no target to be compared against at all; frozen content last because it
#: is the only dimension whose failure can be repaired without touching money.
DIMENSION_ORDER: Final[tuple[Dimension, ...]] = (
    Dimension.PRODUCT_IDENTITY,
    Dimension.CURRENCY,
    Dimension.CADENCE,
    Dimension.PRORATION,
    Dimension.FROZEN_CONTENT,
)


# ── The five dimension outcomes ────────────────────────────────────────────


class ProductIdentityOutcome(ReportEnum):
    """Vendor's product-qualified commercial identity (ADR-0003), as read.

    `CODE_ABSENT` is the pre-`v011` row `OfferVersion.product_code` is nullable
    for. `CODE_UNDECLARED` is never repaired by case-folding: `acme` and `ACME`
    are different identities, and folding them invents one.
    """

    QUALIFIED = auto()
    CODE_ABSENT = auto()
    CODE_UNTRIMMED = auto()
    CODE_UNDECLARED = auto()
    MULTI_PRODUCT_AGREEMENT = auto()


class CurrencyOutcome(ReportEnum):
    """Exact money, or a refusal. Never a rounding.

    `NOT_QUANTIZED` is a blocker rather than a repair on purpose: quantizing an
    over-precise amount at backfill time invents money that no one agreed to,
    and does it silently across the whole cohort.
    """

    EXACT = auto()
    EXACT_ZERO_AMOUNT = auto()
    CODE_UNKNOWN = auto()
    NOT_DECIMAL = auto()
    NOT_QUANTIZED = auto()
    NEGATIVE = auto()
    MIXED_CURRENCY_AGREEMENT = auto()


class CadenceOutcome(ReportEnum):
    """The billing cadence derived from the agreement term.

    Derived, never defaulted. A term that is not a whole number of months, or is
    a whole number the target has no cadence for, is `INDETERMINATE` — the
    target owns cadence, and guessing one here would put a price on a period
    nobody agreed to.
    """

    MONTHLY = auto()
    QUARTERLY = auto()
    SEMI_ANNUAL = auto()
    ANNUAL = auto()
    INDETERMINATE = auto()
    TERM_NOT_POSITIVE = auto()
    TERM_OPEN_ENDED = auto()


class ProrationOutcome(ReportEnum):
    """Whether the first target period needs the target's proration policy.

    The backfill carries NO proration. Vendor holds a whole-period price and no
    proration concept at all, so there is nothing to carry; what this dimension
    records is whether the target will have to apply its own policy, which is a
    fact the target's owner needs before the cutover, not after.
    """

    NONE_REQUIRED = auto()
    TARGET_OWNED_MISALIGNED = auto()
    ANCHOR_INDETERMINATE = auto()


class FrozenContentOutcome(ReportEnum):
    """The frozen agreement snapshot, and whether its digest can travel.

    The failure members mirror `vendor_cp.approvals_authority
    .DIGEST_REJECTION_REASONS` one for one, because the translation rule is
    IMPORTED from there rather than restated. Two opinions about what a digest
    is would be exactly the drift that rule exists to prevent.
    """

    TRANSLATABLE = auto()
    NOT_FROZEN = auto()
    STALE_AGAINST_ACTIVATION = auto()
    DIGEST_EMPTY = auto()
    DIGEST_ALREADY_PREFIXED = auto()
    DIGEST_WRONG_LENGTH = auto()
    DIGEST_UPPERCASE = auto()
    DIGEST_NON_HEX = auto()


#: Which members of each dimension enum BLOCK a row. Declared rather than
#: inferred from the member name: a rule that read "anything not called
#: QUALIFIED blocks" would silently reclassify a member added later.
BLOCKING_OUTCOMES: Final[frozenset[ReportEnum]] = frozenset(
    {
        ProductIdentityOutcome.CODE_ABSENT,
        ProductIdentityOutcome.CODE_UNTRIMMED,
        ProductIdentityOutcome.CODE_UNDECLARED,
        ProductIdentityOutcome.MULTI_PRODUCT_AGREEMENT,
        CurrencyOutcome.CODE_UNKNOWN,
        CurrencyOutcome.NOT_DECIMAL,
        CurrencyOutcome.NOT_QUANTIZED,
        CurrencyOutcome.NEGATIVE,
        CurrencyOutcome.MIXED_CURRENCY_AGREEMENT,
        CadenceOutcome.INDETERMINATE,
        CadenceOutcome.TERM_NOT_POSITIVE,
        CadenceOutcome.TERM_OPEN_ENDED,
        ProrationOutcome.ANCHOR_INDETERMINATE,
        FrozenContentOutcome.NOT_FROZEN,
        FrozenContentOutcome.STALE_AGAINST_ACTIVATION,
        FrozenContentOutcome.DIGEST_EMPTY,
        FrozenContentOutcome.DIGEST_ALREADY_PREFIXED,
        FrozenContentOutcome.DIGEST_WRONG_LENGTH,
        FrozenContentOutcome.DIGEST_UPPERCASE,
        FrozenContentOutcome.DIGEST_NON_HEX,
    }
)


# ── Comparison ─────────────────────────────────────────────────────────────


class ParityVerdict(ReportEnum):
    """`NOT_COMPARABLE` is a third verdict, never a quiet `MATCHED`.

    A dimension the target observation does not cover has not been compared. A
    comparator that reported that as agreement would report its own blind spot
    as success, which is the failure this enum's third member exists for.
    """

    MATCHED = auto()
    DIVERGED = auto()
    NOT_COMPARABLE = auto()


class ParitySubject(ReportEnum):
    """The two parity claims, kept apart because they are different claims.

    Equal row counts say nothing about whether the rows MEAN the same thing, and
    the failure mode worth catching — every row present, every cadence wrong —
    reads as success under a count check alone.
    """

    ROW_COUNT = auto()
    TARGET_SEMANTIC = auto()


# ── Tally subjects ─────────────────────────────────────────────────────────


class TallySubject(ReportEnum):
    """What a tally in a report is a tally OF.

    Named from a closed enum rather than by carrying the domain class's name as
    text, so a report's alphabet stays finite and reviewable.
    """

    SOURCE_COVERAGE = auto()
    SOURCE_KIND = auto()
    BUCKET = auto()
    EXCLUSION = auto()
    BLOCKING_DIMENSION = auto()
    PRODUCT_IDENTITY = auto()
    CURRENCY = auto()
    CADENCE = auto()
    PRORATION = auto()
    FROZEN_CONTENT = auto()
    PARITY = auto()


#: The one enum each tally subject may hold members of. `report.py` validates
#: every key against this, so a tally cannot mix domains or hold a stray object.
TALLY_DOMAIN: Final[dict[TallySubject, type[ReportEnum]]] = {
    TallySubject.SOURCE_COVERAGE: SourceCoverage,
    TallySubject.SOURCE_KIND: SourceKind,
    TallySubject.BUCKET: Bucket,
    TallySubject.EXCLUSION: ExclusionReason,
    TallySubject.BLOCKING_DIMENSION: Dimension,
    TallySubject.PRODUCT_IDENTITY: ProductIdentityOutcome,
    TallySubject.CURRENCY: CurrencyOutcome,
    TallySubject.CADENCE: CadenceOutcome,
    TallySubject.PRORATION: ProrationOutcome,
    TallySubject.FROZEN_CONTENT: FrozenContentOutcome,
    TallySubject.PARITY: ParityVerdict,
}

#: The tally subject each dimension's outcomes are counted under.
DIMENSION_SUBJECT: Final[dict[Dimension, TallySubject]] = {
    Dimension.PRODUCT_IDENTITY: TallySubject.PRODUCT_IDENTITY,
    Dimension.CURRENCY: TallySubject.CURRENCY,
    Dimension.CADENCE: TallySubject.CADENCE,
    Dimension.PRORATION: TallySubject.PRORATION,
    Dimension.FROZEN_CONTENT: TallySubject.FROZEN_CONTENT,
}

#: Which dimensions apply to which source kind. A catalogue price has no term,
#: so cadence, proration and the frozen snapshot are not questions about it —
#: and reporting them as `NOT_APPLICABLE` for every offer version would bury the
#: agreement rows those dimensions are really about.
DIMENSIONS_BY_SOURCE_KIND: Final[dict[SourceKind, tuple[Dimension, ...]]] = {
    SourceKind.OFFER_VERSION: (Dimension.PRODUCT_IDENTITY, Dimension.CURRENCY),
    SourceKind.AGREEMENT_LINE: DIMENSION_ORDER,
}

#: Every enum a report may name a member of. `report.py` derives the render
#: vocabulary from this, so adding a category to a dimension without adding its
#: enum here makes the render refuse rather than silently widen the alphabet.
REPORT_ENUMS: Final[tuple[type[ReportEnum], ...]] = (
    SourceKind,
    SourceCoverage,
    Bucket,
    ExclusionReason,
    Dimension,
    ProductIdentityOutcome,
    CurrencyOutcome,
    CadenceOutcome,
    ProrationOutcome,
    FrozenContentOutcome,
    ParityVerdict,
    ParitySubject,
    TallySubject,
)


__all__ = [
    "BLOCKING_OUTCOMES",
    "DIMENSIONS_BY_SOURCE_KIND",
    "DIMENSION_ORDER",
    "DIMENSION_SUBJECT",
    "REPORT_ENUMS",
    "TALLY_DOMAIN",
    "Bucket",
    "CadenceOutcome",
    "CurrencyOutcome",
    "Dimension",
    "ExclusionReason",
    "FrozenContentOutcome",
    "ParitySubject",
    "ParityVerdict",
    "ProductIdentityOutcome",
    "ProrationOutcome",
    "ReportEnum",
    "SourceCoverage",
    "SourceKind",
    "TallySubject",
]
