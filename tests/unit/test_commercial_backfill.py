"""The five transformations, the cohort rules, and the two parity claims.

Pure Python throughout — no session, no database, no clock. Every function under
test is deterministic, which is the property that makes a plan comparable across
runs at all, so a test kit would add nothing here except something else to
maintain.

The edge cases are the point. A cadence derivation that works on the first of
the month and a currency check that works for USD are not evidence of anything:
the rows that decide whether a backfill is safe are the ones anchored on 31
January, priced in a three-decimal currency, or carrying an approval for content
that has since changed.
"""

from __future__ import annotations

import importlib.util
import json
from datetime import date
from pathlib import Path

import pytest

from vendor_cp.commercial_backfill import (
    Bucket,
    CadenceOutcome,
    CohortRules,
    CurrencyOutcome,
    Dimension,
    ExclusionReason,
    FrozenContentOutcome,
    ParitySubject,
    ParityVerdict,
    ProductIdentityOutcome,
    ProrationOutcome,
    SourceCoverage,
    SourceKind,
    SourceRow,
    SourceRowError,
    classify,
    compare,
    is_complete_cohort,
    observe,
    plan,
    render,
    repair_statements,
)
from vendor_cp.commercial_backfill.report import UnsafeReportValue
from vendor_cp.commercial_backfill.transforms import (
    add_months,
    cadence_outcome,
    currency_outcome,
    frozen_content_outcome,
    product_identity_outcome,
    proration_outcome,
    whole_months,
)
from vendor_cp.commercial_backfill.vocabulary import TallySubject

HASH = "c" * 64


def rules(**overrides: object) -> CohortRules:
    base: dict[str, object] = {
        "declared_product_codes": frozenset({"acme"}),
    }
    base.update(overrides)
    return CohortRules(**base)  # type: ignore[arg-type]


def line(**overrides: object) -> SourceRow:
    base: dict[str, object] = {
        "kind": SourceKind.AGREEMENT_LINE,
        "fingerprint": "a" * 64,
        "amount": "10.00",
        "currency_code": "NGN",
        "product_code": "acme",
        "agreement_status": "ACTIVE",
        "content_hash": HASH,
        "term_start": date(2026, 1, 1),
        "term_end_exclusive": date(2027, 1, 1),
    }
    base.update(overrides)
    return SourceRow(**base)  # type: ignore[arg-type]


# ── Product identity ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        pytest.param("acme", ProductIdentityOutcome.QUALIFIED, id="declared"),
        pytest.param(None, ProductIdentityOutcome.CODE_ABSENT, id="pre-v011-null"),
        pytest.param("", ProductIdentityOutcome.CODE_ABSENT, id="empty"),
        pytest.param(
            " acme", ProductIdentityOutcome.CODE_UNTRIMMED, id="leading-space"
        ),
        pytest.param(
            "acme ", ProductIdentityOutcome.CODE_UNTRIMMED, id="trailing-space"
        ),
        pytest.param("ACME", ProductIdentityOutcome.CODE_UNDECLARED, id="case-differs"),
        pytest.param("other", ProductIdentityOutcome.CODE_UNDECLARED, id="unknown"),
    ],
)
def test_product_identity_edges(
    code: str | None, expected: ProductIdentityOutcome
) -> None:
    """`ACME` is UNDECLARED, not QUALIFIED. Case-folding two product codes
    together invents an identity nobody published, silently, for every row."""
    assert (
        product_identity_outcome(
            code, sibling_product_codes=(), declared_product_codes=frozenset({"acme"})
        )
        is expected
    )


def test_an_agreement_naming_two_products_blocks() -> None:
    """`vendor_cp.contracts.adapter._single_product` refuses the same shape at
    the HTTP boundary; a cohort that accepted it would backfill a contract whose
    product depends on which line was read first."""
    assert (
        product_identity_outcome(
            "acme",
            sibling_product_codes=("beta",),
            declared_product_codes=frozenset({"acme", "beta"}),
        )
        is ProductIdentityOutcome.MULTI_PRODUCT_AGREEMENT
    )


# ── Currency ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("amount", "code", "expected"),
    [
        pytest.param("10.00", "NGN", CurrencyOutcome.EXACT, id="two-decimal"),
        pytest.param("0.00", "NGN", CurrencyOutcome.EXACT_ZERO_AMOUNT, id="zero"),
        pytest.param("1000", "JPY", CurrencyOutcome.EXACT, id="zero-decimal-currency"),
        pytest.param(
            "1000.00", "JPY", CurrencyOutcome.NOT_QUANTIZED, id="jpy-with-minor"
        ),
        pytest.param(
            "1.000", "BHD", CurrencyOutcome.EXACT, id="three-decimal-currency"
        ),
        pytest.param("1.00", "BHD", CurrencyOutcome.NOT_QUANTIZED, id="bhd-too-few"),
        pytest.param("10.000", "NGN", CurrencyOutcome.NOT_QUANTIZED, id="too-precise"),
        pytest.param("10", "NGN", CurrencyOutcome.NOT_QUANTIZED, id="unquantized"),
        pytest.param("-1.00", "NGN", CurrencyOutcome.NEGATIVE, id="negative"),
        pytest.param("+10.00", "NGN", CurrencyOutcome.NOT_DECIMAL, id="explicit-plus"),
        pytest.param("1E+2", "NGN", CurrencyOutcome.NOT_DECIMAL, id="exponent"),
        pytest.param("1,000.00", "NGN", CurrencyOutcome.NOT_DECIMAL, id="separator"),
        pytest.param(" 10.00", "NGN", CurrencyOutcome.NOT_DECIMAL, id="whitespace"),
        pytest.param("10.00", "XYZ", CurrencyOutcome.CODE_UNKNOWN, id="unknown-code"),
        pytest.param("10.00", "ngn", CurrencyOutcome.CODE_UNKNOWN, id="lowercase-code"),
    ],
)
def test_currency_edges(amount: str, code: str, expected: CurrencyOutcome) -> None:
    """The two directions an assumed exponent is wrong: JPY by a hundred, BHD by
    a thousand. Both are `NOT_QUANTIZED` rather than a repair, because
    quantizing here invents money across the whole cohort in a run whose entire
    output is counts."""
    assert currency_outcome(amount, code) is expected


def test_a_mixed_currency_agreement_blocks() -> None:
    """One target price cannot hold two currencies, and picking one is a pricing
    decision the target owns."""
    assert (
        currency_outcome("10.00", "NGN", sibling_currency_codes=("USD",))
        is CurrencyOutcome.MIXED_CURRENCY_AGREEMENT
    )


# ── Cadence ────────────────────────────────────────────────────────────────


def test_month_addition_clamps_to_the_shorter_month() -> None:
    """31 January plus one month is 28 February — and 29 in a leap year. Stated
    here rather than depending on a billing library to agree."""
    assert add_months(date(2026, 1, 31), 1) == date(2026, 2, 28)
    assert add_months(date(2028, 1, 31), 1) == date(2028, 2, 29)
    assert add_months(date(2026, 12, 15), 1) == date(2027, 1, 15)
    assert add_months(date(2026, 1, 31), 12) == date(2027, 1, 31)


def test_whole_months_finds_no_match_for_a_day_count() -> None:
    """A 30-day term is not a month, and dividing days by 30 is how February
    becomes a rounding error."""
    assert whole_months(date(2026, 1, 1), date(2026, 1, 31)) is None
    assert whole_months(date(2026, 1, 1), date(2026, 2, 1)) == 1


@pytest.mark.parametrize(
    ("start", "end_exclusive", "expected"),
    [
        pytest.param(
            date(2026, 1, 1),
            date(2026, 2, 1),
            CadenceOutcome.MONTHLY,
            id="monthly",
        ),
        pytest.param(
            date(2026, 1, 1),
            date(2026, 4, 1),
            CadenceOutcome.QUARTERLY,
            id="quarterly",
        ),
        pytest.param(
            date(2026, 1, 1),
            date(2026, 7, 1),
            CadenceOutcome.SEMI_ANNUAL,
            id="semi-annual",
        ),
        pytest.param(
            date(2026, 1, 1),
            date(2027, 1, 1),
            CadenceOutcome.ANNUAL,
            id="annual",
        ),
        pytest.param(
            date(2026, 1, 1),
            date(2028, 1, 1),
            CadenceOutcome.INDETERMINATE,
            id="two-year-term-is-not-annual",
        ),
        pytest.param(
            date(2026, 1, 1),
            date(2026, 3, 1),
            CadenceOutcome.INDETERMINATE,
            id="two-month-term",
        ),
        pytest.param(
            date(2026, 1, 1),
            date(2026, 1, 31),
            CadenceOutcome.INDETERMINATE,
            id="thirty-day-term",
        ),
        pytest.param(
            date(2026, 1, 31),
            date(2026, 2, 28),
            CadenceOutcome.MONTHLY,
            id="month-end-anchored",
        ),
        pytest.param(
            date(2028, 2, 29),
            date(2028, 3, 29),
            CadenceOutcome.MONTHLY,
            id="leap-day-anchored",
        ),
        pytest.param(
            date(2026, 1, 1),
            date(2026, 1, 1),
            CadenceOutcome.TERM_NOT_POSITIVE,
            id="zero-length",
        ),
        pytest.param(
            date(2026, 2, 1),
            date(2026, 1, 1),
            CadenceOutcome.TERM_NOT_POSITIVE,
            id="reversed",
        ),
        pytest.param(
            date(2026, 1, 1),
            None,
            CadenceOutcome.TERM_OPEN_ENDED,
            id="open-ended",
        ),
    ],
)
def test_cadence_edges(
    start: date,
    end_exclusive: date | None,
    expected: CadenceOutcome,
) -> None:
    """A 24-month term is INDETERMINATE, not ANNUAL. Folding it would backfill a
    contract that bills twice, and the number of periods a term becomes is the
    target's decision rather than this planner's."""
    assert cadence_outcome(start, end_exclusive) is expected


# ── Proration ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("start", "cadence", "expected"),
    [
        pytest.param(
            date(2026, 1, 1),
            CadenceOutcome.MONTHLY,
            ProrationOutcome.NONE_REQUIRED,
            id="first-of-month",
        ),
        pytest.param(
            date(2026, 1, 28),
            CadenceOutcome.MONTHLY,
            ProrationOutcome.NONE_REQUIRED,
            id="last-universal-day",
        ),
        pytest.param(
            date(2026, 1, 29),
            CadenceOutcome.MONTHLY,
            ProrationOutcome.TARGET_OWNED_MISALIGNED,
            id="twenty-ninth",
        ),
        pytest.param(
            date(2026, 1, 31),
            CadenceOutcome.ANNUAL,
            ProrationOutcome.TARGET_OWNED_MISALIGNED,
            id="month-end",
        ),
        pytest.param(
            date(2028, 2, 29),
            CadenceOutcome.ANNUAL,
            ProrationOutcome.TARGET_OWNED_MISALIGNED,
            id="leap-day",
        ),
        pytest.param(
            date(2026, 1, 1),
            CadenceOutcome.INDETERMINATE,
            ProrationOutcome.ANCHOR_INDETERMINATE,
            id="no-period-length",
        ),
        pytest.param(
            None,
            CadenceOutcome.MONTHLY,
            ProrationOutcome.ANCHOR_INDETERMINATE,
            id="no-anchor",
        ),
    ],
)
def test_proration_edges(
    start: date | None, cadence: CadenceOutcome, expected: ProrationOutcome
) -> None:
    """The backfill carries NO proration — Vendor has none to carry. What this
    records is whether the target is going to face a short first period, which
    its owner needs before the cutover rather than in the first invoice run."""
    assert proration_outcome(start, cadence) is expected


# ── Frozen content ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("content", "activation", "expected"),
    [
        pytest.param(HASH, HASH, FrozenContentOutcome.TRANSLATABLE, id="matching"),
        pytest.param(HASH, None, FrozenContentOutcome.TRANSLATABLE, id="no-activation"),
        pytest.param(
            HASH,
            "d" * 64,
            FrozenContentOutcome.STALE_AGAINST_ACTIVATION,
            id="stale",
        ),
        pytest.param(None, None, FrozenContentOutcome.NOT_FROZEN, id="never-frozen"),
        pytest.param("", None, FrozenContentOutcome.NOT_FROZEN, id="empty"),
        pytest.param(
            f"sha256:{HASH}",
            None,
            FrozenContentOutcome.DIGEST_ALREADY_PREFIXED,
            id="already-prefixed",
        ),
        pytest.param(
            "c" * 63, None, FrozenContentOutcome.DIGEST_WRONG_LENGTH, id="short"
        ),
        pytest.param(
            "C" * 64, None, FrozenContentOutcome.DIGEST_UPPERCASE, id="uppercase"
        ),
        pytest.param("z" * 64, None, FrozenContentOutcome.DIGEST_NON_HEX, id="non-hex"),
    ],
)
def test_frozen_content_edges(
    content: str | None, activation: str | None, expected: FrozenContentOutcome
) -> None:
    """The stale case is `vendor_cp.contracts.adapter.active_snapshot`'s rule
    applied to a whole cohort: a row carrying an approval for content that has
    since changed is not a row to backfill quietly."""
    assert frozen_content_outcome(content, activation) is expected


# ── Cohort membership ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        pytest.param("ACTIVE", None, id="active-is-in"),
        pytest.param("SUSPENDED", None, id="suspended-is-in"),
        pytest.param("DRAFT", ExclusionReason.NOT_COMMERCIAL_STATE_YET, id="draft"),
        pytest.param(
            "PROPOSED", ExclusionReason.NOT_COMMERCIAL_STATE_YET, id="proposed"
        ),
        pytest.param(
            "APPROVED", ExclusionReason.NOT_COMMERCIAL_STATE_YET, id="approved"
        ),
        pytest.param(
            "TERMINATED",
            ExclusionReason.TERMINATED_BEFORE_COHORT_START,
            id="terminated",
        ),
        pytest.param(
            "CANCELLED",
            ExclusionReason.TERMINATED_BEFORE_COHORT_START,
            id="cancelled",
        ),
    ],
)
def test_cohort_membership_by_status(
    status: str, expected: ExclusionReason | None
) -> None:
    """SUSPENDED is IN. A suspended agreement is a contract that exists and is
    not billing — a state the target has and must be told about. Leaving it out
    silently drops paying relationships that happen to be paused on the day."""
    verdict = classify(line(agreement_status=status), rules())
    assert verdict.exclusion is expected


def test_a_draft_is_excluded_rather_than_reported_as_a_frozen_content_blocker() -> None:
    """Why membership is decided before any transformation.

    A draft has no frozen hash. Transformation-first would report every draft as
    a blocker — a queue of work items that are not work, burying the rows that
    really are blocked.
    """
    verdict = classify(line(agreement_status="DRAFT", content_hash=None), rules())
    assert verdict.bucket is Bucket.EXCLUDED
    assert verdict.exclusion is ExclusionReason.NOT_COMMERCIAL_STATE_YET
    assert verdict.blocking_dimension is None


def test_an_unreferenced_offer_version_is_catalogue_not_commercial_state() -> None:
    row = SourceRow(
        kind=SourceKind.OFFER_VERSION,
        fingerprint="b" * 64,
        amount="10.00",
        currency_code="NGN",
        product_code="acme",
        referenced_by_cohort_line=False,
    )
    verdict = classify(row, rules())
    assert verdict.exclusion is ExclusionReason.OFFER_VERSION_NEVER_REFERENCED


def test_a_superseded_version_is_excluded() -> None:
    verdict = classify(line(is_superseded=True), rules())
    assert verdict.exclusion is ExclusionReason.SUPERSEDED_AGREEMENT_VERSION


def test_a_zero_quantity_line_is_excluded() -> None:
    verdict = classify(line(quantity=0), rules())
    assert verdict.exclusion is ExclusionReason.ZERO_QUANTITY_LINE


def test_an_unknown_agreement_status_is_refused_at_construction() -> None:
    """The failure worth catching. If the agreements module gains a status this
    assembly has never seen, a classifier that fell through would put those rows
    in MAPPED — silently changing who is in the cohort, in the direction that
    backfills them."""
    with pytest.raises(SourceRowError):
        line(agreement_status="RENEGOTIATING")


def test_a_fingerprint_must_be_a_digest() -> None:
    with pytest.raises(SourceRowError):
        line(fingerprint="not-a-digest")


def test_the_first_blocking_dimension_in_declared_order_is_reported() -> None:
    """Two dimensions block; the report names product identity, every time.
    Deterministic, so two runs over the same rows produce the same report."""
    verdict = classify(line(product_code="other", amount="10.000"), rules())
    assert verdict.bucket is Bucket.BLOCKED
    assert verdict.blocking_dimension is Dimension.PRODUCT_IDENTITY


# ── The planner ────────────────────────────────────────────────────────────


def _cohort() -> tuple[SourceRow, ...]:
    return (
        line(fingerprint="a" * 64),
        line(fingerprint="b" * 64, amount="10.000"),
        line(fingerprint="d" * 64, agreement_status="DRAFT", content_hash=None),
    )


def test_every_row_lands_in_exactly_one_bucket() -> None:
    outcome = plan(_cohort(), rules(), enumerated=frozenset(SourceKind))
    buckets = outcome.report.tally_for(TallySubject.BUCKET)
    assert buckets.total().value == len(_cohort())
    assert buckets.of(Bucket.MAPPED).value == 1
    assert buckets.of(Bucket.BLOCKED).value == 1
    assert buckets.of(Bucket.EXCLUDED).value == 1


def test_every_excluded_row_carries_a_reason_and_every_blocked_row_a_dimension() -> (
    None
):
    outcome = plan(_cohort(), rules(), enumerated=frozenset(SourceKind))
    buckets = outcome.report.tally_for(TallySubject.BUCKET)
    assert outcome.report.tally_for(TallySubject.EXCLUSION).total() == buckets.of(
        Bucket.EXCLUDED
    )
    assert outcome.report.tally_for(
        TallySubject.BLOCKING_DIMENSION
    ).total() == buckets.of(Bucket.BLOCKED)


def test_a_plan_over_one_source_kind_is_not_a_complete_cohort() -> None:
    """Not zero rows — an unknown number of rows. The distinction the coverage
    tally exists for, and the state this assembly is in today."""
    outcome = plan(_cohort(), rules(), enumerated=frozenset({SourceKind.OFFER_VERSION}))
    coverage = outcome.report.tally_for(TallySubject.SOURCE_COVERAGE)
    assert coverage.of(SourceCoverage.AGREEMENT_LINE_NOT_ENUMERABLE).value == 1
    assert not is_complete_cohort(outcome.report)
    assert is_complete_cohort(
        plan(_cohort(), rules(), enumerated=frozenset(SourceKind)).report
    )


def test_a_plan_renders_only_counts_and_categories() -> None:
    """The whole constraint, end to end. Every rendered line is two declared
    names and at most one integer."""
    outcome = plan(_cohort(), rules(), enumerated=frozenset(SourceKind))
    rendered = render(outcome.report)
    assert "BUCKET MAPPED 1" in rendered
    for text in rendered.splitlines():
        parts = text.split(" ")
        assert 2 <= len(parts) <= 3, text
        assert all(part.isupper() or part.isdigit() for part in parts), text


def test_the_plan_is_the_same_whatever_order_the_rows_arrive_in() -> None:
    """Comparability across runs is the reason the planner is pure."""
    rows = _cohort()
    first = plan(rows, rules(), enumerated=frozenset(SourceKind)).report
    second = plan(
        tuple(reversed(rows)), rules(), enumerated=frozenset(SourceKind)
    ).report
    assert render(first) == render(second)


def test_no_declared_product_code_blocks_every_row() -> None:
    """A degenerate but reachable configuration, and it must be loud. An empty
    catalogue silently mapping everything would be the worst possible default."""
    outcome = plan(
        _cohort(),
        rules(declared_product_codes=frozenset()),
        enumerated=frozenset(SourceKind),
    )
    buckets = outcome.report.tally_for(TallySubject.BUCKET)
    assert buckets.of(Bucket.MAPPED).value == 0


# ── The comparator ─────────────────────────────────────────────────────────


def test_row_count_parity_can_match_while_semantic_parity_diverges() -> None:
    """The failure a count check alone reports as success: every row present,
    every cadence wrong."""
    outcome = plan((line(),), rules(), enumerated=frozenset(SourceKind))
    result = compare(
        outcome,
        observe(
            row_count=1,
            dimension_counts={Dimension.CADENCE: {CadenceOutcome.MONTHLY: 1}},
        ),
    )
    verdicts = {row.subject: row.verdict for row in result.parity}
    assert verdicts[ParitySubject.ROW_COUNT] is ParityVerdict.MATCHED
    assert verdicts[ParitySubject.TARGET_SEMANTIC] is ParityVerdict.DIVERGED


def test_an_unobserved_dimension_is_not_comparable_rather_than_matched() -> None:
    """A comparator that reported its own blind spot as agreement would be the
    most expensive kind of green."""
    outcome = plan((line(),), rules(), enumerated=frozenset(SourceKind))
    result = compare(outcome, observe(row_count=1, dimension_counts={}))
    verdicts = {row.subject: row.verdict for row in result.parity}
    assert verdicts[ParitySubject.TARGET_SEMANTIC] is ParityVerdict.NOT_COMPARABLE


def test_full_semantic_parity_matches_when_every_dimension_agrees() -> None:
    """NON-VACUITY: a comparator that never says MATCHED proves nothing by
    saying DIVERGED."""
    outcome = plan((line(),), rules(), enumerated=frozenset(SourceKind))
    result = compare(
        outcome,
        observe(
            row_count=1,
            dimension_counts={
                Dimension.PRODUCT_IDENTITY: {ProductIdentityOutcome.QUALIFIED: 1},
                Dimension.CURRENCY: {CurrencyOutcome.EXACT: 1},
                Dimension.CADENCE: {CadenceOutcome.ANNUAL: 1},
                Dimension.PRORATION: {ProrationOutcome.NONE_REQUIRED: 1},
                Dimension.FROZEN_CONTENT: {FrozenContentOutcome.TRANSLATABLE: 1},
            },
        ),
    )
    verdicts = {row.subject: row.verdict for row in result.parity}
    assert verdicts[ParitySubject.ROW_COUNT] is ParityVerdict.MATCHED
    assert verdicts[ParitySubject.TARGET_SEMANTIC] is ParityVerdict.MATCHED


def test_semantic_parity_compares_mapped_rows_only() -> None:
    """Excluded and blocked rows were never going to the target. Counting them
    would make a correct backfill look short by exactly the number of rows it
    was right to leave behind."""
    outcome = plan(_cohort(), rules(), enumerated=frozenset(SourceKind))
    result = compare(
        outcome,
        observe(
            row_count=1,
            dimension_counts={Dimension.CADENCE: {CadenceOutcome.ANNUAL: 1}},
        ),
    )
    verdicts = {row.subject: row.verdict for row in result.parity}
    assert verdicts[ParitySubject.ROW_COUNT] is ParityVerdict.MATCHED


def test_a_comparison_renders_only_counts_and_categories() -> None:
    outcome = plan((line(),), rules(), enumerated=frozenset(SourceKind))
    rendered = render(compare(outcome, observe(row_count=1, dimension_counts={})))
    assert "ROW_COUNT MATCHED" in rendered
    assert "TARGET_SEMANTIC NOT_COMPARABLE" in rendered


def test_an_observation_refuses_a_category_from_another_dimension() -> None:
    with pytest.raises(UnsafeReportValue):
        observe(
            row_count=1,
            dimension_counts={Dimension.CADENCE: {CurrencyOutcome.EXACT: 1}},
        )


# ── The rehearsal shadow ───────────────────────────────────────────────────


def test_the_repair_is_idempotent_in_shape() -> None:
    """Same verdicts in, byte-identical statements out — the property the
    disposable-PostgreSQL rehearsal then proves against a real database."""
    outcome = plan(_cohort(), rules(), enumerated=frozenset(SourceKind))
    assert repair_statements(outcome.verdicts) == repair_statements(outcome.verdicts)


def test_an_empty_cohort_still_clears_a_previous_run() -> None:
    """`NOT IN ()` is not valid SQL, and skipping the delete would leave a
    previous run's rows behind — the drift a repair exists to remove."""
    statements = repair_statements(())
    assert any(text.startswith("DELETE FROM bf_rehearsal.") for text in statements)
    assert not any("NOT IN ()" in text for text in statements)


def test_every_verdict_reaches_the_shadow() -> None:
    """One statement per row, so a repaired rehearsal holds the whole plan and
    not just the interesting part of it."""
    outcome = plan(_cohort(), rules(), enumerated=frozenset(SourceKind))
    inserts = [s for s in repair_statements(outcome.verdicts) if s.startswith("INSERT")]
    assert len(inserts) == len(_cohort())


# ── The reconciliation command ─────────────────────────────────────────────


#: Loaded BY PATH. `scripts/` is not a package and the repository root is not on
#: `sys.path` under pytest's rootdir insertion, so an ordinary import would bind
#: to whatever else happened to be importable — or fail depending on collection
#: order. The same reasoning `tests/architecture/import_scanner.py` records for
#: its own uniquely-named module.
def _command_main(argv: list[str]) -> int:
    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location(
        "vendor_cp_reconcile_backfill_shadow",
        root / "scripts" / "reconcile_backfill_shadow.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    exit_code: int = module.main(argv)
    return exit_code


def test_the_command_refuses_without_the_disposable_confirmation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """It never sees a database, so it cannot check the premise. Making the
    operator STATE it is honest; inferring it would not be."""
    export = tmp_path / "rows.json"
    export.write_text("[]")
    assert _command_main(["--source-export", str(export)]) == 2
    assert "confirm-disposable" in capsys.readouterr().err


def test_the_command_refuses_an_export_with_an_unrecognised_field(
    tmp_path: Path,
) -> None:
    """A silently dropped field is a row classified on less information than the
    exporter thought it sent."""
    export = tmp_path / "rows.json"
    export.write_text(json.dumps([{"kind": "OFFER_VERSION", "surprise": 1}]))
    assert _command_main(["--source-export", str(export), "--confirm-disposable"]) == 3


def test_the_command_reports_and_emits_repair_sql(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    export = tmp_path / "rows.json"
    export.write_text(
        json.dumps(
            [
                {
                    "kind": "OFFER_VERSION",
                    "fingerprint": "b" * 64,
                    "amount": "10.00",
                    "currency_code": "NGN",
                    "product_code": "acme",
                }
            ]
        )
    )
    code = _command_main(
        [
            "--source-export",
            str(export),
            "--product-code",
            "acme",
            "--enumerated",
            "OFFER_VERSION",
            "--confirm-disposable",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert "BUCKET MAPPED 1" in captured.err
    assert "AGREEMENT_LINE_NOT_ENUMERABLE" in captured.err
    assert "INSERT INTO bf_rehearsal.shadow_verdicts" in captured.out
    assert "GRANT" not in captured.out.upper()
