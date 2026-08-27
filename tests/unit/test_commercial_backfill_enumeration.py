"""The exact Agreements a2 page walk and its coverage-to-parity boundary."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import date
from typing import cast
from unittest.mock import patch
from uuid import UUID

import pytest
from sqlalchemy.orm import Session

from vendor_cp.commercial_backfill import (
    AgreementEnumerationError,
    Bucket,
    CohortRules,
    ExclusionReason,
    ParitySubject,
    ParityVerdict,
    SourceCoverage,
    compare,
    observe,
    plan_sources,
    render,
    walk_agreement_lines,
)
from vendor_cp.commercial_backfill.planner import PlanOutcome
from vendor_cp.commercial_backfill.vocabulary import (
    DIMENSION_ORDER,
    TallySubject,
)
from vendor_cp.contracts.adapter import ContractPage, ContractView, LineView

HASH = "c" * 64


class _ReadOnlySession:
    def __init__(self) -> None:
        self.statements: list[str] = []

    def execute(self, statement: object) -> None:
        self.statements[:] = [str(statement)]


DB_VALUE = _ReadOnlySession()
DB = cast(Session, DB_VALUE)


def _contract(
    number: int,
    *,
    status: str = "active",
    line_count: int = 1,
    superseded_by_id: UUID | None = None,
) -> ContractView:
    agreement_id = UUID(int=number)
    return ContractView(
        id=agreement_id,
        reference=f"agreement-{number}",
        agreement_family_id=UUID(int=10_000 + number),
        agreement_version=1,
        product_code="acme",
        counterparty_ref=f"counterparty-{number}",
        agreement_type="commercial",
        term_start=date(2026, 1, 1),
        term_end_exclusive=date(2027, 1, 1),
        status=status,
        content_hash=HASH,
        record_version=1,
        activation_rule=None,
        superseded_by_id=superseded_by_id,
        lines=tuple(
            LineView(
                line_no=line_no,
                product_code="acme",
                capability_code=f"cap.{line_no}",
                quantity=line_no,
                unit_amount="10.00",
                unit_currency_code="NGN",
                offer_ref=f"offer-{line_no}",
                release_ref=None,
            )
            for line_no in range(1, line_count + 1)
        ),
    )


class _Pages:
    def __init__(self, pages: Sequence[ContractPage]) -> None:
        self.pages = list(pages)
        self.afters: list[UUID | None] = []

    def __call__(
        self,
        db: Session,
        *,
        after: UUID | None = None,
        limit: int = 100,
    ) -> ContractPage:
        assert db is DB
        assert DB_VALUE.statements == [
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
        ]
        assert limit > 0
        self.afters.append(after)
        return self.pages.pop(0)


def _rules() -> CohortRules:
    return CohortRules(declared_product_codes=frozenset({"acme"}))


def _matching_observation(outcome: PlanOutcome):
    mapped = outcome.report.tally_for(TallySubject.BUCKET).of(Bucket.MAPPED).value
    dimensions = {
        dimension: {
            member: count.value
            for member, count in outcome.mapped_dimension_tally(dimension).nonzero()
        }
        for dimension in DIMENSION_ORDER
    }
    return observe(row_count=mapped, dimension_counts=dimensions)


def _walk(
    pages: _Pages,
    *,
    page_size: int = 100,
    max_pages: int = 1_000,
):
    with patch(
        "vendor_cp.commercial_backfill.enumeration.list_agreements",
        pages,
    ):
        return walk_agreement_lines(DB, page_size=page_size, max_pages=max_pages)


def test_final_page_proves_coverage_and_preserves_materialized_lines() -> None:
    first = _contract(1, line_count=2)
    second = _contract(2)
    pages = _Pages(
        (
            ContractPage(items=(first,), next_after=first.id),
            ContractPage(items=(second,), next_after=None),
        )
    )

    walked = _walk(pages, page_size=1, max_pages=2)

    assert walked.coverage is SourceCoverage.AGREEMENT_LINE_ENUMERATED
    assert walked.complete is True
    assert walked.pages_read == 2
    assert pages.afters == [None, first.id]
    assert len(walked.rows) == 3
    assert len({row.fingerprint for row in walked.rows}) == 3
    assert [row.quantity for row in walked.rows] == [1, 2, 1]
    assert all(row.agreement_status == "ACTIVE" for row in walked.rows)
    assert all(row.term_end_exclusive == date(2027, 1, 1) for row in walked.rows)
    assert all(row.sibling_product_codes == ("acme", "acme") for row in walked.rows[:2])


def test_partial_page_budget_is_unknown_and_cannot_match_parity() -> None:
    first = _contract(1)
    walked = _walk(
        _Pages((ContractPage(items=(first,), next_after=first.id),)),
        page_size=1,
        max_pages=1,
    )
    outcome = plan_sources(
        walked,
        (),
        _rules(),
        offer_versions_enumerated=True,
    )
    comparison = compare(outcome, _matching_observation(outcome))
    verdicts = {line.subject: line.verdict for line in comparison.parity}

    assert walked.rows, "partial is not zero rows"
    assert walked.coverage is SourceCoverage.AGREEMENT_LINE_NOT_ENUMERABLE
    assert (
        outcome.report.tally_for(TallySubject.SOURCE_COVERAGE)
        .of(SourceCoverage.AGREEMENT_LINE_NOT_ENUMERABLE)
        .value
        == 1
    )
    assert verdicts == {
        ParitySubject.ROW_COUNT: ParityVerdict.NOT_COMPARABLE,
        ParitySubject.TARGET_SEMANTIC: ParityVerdict.NOT_COMPARABLE,
    }


def test_empty_final_page_is_a_proven_zero_row_estate() -> None:
    walked = _walk(_Pages((ContractPage(items=(), next_after=None),)))
    assert walked.complete is True
    assert walked.rows == ()


def test_repeated_cursor_fails_instead_of_recounting_a_page() -> None:
    first = _contract(1)
    second = _contract(2)
    pages = _Pages(
        (
            ContractPage(items=(first,), next_after=first.id),
            ContractPage(items=(second,), next_after=first.id),
        )
    )
    with pytest.raises(AgreementEnumerationError, match="repeated a cursor"):
        _walk(pages, max_pages=2)


def test_empty_nonfinal_page_fails_instead_of_becoming_zero() -> None:
    with pytest.raises(AgreementEnumerationError, match="empty agreement page"):
        _walk(_Pages((ContractPage(items=(), next_after=UUID(int=1)),)))


def test_superseded_owner_status_has_the_specific_exclusion() -> None:
    contract = _contract(1, status="superseded", superseded_by_id=UUID(int=2))
    walked = _walk(_Pages((ContractPage(items=(contract,), next_after=None),)))
    outcome = plan_sources(
        walked,
        (),
        _rules(),
        offer_versions_enumerated=True,
    )
    _, verdict = outcome.verdicts[0]
    assert verdict.bucket is Bucket.EXCLUDED
    assert verdict.exclusion is ExclusionReason.SUPERSEDED_AGREEMENT_VERSION


def test_complete_walk_produces_separate_value_free_parity_claims() -> None:
    contract = _contract(1)
    walked = _walk(_Pages((ContractPage(items=(contract,), next_after=None),)))
    outcome = plan_sources(
        walked,
        (),
        _rules(),
        offer_versions_enumerated=True,
    )

    rendered = render(compare(outcome, _matching_observation(outcome)))

    assert "ROW_COUNT MATCHED" in rendered
    assert "TARGET_SEMANTIC MATCHED" in rendered
    assert str(contract.id) not in rendered
    assert contract.lines[0].unit_amount not in rendered
    assert contract.reference not in rendered
    assert contract.term_start.isoformat() not in rendered


@pytest.mark.parametrize(("page_size", "max_pages"), [(0, 1), (1, 0), (True, 1)])
def test_walk_bounds_are_positive_whole_numbers(page_size: int, max_pages: int) -> None:
    with pytest.raises(AgreementEnumerationError):
        _walk(
            _Pages((ContractPage(items=(), next_after=None),)),
            page_size=page_size,
            max_pages=max_pages,
        )
