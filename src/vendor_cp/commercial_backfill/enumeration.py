"""Bounded, read-only enumeration of Commercial Agreements source lines.

The exact-pinned Agreements a2 owner supplies one bounded UUID-keyset page at
a time.  This module is the assembly-owned WALK over that public reader: it
passes the opaque cursor back unchanged, projects every materialized line into
the already-contracted ``SourceRow`` shape, and calls a run complete only after
the owner returns ``next_after=None``.

Page-budget exhaustion is a normal, explicitly INCOMPLETE result.  A broken
page contract (a repeated cursor, duplicate agreement, over-sized page or a
successor cursor on an empty page) is different: the run fails closed and no
report is produced.  Nothing here writes, connects, chooses a target authority
or receives target rows.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from hashlib import sha256
from typing import Final
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from vendor_cp.commercial_backfill.cohort import CohortRules, SourceRow
from vendor_cp.commercial_backfill.planner import PlanOutcome, plan
from vendor_cp.commercial_backfill.vocabulary import SourceCoverage, SourceKind
from vendor_cp.contracts.adapter import (
    AGREEMENT_PAGE_SIZE,
    AGREEMENT_STATUS_NAMES,
    SUPERSEDED_AGREEMENT_STATUS,
    ContractPage,
    ContractView,
    LineView,
    list_agreements,
)

DEFAULT_MAX_AGREEMENT_PAGES: Final[int] = 1_000
_READ_ONLY_SNAPSHOT: Final[str] = (
    "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
)


class AgreementEnumerationError(ValueError):
    """The owner page stream cannot support a complete-cohort claim."""


@dataclass(frozen=True, slots=True)
class AgreementLineEnumeration:
    """Projected lines plus an explicit statement about run coverage.

    ``rows`` may be non-empty while ``coverage`` is
    ``AGREEMENT_LINE_NOT_ENUMERABLE``.  That is a bounded partial walk, not a
    zero-row estate and not admissible parity evidence.
    """

    rows: tuple[SourceRow, ...]
    coverage: SourceCoverage
    pages_read: int

    def __post_init__(self) -> None:
        if self.coverage not in {
            SourceCoverage.AGREEMENT_LINE_ENUMERATED,
            SourceCoverage.AGREEMENT_LINE_NOT_ENUMERABLE,
        }:
            raise AgreementEnumerationError(
                "an agreement-line walk carries agreement-line coverage"
            )
        if (
            isinstance(self.pages_read, bool)
            or not isinstance(self.pages_read, int)
            or self.pages_read < 1
        ):
            raise AgreementEnumerationError("an agreement-line walk reads a page")
        if any(row.kind is not SourceKind.AGREEMENT_LINE for row in self.rows):
            raise AgreementEnumerationError(
                "an agreement-line walk carries agreement lines only"
            )

    @property
    def complete(self) -> bool:
        return self.coverage is SourceCoverage.AGREEMENT_LINE_ENUMERATED


def _line_fingerprint(agreement_id: UUID, line_no: int) -> str:
    """Digest the owner's stable agreement-line natural key.

    The digest is internal rehearsal identity and never reaches a report.  It
    intentionally excludes mutable commercial values so a changed category
    repairs the same shadow row instead of creating a second row.
    """
    if isinstance(line_no, bool) or not isinstance(line_no, int) or line_no < 1:
        raise AgreementEnumerationError("an agreement line has a positive line number")
    natural_key = f"agreement-line-v1:{agreement_id.hex}:{line_no}".encode()
    return sha256(natural_key).hexdigest()


def _status_name(value: str) -> str:
    """Normalize the exact owner's lowercase value to the cohort enum name."""
    try:
        return AGREEMENT_STATUS_NAMES[value]
    except KeyError as exc:
        raise AgreementEnumerationError(
            "an agreement status is outside the exact-pinned owner vocabulary"
        ) from exc


def _source_row(
    agreement: ContractView,
    line: LineView,
    *,
    sibling_product_codes: tuple[str, ...],
    sibling_currency_codes: tuple[str, ...],
) -> SourceRow:
    status = _status_name(agreement.status)
    return SourceRow(
        kind=SourceKind.AGREEMENT_LINE,
        fingerprint=_line_fingerprint(agreement.id, line.line_no),
        amount=line.unit_amount,
        currency_code=line.unit_currency_code,
        product_code=line.product_code,
        sibling_product_codes=sibling_product_codes,
        sibling_currency_codes=sibling_currency_codes,
        quantity=line.quantity,
        agreement_status=status,
        is_superseded=(
            agreement.superseded_by_id is not None
            or status == SUPERSEDED_AGREEMENT_STATUS
        ),
        content_hash=agreement.content_hash,
        term_start=agreement.term_start,
        term_end_exclusive=agreement.term_end_exclusive,
    )


def _project_agreement(agreement: ContractView) -> tuple[SourceRow, ...]:
    products = tuple(line.product_code for line in agreement.lines)
    currencies = tuple(line.unit_currency_code for line in agreement.lines)
    rows = tuple(
        _source_row(
            agreement,
            line,
            sibling_product_codes=products,
            sibling_currency_codes=currencies,
        )
        for line in agreement.lines
    )
    fingerprints = {row.fingerprint for row in rows}
    if len(fingerprints) != len(rows):
        raise AgreementEnumerationError(
            "an agreement page repeats an agreement-line natural key"
        )
    return rows


def walk_agreement_lines(
    db: Session,
    *,
    page_size: int = AGREEMENT_PAGE_SIZE,
    max_pages: int = DEFAULT_MAX_AGREEMENT_PAGES,
) -> AgreementLineEnumeration:
    """Walk at most ``max_pages`` and prove completion only on the final page.

    The caller supplies an UNUSED session from the kernel-owned transaction
    boundary. The first statement makes the database enforce a repeatable-read,
    read-only snapshot; PostgreSQL refuses it after another statement has run.
    Every domain read then remains behind the exact-pinned owner's typed adapter.
    """
    if isinstance(page_size, bool) or not isinstance(page_size, int) or page_size < 1:
        raise AgreementEnumerationError("page_size is a positive whole number")
    if isinstance(max_pages, bool) or not isinstance(max_pages, int) or max_pages < 1:
        raise AgreementEnumerationError("max_pages is a positive whole number")

    db.execute(text(_READ_ONLY_SNAPSHOT))

    after: UUID | None = None
    seen_cursors: set[UUID] = set()
    seen_agreements: set[UUID] = set()
    rows: list[SourceRow] = []
    complete = False
    pages_read = 0

    for _ in range(max_pages):
        page = list_agreements(db, after=after, limit=page_size)
        if not isinstance(page, ContractPage):
            raise AgreementEnumerationError(
                "the agreement reader returned a ContractPage"
            )
        pages_read += 1
        if len(page.items) > page_size:
            raise AgreementEnumerationError(
                "the agreement reader exceeded its page bound"
            )

        for agreement in page.items:
            if agreement.id in seen_agreements:
                raise AgreementEnumerationError(
                    "the agreement page stream repeated an agreement"
                )
            seen_agreements.add(agreement.id)
            rows.extend(_project_agreement(agreement))

        if page.next_after is None:
            complete = True
            break
        if not page.items:
            raise AgreementEnumerationError(
                "an empty agreement page cannot advertise a successor"
            )
        if page.next_after in seen_cursors:
            raise AgreementEnumerationError(
                "the agreement page stream repeated a cursor"
            )
        seen_cursors.add(page.next_after)
        after = page.next_after

    coverage = (
        SourceCoverage.AGREEMENT_LINE_ENUMERATED
        if complete
        else SourceCoverage.AGREEMENT_LINE_NOT_ENUMERABLE
    )
    return AgreementLineEnumeration(
        rows=tuple(rows),
        coverage=coverage,
        pages_read=pages_read,
    )


def plan_sources(
    agreements: AgreementLineEnumeration,
    offer_versions: Sequence[SourceRow],
    rules: CohortRules,
    *,
    offer_versions_enumerated: bool,
) -> PlanOutcome:
    """Feed a walk into the existing planner without caller-declared coverage.

    Agreement coverage is DERIVED from the page walk.  A caller cannot pass a
    partial tuple of lines and independently label it complete.  Offer coverage
    remains explicit because its separate read-only export is not changed by
    this slice.
    """
    if any(row.kind is not SourceKind.OFFER_VERSION for row in offer_versions):
        raise AgreementEnumerationError(
            "the offer-version input carries offer versions only"
        )
    enumerated: set[SourceKind] = set()
    if agreements.complete:
        enumerated.add(SourceKind.AGREEMENT_LINE)
    if offer_versions_enumerated:
        enumerated.add(SourceKind.OFFER_VERSION)
    return plan(
        (*offer_versions, *agreements.rows),
        rules,
        enumerated=frozenset(enumerated),
    )


__all__ = [
    "DEFAULT_MAX_AGREEMENT_PAGES",
    "AgreementEnumerationError",
    "AgreementLineEnumeration",
    "plan_sources",
    "walk_agreement_lines",
]
