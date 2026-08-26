"""Read-only aggregate evidence for the commercial schema-shadow cutover.

This service observes the incumbent Vendor offer/agreement sources and the
composed Billing/Subscriptions PLATFORM tables in one repeatable-read,
read-only transaction.  It does not choose a backfill cohort, map recurrence,
compare target semantics, seal a watermark or author either module's state.

The returned shape is deliberately aggregate-only: no ids, references,
amounts, labels or timestamps can be serialized by this service.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Final

from sqlalchemy import MetaData, Table, func, select, text
from sqlalchemy.orm import Session

REPORT_SCHEMA_VERSION: Final[int] = 1

# Frozen to the two exact module releases composed by ADR-0012.  The
# architecture test keeps these runtime observations in sync with each public
# manifest.  A later release changes this list and its report contract in the
# same reviewed slice; it never silently broadens an old report.
BILLING_PLATFORM_TABLES: Final[tuple[str, ...]] = (
    "platform_billing_accounts",
    "platform_rated_obligations",
    "platform_documents",
    "platform_document_lines",
    "platform_document_events",
    "platform_confirmed_settlements",
    "platform_posting_groups",
    "platform_posting_effects",
    "platform_allocation_effects",
    "platform_applied_tax_snapshots",
    "platform_applied_fx_snapshots",
    "platform_party_tax_identity_snapshots",
    "platform_invoice_document_facts",
    "platform_document_artifacts",
    "platform_accounting_facts",
    "platform_receivable_position_facts",
    "platform_receivable_exposure_facts",
)

SUBSCRIPTIONS_PLATFORM_TABLES: Final[tuple[str, ...]] = (
    "platform_offers",
    "platform_offer_versions",
    "platform_offer_version_prices",
    "platform_subscription_contracts",
    "platform_subscription_contract_versions",
    "platform_subscription_contract_lines",
    "platform_recurring_charge_occurrences",
    "platform_subscription_billing_arrangements",
    "platform_subscription_billing_grants",
)


@dataclass(frozen=True, slots=True)
class SourceCompleteness:
    """Counts about the incumbent sources; never a cohort decision."""

    offer_versions: int
    offers_missing_product_identity: int
    agreement_headers: int
    agreement_lines: int
    non_draft_agreements_without_frozen_content: int


@dataclass(frozen=True, slots=True)
class SourceMapping:
    """Mechanical source-link differences requiring mapping or repair."""

    agreement_lines_without_resolved_offer: int
    agreement_lines_with_frozen_offer_mismatch: int

    @property
    def blocker_count(self) -> int:
        return (
            self.agreement_lines_without_resolved_offer
            + self.agreement_lines_with_frozen_offer_mismatch
        )


@dataclass(frozen=True, slots=True)
class TargetPopulation:
    """Aggregate population of one composed read-only module plane."""

    expected_tables: int
    present_tables: int
    populated_tables: int
    rows: int


@dataclass(frozen=True, slots=True)
class CommercialShadowReadinessReport:
    """PII-free observation; explicitly not sealed cutover evidence."""

    schema_version: int
    source_completeness: SourceCompleteness
    source_mapping: SourceMapping
    billing_target: TargetPopulation
    subscriptions_target: TargetPopulation

    def to_dict(self) -> dict[str, object]:
        """Return the complete aggregate-only JSON contract."""
        return asdict(self)


def observe_commercial_shadow_readiness(
    db: Session,
) -> CommercialShadowReadinessReport:
    """Observe one consistent snapshot without gaining a write path.

    This must be the first use of ``db``.  PostgreSQL refuses the transaction
    mode change after a statement has run, so a caller cannot accidentally
    append this report to a mutating transaction and describe it as read-only.
    The database, rather than a code convention, rejects any later write.
    """
    db.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))

    source = SourceCompleteness(
        offer_versions=_count(db, "SELECT count(*) FROM public.offer_versions"),
        offers_missing_product_identity=_count(
            db,
            """
            SELECT count(*)
              FROM public.offer_versions
             WHERE product_code IS NULL
                OR product_code = ''
                OR product_code <> btrim(product_code)
            """,
        ),
        agreement_headers=_count(db, "SELECT count(*) FROM mod_agreements.agreements"),
        agreement_lines=_count(
            db, "SELECT count(*) FROM mod_agreements.agreement_lines"
        ),
        non_draft_agreements_without_frozen_content=_count(
            db,
            """
            SELECT count(*)
              FROM mod_agreements.agreements
             WHERE status <> 'draft'
               AND (accepted_snapshot IS NULL OR content_hash IS NULL)
            """,
        ),
    )

    mapping = SourceMapping(
        agreement_lines_without_resolved_offer=_count(
            db,
            """
            SELECT count(*)
              FROM mod_agreements.agreement_lines AS line
         LEFT JOIN public.offer_versions AS offer
                ON offer.id::text = line.offer_ref
             WHERE offer.id IS NULL
            """,
        ),
        agreement_lines_with_frozen_offer_mismatch=_count(
            db,
            """
            SELECT count(*)
              FROM mod_agreements.agreement_lines AS line
              JOIN public.offer_versions AS offer
                ON offer.id::text = line.offer_ref
             WHERE offer.product_code IS DISTINCT FROM line.product_code
                OR offer.amount IS DISTINCT FROM line.unit_amount
                OR offer.currency_code IS DISTINCT FROM line.unit_currency_code
            """,
        ),
    )

    return CommercialShadowReadinessReport(
        schema_version=REPORT_SCHEMA_VERSION,
        source_completeness=source,
        source_mapping=mapping,
        billing_target=_target_population(
            db, schema="mod_billing", tables=BILLING_PLATFORM_TABLES
        ),
        subscriptions_target=_target_population(
            db,
            schema="mod_subscriptions",
            tables=SUBSCRIPTIONS_PLATFORM_TABLES,
        ),
    )


def _count(db: Session, statement: str) -> int:
    return int(db.execute(text(statement)).scalar_one())


def _target_population(
    db: Session, *, schema: str, tables: tuple[str, ...]
) -> TargetPopulation:
    present = 0
    populated = 0
    rows = 0
    metadata = MetaData()
    for table_name in tables:
        exists = bool(
            db.execute(
                text(
                    """
                    SELECT EXISTS (
                        SELECT 1
                          FROM information_schema.tables
                         WHERE table_schema = :schema
                           AND table_name = :table
                    )
                    """
                ),
                {"schema": schema, "table": table_name},
            ).scalar_one()
        )
        if not exists:
            continue
        present += 1
        relation = Table(table_name, metadata, schema=schema)
        row_count = int(
            db.execute(select(func.count()).select_from(relation)).scalar_one()
        )
        rows += row_count
        populated += int(row_count > 0)
    return TargetPopulation(
        expected_tables=len(tables),
        present_tables=present,
        populated_tables=populated,
        rows=rows,
    )


__all__ = [
    "BILLING_PLATFORM_TABLES",
    "SUBSCRIPTIONS_PLATFORM_TABLES",
    "CommercialShadowReadinessReport",
    "SourceCompleteness",
    "SourceMapping",
    "TargetPopulation",
    "observe_commercial_shadow_readiness",
]
