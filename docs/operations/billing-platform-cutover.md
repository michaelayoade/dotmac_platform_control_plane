# Billing platform cutover runbook

This runbook prepares a future, separately authorized Vendor CP activation of
`dotmac-billing`. It is not a deployment instruction for the current change.
No command here may be run against production without Michael explicitly naming
and authorizing the target.

## Preconditions

- The exact `dotmac-billing==0.1.0a1` and its declared kernel floor install from
  the approved registry; the wheel contains `bi_0001_billing` and `py.typed`.
- Vendor's lockfile resolves only exact registry pins and all repository checks
  are green on that revision.
- Fresh and `v014 -> heads` migration rehearsals pass. The live catalogue shows
  every `mod_billing.platform_*` table, no tenant Billing table, no Billing row,
  and the two Vendor link tables with the expected privilege posture.
- Finance accepts the preview's seller/customer identity, service period, exact
  line/tax totals, currency, FX purpose, due-date basis and accounting inputs.
- Numbering is bound before issuance. Rendering plus Files are ready before a
  legal document is promised. ERP/the selected finance authority accepts
  `AccountingFactV1` idempotently. Integrator or a finance-reviewed adapter is
  the independent source of confirmed settlement evidence.
- Full, partial, overpayment-to-credit, reversal, refund, duplicate replay and
  changed-fingerprint conflict scenarios are green with production-shaped data.

## Activation sequence

1. Quiesce every candidate commercial-money entry point. The expected set is
   empty; discovering one is a stop condition, not a migration task.
2. Record the deployment revision, exact module versions, database backup id,
   Integrator checkpoint, outbox watermark and the zero-row counts below.
3. Apply the composed migration to `heads` and rerun the privilege/FK checks.
4. Preview one approved contract without persistence or numbering. Finance
   records acceptance of the immutable input and expected facts.
5. Enable the one guarded Billing command adapter. Issue one invoice, render and
   store its official artifact, then reconcile before proceeding.
6. Accept one independently confirmed settlement and apply one same-currency
   allocation. Reconcile documents, allocations, all three position lanes,
   accounting facts and outbox delivery before widening traffic.
7. Resume one input family at a time. Reconcile after each family; product
   consequences remain asynchronous and owned by Vendor services.

## Read-only reconciliation queries

Run as an audit-capable read-only role. A query returning rows is a blocker
unless the query explicitly reports inventory.

```sql
-- Preparation must begin empty; no fake tenant can explain a row.
SELECT 'accounts' AS population, count(*)
FROM mod_billing.platform_billing_accounts
UNION ALL SELECT 'documents', count(*) FROM mod_billing.platform_documents
UNION ALL SELECT 'settlements', count(*) FROM mod_billing.platform_confirmed_settlements
UNION ALL SELECT 'posting_groups', count(*) FROM mod_billing.platform_posting_groups;

-- Rebuild the three exact lanes from immutable effects and compare the newest
-- recorded position fact. Zero rows means equality; there is no tolerance.
WITH rebuilt AS (
  SELECT billing_account_id, currency, minor_units,
         sum(amount_delta) FILTER (WHERE lane = 'receivable') AS receivable,
         sum(amount_delta) FILTER (WHERE lane = 'available_credit') AS credit,
         sum(amount_delta) FILTER (WHERE lane = 'prepaid_funding') AS prepaid
  FROM mod_billing.platform_posting_effects
  GROUP BY billing_account_id, currency, minor_units
), latest AS (
  SELECT DISTINCT ON (billing_account_id, currency)
         billing_account_id, currency, minor_units,
         collectible_receivable, available_credit, prepaid_funding,
         source_version, state_fingerprint
  FROM mod_billing.platform_receivable_position_facts
  ORDER BY billing_account_id, currency, source_version DESC
)
SELECT rebuilt.*, latest.collectible_receivable, latest.available_credit,
       latest.prepaid_funding, latest.source_version, latest.state_fingerprint
FROM rebuilt FULL JOIN latest USING (billing_account_id, currency, minor_units)
WHERE coalesce(rebuilt.receivable, 0::numeric) IS DISTINCT FROM
      coalesce(latest.collectible_receivable, 0::numeric)
   OR coalesce(rebuilt.credit, 0::numeric) IS DISTINCT FROM
      coalesce(latest.available_credit, 0::numeric)
   OR coalesce(rebuilt.prepaid, 0::numeric) IS DISTINCT FROM
      coalesce(latest.prepaid_funding, 0::numeric);

-- No allocation may point at missing settlement/document evidence.
SELECT allocation.id, allocation.settlement_id, allocation.document_id
FROM mod_billing.platform_allocation_effects AS allocation
LEFT JOIN mod_billing.platform_confirmed_settlements AS settlement
  ON settlement.id = allocation.settlement_id
LEFT JOIN mod_billing.platform_documents AS document
  ON document.id = allocation.document_id
WHERE settlement.id IS NULL
   OR (allocation.document_id IS NOT NULL AND document.id IS NULL);

-- Every local link targets a platform Billing account and exactly one local
-- subject. Foreign keys enforce this; the query exposes any disabled-constraint
-- or bulk-load drift.
SELECT link.billing_account_id
FROM public.billing_vendor_account_links AS link
LEFT JOIN mod_billing.platform_billing_accounts AS account
  ON account.id = link.billing_account_id
LEFT JOIN public.vendor_accounts AS subject ON subject.id = link.vendor_account_id
WHERE account.id IS NULL OR subject.id IS NULL
UNION ALL
SELECT link.billing_account_id
FROM public.billing_contract_links AS link
LEFT JOIN mod_billing.platform_billing_accounts AS account
  ON account.id = link.billing_account_id
LEFT JOIN public.contracts AS subject ON subject.id = link.contract_id
WHERE account.id IS NULL OR subject.id IS NULL;

-- Accounting facts are immutable and unique by their stable digest. Any group
-- with no fact, or more than one V1 fact, is a blocker.
SELECT posting.id, count(fact.id) AS fact_count
FROM mod_billing.platform_posting_groups AS posting
LEFT JOIN mod_billing.platform_accounting_facts AS fact
  ON fact.posting_group_id = posting.id AND fact.fact_version = 1
GROUP BY posting.id
HAVING count(fact.id) <> 1;
```

The application reconciler must also call Billing's rebuild operation for every
account/currency and compare its returned `state_fingerprint` with the newest
stored fact. SQL totals prove amounts; the canonical rebuild proves ordering and
hash identity.

## Rollback boundary

Before any Billing financial fact exists after the recorded watermark: stop the
new adapter, prove all four module counts remain zero, restore the previous
application revision, and—only through a reviewed forward migration—remove the
empty Vendor link tables if required. Do not run an unreviewed schema downgrade.

After the first rated obligation, document, settlement or posting group exists:
rollback is roll-forward only. Stop inputs, preserve the Integrator checkpoint,
repair/replay Billing, reconcile exact positions and resume from the watermark.
Never enable a Vendor-local invoice, settlement, allocation or balance writer.

