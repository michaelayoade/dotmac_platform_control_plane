# ADR-0007: prepare Billing on the platform plane

- **Status:** Accepted for preparation; production issuance is not authorized
- **Date:** 2026-08-17
- **Decision owner:** Michael
- **Depends on:** Dotmac Starter ADR-0020, ADR-0023, ADR-0024 and ADR-0030

## Context

Vendor CP owns vendor accounts and commercial contracts but has no invoice,
credit-note, settlement, allocation, receivable, refund, reversal or balance
writer. That absence was revalidated at
`f8f8c3fd636e663e4a17275c19e82fc1667aa52a`. It makes Vendor the greenfield
first adopter of `dotmac-billing`, not permission to create a local financial
owner beside it.

Billing `0.1.0a1` owns operational receivables. ERP or its selected replacement
retains GL, journals, accounts, fiscal periods, statutory accounting, treasury
and tax returns. Integrator retains PSP clients, credentials, webhook
verification, retries and checkpoints. Numbering, document rendering and Files
remain independent owners. Vendor retains its commercial contracts and every
product consequence.

## Decision

1. Vendor declares exact dependencies on `dotmac-kernel==0.1.0a69` and
   `dotmac-billing==0.1.0a1`. No path dependency is a deployable substitute.
2. The assembly composes Billing's `bi` lineage and explicitly selects only
   `ModulePlane.PLATFORM`. A tenant repository, nullable tenant, sentinel tenant
   or fake tenant is forbidden.
3. `vendor_cp.billing.authority` binds the sole `internal` commercial authority
   to a typed platform repository descriptor. Billing's own duplicate-authority
   refusal remains active.
4. Vendor migration `v015` uses Billing's public platform link helper to relate
   Billing accounts to local vendor accounts and contracts. The links live in
   Vendor's lineage, reference `mod_billing.platform_billing_accounts`, have no
   tenant column or RLS, grant usable DML to `platform_api`, and revoke all
   table and column privileges from `app_user`.
5. This preparation change adds no Billing route and invokes no money service.
   It does not issue a document, accept a settlement, allocate funding, post an
   accounting fact, render bytes, or cause a product consequence.

## Release and activation gate

`dotmac-billing 0.1.0a1` is intentionally unpublished while the Starter,
Vendor and Sub draft PRs are reviewed. Therefore the Vendor lockfile cannot be
truthfully refreshed and clean registry installation remains externally
blocked until a separately authorized Billing release produces the exact tag
and package. Do not replace that gate with a path dependency or copied module.

After publication, a follow-up activation change must satisfy every gate in
`docs/operations/billing-platform-cutover.md`: clean lock/install, fresh and
predecessor migrations, platform privilege audit, production-shaped preview,
Finance acceptance, Numbering/Rendering/Files readiness, accounting-fact
receipt, exact reconciliation and explicit deployment authorization.

## Consequences

- There is still no Vendor financial writer to retire and no financial data to
  backfill.
- Composition is reviewable before activation, but is not evidence of adoption
  or production use.
- Before the first post-watermark Billing fact, rollback may remove the
  unactivated assembly change and its empty link/module tables. After any
  Billing financial fact exists, rollback is roll-forward only; enabling a
  local writer would create two authorities.
