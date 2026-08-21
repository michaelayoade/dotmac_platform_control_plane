# ADR-0008: Commercial Agreements greenfield authority switch

- **Status:** Accepted
- **Date:** 2026-08-20
- **Owner:** Vendor control plane / `dotmac-commercial-agreements`

## Context

ADR-0007 orders Commercial Agreements first in the in-place recomposition. Its
original step said to migrate legacy contract rows while preserving their
content hashes and deriving history only from evidence. That is the correct
protocol for a populated estate, but the premise did not survive inspection.

The authorized check against Vendor's designated sole target found
`TARGET_ABSENT`: no Compose database service and no data volume. The same
observation already governed the Approvals and Allocation greenfield switches.
There are therefore no contract rows, hashes or history to preserve. Creating
synthetic contracts or audit history would fabricate evidence rather than
migrate it.

The released `dotmac-commercial-agreements==0.1.0a1` owns agreement identity,
accepted snapshots, lifecycle, append-only history, platform audit and
versioned outbox facts. It requires the kernel's `idempotency_ledger.v1` and
`platform_audit_log.v1` effects and is platform-only and atomic: it has no plane
selection.

## Decision

Vendor switches directly, in one coherent change:

1. Exact-pin `dotmac-commercial-agreements==0.1.0a1` from Forgejo and compose
   its public manifest and `versions_dir()` lineage.
2. Bind `idempotency_ledger.v1` to kernel revision
   `0018_idempotency_one_owner` and `platform_audit_log.v1` to
   `0026_platform_audit_log`.
3. Make `vendor_cp.contracts.adapter` the only runtime seam. It resolves local
   immutable offer versions into frozen `CommercialTerms`, supplies the
   product-qualified capability catalogue, and converts the exact approved
   `dotmac-approvals` request into content-bound `ApprovalEvidence`.
4. Route the module's `agreement.activated.v1` fact to Entitlement Allocation.
   The allocation adapter asks Commercial Agreements for an active snapshot;
   it does not read agreement ORM rows or maintain another lifecycle opinion.
5. Apply Vendor revision `v015_agreements_authority`. It takes
   `ACCESS EXCLUSIVE` on the legacy parent-before-child tables, rechecks that
   both are empty, and only then drops them child-before-parent. A populated row
   aborts the transaction and leaves both owners intact.
6. Delete `vendor_cp.contracts.service`, its models and the Vendor-owned audit
   declarations. The module is the sole lifecycle/history/audit/outbox writer.

The HTTP surface keeps its Vendor route prefix but adopts the module's
`draft → proposed → approved → active` vocabulary and optimistic concurrency.
Approval and activation remain separate and activation requires both the exact
approval evidence and a named activation-rule reference.

## Amendment to ADR-0007 step 2

The instruction to migrate rows applies only when rows exist. For this measured
greenfield target it is superseded by the fail-closed empty-estate switch above.
If `v015` observes any row, the amendment's premise is false and the migration
must stop; the populated-estate protocol then requires a new decision and real
parity evidence.

## Consequences

- This repository, runtime and database remain the Vendor assembly; no second
  repository or monolith replacement is created.
- `public.contracts` and `public.contract_lines` disappear at composed heads;
  `mod_agreements` is the only agreement persistence owner.
- Vendor keeps local offers and typed assembly adapters, not a fork of agreement
  decisions or history.
- This change establishes composition and code authority, not adoption. Starter
  adoption evidence is updated only after Vendor actually runs the released
  module with the former local writer absent.
- Licensing issuer is the next ADR-0007 authority slice.

## Lifecycle — adopted 2026-08-21

Composed and authoritative in code is not adopted. This one ran.

Deploy run `32485479666` took production to
`af9fcf6d3fbd259fbef6b589d37b39d548f7ba8e` at image
`sha256:45715e425dc248d85fe374fa5d347087328a445cf7ead1f8abc29f05f0117b0d`,
applying `v015` along with kernel `0024`–`0026`, `v016` and the a5/a6
verification revisions in a single run.

Verified directly against that database at 2026-08-21T14:17:32Z rather than
inferred from the deploy succeeding:

- applied heads `ap_0002_outbox_relay`, `ea_0003_platform_audit_log`,
  `rl_0001_release_artifacts`, `v016_licensing_authority`;
- `mod_agreements` live;
- `public.contracts` and `public.contract_lines` **absent**, which is the
  local-writer half of the adoption test;
- `app_user` holding **zero** privileges on any `mod_*` schema.

The greenfield premise `v015` rechecks under `ACCESS EXCLUSIVE` held: the
migration did not abort, so the legacy tables were empty at execution time as
well as at observation time.

**Owed at the extraction source:** `packages/dotmac-commercial-agreements/EXTRACTION.toml`
in `dotmac_starter_mt` should gain this assembly as a contract consumer and this
run as adoption evidence. That dossier is the authority for adoption
(`AGENTS.md` rule 17); this section cites what it will record, and does not
substitute for it.
