# ADR-0012: Billing and Subscriptions enter as PLATFORM schema shadows

- **Status:** Accepted for schema-only shadow composition
- **Date:** 2026-08-25
- **Owner:** Vendor control plane assembly
- **Authority status:** unchanged; this record does not authorize a writer
  cutover
- **Fleet sources:** Starter ADR-0020 and ADR-0030

## Release evidence

The two exact pins have immutable external coordinates rather than being
inferred from a source version:

- `dotmac-billing==0.1.0a1`: Starter release run `32673114414`, commit
  `92a1626b16d7e068f92536d8cfcb2ef9b6f270c2`. Its build and publish jobs, plus
  the verify job's install-from-Forgejo, composition verification and tag steps,
  succeeded; the run failed only when its later release-record opener failed.
  Annotated tag `dotmac-billing-v0.1.0a1` peels to that commit. The truthful
  generated record later merged and is present at Starter
  `8afbd7db7a3c9cdf2b47a54355fd67da4c38f45d`,
  `tests/architecture/test_released_migrations.py`.
- `dotmac-subscriptions==0.1.0a3`: successful Starter release run
  `32851152575`, commit
  `ad6c5824086f6f550447caeabe820e860cdfe23c`; annotated tag
  `dotmac-subscriptions-v0.1.0a3` peels to that commit. Its generated release
  record is present at the same immutable Starter commit and path.

These coordinates prove release/pinnability. They do not prove Vendor adoption,
deployment or a commercial-authority switch.

## Decision

Vendor exact-pins both distributions from Forgejo, composes their public
migration locators and manifests, and selects `ModulePlane.PLATFORM` explicitly
for `billing` and `subscriptions`. Neither tenant plane is installed; no fake or
sentinel tenant exists.

`v019_commercial_shadow` depends on `bi_0001_billing` and
`su_0003_billing_treatments`. In the same composed transaction that creates the
selected platform tables, it removes every effective `INSERT`, `UPDATE`,
`DELETE`, `TRUNCATE`, `REFERENCES` and `TRIGGER` privilege from `platform_api`,
including Billing a1's column-level `UPDATE (id)` grant. `SELECT` remains for
future comparison. `app_user` retains no privilege. The migration verifies the
effective table and column outcomes before commit and refuses downgrade because
restoring write access before a sealed cutover would create an unapproved
writer.

This change adds no runtime adapter and never calls Billing's
`bind_commercial_authority`. It writes and backfills no commercial row, does no
dual-write, emits no rated obligation, accepts no settlement, changes no local
offer/contract writer and selects no payment provider. Billing and Subscriptions
remain peer modules; composition does not create a Python dependency between
them.

Collections is deliberately absent. The fleet order keeps Sub as Collections'
first cutover/source adopter. Composing Billing and Subscriptions here does not
license Vendor to jump that gate.

## Read-only readiness evidence

`scripts/report_commercial_shadow_readiness.py` opens the kernel-owned platform
session and makes its first statement `SET TRANSACTION ISOLATION LEVEL
REPEATABLE READ, READ ONLY`. PostgreSQL therefore enforces that the entire
observation is one consistent, non-mutating snapshot. The command emits JSON
counts only; it never serializes an id, reference, amount, label or timestamp.

The report keeps three different questions separate:

1. **source completeness** counts Vendor's immutable `public.offer_versions`
   rows and the authoritative `mod_agreements` headers/lines, including
   historical offers without product identity and non-draft agreements without
   frozen content;
2. **source mapping** counts agreement lines whose opaque offer reference does
   not resolve to the Vendor offer row and lines whose frozen product/amount/
   currency differs from that source; and
3. **target population** reports only the number of expected, present,
   populated and total rows for each of the two composed PLATFORM planes.

This is backfill-planning input, not parity or sealed cutover evidence. The
absence of a Vendor Billing writer is a repository-local inventory fact; it
does not by itself prove that a selected deployment has no incumbent Billing
authority. The command does not choose which agreement types form the
Subscriptions cohort, invent cadence/proration terms, compare module semantics,
or provide the final under-lock watermark.

## Cutover order and gates

Vendor is the first cutover assembly for both Billing and Subscriptions. Schema
composition is only the expand step; each authority move remains a separate
reviewable change.

Before any Billing runtime authority is selected:

1. name the current invoice/receivables authority for the target deployment and
   inventory it under lock;
2. choose exactly one authority (`internal`, `provider_owned`, or
   `external_finance`) and keep provider transport in Dotmac Integrator;
3. backfill only if the inventory finds owned history, then prove complete
   immutable parity through a read-only comparison;
4. seal a final watermark, reconcile through it, retire the former writer and
   grant module DML in the same cutover transaction; and
5. prove rollback ends before the seal and that one writer remains after it.

Before Subscriptions authority moves:

1. inventory Vendor's local offer/contract/cadence/occurrence writers and every
   persisted row they own;
2. map product-specific capability terms through Vendor-owned links rather than
   copying them into the shared module;
3. backfill immutable offer/price and contract versions where history exists,
   then prove semantic parity and zero unresolved drift;
4. establish a sealed final watermark, quiesce and retire the local writer, and
   grant module DML atomically; and
5. wire rated-obligation output only through a typed assembly adapter into the
   already selected Billing authority, with a receipt/reconciliation path.

In this schema-only slice the 26 platform tables start empty and remain
read-only to the online role. A later backfill requires its own authorised,
offline migration/reconciliation slice and parity evidence; it does not grant
runtime write authority. No checked-in fact in this change claims adoption or
production deployment.
