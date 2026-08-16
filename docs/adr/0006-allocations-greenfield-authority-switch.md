# ADR-0006: Allocation authority moves greenfield — the last local writer

- **Status:** Accepted
- **Date:** 2026-08-16
- **Owner:** Vendor control plane
- **Follows:** ADR-0005 (approvals), which established the pattern

## Context

`vendor_cp.allocations` was the last local writer in this assembly. Release
Catalog already owned its write path; ADR-0005 moved approvals; this completes
the set.

The same observation justifies the same path. A direct authorized check against
the designated sole target found
`TARGET_ABSENT | db_service_absent | volume_absent`: no Compose `db` service and
no data volume, so no Vendor CP database has ever been provisioned and there is
no allocation estate anywhere.

As in ADR-0005, that is an observation and not an inference — and the read-only
inventory tool built for the question never ran. Its contribution was enforcing
the evidence boundary, refusing to convert "no mechanism to run this" into "the
target is absent". The greenfield path is valid because someone looked.

## Decision

Move the authority in one forward migration
(`v014_allocations_authority_switch`), and retire the local writer.

1. **Empty is the premise, and it is CHECKED.** The migration locks both legacy
   tables, counts them, and raises if either holds a row — in which case nothing
   happens: no grant, no drop. The error names ADR-0031's protocol as what a
   populated estate would need instead.
2. **`ACCESS EXCLUSIVE`, taken once and up front**, because the same migration
   DROPs those tables and `DROP TABLE` takes that lock. Escalating from `SHARE`
   mid-transaction invites deadlock, and locking first is also what makes the
   emptiness check meaningful: under it, "empty when checked" and "empty when
   dropped" are the same statement. `allocation_entries` drops before
   `allocations`, since the entries carry the foreign key.
3. **`platform_api` gains DML on `mod_ealloc`**, verified as an EFFECTIVE outcome
   in both directions — it holds what it needs and nothing beyond it, and the
   tenant role still holds nothing.
4. **A typed adapter is the only seam.** `vendor_cp.allocations.adapter` maps
   Vendor's contract into the module's `ContractSnapshot`, with no `Any` at the
   boundary.

   The division of rules is the interesting part. Vendor keeps the checks about
   VENDOR'S contract — that it is `ACTIVE`, and that the activation event's
   digest still matches the contract's current version — because only Vendor can
   say what "stale" means about its own aggregate, and pushing that into the
   module would give it an opinion about a domain it deliberately has no model
   of. The module keeps every rule about what a valid allocation IS: capabilities
   declared by the product's catalogue, non-empty entries, no duplicates,
   idempotency on the source event.
5. **Both entry points go through it.** Contract activation stages via
   `ContractEventConsumer`, which resolves the catalogue reader per delivery
   rather than holding one — it is built from configured release pins and held
   evidence that an operator may change between deliveries, and caching it would
   pin a decision this consumer has no authority over. Licensing reads
   allocations through the adapter and takes the product from the module's
   `allocation_product()`.
6. **The legacy models, tables and call sites are gone**, and the call-site
   ratchet is held at zero.

## What is deliberately NOT built

Against an empty estate, each is machinery producing no information that would
still have to be maintained and believed: **parity comparison** (nothing to
compare), **backfill** (nothing to migrate), **synthetic records** (no history to
represent), **sealed legacy evidence** (ADR-0031 is the standard for a cutover
WITH data; this is not one, and sealing an empty set produces a digest of nothing
that later reads as proof of something).

## Retired artifacts, and why deletion rather than retention

Two removals go beyond the runtime writer (`allocations/service.py` and
`models.py`). Recording them here because a reader of the merge commit could not
otherwise tell why they vanished — the gap that cost a review round on #51.

**The allocation cutover preflight** (`allocations/preflight.py` and its test). It
audited legacy allocation rows for the sealed cutover ADR-0004 designed: mapping
proposals, classification digests, divergence reports. It reads
`public.allocations`, which `v014` drops.

**The shadow-overlap exemption** (`shadow_overlaps.py` and its architecture
test). It waived two host-squatter violations in the composed live-catalogue gate
while the legacy tables shadowed `mod_ealloc`.

Four reasons, applying to both:

1. **The switch removes their schema AND their consumers.** Both are about tables
   `v014` drops. Retained, they would not be reference implementations but the
   appearance of them — code that cannot run, which the next reader discovers by
   trying it.
2. **`b76f5fa` preserves them** — artifacts, tests and review history — as
   immutable historical reference evidence. Retirement removes them from the
   working tree, not from the record.
3. **A later cutover implements locally**, from ADR-0031's protocol and that
   product's own CURRENT inventory, rather than resurrecting code whose shape was
   determined by a schema and consumers that no longer exist.
4. **The extraction bar is unchanged: two CURRENT consumers.** That Vendor once
   had an implementation is not one of them.

The exemption earns an extra sentence. It was REMOVED rather than lowered,
because an exemption whose premise has evaporated is worse than none: it keeps
widening a gate for facts nobody has examined (ADR-0018). The composed audit now
consumes the kernel gate raw, which is strictly stronger than subtracting two
declared waivers, and a guard fails the build if a subtraction helper returns.
`test_stale_claims.py` gained matching coverage — it now fails if a document
still describes a retired exemption as live, which is the gap that let the
sealed-cutover prose survive its own supersession in #51.

## Offers and licensing stay disabled

The `production-bootstrap` profile continues to withhold both surfaces. Their
module ownership is unsettled, and enabling them now would begin creating fresh
legacy production data immediately after three domains were cleaned up — the
precise shape of the problem this sequence of changes exists to remove.

## Lifecycle

**Below adopted.** Vendor CP now has no local writer for release artifacts,
approvals or allocations. Adoption is earned by running in production with the
local writer proven absent, not by landing code, and nothing has run.
