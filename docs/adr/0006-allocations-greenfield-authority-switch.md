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
(`v014_allocations_authority`), and retire the local writer.

1. **Empty is the premise, and it is CHECKED.** The migration locks both legacy
   tables, counts them, and raises if either holds a row — in which case nothing
   happens: no grant, no drop. The error names `dotmac_starter_mt` ADR-0031's protocol as what a
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

   **The caller cannot supply one.** An earlier draft of this switch left
   `product` on `IssueLicenceCommand` and `IssueLicenceRequest` while this
   document already described issuance as reading `allocation_product()` — and
   issuance in fact used the caller's value to select the licence LINEAGE, with
   nothing comparing it to the allocation. A disagreeing caller would have filed
   a signed document under the wrong lineage silently. Both fields are now
   removed; the HTTP schema REJECTS a supplied `product` rather than ignoring it,
   because silently dropping it would leave a caller believing it had chosen.
   The single allocation-owned value reaches lineage, signed payload, audit
   record and outbox event, and
   `test_the_adapter_exposes_no_unused_public_surface` fails the build if an
   adapter function the documentation names again has no caller.
6. **The legacy models, tables and call sites are gone**, and the call-site
   ratchet is held at zero.

## What is deliberately NOT built

Against an empty estate, each is machinery producing no information that would
still have to be maintained and believed: **parity comparison** (nothing to
compare), **backfill** (nothing to migrate), **synthetic records** (no history to
represent), **sealed legacy evidence** (`dotmac_starter_mt` ADR-0031 is the standard for a cutover
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
3. **A later cutover implements locally**, from `dotmac_starter_mt` ADR-0031's protocol and that
   product's own CURRENT inventory, rather than resurrecting code whose shape was
   determined by a schema and consumers that no longer exist.
4. **The extraction bar is unchanged: two CURRENT consumers.** That Vendor once
   had an implementation is not one of them.

The exemption earns an extra sentence. It was REMOVED rather than lowered,
because an exemption whose premise has evaporated is worse than none: it keeps
widening a gate for facts nobody has examined (`dotmac_starter_mt` ADR-0018). The composed audit now
consumes the kernel gate raw, which is strictly stronger than subtracting two
declared waivers, and a guard fails the build if a subtraction helper returns.
`test_stale_claims.py` gained matching coverage — it now fails if a document
still describes a retired exemption as live, which is the gap that let the
sealed-cutover prose survive its own supersession in #51.

## Offers and licensing stay disabled

The `production-bootstrap` profile continues to withhold both surfaces. Their
module ownership is unsettled, and enabling them now would begin creating fresh
legacy production data immediately after the authority cutovers — the
precise shape of the problem this sequence of changes exists to remove.

## Lifecycle

**Adopted, on evidence, since 2026-08-17.** This section said adoption is
earned by running in production with the local writer proven absent, "and
nothing has run". It ran two days later, and the sentence outlived the fact —
which is the failure mode `tests/architecture/test_stale_claims.py` exists for
and did not cover, because a lifecycle label is prose about the world rather
than about this repository.

Production deploy `32022599873` runs main `f8f8c3fd636e663e4a17275c19e82fc1667aa52a`
at immutable image `sha256:56ec553139c449dc7da46a8873b3c03e95a61e43c970cd1675e28a202b2991cc`
with `mod_ealloc` live and `public.allocations` / `public.allocation_entries`
absent. **The oracle for that claim**, since adoption is not observable from this
repository (`AGENTS.md` rule 17): an `adoption_evidence` citation at
`dotmac_starter_mt@20d24703e70e4d361de2f406165df4b36cbee507`, path
`packages/dotmac-entitlement-allocation/EXTRACTION.toml`, where `status =
"adopted"`, `contract_consumers` names this assembly, and `adoption_evidence`
carries the same commit, deploy run, image digest, `v014_allocations_authority`
head and live `mod_ealloc` schema. It is held at `adopted`, not advanced to
`reuse-proven`, until a second real vendor or OEM control plane completes its
own cutover — also the dossier's call, not this one's.

## Adoption plan — discharged 2026-08-21

**Repin to `0.1.0a6` — done.** This assembly pinned `0.1.0a4`, which declared
neither of the two kernel effects `stage_allocation` writes at request time: the
idempotency ledger it delegates at-most-once execution to, and the platform
audit log it writes inside that same operation. a6 declares both and adds the
DDL-free `ea_0002` and `ea_0003` verification revisions.

`0.1.0a5` carried only the first half of that repair and was deliberately never
published; it must not be pinned, and
`test_the_unpublished_release_is_never_pinned` refuses it rather than leaving
that to memory.

**No binding was added, and that is the point of the exercise.** Both effects
were already bound — to kernel `0018_idempotency_one_owner` and
`0026_platform_audit_log` — because Commercial Agreements and Licensing declare
them. So unlike the approvals repin, this one gave an existing binding a
consumer that had been depending on it silently since a1. The bindings test now
derives the required set from every composed manifest, which is what turns that
from a thing someone noticed into a thing the build checks.

**Not owed:** delivery or acknowledgement state here. Licence issuance owns
that lifecycle, and ADR-0010 moves its transport half to Integrator.

See `docs/cutover-readiness.md` for how this sits beside the ADR-0007 slices.
