# ADR-0005: Approvals authority moves greenfield, because the estate was empty

- **Status:** Accepted
- **Date:** 2026-08-15
- **Owner:** Vendor control plane
- **Supersedes:** ADR-0004 (the sealed-cutover design)

## Context

ADR-0004 designed a careful sealed cutover: lock the legacy approval tables,
digest and seal them, compare them against `dotmac_approvals`' policy engine on
five shared safety properties, dispose of incomplete groups by rule, then move
the authority inside one transaction. The design was sound for the situation it
assumed — a running control plane with approval history worth preserving.

That assumption was never checked, and it was wrong.

Rather than infer it, the question was settled by looking.

Michael ran a direct, authorized Docker-boundary check against the designated
sole target. The observation was
**`TARGET_ABSENT | db_service_absent | volume_absent`**: neither the Compose `db`
service nor its data volume exists. No Vendor CP database has been provisioned,
so there is no approval history anywhere.

**The read-only inventory tool (PR #50) never ran.** It is worth being exact
about this, because the obvious summary inverts the lesson. The tool's
contribution was not the measurement — it was enforcing the EVIDENCE BOUNDARY.
Asked to run against production through a relayed authorization, the agent
refused, on the grounds that an agent relay is not the user's consent; and when
no mechanism existed to run the merged revision inside the private network
without publishing an image, it reported that and stopped rather than reporting
`TARGET_ABSENT`. Inability to run a tool is not an observation about the thing
the tool measures, and letting the first quietly become the second would have
manufactured the exact false evidence the tool existed to prevent — on the most
consequential decision in the programme.

So: the greenfield path is valid because someone looked, not because looking
proved difficult.

## Decision

Move the authority **greenfield**, in one forward migration
(`v013_approvals_authority_switch`), and retire the local writer.

1. **Empty is the premise, and it is CHECKED.** The migration locks both legacy
   tables, counts them, and raises if either holds a row — in which case nothing
   happens at all: no grant moves, no column is added, nothing is dropped. A
   populated estate needs ADR-0004's sealed cutover, and the migration says so in
   its own error message.
2. **`ACCESS EXCLUSIVE`, taken once and up front.** The same migration DROPs
   those tables, and `DROP TABLE` takes `ACCESS EXCLUSIVE`. Taking `SHARE` first
   and escalating later invites deadlock — two transactions can each hold `SHARE`
   and each wait forever for the other to release it. Acquiring the strongest
   lock needed, before anything is read, also makes the emptiness check
   meaningful: under it, "empty when checked" and "empty when dropped" are the
   same statement.
3. **`platform_api` regains DML on `mod_approvals`**, reversing v012's shadow
   revoke as a new FORWARD revision. v012's `downgrade()` stays fail-closed and
   is not the mechanism; an authority moves forward deliberately or not at all.
   The result is verified as an EFFECTIVE outcome in both directions — the online
   role holds what it needs and nothing beyond it, and the tenant role still
   holds nothing.
4. **A typed adapter is the only seam.** `vendor_cp.approvals.adapter` maps
   Vendor's vocabulary onto the module's, with no `Any` at the boundary. It uses
   the eligibility mapping and digest translation ADR-0004 § 2 and § 4a declared
   before any code existed to use them.
5. **Contracts own their request.** `submit()` opens an approval request — the
   subject's owner is what knows the content digest to bind it to — and stores
   `approval_request_id`; `approve()` evaluates that request; `reject()` clears
   it, because an approval is for exact content and reusing a request would carry
   decisions across a change they were never given for.
6. **The legacy writer, its models and its tables are removed**, and the ratchet
   on its call sites is held at zero.

## What is deliberately NOT built

Against an empty estate each of these is elaborate machinery producing no
information, and every one of them would have to be maintained and believed:

- **parity comparison** — there is nothing to compare;
- **backfill** — there is nothing to migrate;
- **synthesized requests** — there is no history to represent, and ADR-0004's
  Ruling 2 refused inventing request identity even when there WAS;
- **sealed legacy evidence** — ADR-0031 is the standard for a cutover with data.
  This is not one, and sealing an empty set would produce a digest of nothing
  that later reads as proof of something.

## Retired artifacts, and why deletion rather than retention

Two things are removed by this change beyond the legacy runtime writer
(`vendor_cp/approvals/service.py` and `models.py`, which point 6 above covers).
Neither is obvious from the diff, so both are recorded here.

**The sealed-cutover implementation.** `src/vendor_cp/approvals_cutover.py` — the
seal transaction's declarations, the canonical evidence encoder, the five shared
safety properties, the disposition rule, the privilege matrix — together with its
architecture test. The file survives in name only: it is now
`approvals_authority.py`, holding the parts that were about MAPPING rather than
migration (the eligibility mapping and the digest translation), which the adapter
uses unchanged.

**The read-only inventory.** `src/vendor_cp/approvals_inventory.py`,
`scripts/approvals_inventory.py` and their tests.

Four reasons, and they apply to both:

1. **The switch removes their schema AND their consumers.** Both query
   `public.approval_policies` and `public.approval_records`, which `v013` drops.
   Retained, they would not be a reference implementation; they would be the
   appearance of one — code that cannot run, against tables that do not exist,
   for a writer that no longer has callers. The next reader would have to
   discover that by trying it.
2. **`c3a0d1b` preserves them as immutable historical reference evidence.** Both
   artifacts, their tests and their review history remain readable at that
   revision. Retirement removes them from the working tree, not from the record —
   and a working tree is a claim about what runs, while a revision is a record of
   what was.
3. **A later cutover implements locally.** From ADR-0031's protocol and that
   product's own CURRENT inventory — not by resurrecting code whose shape was
   determined by a schema and a set of consumers that no longer exist. Code
   carried forward for reuse arrives with assumptions nobody re-examines, which
   is precisely how a sealed cutover would end up designed around Vendor's
   vanished tables.
4. **The extraction bar is unchanged: TWO CURRENT CONSUMERS.** That Vendor once
   had an implementation is not one of them, and "we already wrote it" is not a
   consumer. Nothing here promotes this work toward a shared module.

The inventory earns a separate note. Its contribution was never the measurement —
it never ran. It was enforcing the evidence boundary: refusing a relayed
authorization, and refusing to convert "no mechanism to run" into "the target is
absent". That lesson belongs in the record above, not in a retained tool.

## Consequences

- The at-most-once obligation ADR-0004 § 4 recorded is discharged by the adapter,
  which wraps every mutation in the kernel's `process_once_platform`: the module
  REFUSES a duplicate decision, Vendor's callers retry commands, and a retried
  command must replay rather than error.
- Approval history begins at the switch. There is no discontinuity to explain,
  because there is nothing before it.
- The inventory tool retires with its purpose. It read tables that no longer
  exist, and the deny-case D1 connection exemption written for it returns to
  empty.

## Lifecycle

**Below adopted.** Composed and authoritative in code is not adopted: the new
owner has not run in production, because nothing has. The lifecycle advances when
it does, on evidence, not on this ADR being accepted.
