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

Rather than infer it, the question was settled by measurement. PR #50 added a
read-only inventory that takes an explicitly named DSN, refuses to discover one
from configuration, opens a `READ ONLY` transaction and emits deterministic
evidence. Its CI proof included a seeded estate, so "reports empty" was a reading
it could have contradicted.

Michael ran the check himself against the designated sole target. The observation
was **`TARGET_ABSENT | db_service_absent | volume_absent`**: neither the Compose
`db` service nor its data volume exists. No Vendor CP database has been
provisioned, so there is no approval history anywhere.

An earlier attempt to run that inventory was refused because the authorization
reached the agent only as a relay, and inability to run a tool is not evidence
about the thing it measures. That refusal is part of this record: the greenfield
path is valid because of an observation, not because of a failure to observe.

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
