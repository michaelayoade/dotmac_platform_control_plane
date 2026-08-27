# ADR-0012: The commercial backfill is contracted before it is composed

- **Status:** Accepted
- **Date:** 2026-08-25
- **Owner:** Vendor control plane
- **Follows:** ADR-0005/0006 (the greenfield switches), ADR-0008 (commercial
  agreements), ADR-0011 (the most recent worked authority cutover)
- **Decides nothing about:** who owns subscriptions or billing

## Context

Every authority cutover this repository has taken so far was GREENFIELD. ADR-0005
and ADR-0006 both rest on the same measured fact — the legacy estate was empty,
checked under lock in the same transaction that dropped it — and both say
explicitly that parity machinery, backfill, synthesized records and sealed
evidence were deliberately NOT built, because building them against an empty set
is elaborate work producing no information.

A commercial backfill is the other case. Vendor's commercial estate is offer
versions and agreement lines, and moving them to a Subscriptions/Billing target
is a cutover WITH data — the shape ADR-0006 § "What is deliberately NOT built"
names as somebody else's problem, and `AGENTS.md` rule 12 points at ADR-0031's
protocol for.

`docs/cutover-readiness.md` is an aggregate readiness statement: what the
remaining slices need. It is the wrong instrument for this. A backfill needs to
know WHICH ROWS, transformed HOW, and what would have to be true before anything
moves.

## Decision

Contract the backfill now; move nothing.

1. **State the cohort exactly, and give every row one of three fates.** `MAPPED`,
   `EXCLUDED` with a stated reason, or `BLOCKED` with the dimension that blocked
   it. `classify` is total, `RowVerdict` refuses the overlap at construction, and
   the planner asserts the buckets sum to the input. **No row is silently
   dropped**, which is the property a backfill dossier is worth nothing without.

2. **Keep coverage separate from bucketing.** A source that cannot be enumerated
   is an unknown number of rows, not zero, and `SourceCoverage` says so. This
   assembly is in that state today: `vendor_cp.contracts.adapter` publishes `get`
   and no listing surface, so nothing here can walk the agreement estate. A plan
   over half an estate must never read as a plan over all of it. Closing that
   gap depends on an upstream `dotmac-commercial-agreements` release with a typed
   paginated reader, followed by an exact Vendor pin and adapter mapping. Vendor
   must not substitute a local reader or query the module's tables directly.

3. **Name the five transformations, and make each return a CATEGORY.** Cadence,
   proration, currency, frozen content, product identity. None returns a
   converted value. A dry-run that produced target values would be a backfill
   that had already run in memory, and conversion belongs to whatever executes
   under the authority that owns the target.

   Three of the five refuse rather than repair, and that is the substance of the
   decision: an over-precise amount is `NOT_QUANTIZED` (quantizing invents money
   across a whole cohort, in a run whose output is counts); `ACME` against a
   declared `acme` is `CODE_UNDECLARED` (folding invents an identity nobody
   published); a 24-month term is `INDETERMINATE`, not `ANNUAL` (folding
   backfills a contract that bills twice).

   Commercial Agreements' expiry transition refuses while
   `as_of <= expiry_date`, so `expiry_date` is the inclusive last covered day.
   Vendor normalizes it exactly once at the existing typed adapter mapping:
   `ContractView.term_end_exclusive` is the following, first uncovered day.
   Backfill input accepts only that explicitly named end-exclusive field and has
   no caller-selectable convention.

4. **Reports carry counts, categories and blocker reasons — structurally.** A
   report holds a cardinality or a member of a closed enum; report enum members
   carry `auto()` so a member value is never text; `Report` has no free-text
   field; `Count(` is ratcheted to one module; and `render()` checks each line
   against a grammar and the declared vocabulary. Four sensitivity tests plant an
   identifier, an amount, a label and a timestamp separately.

   Recorded as WEAKER than it sounds: a caller could pass an amount where a row
   count belongs and nothing can tell an integer from an integer. The alphabet is
   closed; the meaning of each integer is not guaranteed.

5. **Keep row-count parity and target semantic parity apart, with no combined
   verdict.** Equal counts say nothing about whether rows mean the same thing,
   and every-row-present-every-cadence-wrong reads as success under a count check
   alone. An unobserved dimension is `NOT_COMPARABLE`, never a quiet `MATCHED`,
   and the overall semantic verdict is the weakest of its dimensions.

6. **The target sends no rows into this repository.** A `TargetObservation`
   carries cardinalities by category, read from the target's own versioned API
   and reduced there. Hard rule 28: applications are independent and compose only
   through versioned APIs and webhooks. This dossier describes a transformation;
   it introduces no shared persistence and no second writer.

7. **The rehearsal reconciler repairs shadow rows without any Vendor runtime
   DML.** It emits SQL and never connects — deny case D1's connection allowlist
   is empty and stays empty — and it emits no `GRANT` at all, revoking from the
   online role on the rehearsal schema instead. The shadow schema is created by
   those statements in a disposable database, is declared by no model and created
   by no revision, and therefore never reaches production. The replay shape has
   no timestamp column or surrogate key; the PostgreSQL migration canary is the
   executable verification for that shape, not a result recorded in this ADR.

8. **Define two gates**, with their conditions typed by evidence kind.
   `incumbent_commercial_writer_retirement` covers retiring
   `vendor_cp.offers.service.publish_offer_version`, this assembly's real current
   price authority. `final_dml_grant` covers the grant that would let a runtime
   role write the backfilled tables, kept separate from the data movement.

   A condition whose evidence is a release run, a peeled tag, a deploy run or an
   adoption citation CANNOT be recorded as discharged — the type refuses it. That
   is `AGENTS.md` rule 17 made structural, and the known-bad case is this
   repository's own `AWAITING_RELEASE_TAG`, which read `pyproject.toml`, was
   described as gating on a release tag, and stayed green when the tag was
   published.

## What this decision deliberately does NOT take

**It does not choose the billing or subscription authority.** That belongs to an
accepted, checked-in contract elsewhere, and it appears here only as the gate
condition `TARGET_AUTHORITY_ACCEPTED` with `adoption_evidence` as its evidence
kind, because this repository cannot observe it.

**It does not run a backfill**, in production or anywhere else. Nothing here
composes a target module or moves a writer. The incumbent writer keeps its
authority.

**It does not build sealed legacy evidence or synthesized records.** ADR-0031
governs a cutover with data and this is the contracting step before one, not the
execution of one.

## Why a planner rather than a migration

An earlier shape for this work would have been a forward revision that staged the
cohort into a Vendor-owned table. Three things are wrong with it, and they are
the reasons for the shape above.

A staging table is a **second copy of commercial state** living in Vendor's
database, which is what hard rule 28 exists to prevent. It is also a **write**,
so it needs privileges, an owner and a retirement plan of its own — a cutover
that acquires an extra authority on the way to moving one. And it makes the dry
run **not dry**: a plan that has already reserved identifiers is a partial
backfill wearing a report's clothes, and the first failure leaves state nobody
planned for. Nothing is reserved before the effect (ADR-0014's shape, applied to
a planner).

## Lifecycle

**Contracted, not composed, and not adopted.** Gate status is derived from the
evidence recorded in the dossier or its named external oracle; this ADR records
the durable conditions and does not snapshot their transient state.

See `docs/commercial-backfill-dossier.md` for the cohort, the field-by-field
source projection, every transformation edge case, and both gates' full condition
tables.

## Amendment — 2026-08-26: the owner reader closes the capability gap

Decision 2 records the a1 boundary at the time this ADR was accepted; it remains
history and is not rewritten. Commercial Agreements a2 adds the bounded,
UUID-keyset `list_agreements` reader to the owner’s top-level public contract.
Vendor exact-pins that version and maps each page through its existing typed
adapter. It still owns no local estate reader and issues no raw query against
the module schema.

This closes only the repository-local CAPABILITY gap. Publication and
pinnability remain external claims: `docs/cutover-readiness.md` must record the
exact a2 `release_run` and 40-character peeled-tag commit before the adoption can
merge. Per-run coverage remains separate too. A caller may report
`AGREEMENT_LINE_ENUMERATED` only after it reaches the final owner page; merely
having the method does not turn an unknown remainder into zero.

No authority moves under this amendment. The incumbent commercial writer and
both gate definitions remain unchanged.
