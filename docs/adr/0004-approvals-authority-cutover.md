# ADR-0004: Approvals authority cutover — one writer, and no invented history

- **Status:** Accepted (contract only — authorises no composition)
- **Date:** 2026-08-15
- **Owner:** Vendor control plane
- **Supersedes nothing. Blocks:** shadow composition of `dotmac-approvals`

## Context

`vendor_cp.approvals` is the Vendor Control Plane's approval authority today. It
owns `public.approval_policies` and `public.approval_records`, and every approval
decision the control plane makes goes through it. It has exactly one external
consumer: `vendor_cp.contracts.service`, which asks it whether a contract's
frozen content has met its quorum before performing the contract's own
transition.

`dotmac-approvals` is the published module that will own that decision. It is not
composed here, not pinned, and has no plane selection (ADR-0028 separates
binding from selection; the assembly's selection tuple is empty). Composing it
first and designing the migration afterwards is how two writers end up live at
once, so this contract comes first.

Two questions blocked it, and both are now decided.

### Ruling 1 — legacy votes are NOT backfilled into module lifecycle tables

Not by direct row writes, and not by a new lifecycle-import API on the module.
Direct writes violate module ownership: the module's tables are its own, and an
assembly writing them is a second writer by definition. An import API is worse
in a subtler way — it would manufacture request facts that never existed, and
those fabricated rows would afterwards be indistinguishable from real ones.

### Ruling 2 — request identity is NOT synthesized

The legacy schema records approvals, not requests. There is no request row, no
requester column, and no persisted terminal state. Any "recovered" request ID or
requester would be invented at migration time and would then look exactly like a
recorded fact.

## Decision

### 1. The two authorities

| | Old | New |
|---|---|---|
| Owner | `vendor_cp.approvals` | `dotmac-approvals` |
| Tables | `public.approval_policies`, `public.approval_records` | `mod_approvals.platform_*` |
| Decision surface | `vendor_cp.approvals.service` | the module's platform surface |
| Consumers | `vendor_cp.contracts.service` (only) | the same, after cutover |

There is exactly **one** authoritative writer at every instant. Shadow is a
bounded migration phase, not parallel operation.

### 2. Identity mapping, and the mapping that deliberately does not exist

**Policy identity maps.** `(policy_code, version)` is the same identity in both
systems, and both treat a published version as immutable. Vendor's `quorum` and
`allow_self_approval` map onto the module's `PolicyRevision`: a Vendor policy is
a single-level revision whose `ApprovalLevel.quorum` is Vendor's `quorum`, and
whose `PolicyRevision.allow_self_approval` is Vendor's flag. Vendor has no
per-level approver identity, no SoD rule and no MFA requirement, so those fields
take their module defaults and MUST NOT be inferred from anything.

**Decision identity maps.** One `ApprovalRecord` is one `RecordedDecision`:
`approver_id` → `actor_id`, action is always `APPROVE` (the legacy schema can
express nothing else), and `level` is 1 because Vendor policies are single-level.

**Request identity does not map, and no mapping will be invented.** A
pre-watermark `ApprovalRecord` has:

- a **source record identity** — its own `ApprovalRecord.id`, which stays;
- an **implicit group key** — the composite
  `(policy_code, policy_version, subject_type, subject_id, content_hash)`, which
  is what the legacy quorum was ever counted over;

and it does **not** have:

- a **request ID** — none was persisted, and one assigned now would be a
  migration artefact wearing the costume of a recorded fact;
- a **recoverable requester** — `submitter_id` lives on the *subject* (the
  contract), not on the approval group; where the subject is gone or the column
  is null the requester is simply unknown;
- a **persisted terminal state** — the legacy design recomputes satisfaction from
  rows on each read, so no row records that a group was ever "approved".

Unknown facts stay unknown. **New module request identity begins at the
watermark**, with a real requester and a real idempotency key. Nothing before the
watermark acquires either.

### 3. The watermark

The watermark is the instant that divides legacy evidence from module requests.

**Recorded as a one-row, insert-only vendor table** created by a vendor migration
(`v0NN_approval_cutover_watermark`) in the cutover change:

| column | meaning |
|---|---|
| `id` | fixed sentinel; a `CHECK` constraint permits exactly one row |
| `recorded_at` | UTC instant of the cutover transaction |
| `alembic_revision` | the composed head at cutover |
| `last_legacy_record_id` | greatest `approval_records.id` in the cutover transaction |
| `last_legacy_recorded_at` | that record's `created_at` |
| `operator_ref` | the platform admin who executed the cutover |

Rules:

- written **exactly once**, inside the cutover transaction, **after** the legacy
  writer is quiesced and **before** the module's surface accepts a request;
- **never updated and never deleted** — `UPDATE`/`DELETE` are revoked from every
  online role, so the boundary cannot be moved after the fact to make a parity
  report look better;
- the identity boundary is `last_legacy_record_id`, not wall-clock time. A clock
  is not a boundary: a retried transaction can commit a legacy row whose
  timestamp precedes a watermark written moments earlier, and an id high-water
  mark is unambiguous under exactly that race.

### 4. Shadow comparison — the six shared safety properties

The module's policy engine (`dotmac_approvals.policy`) imports no persistence.
It is a function of values, so it can evaluate legacy evidence **without the
module being composed** and without a single row being written anywhere.

Shadow comparison converts each legacy group into module value objects
(`PolicyRevision`, `RecordedDecision`, `Actor`) and compares the two engines'
answers on exactly these six properties — the ones both systems genuinely share:

| # | Code | Property | Legacy mechanism | Module mechanism |
|---|---|---|---|---|
| 1 | `immutable_policy_versions` | A published policy version is never rewritten | `uq_approval_policies_code_ver`, no UPDATE path | `PolicyRevision` frozen; `PolicyVersionExists` |
| 2 | `content_digest_binding` | An approval binds to the exact content it approved | `content_hash` inside the record's unique key | `ContentChanged` on a stale digest |
| 3 | `fail_closed_missing_policy` | A missing policy or version refuses, never permits | `evaluate` returns `policy_not_found`, satisfied `False` | `PolicyNotFound` |
| 4 | `command_idempotency` | Replaying one command records one decision | `process_once_platform` + the record unique constraint | `check_not_duplicate` + the module's own constraint |
| 5 | `distinct_actor_quorum` | Quorum counts PEOPLE, so one actor cannot satisfy it alone | `count(distinct approver_id)` | `distinct_approvers` / `level_satisfied` |
| 6 | `self_approval_excluded` | The requester's own approval does not count unless permitted | submitter filtered out of the distinct count | `check_self_approval`, refusing by default |

The `Code` column is the identity: `src/vendor_cp/approvals_cutover.py` declares
the same six codes, and a test fails if this table and that declaration drift
apart. A contract whose prose and whose enforced constants disagree is worse than
either alone.

**Scope is a decision, not an omission.** The module's per-level approver
eligibility, SoD rules, MFA requirement and multi-level sequencing are compared
against **nothing**, because Vendor never expressed them. Comparing them would
mean inventing a legacy expectation to compare against — the same fabrication
Ruling 2 refuses, one layer up.

A shadow comparison **reads legacy rows and writes nothing**, in either system.

### 5. Disposition of legacy groups

Every pre-watermark group is classified by re-evaluating property 5 and 6 over
its own rows. There are exactly two outcomes and they are handled differently.

**Satisfied groups reconcile against the subject owner's completed transition.**
A satisfied group's real consequence is not the approval — it is the contract
that moved out of `PENDING_APPROVAL`. Reconciliation asserts that consequence
happened: for every satisfied group there is a subject whose transition is
complete and whose `content_hash` still matches the group's. A satisfied group
whose subject never transitioned, or whose subject's content has since changed,
is a **finding** to be resolved before cutover — not a row to repair.

**Incomplete groups are DRAINED or RESTARTED, and the choice is made by rule,
not case by case:**

- **DRAIN** — the subject is still live, still `PENDING_APPROVAL`, and its
  `content_hash` is unchanged. The legacy owner keeps the group and it is
  completed under the legacy authority **before** the watermark. Draining is
  preferred wherever it is possible, because the approvers already gave a real
  opinion about that exact content and restarting would discard it.
- **RESTART** — anything else. Specifically: the subject's content has changed
  since the approvals were recorded (the votes no longer bind to what would be
  approved); or the subject is terminal/cancelled (there is nothing to approve);
  or the group's policy version no longer exists; or the group cannot be drained
  before the watermark for operational reasons. A restarted group becomes a
  **genuine module request after cutover**, with a real requester and a real
  idempotency key, and its legacy rows stay exactly where they are as evidence.

The drain window is bounded: if a drainable group has not been completed by the
scheduled watermark, it becomes a RESTART. The rule never depends on judgement
about a particular customer or contract.

**No legacy row is modified, moved or deleted by any of this.** Pre-watermark
`ApprovalRecord` rows remain immutable, read-only legacy evidence, in place,
owned by Vendor.

### 6. Parity measurements, and the differences that are accepted

Before cutover the shadow comparison must report, over **all** pre-watermark
groups:

1. **Satisfaction agreement** — for every group, legacy `satisfied` equals the
   module engine's `Evaluation.state is APPROVED`. Target: 100%. Any disagreement
   blocks cutover; there is no tolerated percentage, because a disagreement here
   means one of the two engines is wrong about whether something was approved.
2. **Distinct-actor agreement** — the legacy distinct count equals
   `len(distinct_approvers(...))`. Target: 100%.
3. **Self-approval exclusion agreement** — for groups where the subject's
   submitter also approved, both engines reach the same answer. Target: 100%.
4. **Reconciliation coverage** — every satisfied group maps to a completed
   subject transition with a matching digest. Target: 100%, findings resolved.
5. **Disposition coverage** — every incomplete group is classified DRAIN or
   RESTART by the rule above, with none unclassified.

**Accepted differences** (present, understood, and not blockers):

- **No request-level parity exists to measure.** There are no legacy requests,
  so request counts, requester identity and request state are not compared. This
  is the direct consequence of Ruling 2.
- **Terminal-state parity is not measurable** pre-watermark: legacy satisfaction
  is derived on read, so "was this rejected?" has no legacy answer. Rejection is
  a module-era fact only.
- **Level structure differs by construction.** Legacy is single-level; the module
  is multi-level. Parity is measured at level 1 and the module's additional
  levels are unused for migrated policies.
- **Ordering and timing differ.** Legacy records carry `created_at` only; the
  module records a decision sequence. Ordering is not compared.

### 7. Rollback boundary

Rollback is available **until the watermark row is committed**. Up to that point
the module has accepted no request, holds no row, and the legacy writer is still
authoritative: rollback is simply resuming legacy writes, and shadow comparison
leaves nothing to undo because it writes nothing.

**After the watermark, rollback is forward-only.** Genuine module requests exist
by then, with real requesters and real idempotency keys, and reverting the
authority would either strand them or require the legacy system to absorb facts
it cannot represent. A defect found after the watermark is fixed in the module
era — by cancelling and re-raising affected requests — not by moving the
boundary backwards. The watermark table's revoked `UPDATE`/`DELETE` makes that
structural rather than a matter of discipline.

### 8. Retirement gate

`vendor_cp.approvals` — models, service, router and schemas — is retired only
when **all** of the following hold:

1. the watermark row exists and the module surface has been authoritative for a
   full operating period agreed with the owner;
2. every incomplete legacy group is disposed: drained before the watermark, or
   restarted as a module request afterwards;
3. `vendor_cp.contracts.service` reads the module's decision, and the legacy
   `evaluate` has no remaining caller (the ratchet's declared set is empty);
4. parity measurements 1-5 hold at their targets on the final pre-watermark run;
5. the read-only legacy evidence has an agreed retention disposition — retained
   in place, or exported under the future contract in § 10.

Retirement drops the legacy code and, separately, decides the fate of the legacy
tables. **The tables are not dropped in the same change that drops the code**:
the evidence outlives the implementation that produced it.

### 9. The ratchet: no new local approval call sites

`src/vendor_cp/approvals_cutover.py` declares the exact set of modules outside
`vendor_cp/approvals/` that use the legacy decision surface. Today that set has
exactly one member: `vendor_cp/contracts/service.py`.

It is **two-directional**. A new caller fails the build — new work must not
deepen a dependency scheduled for retirement, and every added caller is another
migration to perform later. A removed caller fails too, because that is cutover
progress and the declaration must be lowered in the same change; the set reaching
empty is retirement gate 3.

Enforced with the shared import scanner
(`tests/architecture/import_scanner.py`), so `import x`, `import x as y`,
`from x import y`, `from x.sub import y`, `from . import y` and relative parent
walks are all seen. A single-form guard here would be worthless: the legacy
surface is a plain module, reachable by every one of those spellings.

### 10. Future work — `RecoveredApprovalEvidence` (named, not built)

If unified historical presentation is ever needed — one screen showing pre- and
post-watermark approvals together — it is a **separate contract** with explicit
provenance on every row, distinguishing recovered legacy evidence from recorded
module facts. It is **not** fabricated `ApprovalRequest` rows in the module's
tables. This ADR names it so the need has somewhere to go; it does not design it
and does not authorise it.

## Consequences

- The legacy tables gain a second, permanent role: evidence. That is why they are
  read-only rather than migrated.
- Some approval history will be visibly discontinuous at the watermark. That is
  the honest rendering of a system that did not record requests.
- The cutover is one coherent change (quiesce → compare → dispose → watermark →
  switch), not a gradual dual-write.

## What this ADR does NOT authorise

Composing `dotmac-approvals`, declaring a `ModulePlaneSelection` for it, or
pinning it. Shadow composition begins only after this contract is accepted **and**
the module ships the public `versions_dir()` locator this repository needs
(recorded during PR #45), in a published release that is then exactly pinned.
