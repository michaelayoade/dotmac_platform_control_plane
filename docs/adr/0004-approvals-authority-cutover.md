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
whose `PolicyRevision.allow_self_approval` is Vendor's flag.

**Eligibility maps too — coarsely, and it must be stated rather than defaulted.**
`ApprovalLevel.approver_kind` and `approver_id` are REQUIRED fields with no
defaults, and `__post_init__` refuses a blank approver, so "Vendor expresses no
eligibility, leave them at their defaults" is not merely imprecise: it does not
construct. It was also untrue. Vendor does express an eligibility rule, just a
coarse one — `vendor_cp.approvals.router` guards every approval with
`require_platform_admin` and records `admin.id` as the approver, so the rule is
**"any authenticated platform admin may approve"**.

That maps explicitly, and the mapping is ASSEMBLY-OWNED because the identity it
needs does not exist in either system:

| Module field | Value | Why |
|---|---|---|
| `approver_kind` | `ApproverKind.ROLE` | the rule names a class of actor, not a person |
| `approver_id` | `PLATFORM_ADMIN_ROLE_ID` | a stable UUID this assembly declares, meaning exactly "authenticated platform admin" |
| `Actor.role_ids` | `{PLATFORM_ADMIN_ROLE_ID}` | every legacy approver held it by construction: appearing in `approval_records` at all means they passed `require_platform_admin` at the time |
| `Actor.mfa_verified` | `False` | Vendor never recorded it; `requires_mfa` stays `False`, so nothing depends on the value |

`PLATFORM_ADMIN_ROLE_ID` is declared once in
`src/vendor_cp/approvals_cutover.py`. It is not recovered from anywhere, and it
is not pretending to be: it is a name this assembly assigns to a rule Vendor
enforced through an authentication guard rather than through data. It is stable
because a value that changed between shadow runs would silently change what the
comparison compared.

Vendor still expresses no SoD rule, no MFA requirement and no multi-level
sequencing, and no per-level NAMED approver. Those stay uncompared — see § 4.

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

### 3. Sealing the legacy evidence set

An earlier draft of this contract proposed a watermark whose boundary was
`max(approval_records.id)`, on the reasoning that an id is unambiguous where a
clock is not. **That was wrong, and it was wrong at the premise.**
`ApprovalRecord.id` comes from the kernel's `uuid_pk()`, which is
`default=uuid4` — random. A high-water mark over random values orders nothing;
"greatest id" has no chronological meaning at all. The argument against clocks
was sound and the substitute was not.

The replacement does not answer the boundary question. It **removes** it.

**Seal, then count and digest:**

1. **Quiesce.** Stop the legacy write path and let in-flight work finish.
2. **Revoke.** `INSERT`, `UPDATE` and `DELETE` on `approval_policies` and
   `approval_records` are revoked from every ONLINE role (`platform_api`); only
   the offline migrator retains DML. After this statement commits, no request
   path in the running system can add a legacy row.
3. **Record the seal.** A one-row, insert-only table
   (`approval_cutover_seal`) records what was sealed:

| column | meaning |
|---|---|
| `sealed_at` | UTC instant of the sealing transaction |
| `alembic_revision` | composed head at sealing |
| `legacy_policy_count` | `count(*)` of `approval_policies` |
| `legacy_record_count` | `count(*)` of `approval_records` |
| `evidence_digest` | canonical digest of the sealed record set (below) |
| `digest_algorithm` | `sha256` — named, so a future change is a visible one |
| `operator_ref` | the platform admin who executed the sealing |

**Why this is strictly stronger than a boundary.** A watermark asserts *when* the
old world ended and then requires every row to be compared against that instant.
A seal makes every legacy row **pre-cutover by construction**: the online roles
cannot write the tables at all, so there is no later row to classify and no race
to reason about. The count and digest are not the boundary — they are evidence
that the set which was compared is the set that was sealed.

**The canonical digest.** Over `approval_records` only (policies are covered by
their own count and are immutable by constraint): each row rendered as the
newline-joined, `\x1f`-separated tuple

`policy_code, policy_version, subject_type, subject_id, content_hash, approver_id`

with `approver_id` lowercased canonical UUID text, rows sorted bytewise by that
rendering, then SHA-256 over the UTF-8 encoding. The row's own `id` is
deliberately excluded: it is random, carries no meaning, and including it would
make the digest depend on a value nothing else in this contract trusts.

**"The watermark" now means the sealing transaction.** It is still the moment
that divides legacy evidence from module requests — it is simply recorded by
sealing the old set rather than by naming a cursor into it. Everywhere below,
"pre-watermark" means "in the sealed set", which after step 2 is every legacy
row that will ever exist.

The seal row is **never updated and never deleted** — `UPDATE`/`DELETE` revoked
from every online role — so the sealed set cannot be restated afterwards to make
a parity report agree.

**If a scalar cursor is ever genuinely required**, an enforced monotonic `BIGINT`
must be added to the legacy table first, backfilled, and made `NOT NULL` with a
sequence default. Do **not** reintroduce a cursor over UUID primary keys. This
paragraph exists because the mistake above was made once with confident
reasoning, and the reasoning is what has to be blocked, not just the code.

### 4. Shadow comparison — five shared safety properties

The module's policy engine (`dotmac_approvals.policy`) imports no persistence.
It is a function of values, so it can evaluate legacy evidence **without the
module being composed** and without a single row being written anywhere.

Shadow comparison converts each legacy group into module value objects
(`PolicyRevision`, `RecordedDecision`, `Actor`, using the eligibility mapping in
§ 2) and compares the two engines' answers on exactly these five properties —
the ones both systems decide the same way:

| # | Code | Property | Legacy mechanism | Module mechanism |
|---|---|---|---|---|
| 1 | `immutable_policy_versions` | A published policy version is never rewritten | `uq_approval_policies_code_ver`, no UPDATE path | `PolicyRevision` frozen; `PolicyVersionExists` |
| 2 | `content_digest_binding` | An approval binds to the exact content it approved | `content_hash` inside the record's unique key | `validate_digest` / `ContentChanged` |
| 3 | `fail_closed_missing_policy` | A missing policy or version refuses, never permits | `evaluate` returns `policy_not_found`, satisfied `False` | `PolicyNotFound` |
| 4 | `distinct_actor_quorum` | Quorum counts PEOPLE, so one actor cannot satisfy it alone | `count(distinct approver_id)` | `distinct_approvers` / `level_satisfied` |
| 5 | `self_approval_excluded` | The requester's own approval does not count unless permitted | submitter filtered out of the distinct count | `check_self_approval`, refusing by default |

The `Code` column is the identity: `src/vendor_cp/approvals_cutover.py` declares
the same five codes, and a test fails if this table and that declaration drift
apart. A contract whose prose and whose enforced constants disagree is worse than
either alone.

#### Why idempotency is NOT on this list

An earlier draft listed `command_idempotency` as a sixth shared property. It is
not one, and comparing it would have reported agreement that does not exist.

- **Vendor REPLAYS.** `record_approval` runs under the kernel's
  `process_once_platform`, and its handler returns the existing row's id when the
  approval is already there. A retried command succeeds and yields the same
  answer.
- **The module REFUSES.** `policy.check_not_duplicate` raises `DuplicateDecision`
  when the actor has already decided that level.

Both prevent double-counting, which is why they look alike; but "succeeds
identically" and "raises" are different observable behaviours, and a caller
retrying an HTTP request gets `200` from one and an error from the other. They
are not the same property and are not compared as one.

#### The at-most-once wrapping is a NEW-ADAPTER OBLIGATION

At-most-once execution is kernel-owned (`dotmac_kernel.idempotency`, ADR-0014),
not module-owned. The cutover adapter that replaces `vendor_cp.approvals.service`
therefore **must** wrap the module's decision call in the same platform
at-most-once primitive Vendor uses today, so that:

- a retried command still succeeds and returns the original outcome, rather than
  surfacing the module's `DuplicateDecision` to a caller who did nothing wrong;
- the module's own duplicate refusal remains as the inner, durable guard.

This obligation is part of the cutover's definition of done, and it is recorded
here because it is the one behavioural difference the migration must actively
bridge rather than merely observe.

#### Scope of the uncompared

Vendor never expressed per-level NAMED approvers, separation of duties, an MFA
requirement, multi-level sequencing or delegation, so those are compared against
**nothing**. Coarse eligibility — "any authenticated platform admin" — IS
expressed and IS mapped (§ 2); only the genuinely richer fine-grained eligibility
is uncompared. Inventing a legacy expectation to compare against would be the
same fabrication Ruling 2 refuses, one layer up.

A shadow comparison **reads legacy rows and writes nothing**, in either system.

### 4a. Digest translation, and the preflight that refuses bad rows

The two systems spell a content digest differently:

- **Vendor** stores `hashlib.sha256(...).hexdigest()` — a bare 64-character
  lowercase hex string, in `content_hash`.
- **The module** requires `sha256:` + 64 lowercase hex (`DIGEST_PREFIX`,
  `DIGEST_LENGTH`), enforced by `validate_digest`, which raises `ContentChanged`
  on anything else.

**The translation is deterministic and total in one direction:**

```
module_digest = "sha256:" + vendor_content_hash
```

valid **iff** `vendor_content_hash` is exactly 64 characters drawn from
`0123456789abcdef`. Nothing is normalised on the way through: an uppercase or
short value is not lowercased or padded into validity, because a digest that
needed repairing is a digest whose provenance is unknown.

**A fail-closed inventory runs before cutover** over every legacy row that
carries a `content_hash`. It classifies each as translatable or not, and **any
untranslatable digest stops the cutover**. It is not skipped, not excluded from
the sealed set, and not translated on a best-effort basis — an approval whose
bound content cannot be expressed in the new system is precisely the case where
proceeding would silently drop the binding that makes the approval mean
anything.

The preflight reports, per failing row: the source record id, the group key, and
the reason (`wrong_length`, `non_hex`, `uppercase`, `already_prefixed`,
`empty`). Resolution is an operator decision recorded against that row's group —
not a code change that widens the accepted format.

### 5. Disposition of legacy groups

Every pre-watermark group is classified by re-evaluating properties 4 and 5
(distinct-actor quorum, self-approval exclusion) over its own rows. There are exactly two outcomes and they are handled differently.

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
6. **Digest translatability** — every legacy `content_hash` translates under
   § 4a. Target: 100%. An untranslatable digest blocks the cutover; there is no
   skip path.
7. **Seal integrity** — the recorded `legacy_record_count` and `evidence_digest`
   recomputed at cutover match the sealed values, proving the compared set is
   the sealed set.

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

Rollback is available **until the seal row is committed**. Up to that point
the module has accepted no request, holds no row, and the legacy writer is still
authoritative: rollback is simply resuming legacy writes, and shadow comparison
leaves nothing to undo because it writes nothing.

**After the watermark, rollback is forward-only.** Genuine module requests exist
by then, with real requesters and real idempotency keys, and reverting the
authority would either strand them or require the legacy system to absorb facts
it cannot represent. A defect found after the watermark is fixed in the module
era — by cancelling and re-raising affected requests — not by moving the
boundary backwards. The seal table's revoked `UPDATE`/`DELETE` makes that
structural rather than a matter of discipline.

### 8. Retirement gate

`vendor_cp.approvals` — models, service, router and schemas — is retired only
when **all** of the following hold:

1. the seal row exists and the module surface has been authoritative for a
   full operating period agreed with the owner;
2. every incomplete legacy group is disposed: drained before the watermark, or
   restarted as a module request afterwards;
3. `vendor_cp.contracts.service` reads the module's decision, and the legacy
   `evaluate` has no remaining caller (the ratchet's declared set is empty);
3a. the new adapter wraps the module call in the kernel's platform at-most-once
   primitive (§ 4), so a retried command still succeeds instead of surfacing
   `DuplicateDecision`;
4. parity measurements 1-7 hold at their targets on the final pre-watermark run;
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
- The cutover is one coherent change (quiesce → revoke → seal → compare → dispose →
  switch), not a gradual dual-write.

## What this ADR does NOT authorise

Composing `dotmac-approvals`, declaring a `ModulePlaneSelection` for it, or
pinning it. Shadow composition begins only after this contract is accepted **and**
the module ships the public `versions_dir()` locator this repository needs
(recorded during PR #45), in a published release that is then exactly pinned.
