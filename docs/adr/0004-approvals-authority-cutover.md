# ADR-0004: Approvals authority cutover — one writer, and no invented history

- **Status:** Accepted. Shadow composition discharged § 9a; the authority
  has NOT moved — see "What this ADR does NOT authorise"
- **Date:** 2026-08-15
- **Owner:** Vendor control plane
- **Supersedes nothing. Discharged by:** the shadow composition (vendor `v012`)

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

An earlier draft proposed a watermark whose boundary was
`max(approval_records.id)`, on the reasoning that an id is unambiguous where a
clock is not. **That was wrong at the premise.** `ApprovalRecord.id` comes from
the kernel's `uuid_pk()`, which is `default=uuid4` — random. A high-water mark
over random values orders nothing.

The replacement does not answer the boundary question. It **removes** it: the old
set is sealed so that no later legacy row can exist, and the seal is proved
rather than asserted.

#### 3.1 One transaction, and everything inside it

Sealing, proving and switching are **one transaction**. A sequence that sealed
first and compared afterwards would forbid rollback at exactly the moment a
parity failure could still be discovered — leaving a failure with no legal exit.
Here every check runs while rollback is still free.

```sql
BEGIN;

-- (1) LOCK FIRST. Operational quiescence is a plan, not a guarantee.
LOCK TABLE public.approval_policies, public.approval_records IN SHARE MODE;

-- (2) preflight: digest translatability over the LOCKED set   (§ 4a)
-- (3) parity:    the five-property comparison, reconciliation,
--                disposition coverage                          (§ 4, § 6)
--     Any failure -> ROLLBACK. Nothing has changed; the locks release.

-- (4) revoke every WRITE and DDL privilege from the online role.
--     SELECT is deliberately NOT revoked: the parity comparison reads these
--     tables, and the sealed evidence stays readable afterwards.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON
  public.approval_policies, public.approval_records FROM platform_api;

-- (5) verify EFFECTIVE privileges are gone                     (§ 3.4)
-- (6) compute the complete content digests over the locked set (§ 3.3)
-- (7) INSERT the single seal row
-- (8) grant the module's platform tables to the online role — the database
--     half of the authority switch

COMMIT;
```

**Why `IN SHARE MODE`.** `SHARE` conflicts with `ROW EXCLUSIVE`, which is what
`INSERT`, `UPDATE` and `DELETE` take. PostgreSQL therefore makes `LOCK TABLE`
wait for every in-flight writer to finish and blocks new writers for the rest of
the transaction
([sql-lock](https://www.postgresql.org/docs/current/sql-lock.html)). It does not
block `SELECT`, so the preflight, the parity comparison and the digests all read
a set that provably cannot move under them.

**The lock is taken before anything is read.** Without it, the sequence had a
gap: an in-flight writer could commit *after* the count and digest were read, and
the seal would attest to a set that had already changed — reintroducing the exact
boundary question the sealed set exists to remove.

**What the lock covers:** both legacy tables, for the whole transaction, against
every writer regardless of role. It does not cover a `TRUNCATE` or DDL from a
superuser session, which take `ACCESS EXCLUSIVE` and would themselves wait; and
it says nothing about tables outside this list, which is why the two tables are
named explicitly rather than discovered.

#### 3.2 The seal row

One row, insert-only, in `approval_cutover_seal`:

| column | meaning |
|---|---|
| `sealed_at` | UTC instant of the sealing transaction |
| `alembic_revision` | composed head at sealing |
| `legacy_policy_count` | `count(*)` of `approval_policies`, under the lock |
| `legacy_record_count` | `count(*)` of `approval_records`, under the lock |
| `policy_digest` | complete-content digest of `approval_policies` |
| `record_digest` | complete-content digest of `approval_records` |
| `digest_algorithm` | `sha256` — named, so a change is a visible one |
| `operator_ref` | the platform admin who executed the sealing |

`UPDATE` and `DELETE` on the seal table are revoked from every online role, so
the sealed set cannot be restated afterwards to make a report agree.

#### 3.3 The digests cover COMPLETE contents

Counts and unique constraints detect insertions and deletions. **Neither detects
an update at all** — and `platform_api` currently holds `UPDATE` and `DELETE` on
both tables (migration `v003`), so a silent change to `quorum`,
`allow_self_approval` or a record's `content_hash` is a live capability, not a
theoretical one. Two digests therefore cover **every column of both tables**:

- `policy_digest` over `approval_policies`: `id`, `policy_code`, `version`,
  `quorum`, `allow_self_approval`, `created_at`, `updated_at`;
- `record_digest` over `approval_records`: `id`, `policy_code`, `policy_version`,
  `subject_type`, `subject_id`, `content_hash`, `approver_id`, `created_at`,
  `updated_at`.

**The framing is a typed, injective DATASET ENVELOPE** (encoding version 2), not
a delimiter-separated one and not a join of encoded rows. Two earlier framings
failed, and both failures are worth keeping written down:

*Version 0* joined column values with `\x1f` and rows with newlines. That is
ambiguous and reachably so: `policy_code`, `subject_type`, `subject_id` and
`content_hash` are plain strings that may legally contain those bytes, so two
different sets could render to byte-identical input. Timestamp text was ambiguous
in a second way — its rendering varied with session timezone, so the same data
hashed differently depending on who connected.

*Version 1* fixed the delimiters with canonical JSON per row, but still hashed
the JOINED ROWS. The domain, version and table therefore lived only inside rows —
and an **empty dataset has no rows**, so empty policies and empty records both
hashed the empty byte string to the same digest. A seal that cannot distinguish
"no policies" from "no records" collides in exactly the case a fresh or fully
drained estate hits. Version 1 also normalised UUIDs and datetimes to plain
strings, so a UUID collided with the identical string and a datetime with its own
rendered text.

**Version 2** hashes one envelope per table:

```json
["dotmac.vendor.approvals.seal", 2, "<table>", [<field names>], [<sorted typed rows>]]
```

- the domain, version, table identity and column list are hashed **even when
  there are no rows at all**;
- every value carries a **type tag** — `["uuid","…"]`, `["timestamp","…"]`,
  `["str","…"]`, `["int",n]`, `["bool",b]`, `["null",null]` — so a UUID, a
  timestamp and a string with the same characters can never share an encoding;
- JSON is emitted with `ensure_ascii=True` and no whitespace, so every delimiter
  inside a string is escaped by the encoding itself;
- timestamps are converted to UTC and rendered `%Y-%m-%dT%H:%M:%S.%fZ`; a naive
  datetime is refused, having no single instant;
- `bool` is handled before `int`, so `True` cannot encode as `1`;
- any other type raises rather than falling back to `str()`, because that
  fallback is precisely how an ambiguous rendering gets in;
- rows sort by their encoded text — deterministic without depending on any
  database order, for the same reason a random primary key cannot serve as a
  cursor.

The framing changed, so the version changed with it: a new framing under an
unchanged version would silently reinterpret digests already recorded. Golden
vectors for the empty and populated cases are pinned in the test suite, so a
future refactor is caught as a changed constant rather than passing because the
implementation and a recomputed expectation moved together.

The declared field lists are checked against the ORM models, so a column added to
either table without being added to its digest fails the build rather than
silently escaping the seal.

#### 3.4 Verify EFFECTIVE privileges, not the statement

Issuing `REVOKE` is not proof the privilege is gone. A grant reaching the role
through `PUBLIC`, or through a role it inherits, survives a direct revoke
([sql-revoke](https://www.postgresql.org/docs/current/sql-revoke.html)).

After step (4) and **before** the seal is written, the transaction asserts the
outcome — as an EXACT matrix, per role, over all seven privileges:

| Role | Required effective privileges |
|---|---|
| `platform_api` | **`SELECT` = true**; `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, `REFERENCES`, `TRIGGER` = false |
| `app_user` | all seven false |
| `app_admin` | unchanged — the offline repair and migration role, which never serves a request |

An earlier draft required all seven false for `platform_api`. That contradicted
the statement above it, since the revoke never touched `SELECT` and `v003` grants
it — and the assertion is the half that had to give, because **the shadow
comparison reads these tables**. Removing the read path would break the very
check the seal exists to enable.

`SELECT = true` is asserted **positively**, not left unmentioned. Without the
positive half, a later over-broad `REVOKE ALL` would silently delete the read
path while every remaining assertion still passed — and a check that never ran
would look identical to a check that passed.

The reader is `has_table_privilege` OR `has_any_column_privilege`. Both answer
"effectively holds", which is what makes inherited and `PUBLIC` grants visible;
the column-level function is what catches a `GRANT UPDATE (quorum)` that a
table-level inquiry reports as revoked.

This is the assembly's canonical privilege query — the same
`ROLE_TABLE_PRIVILEGES_SQL` the composed live-catalogue audit uses — so the
sealing path and the standing audit cannot drift apart in what they consider
"revoked".

Any surviving privilege **aborts the transaction**. Assert the outcome, never the
action.

#### 3.5 If a scalar cursor is ever genuinely required

Add an enforced monotonic `BIGINT` to the legacy table first, backfill it, and
make it `NOT NULL` with a sequence default. Do **not** reintroduce a cursor over
UUID primary keys. This paragraph exists because the mistake was made once with
confident reasoning, and it is the reasoning that has to be blocked.

**"The watermark" now means this sealing transaction.** It is still the moment
that divides legacy evidence from module requests — it is simply recorded by
sealing the old set rather than by naming a cursor into it. Everywhere below,
"pre-watermark" means "in the sealed set", which after commit is every legacy row
that will ever exist.

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
7. **Seal integrity** — the counts and both complete-content digests
   (`policy_digest`, `record_digest`) are computed under the lock in the same
   transaction that records them, so the set compared IS the set sealed. There is
   no separate later recomputation to disagree, which is the point of doing all
   of it inside one transaction.

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

The boundary is the sealing transaction's `COMMIT`, and every check that could
justify aborting runs before it.

**Before commit, rollback is free and total.** The preflight (§ 4a) and the parity
comparison (§ 6) both run inside the transaction, under the lock, after nothing
has been written. A failure at either point is a `ROLLBACK`: the locks release,
no privilege has changed, no seal exists, and the legacy authority is still
serving. This is the repair of an earlier draft that sealed first and compared
afterwards while forbidding rollback after sealing — which left a parity failure
with no legal exit.

**After commit, rollback is forward-only.** The online role can no longer write
the legacy tables, so there is no "resume the old writer" to return to; genuine
module requests begin, with real requesters and real idempotency keys. A defect
found afterwards is fixed in the module era — by cancelling and re-raising
affected requests — not by moving the boundary backwards. The seal table's
revoked `UPDATE`/`DELETE` makes that structural rather than a matter of
discipline.

**Between commit and the adapter deploy there is a deliberate write freeze.**
The legacy path is physically incapable of writing and the new adapter is not yet
serving, so approvals are briefly unavailable. That is a planned, announced
outage and it is the honest cost of never having two writers: the alternative is
an overlap window in which both could write, which is the thing this whole
contract exists to prevent.

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

### 9a. Obligation on the shadow-composition migration

**Composing the module grants the online platform role a second write surface,
unless the composing migration takes it away in the same transaction.**

`ap_0001_approvals` grants `platform_api` `SELECT, INSERT, UPDATE, DELETE` on the
module's platform tables the moment it runs. That is correct for an assembly
where the module IS the authority. Here it is not: while the legacy writer is
still authoritative, a platform role able to write `mod_approvals` is a second
writer that nothing in this contract permits — created not by anyone's decision
but as a side effect of installing a lineage.

So the shadow-composition change **must**, in the same migration transaction that
runs `ap_0001_approvals`:

1. revoke `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, `REFERENCES` and `TRIGGER` on
   every `mod_approvals` table from `platform_api`;
2. retain `SELECT`, so the shadow comparison and the eventual reconciliation can
   read the module's side;
3. verify the resulting EFFECTIVE privileges the same way § 3.4 does, and fail
   the migration if any write privilege survives;
4. leave `app_user` with nothing, as the module's own migration already does.

The grant is restored — by the cutover change, not by the composing one — as step
(8) of the sealing transaction in § 3.1, which is the single moment the authority
moves.

**IMPLEMENTED** by vendor migration `v012_approvals_shadow_readonly`, which also
verifies its own outcome before it can commit. Recording the obligation before
the phase that discharges it was the point: it falls between two phases, and the
phase that creates the exposure is not the one that reads this contract closely.

One clarification the implementation settled, worth keeping: `ModulePlane.PLATFORM`
selects STORAGE SHAPE, never WRITE AUTHORITY. Shadow-versus-active is Vendor's
migration state, so Vendor owns the restriction. A greenfield adopter should
receive the module's normal write grants; asking the module to weaken them for
everyone would push one product's migration state into a shared contract.

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
- The cutover is ONE transaction — lock → preflight → parity → revoke → verify →
  digest → seal → grant — followed by the adapter deploy. Never a gradual
  dual-write: there is no window in which both writers are able to act.

## What this ADR does NOT authorise

Any WRITE to the module's tables, or any move of the approval authority.

Composition itself has now happened — `dotmac-approvals==0.1.0a4` is pinned,
composed and PLATFORM-selected, read-only under § 9a — but that is installation,
not adoption. `vendor_cp.approvals` remains the sole authoritative writer until
the sealing transaction in § 3.1, and the module's tables stay empty until then.
