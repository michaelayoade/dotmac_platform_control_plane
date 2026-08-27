# Commercial backfill — cohort and mapping dossier

**Dated 2026-08-25; updated 2026-08-26.** The exact cohort a commercial backfill
would move, the five transformations each row must survive, and the two gates
that would have to open before anything moves. The machine-readable half is
`src/vendor_cp/commercial_backfill/`, held by
`tests/architecture/test_commercial_backfill.py`; where the two disagree, the
test is the one that fails.

**This document takes no authority decision.** It **does not choose** who owns
subscriptions or billing after a move, and nothing here composes a module, takes
a pin, moves a writer or runs a backfill. It is the contracting step `AGENTS.md`
rule 12 requires before a cutover is composed — the premise written down first,
in a shape a later change can be held to. The owner is settled by an accepted,
checked-in contract elsewhere, recorded here as the gate condition
`TARGET_AUTHORITY_ACCEPTED`, whose evidence kind is `adoption_evidence` because
this repository cannot observe it.

It refines `docs/cutover-readiness.md` from an aggregate readiness statement into
an exact cohort. Where that document asks "what do the remaining slices need",
this one answers "which rows, transformed how, and what would have to be true".

## The rule this document is written under

`AGENTS.md` rule 17. Repository-local transition claims are derived from
repository-local facts; release, registry and production-adoption claims require
an authoritative external oracle carrying immutable coordinates.

Everything asserted below is the first kind: which attributes this assembly's
models declare, which functions its adapters publish, what a pure classifier
does with a given row. **No claim is made here about a release, a registry, a
production database or another product's state.** The two conditions that need
an oracle are named with their kind and their owner and are not discharged;
`tests/architecture/test_commercial_backfill.py
::test_no_condition_needing_an_oracle_is_recorded_as_discharged` fails the build
if one ever is.

The known-bad case this shape exists to refuse is already in this repository's
history: `AWAITING_RELEASE_TAG` read `pyproject.toml`, was described as gating on
a release tag, and stayed green when the tag was published.

## The hard output constraint

**No report produced by this work emits an identifier, an amount, a label or a
timestamp.** Counts, categories and blocker reasons only.

That is structural, not a convention. Three layers, and they are stacked because
the first two bound what a report CAN hold and the third checks what actually
left:

1. A report holds a `Count` — a cardinality — or a member of a closed enum
   declared in `vocabulary.py`. Every report enum's members carry `auto()`
   rather than a string value, so a member value is never text. `Report` has no
   free-text field of any kind, and the architecture test refuses one by name
   (`note`, `title`, `summary`, …) as well as by annotation.
2. Counts are obtained by COUNTING members. The planner and the comparator never
   construct a `Count`; a ratchet holds `Count(` to `report.py`. The numbers in
   a report come from `len()` over classified rows.
3. `render()` checks what it produced, line by line, against a grammar (two
   declared names and at most one integer) and the declared vocabulary. Both
   halves are load-bearing: without the grammar a timestamp passes as a run of
   integers; without the vocabulary any upper-case token does.

Four sensitivity tests plant an identifier, an amount, a label and a timestamp —
separately, because one combined string passes as soon as the first is caught.

**Stated as weaker than it sounds, deliberately.** A caller could pass an amount
in minor units where a row count belongs, and nothing can tell an integer from
an integer. The guarantee is that a report's alphabet is closed, not that every
integer in it is meaningful.

## The cohort

Every Vendor source row that could produce a Subscriptions contract or price, or
a Billing input, on the target side. Two kinds, `SourceKind`:

| `SourceKind` | What it is | Where it is read from |
| --- | --- | --- |
| `AGREEMENT_LINE` | the price, quantity, capability and term a target contract would be built from | `vendor_cp.contracts.adapter` — `ContractView` / `LineView` |
| `OFFER_VERSION` | the immutable priced catalogue row a line's terms were frozen from | `vendor_cp.offers.models.OfferVersion` |

### Every enumerated row lands in exactly one bucket

`Bucket` has three members and no fourth. `MAPPED`, `EXCLUDED` with a stated
reason, or `BLOCKED` with the dimension that blocked it.

`classify` is a total function — every path returns a verdict, and the
architecture test walks its control flow for the shapes that lose a row (a
`continue`, a bare `return`, a `return None`). The planner asserts the same
claim from the other end: the three buckets sum to the number of rows, every
excluded row carries a reason, every blocked row names a dimension.

`RowVerdict` refuses the overlap structurally: a `MAPPED` verdict carrying an
exclusion reason, or a `BLOCKED` verdict naming no dimension, raises at
construction.

### Coverage is a separate claim from bucketing

A source that could not be enumerated is not zero rows — it is an unknown number
of rows, and the two must never render the same. `SourceCoverage` carries it:
`OFFER_VERSION_ENUMERATED`, `OFFER_VERSION_NOT_ENUMERABLE`,
`AGREEMENT_LINE_ENUMERATED`, `AGREEMENT_LINE_NOT_ENUMERABLE`.

The selected `dotmac-commercial-agreements==0.1.0a2` public contract adds a
bounded UUID-keyset estate reader, and `vendor_cp.contracts.adapter` maps each
owner page into Vendor's existing typed view. This repository adds no local
reader, does not query the module schema directly, and does not read another
application’s database. Source inspection proves that adapter relationship;
`docs/cutover-readiness.md` is the oracle-bearing source for the a2 release and
pin, and the adoption guard refuses merge unless it records both the exact
`release_run` and the 40-character peeled-tag commit.

Reader availability and run coverage remain separate. The planner must report
`AGREEMENT_LINE_NOT_ENUMERABLE` when the export did not reach the final owner
page; the presence of a method never renders an unknown remainder as zero. Only
a completed page walk may report `AGREEMENT_LINE_ENUMERATED`.

### Exclusions, and why they are decided first

`ExclusionReason`, in declared order:

| Reason | Rule |
| --- | --- |
| `OFFER_VERSION_NEVER_REFERENCED` | an offer version nothing references is CATALOGUE, not commercial state |
| `NOT_COMMERCIAL_STATE_YET` | `DRAFT`, `PROPOSED`, `APPROVED` — not yet a commercial relationship |
| `TERMINATED_BEFORE_COHORT_START` | `REJECTED`, `CANCELLED`, `TERMINATED`, `EXPIRED` |
| `SUPERSEDED_AGREEMENT_VERSION` | a newer version of the same agreement family carries the truth |
| `ZERO_QUANTITY_LINE` | a line for nothing produces no target price |

`ACTIVE` and `SUSPENDED` are IN. A suspended agreement is a contract that exists
and is not billing — a state the target has and must be told about; leaving it
out silently drops paying relationships that happen to be paused on cutover day.

Membership is decided BEFORE any transformation. A draft has no frozen content
hash, so a transformation-first order would report every draft as a
`FROZEN_CONTENT` blocker — a queue of work items that are not work, burying the
rows that really are blocked.

**A status outside the declared vocabulary is refused at row construction**, not
classified. If the agreements module gains a status this assembly has never
seen, a classifier that fell through would put those rows in `MAPPED` — silently
changing who is in the cohort, in the direction that backfills them.

## Source projection

The fields a `SourceRow` carries, and the attribute each is read from. Held
against the real declarations by
`test_the_source_projection_reads_attributes_that_exist`, because a mapping
dossier that named a field nobody has reads exactly as confidently as one that
did not.

| `SourceRow` field | Read from |
| --- | --- |
| `product_code` | `OfferVersion.product_code` / `LineView.product_code` |
| `amount`, `currency_code` | `OfferVersion.amount` + `.currency_code`; `LineView.unit_amount` + `.unit_currency_code` |
| `quantity` | `LineView.quantity` |
| `content_hash` | `ContractView.content_hash` (frozen at propose) |
| `activation_content_hash` | the activation event's bound digest |
| `agreement_status` | `ContractView.status` |
| `term_start` | `ContractView.term_start`, mapped from `AgreementView.effective_date` |
| `term_end_exclusive` | `ContractView.term_end_exclusive`, normalized once from inclusive `AgreementView.expiry_date` |
| `sibling_product_codes`, `sibling_currency_codes` | the other lines of the same agreement |
| `referenced_by_cohort_line` | whether any cohort line names this `offer_ref` |
| `fingerprint` | a digest of the row's natural key — used ONLY by the rehearsal shadow, never by a report |

## The five transformations

Each returns a CATEGORY, never a converted value. A dry-run planner that
produced target values would be a backfill that had already run in memory, and
its output could not honour the constraint above without stripping what it had
just computed. Conversion belongs to whatever executes the backfill, under the
authority that owns the target.

`Dimension` fixes the evaluation order, so a row failing two dimensions is
always reported against the same one: `PRODUCT_IDENTITY`, `CURRENCY`, `CADENCE`,
`PRORATION`, `FROZEN_CONTENT`.

### 1. Product identity — `ProductIdentityOutcome`

`QUALIFIED`, or one of `CODE_ABSENT`, `CODE_UNTRIMMED`, `CODE_UNDECLARED`,
`MULTI_PRODUCT_AGREEMENT`.

Mirrors the two refusals already in the assembly rather than inventing a third:
`offers.service._require_product_code` refuses a blank or untrimmed code, and
`contracts.adapter._single_product` refuses an agreement naming more than one
product.

*Edge cases.* `CODE_ABSENT` is the pre-`v011` row `OfferVersion.product_code` is
nullable for. **`ACME` against a declared `acme` is `CODE_UNDECLARED`, never
folded**: case-folding two product codes together invents an identity nobody
published, silently, for every row. A product declared here with no counterpart
on the target is a TARGET fact needing an oracle, so it is a gate condition
rather than a local blocker.

### 2. Currency — `CurrencyOutcome`

`EXACT`, `EXACT_ZERO_AMOUNT`, or one of `CODE_UNKNOWN`, `NOT_DECIMAL`,
`NOT_QUANTIZED`, `NEGATIVE`, `MIXED_CURRENCY_AGREEMENT`.

Vendor stores an exact decimal string plus an ISO-4217 code and reconstructs
`Money`; never a float. The check is that the stored string is already quantized
to the currency's minor-unit exponent.

*Edge cases.* Zero-decimal currencies (`JPY`, `KRW`, `XOF`, …) and three-decimal
currencies (`BHD`, `KWD`, `TND`, …) are the two directions an assumed exponent
is wrong — by a hundred and by a thousand. An unknown code fails closed rather
than assuming two decimals. `1E+2`, `+10.00`, `1,000.00` and a leading space are
`NOT_DECIMAL`: they parse under `Decimal` and none of them is what the writer
stored, and accepting a spelling this writer never produced means accepting one
some other writer did. A zero amount is reported separately so an unexpected
free line is visible before it becomes the target's opening balance.

**`NOT_QUANTIZED` blocks; it never repairs.** Quantizing an over-precise amount
would invent money across the whole cohort, in a run whose entire output is
counts.

### 3. Cadence — `CadenceOutcome`

`MONTHLY`, `QUARTERLY`, `SEMI_ANNUAL`, `ANNUAL`, or one of `INDETERMINATE`,
`TERM_NOT_POSITIVE`, `TERM_OPEN_ENDED`.

Vendor holds a whole-period price and NO recurrence at all, so cadence is not
carried — it is derived from the agreement term, and only where the derivation
is exact. Whole calendar months, found by searching for `n` where
`add_months(start, n)` lands on the term's first uncovered day.

*Edge cases.* Month addition clamps to the shorter month, so 31 January plus one
month is 28 February and 29 in a leap year; that is why the derivation searches
rather than dividing, because clamping is not invertible and dividing days by 30
turns February into a rounding error. A 30-day term is not a month. **A
24-month term is `INDETERMINATE`, not `ANNUAL`** — folding it would backfill a
contract that bills twice, and how many periods a term becomes is the target's
decision. Terms are dates, so no timezone or DST question arises.

**The term boundary is normalized once, never selected by a caller.** The pinned
Commercial Agreements service refuses expiry while `as_of <= expiry_date`, so
its `expiry_date` is inclusive. `vendor_cp.contracts.adapter._view` translates
that last covered day to `ContractView.term_end_exclusive`, the first uncovered
day. The backfill source field has the same explicit name, cadence consumes it
as-is, and neither the CLI nor `CohortRules` carries a convention switch. This
prevents both an off-by-one mapping and accidental double-normalization.

### 4. Proration — `ProrationOutcome`

`NONE_REQUIRED`, `TARGET_OWNED_MISALIGNED`, or `ANCHOR_INDETERMINATE`.

**The backfill carries no proration, because Vendor has none to carry.** What
this dimension records is whether the TARGET will face a short first period —
a fact its owner needs before the cutover rather than in the first invoice run.

The rule: a term anchored on day 1–28 repeats its own anchor in every month, so
no short period is created. A term anchored on 29, 30 or 31 cannot, and the
target's clamping and proration policy decides what the short period costs.

*Edge cases.* A 29 February anchor is `TARGET_OWNED_MISALIGNED` like any other
day past 28. A blocking cadence gives `ANCHOR_INDETERMINATE`, which blocks in its
own right so the report shows how many rows the cadence problem affects
downstream and not only how many rows have it.

### 5. Frozen content — `FrozenContentOutcome`

`TRANSLATABLE`, or one of `NOT_FROZEN`, `STALE_AGAINST_ACTIVATION`,
`DIGEST_EMPTY`, `DIGEST_ALREADY_PREFIXED`, `DIGEST_WRONG_LENGTH`,
`DIGEST_UPPERCASE`, `DIGEST_NON_HEX`.

Two questions, and both must hold: the agreement HAS a frozen snapshot
(`content_hash` is set at propose), and the snapshot the activation event bound
to is still the current one. The second is
`contracts.adapter.active_snapshot`'s stale-event rule applied to a whole cohort
instead of one delivery — a row failing it carries an approval for content that
has since changed.

The five digest categories **mirror `vendor_cp.approvals_authority
.DIGEST_REJECTION_REASONS` one for one and are imported, never restated.** That
module is this assembly's one opinion about what a content digest is, and a
second opinion would drift from it in exactly the way that rule exists to stop.
A test fails if a reason is added there and left unmapped here.

## The dry-run planner

`plan()` takes projected source rows and returns a `Report`. Dry-run is a
property of the signature, not a flag: no session, no connection, no clock, no
output path, so there is nothing it could write to. Making it write is a
signature change, which is a review.

It emits, as tallies over closed domains: `SOURCE_COVERAGE`, `SOURCE_KIND`,
`BUCKET`, `EXCLUSION`, `BLOCKING_DIMENSION`, and one per dimension —
`PRODUCT_IDENTITY`, `CURRENCY`, `CADENCE`, `PRORATION`, `FROZEN_CONTENT`.

Dimension tallies count rows that REACHED the transformations (mapped and
blocked); an excluded row never ran one, and giving it a category would invent
an outcome for a row nobody transformed.

Nothing is staged, reserved or identified in advance. A plan that had already
claimed target identifiers would be a partial backfill wearing a report's
clothes.

## The read-only semantic comparator

Two claims, kept apart, and there is no combined verdict anywhere — because the
moment one exists, someone reads it. `ParitySubject` names them:

* **`ROW_COUNT`** — does the target hold as many rows as the plan intends to
  send? Compared against `MAPPED` only: excluded and blocked rows were never
  going, and counting them makes a correct backfill look short by exactly the
  number of rows it was right to leave behind.
* **`TARGET_SEMANTIC`** — per dimension, do the categories the plan expects match
  the categories the target shows?

They are different claims and collapsing them lets a matching count vouch for a
meaning nobody checked. A cohort backfilled with every cadence wrong has perfect
row-count parity.

`ParityVerdict` has three members: `MATCHED`, `DIVERGED`, `NOT_COMPARABLE`. A
dimension the observation does not cover is `NOT_COMPARABLE`, never a quiet
`MATCHED`, and the overall semantic verdict is the WEAKEST of its dimensions —
parity over four of five dimensions is not parity, and rounding it up is how a
blind spot becomes a sign-off. The `PARITY` tally carries the per-dimension
verdicts so a reader sees which diverged without the report naming a row.

**The target never sends rows here.** `TargetObservation` carries cardinalities
by category, read by an operator from the target's own versioned API and reduced
there. Vendor receives no target rows, stores none, and holds no copy of the
target's state — which is what keeps this a description of a transformation
rather than a second, drifting copy, and what keeps it inside hard rule 28:
applications are independent and compose only through versioned APIs and
webhooks.

## The rehearsal reconciler

`scripts/reconcile_backfill_shadow.py` repairs the shadow rows of a **test or
development** rehearsal. Three properties keep it there.

**It is not a Vendor table.** The shadow schema is created by the repair
statements themselves, in a disposable database, by the migrator role. No
revision creates it, no model declares it — there is no `__tablename__` anywhere
in the package — so `vendor_cp.cutover_readiness`'s declared vendor-owned table
set does not move and nothing reaches a production database.

**It never connects and never grants.** The command returns SQL text; an
operator applies it under the migrator role, which is how every privileged
statement in this repository already runs. Deny case D1 keeps the kernel the one
owner of a connection here and the connection allowlist stays empty. There is no
`GRANT` in anything it emits — the repair REVOKEs from Vendor's online role on
the rehearsal schema instead, guarded so it is a no-op where that role does not
exist. `--confirm-disposable` is required because the command never sees a
database and cannot check the premise itself; making the operator state it is
honest, inferring it would not be.

**Replay-safety is designed.** The shadow table has no timestamp column and no
surrogate key: a row is its fingerprint plus a handful of category names, so two
runs produce byte-identical state and a byte-identical report. Rows no longer in
the cohort are deleted, rows that are get an upsert, and the empty cohort takes
its own branch because `NOT IN ()` is not valid SQL and skipping the delete would
leave the previous run behind. `tests/migration/test_commercial_backfill_replay.py`
is the PostgreSQL canary responsible for exercising replay and effective
privileges; this dossier does not preserve a transient run result as a fact.

Every value that reaches an emitted statement comes from a closed set — an
upper-case member name, or a 64-character lowercase hex fingerprint — and
`_literal` refuses anything else before quoting it. That is stronger than
escaping: nothing that could need escaping can reach the statement.

## Gate conditions and evidence

The tables below define conditions. They do not snapshot gate state; current
evidence belongs in a review dossier or in the named immutable external oracle.

### `incumbent_commercial_writer_retirement`

Vendor's incumbent commercial writer is
`vendor_cp.offers.service.publish_offer_version`, the one owner of the immutable
priced `offer_versions` rows. It is a real, current authority over price. **It is
not retired here.**

| Condition | Evidence | Owner |
| --- | --- | --- |
| `TYPED_PAGINATED_AGREEMENT_READER_RELEASED` | `release_run` | `dotmac-commercial-agreements` release owner |
| `COHORT_FULLY_ENUMERABLE` | local fact | vendor control plane |
| `ZERO_BLOCKED_ROWS` | local fact | vendor control plane |
| `SEMANTIC_PARITY_PROVEN` | local fact | vendor control plane |
| `TARGET_AUTHORITY_ACCEPTED` | `adoption_evidence` | the owning repository's extraction dossier |
| `BACKFILL_EXECUTED_IN_PRODUCTION` | `deployment_run` | the operator, against a host Michael names explicitly |

### `final_dml_grant`

The last step of a backfill is the grant that lets the target's runtime role
write what it has just been given. That is a separate decision from the data
movement, and this gate keeps it separate.

| Condition | Evidence | Owner |
| --- | --- | --- |
| `INCUMBENT_RETIREMENT_GATE_OPEN` | local fact | vendor control plane |
| `NO_VENDOR_RUNTIME_DML_ADDED` | local fact | vendor control plane |
| `REHEARSAL_REPLAY_PROVEN` | local fact | vendor control plane |
| `EFFECTIVE_PRIVILEGES_VERIFIED_BOTH_WAYS` | local fact | vendor control plane |
| `GRANT_APPLIED_IN_PRODUCTION` | `deployment_run` | the operator, against an explicitly named host |

`EFFECTIVE_PRIVILEGES_VERIFIED_BOTH_WAYS` is the shape ADR-0006 § 3 used for
`mod_ealloc` — the role holds what it needs and nothing beyond it, verified as an
effective outcome rather than by reading a `GRANT` statement back.

## What this document is not

It is not an authority to compose and it takes no decision that belongs in an
ADR. ADR-0012 records the contracting decision; `docs/cutover-readiness.md` owns
the remaining slice sequence. If this document and an ADR disagree, the ADR wins
and this file is the drift.
