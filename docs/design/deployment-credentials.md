# DeploymentCredentialService — WS8 V6 deployment authentication design

> **Status:** Implementation brief (2026-08-04). The kernel contract this
> depends on is **published** (dotmac-kernel **0.1.0a9**, tagged
> `dotmac-kernel-v0.1.0a9`, pinned in `pyproject.toml`): `DeploymentSigner`,
> `DeploymentVerificationKey`, `AppliedStateEnvelope` + `verify_applied_state`,
> `DeploymentPossessionChallenge` / `DeploymentPossessionResponse` +
> `verify_possession`, `VerifiedAppliedState`, `VerifiedDeploymentPossession`.
> The governing decision is
> `dotmac_starter_mt/docs/adr/0007-deployment-authenticated-applied-state.md`;
> this document fixes the VENDOR side of it and defers to the ADR on any
> conflict. The authoritative lifecycle remains
> `docs/design/domain-foundation.md`.

## Why this slice exists

The control plane can verify everything about a licence **document** — its
signature, the key's status, its binding, version and digest — and nothing
about the **caller**. `EntitlementProjectionService` is correct to fail closed
on that: `active` is defined to mean "the data plane committed this exact
version", and a caller that has proven no identity cannot establish that for
any licence, bound or unbound. But the consequence is that **`active` is
unreachable in production** — the pipeline's terminal state has never been
entered by a real deployment.

This slice does not change what activation means or when it is granted. It
supplies the one missing input: a **proven** deployment identity. The
activation rules in `EntitlementProjectionService` are unchanged, and this
document must not be read as amending them.

## Owners and scope

Three owners, deliberately not two. An earlier draft folded admission into
`DeploymentCredentialService`, which left the receipt row, the receipt clock
and the replay verdict without a named writer — the exact shape of gap this
architecture exists to prevent.

- **`DeploymentCredentialService`** (new) owns the **credential**: registration,
  possession challenges, activation, rotation, retirement, revocation, and the
  **eligibility lookup** — given a `key_id` and a receipt time, which
  credential (if any) may admit that report, and what `deployment_ref` it
  resolves to. It writes no receipts and decides nothing about entitlements.
- **`AppliedStateAdmissionService`** (new) is the canonical writer for
  **admission**: stamping the server receipt time, persisting the raw inbound
  evidence, parsing, calling kernel verification, asking
  `DeploymentCredentialService` for eligibility, and deciding
  accepted / idempotent-replay / conflict / quarantined. It owns both receipt
  tables and nothing else. It does not activate anything.
- **`EntitlementProjectionService`** (existing) remains the **sole consequence
  owner**: delivery and acknowledgement state, and the digest/version/binding
  rules that decide activation. It consumes a proven identity exactly where it
  already accepts `authenticated_deployment_ref`. Its rules are untouched by
  this slice.

The split matters because the three answer different questions — *may this key
speak?*, *what exactly arrived and have we seen it before?*, and *what follows
from it?* — and a single service answering all three would make the receipt
clock a private detail of credential logic, where nothing could depend on it.
- **Kernel** owns the envelope contract, its serialization and the conformance
  vectors, and holds **no production key custody**.
- **Fleet / deployment owner** owns the authoritative Deployment entity and
  the binding of a credential to it. That service does not exist yet — see
  "Enrollment authority" below, which is deliberately a stopgap.

Neither owner writes a product database (ruling C4, deny-cases D1/D2). No
private key material enters this repo: the vendor stores **public** keys only.

## Two adapters, one decision path

There are two ingestion surfaces, and they must never become two sets of
rules. The rules live in one private consequence core; the adapters differ
only in what identity they are structurally capable of supplying.

| Adapter | Identity | Can activate? |
|---|---|---|
| **Admin ingestion** (`POST /licensing/acknowledgements`, platform-admin auth) | none — the parameter does not exist on this path | **Never.** Records `unverified_identity` evidence. |
| **Authenticated ingestion** (new, deployment-signed) | a kernel `VerifiedAppliedState` | Yes, subject to the unchanged projection rules. |

Two properties are load-bearing:

1. **Admin ingestion cannot accept a proven-identity argument at all.** Not
   "passes `None`" — the argument is absent from its signature. A parameter
   that merely defaults to `None` is one careless keyword away from an admin
   route activating a licence, and that is exactly the failure this whole
   slice exists to prevent. The type system should make the mistake
   unexpressible rather than the code merely avoid it.
2. **Authenticated ingestion requires a `VerifiedAppliedState`**, not a string.
   Accepting a `deployment_ref: str` would let any caller that can reach the
   function supply an identity; requiring the kernel's verified result means
   the only way to obtain one is to have verified a signature.

Both call one private `_apply_acknowledgement(...)` core that takes the proven
ref (or its explicit absence) and applies the existing rules. One decision
path, two typed doors.

## Credential registry

### States

`pending → active → retired`, and `* → revoked`. Nothing returns from
`revoked`.

- **`pending`** — registered but unproven. Registration proves only that
  someone submitted a public key; it does not prove the deployment holds the
  private half. A key that authenticated from the moment it was pasted in
  would let a typo, or an operator with control-plane write access, bind an
  identity the real deployment never had.
- **`active`** — possession proven, `activated_at` stamped. Admits reports
  received from that instant.
- **`retired`** — rotated out, `retired_at` stamped. Admits nothing received
  at or after that instant, and stays attributable for what it already
  signed.
- **`revoked`** — terminal, `revoked_at` stamped. Same admission cut, never
  reinstated.

**The three timestamps are the authority**, because admission is decided for a
report received at some past instant, not for "now". A status check alone
cannot answer whether a credential was eligible when a given report arrived —
see "The eligibility predicate".

If a `status` column is stored at all, it is a **single-writer, rebuildable
projection of those timestamps**, never independently writable authority:

- one writer — the lifecycle transition in `DeploymentCredentialService`, which
  sets the timestamp and derives the status in the same statement;
- **database constraints tying it to the timestamps**, so the two cannot
  disagree even under a direct SQL edit. A `CHECK` is sufficient here:
  `revoked` iff `revoked_at IS NOT NULL`; `retired` iff `retired_at IS NOT
  NULL AND revoked_at IS NULL`; `active` iff `activated_at IS NOT NULL` and
  neither of the others; `pending` iff all three are NULL;
- fully reconstructible from the timestamps, so it can be dropped and rebuilt
  without loss.

The alternative — a status anyone may set — reintroduces exactly the drift this
section exists to prevent: a row reading `active` whose `revoked_at` is set,
where which one wins depends on which query the reader happened to write.

### Uniqueness

Two independent constraints, both global, both enforced in the database rather
than by a service-layer check:

- **`key_id` unique across ALL states, including revoked.** ADR-0007 §6 makes
  revocation terminal: a revoked `key_id` is never reinstated, because
  reinstating it would retroactively re-trust everything it can sign. A
  partial index that excluded revoked rows would permit exactly that
  reinstatement, so the constraint is unconditional.
- **Public-key fingerprint unique globally.** This is defence in depth against
  the substitution attack ADR-0007 §4 describes: signing `key_id` into the
  envelope makes the substitution unexploitable, and fingerprint uniqueness
  makes its precondition — the same public key registered twice under
  different ids — unreachable. Both, because either alone is one mistake away
  from the exploit.

**The fingerprint hashes the DECODED canonical Ed25519 key bytes**, not the
base64 text. Base64 is not a canonical encoding: padding variants, the
URL-safe versus standard alphabet, and incidental whitespace all render the
same 32-byte key as different strings, so a text fingerprint would let the
identical key register twice and silently defeat the constraint above. Store
`sha256(raw_32_bytes)` in the `sha256:<hex>` form used elsewhere in WS8, and
compute it after decoding and length-validating the key.

## Enrollment authority (temporary: platform-admin policy)

Registration requires an **authorized enrollment subject**. Anyone who can
register an arbitrary `deployment_ref` can create an identity the fleet never
authorised, and the possession challenge would then faithfully prove control
of a key bound to a deployment that does not exist.

The authoritative Deployment entity belongs to `FleetDesiredStateService`,
which is not built. Until it is, **the enrollment authority is platform-admin
policy**: a platform admin asserts that this `deployment_ref` should exist, and
that assertion is what authorises the registration.

**An `active` `LicenceDeliveryTarget` is an eligibility INPUT to that policy,
not the authority.** Be precise about what it does and does not buy:

- It **is** a useful typo and scope guard. It catches a mistyped
  `deployment_ref` and constrains registration to refs this customer's
  licences may legitimately reach.
- It **is not** proof that a Deployment exists. The same platform-admin
  authority can create the target and then the credential, so requiring one
  before the other adds a step, not an independent authority. Calling it proof
  would be laundering a single actor's assertion through two tables and
  presenting the result as corroboration.

Constraints on the borrow, all of which the implementation must carry:

1. **One narrow reader.** Exactly one function in
   `DeploymentCredentialService` reads `LicenceDeliveryTarget`, and only during
   registration. Nothing else in the credential path may touch it.
2. **Authorisation provenance in the audit event.** The registration audit
   records *which* admin asserted the enrollment and *that* the authority was
   the interim admin policy — not merely that a target existed. When the fleet
   slice lands, historic registrations must remain readable as "authorised
   under the stopgap", or the cutover silently rewrites the past.
3. **No credential lifecycle coupling to target status.** A target later going
   inactive, or being deleted, must NOT retire, revoke or otherwise disturb an
   existing credential. The target gated one moment — registration — and has no
   standing over a credential whose possession has since been proven.
   Coupling them would let a delivery-routing edit revoke a proven identity.
4. **An architecture canary** asserting the reader appears only on the
   registration path, so the borrow cannot spread by ordinary refactoring. This
   is the mechanism that keeps the stopgap from calcifying into ownership;
   a comment asking politely would not survive contact.

### Retirement gates

The stopgap is retired against `FleetDesiredStateService` in explicit phases,
not swapped in one commit:

- **Shadow.** Fleet is consulted alongside the target check; disagreements are
  recorded and reviewed, and neither blocks the other. This is what surfaces
  refs that were enrolled under the admin policy but do not correspond to a
  real Deployment.
- **Cutover.** Fleet becomes the authority; the target check is demoted to a
  warning, then removed from the decision.
- **Stopgap retirement.** The narrow reader and its canary are deleted, and
  this section is replaced by the Fleet contract. Retirement is not complete
  while any code path still reads a delivery target for authorisation.

## Possession proof

The vendor issues a `DeploymentPossessionChallenge` (kernel type) bound to
`challenge_id`, `key_id`, `deployment_ref`, a >=16-byte nonce and a
timezone-aware `expires_at`, and **stores it**. The deployment answers with a
`DeploymentPossessionResponse` carrying only `challenge_id`, `key_id` and the
signature.

The vendor's stored challenge is authoritative for the nonce, deployment and
expiry. The response's two identifiers are **routing** — they say which stored
challenge to load — and verification requires them to match that record
exactly. The kernel refuses a response that echoes the nonce, deployment or
expiry, so no ingestion code may read those from the answer.

### The activation transaction

Activation is one transaction, and the locking is part of the contract:

1. `SELECT ... FOR UPDATE` the challenge row **and** its credential row,
   ordered consistently (credential first, then challenge) so concurrent
   activations cannot deadlock.
2. Verify with `verify_possession(stored_challenge, response, key=..., now=...)`.
3. On success, in the SAME transaction: mark the challenge consumed, move the
   credential `pending → active`, and **invalidate every sibling challenge**
   outstanding for that credential.
4. Write platform audit and commit.

Sibling invalidation is not housekeeping. Issuing a second challenge while a
first is outstanding is normal (a retry, an operator re-issuing after a
timeout), and leaving the others valid would mean one proof of possession
could be followed by a second, independent activation path using a challenge
whose response may have been captured elsewhere. One possession proof
activates one credential, once.

### A failed proof does NOT consume the challenge

Consumption happens **only on successful verification**, in step 3. A failed
attempt leaves the challenge outstanding until it expires on its own.

Consuming on failure would be a denial-of-service on enrollment, available to
anyone who learns the routing identifiers: `challenge_id` and `key_id` are not
secrets — they travel in the response and identify a record, they do not
authenticate it — so an attacker who observes them could burn every challenge
as it is issued by posting garbage signatures, and the real deployment could
never enroll.

Be precise about what is what, because "secret" is the wrong word for two of
these three. The **private key** is the only secret. The **nonce** is not
secret — it is *unpredictable and single-use*, which is what stops a response
being precomputed before the challenge is issued. The **signature** is not
secret either; it is *public evidence*, which is the whole point of preferring
Ed25519 (§1: portable, checkable by any third party). The identifiers are
merely an address. What makes the response unforgeable is possession of the
private key, not the confidentiality of anything transmitted.

Invalid attempts are **counted and rate-limited separately**, per challenge and
per credential, so repeated failures are visible and throttled without
destroying the legitimate holder's ability to answer. A burst of failures is a
signal to surface to an operator, not a reason to invalidate the enrollment.

Expiry remains the challenge's bound on how long a captured response stays
useful, and is checked before the signature, because "expired" and "bad
signature" send an operator to completely different places.

## Applied-state receipts

`LicenceAckRecord` is the legacy acknowledgement log. It cannot serve as the
record of a signed report: it has no `report_id`, no signed bytes, no
`key_id`, no server receipt time, and no replay digest. Extending it would
also blur two different things — an operator-submitted claim and a
cryptographically signed attestation.

**Two records, not one.** An earlier draft used a single append-only table
keyed uniquely on `(authenticated_deployment_ref, report_id)`. That cannot
work, and the failure is instructive: the second arrival under a given key is
exactly the row worth keeping — the replay, or the conflicting bytes — and the
unique constraint forbids inserting it. Updating the first row instead would
break append-only semantics AND discard the conflicting bytes, destroying the
evidence the table exists to preserve. The same schema also had nowhere to put
an attempt that never resolved to an identity at all: unknown `key_id`,
malformed envelope, bad signature. Those are the tripwires.

So: an append-only log of **attempts**, and one canonical **report** record
per idempotency key.

### `applied_state_receipt_attempts` — append-only, one row per arrival

Every inbound authenticated-ingestion attempt, whatever happens to it,
including the ones that never verified:

| Column | Purpose |
|---|---|
| `received_at` | the trusted receipt instant — see "Capturing receipt time" |
| `raw_body` (bytes, **bounded**) | the EXACT inbound bytes, truncated at the evidence-storage cap with a flag recording that truncation occurred |
| `raw_body_digest` | `sha256:` over the full body as received, computed BEFORE truncation; meaningful only for bodies within the absolute ingress cap |
| `signature_status` | `unresolved` / `invalid` / `valid` — did this key sign these bytes? |
| `eligibility_at_receipt` | `n/a` / `eligible` / `not_eligible` — was that credential admitted at `received_at`? |
| `key_id` | as presented; meaningless until resolved, kept for triage |
| `authenticated_deployment_ref` | the PROVEN identity, NULL unless `signature_status = valid` |
| `report_id`, `claimed_deployment_ref` | parsed from the payload; evidence only |
| `signature` (bytes) | so a verified attempt stays independently checkable |
| `disposition` | accepted / idempotent-replay / conflict / unknown-key / malformed / bad-signature / not-eligible / deployment-mismatch / body-too-large |
| `report_ref` | FK to the canonical report row when one was established, else NULL |

A row is written on EVERY path, including the ones that fail before an identity
exists, because an unknown `key_id` or a bad signature against a known one is
precisely the evidence an operator needs and the thing a fail-closed system
would otherwise discard silently.

### Signature validity and eligibility are separate persisted facts

An earlier draft stored one `verification` flag meaning "valid under an
**eligible** credential". That collapses the two questions the eligibility
section is careful to distinguish, and it destroys information: garbage
naming a revoked key and a genuinely signed but late report from that same key
would both land as "not verified", which are completely different operational
events — the first is an attacker or a bug, the second is a deployment that was
offline during a rotation.

So resolve them independently:

- **`signature_status`** answers *did this key sign these bytes?* Verification
  material is resolved for any KNOWN `key_id` **regardless of lifecycle state**
  — including retired and revoked. A revoked key's signature is still a fact,
  and refusing to evaluate it would throw away the evidence that the compromised
  key is still being used. `unresolved` means no such `key_id` is registered,
  so there was nothing to check against.
- **`eligibility_at_receipt`** answers *was that credential admitted at
  `received_at`?* — the timeline predicate below. `n/a` when
  `signature_status` is not `valid`, because eligibility of an unproven claim
  is not a meaningful question.

**Only `eligibility_at_receipt = eligible` gates consequences.** A `valid` +
`not_eligible` attempt is recorded, attributable, and activates nothing.

### Two caps, not one

`raw_body` is attacker-controlled and unauthenticated at the moment it is
stored, so it needs bounding — but a single cap conflates two different
protections:

- **Evidence-storage cap.** Above this, `raw_body` is truncated and the flag is
  set. The row still exists and is still useful; only the stored copy of the
  bytes is shortened.
- **Absolute ingress/read cap.** Above this, the request is **not read at all**
  past the limit. This is the one that matters for safety: without it, "read
  the whole body, hash it, then truncate for storage" still reads and hashes
  unbounded attacker-supplied input, so the write amplifier is merely moved
  from disk to memory and CPU.

The pre-truncation digest is therefore sound **only for bodies within the
absolute cap** — it is a digest of everything that was legitimately read. Past
that cap there is no complete body to hash, and claiming a digest would be a
lie about evidence we never held.

A body beyond the absolute cap is recorded as `body-too-large`: an attempt row
with whatever prefix the evidence cap allows, `raw_body_digest` NULL, and
`signature_status = unresolved`. Refusing to store anything would discard the
signal that someone is posting oversized payloads.

### Capturing receipt time

`received_at` is the trusted instant the entire eligibility rule rests on, so
where it comes from is part of the contract, not an implementation detail:

- **From the same database clock** as `activated_at`, `retired_at` and
  `revoked_at`. Comparing an application-server timestamp against
  database-written lifecycle timestamps compares two clocks that drift
  independently, and a few hundred milliseconds of skew at a revocation
  boundary decides whether a compromised key's report is admitted.
- **After the complete bounded body has arrived**, and **before parsing
  begins.** Both halves matter. Stamping at request *start* lets a slow or
  chunked upload begin before a revocation and finish after it while keeping
  the earlier timestamp — a trivially exploitable way to be admitted by a key
  that was revoked mid-transfer. Stamping after parsing makes the receipt time
  depend on how long parsing took, which is attacker-influenced through payload
  shape.

So: read up to the absolute cap, stop, take the database clock, then parse.

### `applied_state_reports` — one canonical row per idempotency key

| Column | Purpose |
|---|---|
| `authenticated_deployment_ref` + `report_id` | **UNIQUE together** — the idempotency key, scoped to the proven identity so one deployment's `report_id` can never collide with another's |
| `payload` (bytes) | the exact signed bytes of the **first eligible verified arrival** |
| `payload_digest` | `sha256:` of those bytes — the replay discriminator |
| `key_id` | which credential verified it — attributable after rotation |
| `first_received_at` | the receipt time that decided eligibility |
| `original_verdict` | the verdict returned to every subsequent identical replay |

"First **eligible verified** arrival", not "first accepted": a report can be
validly signed, eligible, and still be **quarantined by the projection** —
unknown digest, deployment mismatch, a version we never issued. Those establish
the canonical row too, and their verdict must be just as stable as an
activation's. Keying only on accepted reports would let a quarantined report_id
be re-sent with different bytes and re-decided, which is exactly the
re-litigation the idempotency key exists to prevent.

Storing the exact bytes and signature — not a parsed projection of them — is
what keeps the report portable evidence a third party can verify, which is the
property ADR-0007 §1 justifies Ed25519 with in the first place.

### Idempotency

On an eligible verified arrival, the admission service compares the incoming
digest to the canonical row's `payload_digest`:

| Case | Verdict |
|---|---|
| No canonical row yet | Create it; proceed to consequences |
| Same key, same digest | **Idempotent replay** — return `original_verdict`, change nothing but the attempt log |
| Same key, different digest | **Conflict → quarantine** — one of the two is forged or a receiver bug; never pick one. Both arrivals survive as attempt rows |
| Older valid report | **Retained as evidence**, may never regress active state |

Every one of these writes an attempt row. Only the first writes a canonical
row. The conflicting bytes are preserved in the attempt log, which is the whole
reason for the split.

Returning `original_verdict` (rather than recomputing) matters: recomputation
against changed licence state could yield a different answer for bytes the
deployment sent once, which would make an at-least-once transport look like a
state change.

### Concurrent first arrivals

"No canonical row yet" cannot be decided by looking. Two simultaneous first
arrivals both observe no row, and both proceed — at-least-once delivery plus a
retrying transport makes this ordinary, not exotic. The read-then-insert race
must be resolved by the database, so the algorithm is part of the contract:

1. **Insert the attempt row in the OUTER transaction.** Evidence is never
   contingent on winning a race; it is written before any contended work.
2. **Attempt the canonical insert inside `conflict_savepoint`** (the kernel's
   conflict-handling seam — feature services never call `db.rollback()`; the
   mutation goes INSIDE the `with` block). Let the unique constraint on
   `(authenticated_deployment_ref, report_id)` be the arbiter.
3. **On a uniqueness collision, load and lock the committed winner**
   (`SELECT ... FOR UPDATE`) and compare digests. Identical bytes are an
   idempotent replay returning the winner's `original_verdict`; different bytes
   are a conflict.
4. **Preserve the losing attempt either way**, with `report_ref` pointing at
   the winner. The loser is not noise — under identical bytes it is the proof
   that delivery retried, and under different bytes it is half the evidence of
   a conflict.

The loser must NOT re-run consequences. It resolves to the winner's verdict, so
two racing identical reports activate a delivery exactly once.

This needs **Postgres canaries**, not SQLite unit tests — the behaviour under
test is a real unique-constraint collision between concurrent transactions,
which the in-memory lane cannot reproduce. Two cases: simultaneous **identical**
first arrivals (both succeed, one verdict, one activation) and simultaneous
**divergent** first arrivals (one canonical row, the other a conflict, both
byte sequences retained).

A freshness window is deliberately NOT used. Applied state is legitimately
delayed — a deployment that was offline reports late — so a timestamp window
would reject exactly the reports the pipeline most needs.

## Credential eligibility and revocation

Eligibility is decided against the **persisted server `received_at`**, never
against the payload's `observed_at` and never against "now" at the moment a
background job happens to re-evaluate.

### Two different questions

Conflating these produced a contradiction in an earlier draft, where `retired`
credentials could admit new reports forever while acceptance case 14 said a
revoked key never verifies:

- **Cryptographic attribution** — *did this key sign these bytes?* Independent
  of lifecycle. Old key material stays verifiable evidence permanently; that is
  what makes a signed report checkable by a third party years later, and
  retiring a key must not retroactively make its past attestations
  unverifiable.
- **Admission eligibility** — *may a report received at time T activate
  anything?* Decided entirely by the persisted timeline.

They are separate, and only the second gates consequences.

### The eligibility predicate

Decided against the **persisted server `received_at`** of that report:

```
activated_at  <= received_at
AND (retired_at IS NULL OR received_at <  retired_at)
AND (revoked_at IS NULL OR received_at <  revoked_at)
```

Read as a window: a credential admits exactly the reports received **from** its
activation, **up to but not including** its retirement or revocation.

Each clause earns its place:

- `activated_at <= received_at` — a `pending` credential admits nothing, and a
  report that arrived *before* possession was proven cannot be retro-admitted
  by later activation. Without this clause, activating a key would silently
  bless everything it had already sent.
- `received_at < retired_at` — retirement ENDS admission. Rotation overlap is
  provided by the two windows overlapping in time, not by a retired key
  accepting new work indefinitely.
- `received_at < revoked_at` — revocation ends admission at its instant.

Both boundaries are **closed against the credential**: a report received at the
exact retirement or revocation instant is refused, because the alternative
resolves a tie in favour of a key the operator has just stood down or declared
compromised.

The whole point is that the test uses a timestamp the **vendor** wrote. The
report's own `observed_at` is a claim inside data the holder of a compromised
key controls, so revocation decided from it could be evaded simply by writing
an earlier timestamp. Persisting `received_at` at ingestion also makes the
decision reproducible: re-running eligibility later yields the same answer it
did at receipt, which a `now()`-based test would not.

Retirement and revocation remain different in intent — one is planned
rotation, the other is a compromise response — but **neither is reversible in
this model, and retirement is not "softer" in effect**. A credential has ONE
eligibility interval. Reactivating a retired key would require modelling
multiple intervals per credential, and until that exists, un-setting
`retired_at` would silently re-admit every report received during the gap. If
a retired key must be used again, register a new credential and prove
possession again.

Revocation is additionally terminal at the identity level: a revoked `key_id`
is never reinstated, which is why its uniqueness constraint spans all states.

What both share is that neither un-signs anything: reports already admitted
stay admitted, and past signatures stay independently verifiable.

## Rotation

Registering a new key while the old one is `active` is normal and expected;
overlapping active keys are the mechanism, not an anomaly. The deployment cuts
over on its own schedule, and the old key is retired afterwards.

Overlap is expressed as **overlapping eligibility windows**, not as a retired
key continuing to admit work: the new credential's `activated_at` precedes the
old one's `retired_at`, so both windows cover the changeover period and either
key's reports are admitted during it. Retiring the old key then closes its
window at a definite instant rather than leaving it open-ended.

Each key carries its own timeline independently, so a report is always
attributable to the specific credential that signed it — and remains so after
both are retired.

## The body's claim stays evidence

`ReceiverAppliedState.deployment_ref` is what the reporter *says*. The proven
identity is what `key_id` *resolves to*. They are stored in separate columns
and never merged.

When they disagree, the report is **quarantined** as `deployment_mismatch`:
recorded as evidence, activating nothing. It is a contradiction, not a mistake
to be resolved in the caller's favour. The kernel already exposes this as
`VerifiedAppliedState.claim_matches_proof`.

### Mapping to the legacy acknowledgement vocabulary

An authenticated `ReceiverAppliedState` must be mapped explicitly onto the
existing `AcknowledgementInput` fields — no implicit reuse, so a future change
to either vocabulary is a visible edit here:

| `ReceiverAppliedState` | `AcknowledgementInput` | Note |
|---|---|---|
| `licence_id` | `licence_id` | |
| `licence_version` | `licence_version` | |
| `digest` | `digest` | matched against the issued digest, unchanged |
| `status` (`applied`/`rejected`) | `status` | same vocabulary |
| `reason` | `reason` | rejection reason, unchanged |
| `deployment_ref` (**claim**) | `deployment_id` (**claim**) | evidence only, both sides |
| resolved from `key_id` | `authenticated_deployment_ref` | the PROVEN identity |
| `report_id`, `keyring_generation`, `revocation_list_version`, `observed_at` | — | no legacy home; live on the receipt row |

The last row is the reason the receipt tables exist rather than columns bolted
onto `LicenceAckRecord`: the signed report carries facts the acknowledgement
vocabulary has no place for, and those facts (keyring generation, applied
revocation-list version) are precisely what make keyring-uptake and
revocation-application lag measurable.

## Acceptance cases

**Enrollment and credentials**

1. Registration without an active `LicenceDeliveryTarget` for that
   `deployment_ref` is refused.
2. The registration audit records the asserting admin and that the authority
   was the interim admin policy.
3. A target going inactive or being deleted does NOT retire, revoke or
   otherwise disturb an existing credential.
4. An architecture canary fails if `LicenceDeliveryTarget` is read anywhere in
   the credential path except registration.
5. A newly registered credential is `pending` and authenticates nothing.
6. The same public key cannot be registered under a second `key_id`
   (fingerprint uniqueness), and the fingerprint is computed on decoded bytes —
   a re-encoded base64 variant of the same key is still refused.
7. A revoked `key_id` cannot be re-registered, in any state.

**Possession**

8. A correct possession response activates the credential, consumes the
   challenge, and invalidates sibling challenges — all in one transaction.
9. Replaying a consumed challenge response activates nothing.
10. A FAILED possession attempt leaves the challenge outstanding: the correct
    response still activates afterwards. Burning a challenge with a bad
    signature must not deny enrollment.
11. Invalid attempts are counted per challenge and per credential.
12. An expired challenge is refused as expired, not as a bad signature.
13. A response naming a different challenge or key is a mismatch, not a
    signature failure.

**Admission and eligibility**

14. A valid signed report resolves to the proven `deployment_ref` and, when
    version and digest match, activates the delivery.
15. A report received BEFORE `activated_at` is refused, and later activation
    does not retro-admit it.
16. A report received at or after `retired_at` is refused admission, even
    though its signature still verifies — attribution and eligibility are
    separate.
17. A report received at or after `revoked_at` is refused, including when its
    payload `observed_at` is backdated to before it. Both boundaries are
    closed against the credential (`received_at == retired_at` and
    `received_at == revoked_at` both fail).
18. During rotation overlap, a report received while two credentials' windows
    both cover it is admitted and attributed to the key that signed it.
19. A signature made by a retired or revoked key remains independently
    verifiable as evidence — lifecycle never un-signs anything.
20. A late but genuinely signed report from a revoked key records
    `signature_status = valid` with `eligibility_at_receipt = not_eligible`,
    and is distinguishable in the log from garbage naming that same `key_id`
    (`signature_status = invalid`).
21. `status`, if stored, cannot disagree with the timestamps — a direct SQL
    write setting `active` alongside a non-NULL `revoked_at` is refused by the
    check constraint.

**Receipts and replay**

22. Every arrival writes an attempt row, including unknown `key_id`, malformed
    envelope and bad signature; those carry a NULL
    `authenticated_deployment_ref`.
23. A body within the absolute ingress cap but over the evidence cap is
    truncated with the flag set, and its digest — computed before truncation —
    still distinguishes it from a different oversized body.
24. A body beyond the ABSOLUTE ingress cap is refused as `body-too-large`
    without being read past the limit, records a NULL `raw_body_digest`, and
    still writes an attempt row.
25. `received_at` comes from the database clock and is stamped after the body
    is fully read and before parsing: a request that begins before a revocation
    and completes after it is NOT admitted.
26. Two simultaneous IDENTICAL first arrivals produce one canonical row, one
    verdict and exactly one activation; both attempt rows survive.
27. Two simultaneous DIVERGENT first arrivals produce one canonical row and one
    conflict; both byte sequences are retained.
28. A byte-identical signed replay returns the ORIGINAL verdict, changes
    nothing, and appends an attempt row.
29. The same `report_id` with different bytes quarantines as a conflict, and
    BOTH byte sequences survive in the attempt log.
30. A report whose signed body claims another deployment is quarantined as
    `deployment_mismatch` and activates nothing.
31. A report QUARANTINED by the projection still establishes the canonical row,
    and re-sending that `report_id` with different bytes is a conflict rather
    than a fresh decision.
32. An older valid report is retained as evidence and cannot regress a newer
    active state.

**Adapters**

33. Admin ingestion cannot supply a proven identity — asserted structurally,
    not merely behaviourally — and always records `unverified_identity`.

## Dependencies and sequencing

| Dependency | Status |
|---|---|
| Kernel ADR-0007 contract (`dotmac-kernel==0.1.0a9`) | **published + pinned** (#30) |
| `EntitlementProjectionService` delivery/ack state | merged (V4) |
| `LicenceDeliveryTarget` (enrollment stopgap) | merged (V4) |
| `FleetDesiredStateService` (real enrollment authority) | **not built** — see "Enrollment authority" |
| Starter receiver signer + transactional outbox | parallel slice; closes the end-to-end proof |

Implementation lands one guarded slice at a time, each with its migration,
typed idempotent commands, platform audit, thin routes and Postgres
rehearsals:

1. `DeploymentCredentialService`: registry + challenge issuance/activation
   (migration, service, admin routes, enrollment audit provenance, the narrow
   delivery-target reader and its architecture canary).
2. `AppliedStateAdmissionService`: both receipt tables, authenticated
   ingestion, and the two-adapter split of the projection entry points.
3. Rotation, retirement and revocation commands, and the full receipt-time
   eligibility window (`activated_at`/`retired_at`/`revoked_at`).

**Ruled:** slice 1 creates ALL timeline columns and sets `activated_at`; slice
2 consumes the complete predicate; slice 3 adds the retirement/revocation
transitions **without changing schema**. The eligibility rule therefore never
runs against a schema that cannot express it, and slice 3 is a behaviour change
rather than a migration against live credential rows.

Postgres rehearsals are mandatory for the concurrency canaries in slice 2
(simultaneous identical and divergent first arrivals) — the in-memory SQLite
lane cannot reproduce a unique-constraint collision between concurrent
transactions, so passing there would prove nothing.

The nine-case cross-plane proof against the starter receiver follows the third
slice; connected delivery is last, because transport automation is separate
from identity proof.
