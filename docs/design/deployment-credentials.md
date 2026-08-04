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

The status column is a summary; **the three timestamps are the authority**,
because admission is decided for a report received at some past instant, not
for "now". A status check alone cannot answer whether a credential was
eligible when a given report arrived — see "The eligibility predicate".

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
never enroll. The nonce and the signature are the secrets; the identifiers are
an address.

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
| `received_at` | server clock, stamped on arrival, before any parsing |
| `raw_body` (bytes, **bounded**) | the EXACT inbound bytes, truncated at a configured cap with a flag recording that truncation occurred |
| `raw_body_digest` | `sha256:` over the full body as received, computed BEFORE truncation, so a truncated row is still comparable |
| `verification` | `untrusted` or `verified` — see below |
| `key_id` | as presented; meaningless until verified, kept for triage |
| `authenticated_deployment_ref` | the PROVEN identity, NULL unless `verification = verified` |
| `report_id`, `claimed_deployment_ref` | parsed from the payload; evidence only |
| `signature` (bytes) | so a verified attempt stays independently checkable |
| `disposition` | accepted / idempotent-replay / conflict / unknown-key / malformed / bad-signature / deployment-mismatch |
| `report_ref` | FK to the canonical report row when one was established, else NULL |

`verification` is a two-value fact and must not be inferred from other
columns: `untrusted` means nothing in this row may be believed — the bytes are
whatever arrived — and `verified` means the signature checked out under an
eligible credential. A row is written on EVERY path, including the ones that
fail before an identity exists, because an unknown `key_id` or a bad signature
against a known one is precisely the evidence an operator needs and the thing a
fail-closed system would otherwise discard silently.

`raw_body` is bounded because it is attacker-controlled and unauthenticated at
the moment it is stored. An unbounded column here is a free write amplifier for
anyone who can reach the endpoint. The pre-truncation digest is what keeps a
truncated row useful: two truncated attempts are still distinguishable.

### `applied_state_reports` — one canonical row per idempotency key

| Column | Purpose |
|---|---|
| `authenticated_deployment_ref` + `report_id` | **UNIQUE together** — the idempotency key, scoped to the proven identity so one deployment's `report_id` can never collide with another's |
| `payload` (bytes) | the exact signed bytes of the FIRST accepted arrival |
| `payload_digest` | `sha256:` of those bytes — the replay discriminator |
| `key_id` | which credential verified it — attributable after rotation |
| `first_received_at` | the receipt time that decided eligibility |
| `original_verdict` | the verdict returned to every subsequent identical replay |

Storing the exact bytes and signature — not a parsed projection of them — is
what keeps the report portable evidence a third party can verify, which is the
property ADR-0007 §1 justifies Ed25519 with in the first place.

### Idempotency

On a verified arrival, the admission service compares the incoming digest to
the canonical row's `payload_digest`:

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

Retirement and revocation remain different in kind even though both close the
window. Retirement is planned and reversible in principle; revocation is
terminal, and a revoked `key_id` is never reinstated (which is why its
uniqueness constraint spans all states). What they share is that neither
un-signs anything: reports already admitted stay admitted, and past signatures
stay verifiable.

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

**Receipts and replay**

20. Every arrival writes an attempt row, including unknown `key_id`, malformed
    envelope and bad signature; those rows carry `verification = untrusted` and
    a NULL `authenticated_deployment_ref`.
21. An oversized body is truncated with the flag set, and its digest — computed
    before truncation — still distinguishes it from a different oversized body.
22. A byte-identical signed replay returns the ORIGINAL verdict, changes
    nothing, and appends an attempt row.
23. The same `report_id` with different bytes quarantines as a conflict, and
    BOTH byte sequences survive in the attempt log.
24. A report whose signed body claims another deployment is quarantined as
    `deployment_mismatch` and activates nothing.
25. An older valid report is retained as evidence and cannot regress a newer
    active state.

**Adapters**

26. Admin ingestion cannot supply a proven identity — asserted structurally,
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

The eligibility predicate spans slices 1 and 3: slice 1 sets `activated_at`
and must already write the timeline columns, so slice 3 adds transitions
rather than retrofitting the schema the admission rule depends on.

The nine-case cross-plane proof against the starter receiver follows the third
slice; connected delivery is last, because transport automation is separate
from identity proof.
