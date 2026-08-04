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

- **`DeploymentCredentialService`** (new) owns the credential: registration,
  possession challenges, activation, rotation, retirement, revocation, and the
  resolution of a signed applied-state report to a **proven**
  `deployment_ref`. It decides nothing about entitlements.
- **`EntitlementProjectionService`** (existing) continues to own delivery and
  acknowledgement state, and consumes the proven identity exactly where it
  already accepts `authenticated_deployment_ref`. Its digest/version/binding
  rules are untouched.
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
- **`active`** — possession proven. Verifies reports and may be used for new
  ones.
- **`retired`** — rotated out. Stops authenticating new reports but stays
  attributable for what it already signed.
- **`revoked`** — terminal. See "Revocation" below.

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

## Enrollment authority

Registration requires an **authorized enrollment subject**. Anyone who can
register an arbitrary `deployment_ref` can create an identity the fleet never
authorised, and the possession challenge would then faithfully prove control
of a key bound to a deployment that does not exist.

The authoritative Deployment entity belongs to `FleetDesiredStateService`,
which is not built. Until it is, registration requires an **`active`
`LicenceDeliveryTarget`** whose `target_ref` matches the `deployment_ref`
being registered.

This is a stopgap and is documented as one. `LicenceDeliveryTarget` is
explicitly a *licensing-owned delivery projection*, not the Deployment
authority — its own docstring says so, and `docs/design/domain-foundation.md`
assigns that entity elsewhere. Using it as the enrollment gate is a deliberate,
bounded borrow: it is the only checked-in record of "a place this customer's
licences may legitimately go", and gating on it is strictly better than
gating on nothing. When the fleet slice lands, this check moves to the real
authority and the projection stops being consulted for authorisation. Do not
let the borrow calcify into ownership: no code may treat a delivery target as
proof that a deployment exists for any purpose beyond this gate.

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

A challenge is single-use whether it succeeds or fails to the point of
consumption; expiry is checked before the signature, because "expired" and
"bad signature" send an operator to completely different places.

## Applied-state receipts

`LicenceAckRecord` is the legacy acknowledgement log. It cannot serve as the
record of a signed report: it has no `report_id`, no signed bytes, no
`key_id`, no server receipt time, and no replay digest. Extending it would
also blur two different things — an operator-submitted claim and a
cryptographically signed attestation.

A new **append-only `applied_state_receipts`** table records every
authenticated report:

| Column | Purpose |
|---|---|
| `report_id` | the receiver's idempotency key, from the signed payload |
| `authenticated_deployment_ref` | the PROVEN identity, resolved from `key_id` |
| `key_id` | which credential verified it — attributable after rotation |
| `payload` (bytes) | the EXACT signed bytes, never a re-serialisation |
| `signature` (bytes) | so the evidence stays independently checkable |
| `payload_digest` | `sha256:` of the signed bytes — the replay discriminator |
| `received_at` | server clock, set on receipt (see below) |
| `claimed_deployment_ref` | the body's claim, evidence only |
| `disposition` | accepted / idempotent-replay / conflict / quarantined |

Storing the exact bytes and signature — not a parsed projection of them — is
what keeps the report portable evidence a third party can verify, which is the
property ADR-0007 §1 justifies Ed25519 with in the first place.

### Idempotency

**`(authenticated_deployment_ref, report_id)` is unique**, scoped to the proven
identity so one deployment's `report_id` can never collide with another's.
Three cases, distinguished by comparing `payload_digest`:

| Case | Verdict |
|---|---|
| Same key, same digest | **Idempotent replay** — return the ORIGINAL verdict, change nothing |
| Same key, different digest | **Conflict → quarantine** — one of the two is forged or a receiver bug; never pick one |
| Older valid report | **Retained as evidence**, may never regress active state |

Returning the original verdict (rather than recomputing) matters: recomputation
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

A credential is eligible for a report when its status is `active` or
`retired` at that instant, and:

```
revoked_at IS NULL OR revoked_at > received_at
```

Equivalently: **`revoked_at <= received_at` fails.** The boundary is closed
against the credential — a report received at the exact revocation instant is
refused, because the alternative resolves a tie in favour of a key the
operator has just declared compromised.

The whole point is that the test uses a timestamp the **vendor** wrote. The
report's own `observed_at` is a claim inside data the holder of a compromised
key controls, so revocation decided from it could be evaded simply by writing
an earlier timestamp. Persisting `received_at` at ingestion also makes the
decision reproducible: re-running eligibility later yields the same answer it
did at receipt, which a `now()`-based test would not.

Retirement and revocation stay different: a `retired` key stops being offered
for NEW reports but still verifies what it already signed, which is what makes
rotation overlap safe.

## Rotation

Registering a new key while the old one is `active` is normal and expected;
overlapping active keys are the mechanism, not an anomaly. The deployment cuts
over on its own schedule, and the old key is retired afterwards. Each key
independently carries its own state and timestamps, so a report is always
attributable to the specific credential that verified it.

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

The last row is the reason the receipt table exists rather than columns bolted
onto `LicenceAckRecord`: the signed report carries facts the acknowledgement
vocabulary has no place for, and those facts (keyring generation, applied
revocation-list version) are precisely what make keyring-uptake and
revocation-application lag measurable.

## Acceptance cases

1. Registration without an active `LicenceDeliveryTarget` for that
   `deployment_ref` is refused.
2. A newly registered credential is `pending` and authenticates nothing.
3. A correct possession response activates the credential, consumes the
   challenge, and invalidates sibling challenges — all in one transaction.
4. Replaying a consumed challenge response activates nothing.
5. An expired challenge is refused as expired, not as a bad signature.
6. A response naming a different challenge or key is a mismatch, not a
   signature failure.
7. The same public key cannot be registered under a second `key_id`
   (fingerprint uniqueness), and the fingerprint is computed on decoded bytes —
   a re-encoded base64 variant of the same key is still refused.
8. A revoked `key_id` cannot be re-registered, in any state.
9. A valid signed report resolves to the proven `deployment_ref` and, when
   version and digest match, activates the delivery.
10. A byte-identical signed replay returns the ORIGINAL verdict and changes
    nothing.
11. The same `report_id` with different bytes quarantines as a conflict.
12. A report whose signed body claims another deployment is quarantined as
    `deployment_mismatch` and activates nothing.
13. A report received after revocation is refused even when its payload
    `observed_at` is backdated to before it.
14. A report signed by a `retired` key still verifies; one signed by a
    `revoked` key never does.
15. An older valid report is retained as evidence and cannot regress a newer
    active state.
16. Admin ingestion cannot supply a proven identity — asserted structurally,
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

1. Credential registry + challenge issuance/activation (migration, service,
   admin routes).
2. Authenticated applied-state ingestion + receipt table + the two-adapter
   split of the projection entry points.
3. Rotation, retirement and revocation commands with the receipt-time
   eligibility rule.

The nine-case cross-plane proof against the starter receiver follows the third
slice; connected delivery is last, because transport automation is separate
from identity proof.
