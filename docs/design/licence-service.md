# LicenceIssuanceService + EntitlementProjectionService — WS8 vendor slice design

> **Status:** Implementation brief (2026-08-01). The kernel WS8 contract has
> **published** (dotmac-kernel **0.1.0a7**: `dotmac_kernel.licensing` — DSSE
> envelope, Ed25519 keyring, offline fail-closed `verify_licence`,
> `verify_revocation_list`, `LicenceAcknowledgement`; design brief
> `dotmac_starter_mt/docs/superpowers/reviews/2026-08-01-ws8-signed-licence-design.md`).
> This document fixes the VENDOR side: issuance, key custody, versioned
> delivery, revocation-list publication, and acknowledgement tracking. The
> authoritative lifecycle is `docs/design/domain-foundation.md` § "Licence /
> entitlement-allocation lifecycle"; this is the focused service view and
> defers to it on any conflict.

## Owners and scope

Two owners, per the domain-foundation lifecycle — deliberately not one:

- **`LicenceIssuanceService`** owns the **signed document**: building the
  `dotmac-licence/1` payload from a staged `Allocation`, lineage/version
  assignment, signing (`staged → issued`), renewal/supersession
  (`active → superseded`), revocation entries, and signed revocation-list
  publication. It is the only code that touches the private signing key
  interface.
- **`EntitlementProjectionService`** owns **delivery and acknowledgement
  state**: staging an immutable `LicenceDelivery` (`issued → delivered`),
  recording inbound acknowledgements (`delivered → active` on an `applied`
  ack; operator-visible on `rejected`), and exposing delivery/ack status.
  It never signs and never builds documents.

Neither owner writes a product database, ever (ruling C4; deny-case **D1**
already makes a product DSN structurally impossible). Delivery is an
authenticated API call / webhook / offline bundle carrying the envelope; the
product data plane verifies with kernel `verify_licence`, writes its OWN WS2
grants, and acks the applied `(licence_id, licence_version, digest)`.

## Document production (from staged allocation)

- **Source of truth:** an immutable `Allocation` (unique per
  `(contract_id, content_hash)`). Issuance reads the allocation's entries; it
  never re-derives from contract lines (one derivation owner —
  `AllocationService`).
- **Lineage:** one licence lineage per `(customer_ref, product)` under the
  contract family. `licence_id` is minted at FIRST issuance for the lineage
  and reused by every subsequent issuance (renewal, amendment, re-issue after
  key compromise); `licence_version` is a strictly monotonic integer assigned
  by the issuance transaction (`max(version) + 1` under the lineage lock).
  This matches the kernel verifier's replay/rollback guard exactly.
- **Payload mapping:** `capabilities[]` from `AllocationEntry`
  (`code` = `capability_code`, `limits = {"quantity": n}` plus any declared
  limit strategy); `subject.customer` = `customer_ref`;
  `subject.deployment_id` present **when the contract binds a deployment**
  (contracted choice, mirrored by the receiver's `require_binding`);
  `issued_at`/`not_before`/`expires_at` from the contract term;
  `grace_days` from the **versioned commercial policy** (never an evaluator
  guess); `constraints` from contracted operational semantics, uninterpreted.
- **The envelope bytes are frozen at issuance.** The exact payload bytes,
  their `sha256:` digest, the envelope JSON, and the signing `key_id` are
  stored on the issuance row. Any change is a NEW version — never an in-place
  edit (same immutability rule as contract versions).

## Signing and key custody

- **Algorithm/format:** exactly the kernel contract — Ed25519 over the payload
  bytes, `dotmac-licence-envelope/1`. Compatibility is proven, not assumed:
  the acceptance suite round-trips every issued envelope through the PINNED
  kernel's `verify_licence` (and revocation lists through
  `verify_revocation_list`). The vendor CP never re-implements or forks the
  verifier.
- **Private-key interface, not key material:** `LicenceSignerProvider` is a
  narrow protocol (`key_id`, `public_key_b64`, `sign(payload: bytes) ->
  signature bytes`). Two modes behind `VENDOR_LICENCE_SIGNING_MODE`:
  - **`ephemeral`** (default; the only mode this phase, matching the D3
    fake-provider posture): an in-memory key generated at startup — dev/test
    only, never persisted.
  - **`configured`** (later phase, design here only): key material loaded
    from a file/env reference whose CANONICAL source is OpenBao
    (`secret/dotmac/licensing/signing-key` — pointer only; the value never
    appears in code, config files, logs, or the database). A non-`ephemeral`
    mode without a resolvable key FAILS STARTUP (same fail-closed posture as
    `VENDOR_PROVIDER_MODE`).
- **Key registry (public material only):** `licence_signing_keys` — `key_id`,
  `public_key_b64`, `status` (`active`/`retired`/`revoked`), timestamps. This
  is the source the distributed keyring is built from; rotation is: insert
  new `active` key → issue new versions under it → mark the old key
  `retired` (installed base keeps verifying) → `revoked` only on compromise
  (with re-issuance of affected lineages at a higher version). The table
  never has a private-key column — structurally, not by convention.

## Delivery (versioned, transport-agnostic, no product writes)

- `EntitlementProjectionService` stages an immutable **`LicenceDelivery`** row
  per issued version: the envelope JSON, digest, target reference, and
  delivery state — and emits `licence.issued` / `licence.delivered` **platform
  outbox events** atomically with the state change (`enqueue_platform_event`,
  same channel discipline as `contract.*`).
- **Transport is a seam, not this slice:** real API/webhook/offline-bundle
  transports are later, contract-gated work; this phase records the staged
  delivery and emits the event (fake/logging transport — D3 stays intact:
  no real-provider SDKs, no network side effects in tests).
- Re-delivery of the same version is expected (at-least-once) and harmless:
  the kernel verifier treats same-version+digest as an idempotent reapply.

## Acknowledgement tracking (the vendor's inbound truth)

- **`LicenceAckRecord`** — one row per inbound acknowledgement:
  `(licence_id, licence_version, digest, status applied|rejected, reason,
  deployment_id, received_at)`, idempotent on
  `(licence_id, licence_version, digest, status)`. The payload vocabulary is
  the kernel's `LicenceAcknowledgement`; the vendor stores what the RECEIVER
  reported — it never infers activation.
- `delivered → active` happens ONLY on an `applied` ack whose digest matches
  the stored issuance digest (an ack for a digest the vendor never issued is
  recorded AND flagged — that is the tamper/mis-issue tripwire the digest
  exists for). A `rejected` ack keeps the delivery non-active with the stable
  kernel error-code reason, operator-visible.
- Inbound path: an authenticated platform surface (platform-admin token this
  phase; product-deployment identity is later, with the real transports).

## Revocation

- `revoke_licence(licence_id, reason)` (commercial admin / ContractService
  consequence) inserts a revocation entry; `publish_revocation_list()` signs a
  `dotmac-licence-revocation/1` payload containing ALL revoked licence ids at
  a **strictly monotonic `list_version`**, stored immutably like issuances.
  Connected and air-gapped deployments import the same signed artifact.
- Key revocation is registry `status`, distributed with the keyring — a
  separate mechanism from licence revocation, per the kernel design.

## Acceptance cases (the tests the implementation must pass)

1. **Round-trip against the pinned kernel:** every issued envelope verifies
   via `dotmac_kernel.licensing.verify_licence` with the registry-built
   keyring; a tampered byte fails. Revocation lists verify via
   `verify_revocation_list`.
2. **Lineage monotonicity:** re-issuance for a lineage yields the same
   `licence_id` and `version + 1`; two concurrent issuances cannot mint the
   same version (unique `(licence_id, licence_version)`).
3. **Issuance is immutable and atomic:** payload bytes/digest/key_id frozen on
   the row; state change + platform audit + `licence.issued` outbox event
   commit in one transaction (never audit-only).
4. **Capabilities come from the allocation:** the payload's capability set
   equals the staged allocation's entries; issuance rejects an allocation
   whose codes are no longer declared (WS1 `require`).
5. **Binding is contracted:** a deployment-bound contract produces a bound
   document; unbound otherwise — and the choice is recorded.
6. **Ack digest discipline:** `applied` ack with the issued digest activates;
   an ack with an unknown digest is recorded + flagged, never activates;
   `rejected` acks surface the kernel reason code; acks are idempotent.
7. **Rotation:** after key rotation, old-key documents still verify against
   the registry keyring (retired), new issuances use the new key; a revoked
   key's documents fail closed and affected lineages re-issue at a higher
   version.
8. **Revocation list is monotonic:** each publication bumps `list_version`;
   a re-import of the same version is idempotent (kernel guard proves it).
9. **No product-plane writes anywhere** (D1/D2 deny cases unchanged); no
   private key material in code, DB rows, fixtures, or logs — the ONLY
   private key in tests is ephemeral (`FakeLicenceSigner` or `ephemeral`
   mode).
10. **Fail-closed startup:** `VENDOR_LICENCE_SIGNING_MODE` other than
    `ephemeral` without resolvable key material refuses to boot (this phase:
    only `ephemeral` is accepted at all).

## Dependencies and sequencing

| Dependency | Status |
|---|---|
| Kernel WS8 (`dotmac_kernel.licensing`, testing signer, `licensing` extra) | **published — 0.1.0a7**, tagged `dotmac-kernel-v0.1.0a7` |
| Vendor repin `==0.1.0a7` (with the `licensing` extra alongside `testing`) | **first PR of this slice** |
| Staged `Allocation` (immutable, v005) | merged (#19) |
| Platform outbox channel | published (0.1.0a6), in use by ContractService |
| Reference product receiver (starter repo) proving verify → local WS2 grant → explainable decision → ack | parallel slice; closes the end-to-end proof |

Implementation lands one guarded slice at a time: (1) repin; (2) key registry +
`LicenceSignerProvider` (ephemeral) + `LicenceIssuanceService` with issuance
tables + round-trip tests; (3) `EntitlementProjectionService` delivery staging
+ ack recording + lifecycle projection; (4) revocation entries + signed list
publication. Each slice: migration, typed idempotent commands, platform audit,
thin routes, Postgres rehearsals.
