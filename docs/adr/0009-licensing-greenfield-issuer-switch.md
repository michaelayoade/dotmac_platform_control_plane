# ADR-0009: Licensing greenfield issuer authority switch

- **Status:** Accepted
- **Date:** 2026-08-20
- **Owner:** Vendor control plane / `dotmac-licensing`

## Context

ADR-0007 orders the Licensing issuer cutover after Commercial Agreements. The
published `dotmac-licensing==0.1.0a1` was extracted product-first from this
repository and owns licence lineage, immutable signed issuances, public
verification-key registration, lifecycle, installation acknowledgements and
revocation. Vendor separately owns product-held private-key custody and
temporarily owns the delivery projection/transport adapter pending ADR-0010.

A populated cutover has three non-negotiable constraints: signed envelopes are
copied byte-for-byte rather than re-serialized, only public verification
material enters the module database, and the revocation-list version plus
cumulative revoked set continue without reset. The authorized observation of
the designated Vendor target was `TARGET_ABSENT`: no database service and no
data volume. There is therefore no issuer estate to migrate. Synthesizing keys,
envelopes, acknowledgements or revocation history would fabricate authority and
evidence.

Delivery remains a different owner. Its local tables include quarantined
acknowledgements that may deliberately name no known issuance; those records
must survive this issuer switch.

## Decision

Vendor switches the issuer directly in one coherent change:

1. Exact-pin `dotmac-licensing==0.1.0a1`, compose its public manifest and
   `versions_dir()`, and bind its idempotency and platform-audit prerequisites
   to the existing kernel providers.
2. Make `vendor_cp.licensing.adapter` the only module seam. It builds a
   `LicensableGrant` from an immutable staged allocation plus its active
   agreement snapshot, and passes product-held signers from
   `vendor_cp.licensing.signing_adapter`.
3. Keep private key material outside the module and database. Only the signer's
   public half is registered by the module before use.
4. Keep Vendor delivery tables, projection, health signals and transports.
   Their `issuance_id` is an opaque reference resolved through the typed
   adapter; no foreign key or ORM import crosses into the module lineage.
5. Forward only authenticated, issuer-valid installation reports to the module.
   Unverified, mismatched and unknown reports stay as Vendor delivery evidence
   and cannot activate either owner.
6. Apply Vendor revision `v016_licensing_authority`. It locks the five legacy
   issuer tables and deliveries, rechecks that the issuer estate is empty,
   discovers and drops delivery's foreign key into that estate, then drops only
   the issuer tables. Any legacy issuer row aborts the transaction and requires
   a separate populated-estate migration satisfying all three constraints
   above.
7. Delete the local issuer and revocation modules. Rename the retained product
   signer and delivery operations so their paths cannot be mistaken for issuer
   ownership. The shared module becomes the sole issuer
   audit/outbox/lifecycle writer.

## Amendment to ADR-0007 step 3

The byte-preserving data migration remains mandatory for any populated estate.
For this directly measured greenfield target it has no rows to act on and is
superseded by the checked empty-estate switch. If `v016` observes any issuer
row, this amendment's premise is false and the migration stops before changing
either owner.

## Consequences

- `mod_licensing` is the only issuer persistence namespace.
- Vendor's five delivery tables and quarantined acknowledgement evidence remain
  in `public`; the issuer's five legacy tables do not.
- Existing route prefixes, signing configuration and delivery operations remain
  continuous while issuer facts adopt the module's versioned event vocabulary.
- This establishes composition and code authority, not production adoption.
  Starter adoption evidence changes only after Vendor actually runs the module
  with the former issuer absent.
- Deployment Control a1 is the next ADR-0007 authority slice. ADR-0010 then
  moves the deliberately retained delivery/retry boundary to Dotmac Integrator
  before Brand Profiles.

## Lifecycle — adopted 2026-08-21

Deploy run `32485479666` took production to
`af9fcf6d3fbd259fbef6b589d37b39d548f7ba8e` at image
`sha256:45715e425dc248d85fe374fa5d347087328a445cf7ead1f8abc29f05f0117b0d`,
applying `v016` in the same run as kernel `0024`–`0026`, `v015` and the a5/a6
verification revisions.

Verified directly against that database at 2026-08-21T14:17:32Z:

- `mod_licensing` live with six tables;
- all five local issuer tables **absent** — `licences`, `licence_issuances`,
  `licence_signing_keys`, `revocation_lists`, `revocation_entries`;
- `app_user` holding **zero** privileges on any `mod_*` schema.

`v016`'s under-lock recheck did not abort, so the five tables were empty at
execution time as well as at observation time.

**What this does NOT adopt.** Vendor's retained delivery projection and
transport evidence — `licence_delivery_targets`, `licence_deliveries`,
`licence_delivery_states`, `licence_delivery_attempts`, `licence_ack_records` —
remain Vendor-owned and were measured empty on the same database. ADR-0010
RETIRES that path rather than adopting it, so it has no adoption milestone to
reach. Its estate measurement is recorded in ADR-0011 § 4.

**Owed at the extraction source:** `packages/dotmac-licensing/EXTRACTION.toml` in
`dotmac_starter_mt` should gain this assembly as a contract consumer and this run
as adoption evidence. That dossier is the authority (`AGENTS.md` rule 17).
