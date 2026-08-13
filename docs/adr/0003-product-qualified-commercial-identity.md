# ADR-0003: Commercial identity is product-qualified at the offer boundary

- **Status:** Accepted
- **Date:** 2026-08-13
- **Owner:** Vendor commercial control plane

## Context

The original vendor implementation published offers and contracts without a
product identity. Licence issuance accepted a caller-supplied product later. That
made it possible to validate a capability in one global configured catalogue,
stage an allocation, and relabel it for another product during issuance. It also
left no truthful `product_code` with which to construct the independent
Entitlement Allocation module's `ContractSnapshot`.

Existing rows cannot be classified mechanically: neither their offer pins,
contract events nor legacy allocations contain evidence naming a product. A
default would manufacture provenance rather than recover it.

## Decision

1. `OfferVersion` is identified by `(product_code, offer_code, version)`.
   Product identity is supplied when the immutable version is published and is
   never rewritten.
2. A contract names one product and may pin only offer versions owned by that
   product. `product_code` is part of its approval-bound content hash and every
   `contract.*` audit/outbox payload.
3. Offer publication and contract submission consume a typed,
   product-qualified catalogue port. The assembly currently materialises that
   port from target-manifest snapshots; a capability declared for product A is
   undeclared for product B.
4. Migration v011 is an expand migration. Historical `product_code` values stay
   NULL. `NOT VALID` checks tolerate those rows but reject new or updated rows
   without a non-blank identity. Services fail closed on an unclassified row.
5. This does not cut allocation authority over. The legacy allocation writer
   remains the only writer until historical mapping, catalogue reconciliation,
   duplicate normalization, parity and licence-source changes all pass together.

## Consequences

- New commercial state can no longer be relabelled between products.
- Operators need an evidence-backed mapping for every historical offer and
  contract before the v011 constraints can be validated.
- Product-local offer codes can coexist without becoming a global naming
  convention.
- The structured environment snapshot is an adapter input, not a new authority;
  target application manifests remain authoritative for capability membership.
