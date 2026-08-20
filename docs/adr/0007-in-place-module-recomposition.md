# ADR-0007: Recompose Vendor in place, one authority at a time

- **Status:** Accepted
- **Date:** 2026-08-20
- **Owner:** Vendor control plane

## Context

The current `dotmac_vendor_control_plane` repository is already the named
product assembly. It owns one runtime, one control-plane database, platform
administration, deployment and the Vendor-specific adapters. Creating a new
repository for the released shared modules would create two candidate Vendor
control planes and split authority over those operational assets.

Kernel `0.1.0a77` and Commercial Agreements, Licensing, Deployment Control and
Brand Profiles `0.1.0a1` are published. Publication makes them installable; it
does not move any Vendor writer or prove product adoption.

The current hard rule saying "no fleet tables" also needs a precise owner. Its
premise is that Vendor must not grow a local fleet engine beside the shared
Deployment Control owner. Read literally, it would also forbid that owner's
`mod_deploy` tables and make the approved composition impossible.

## Decision

Retain this repository, runtime and database as the Vendor assembly. Recompose
it through expand/migrate/contract changes, never through a replacement repo or
a parallel application.

1. Upgrade the existing kernel pin from a61 to a77 as a compatibility change.
   This step composes no new module and moves no domain authority. Because the
   cumulative jump crosses a68, declare every existing Vendor platform-audit
   action on exactly one installed feature manifest before taking the pin.
2. Cut Commercial Agreements over first. Its change must pin and compose a1,
   migrate contract rows without changing content hashes, derive history only
   from real audit evidence, switch the adapter once, and retire the local
   contracts owner.
3. Cut the Licensing issuer over next. Preserve signed envelopes byte-for-byte,
   migrate only public verification material, preserve revocation continuity,
   and retire the issuer half while keeping Vendor's delivery adapter until its
   separately owned transport boundary moves.
4. Compose Deployment Control a1 as a greenfield platform owner. Module-owned
   desired-state tables in `mod_deploy` are permitted by this decision;
   Vendor-owned fleet tables, a Vendor `DeploymentRunner`, provider clients,
   provider credentials, connector retries and schedules remain forbidden.
   External execution stays in Dotmac Integrator. The abandoned local V6 PR
   line is retired when this composition lands.
5. Compose Brand Profiles' platform plane only after the checked-in Sub-first
   adoption completes. Reversing that order requires an explicit amendment to
   the extraction decision; Vendor will not silently become the first adopter.

Every authority-moving step requires its own cutover ADR or dated amendment,
data premise, forward migration, one-writer proof, focused architecture and
behaviour tests, and retirement of the replaced local owner. Exact-pinning an
unused module in advance is not progress and is forbidden: the package enters
with the coherent slice that consumes it.

## Consequences

- Existing routes, authentication, operator configuration, deployment history
  and the control-plane database remain continuous.
- The kernel uplift can land independently and be validated without claiming
  that any of the four modules is composed or adopted.
- Deployment state may eventually exist in this database under its independent
  module schema without reopening a Vendor-local fleet or connector engine.
- Brand Profiles preserves the published first-adopter evidence order.
- Adoption evidence is recorded only after a product has actually run the
  released owner with its former local writer absent.
