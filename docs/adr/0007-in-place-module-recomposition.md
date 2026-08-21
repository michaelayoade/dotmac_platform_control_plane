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
5. Move licence delivery to Dotmac Integrator under ADR-0010. This follows
   Deployment Control so routing consumes its authoritative deployment
   reference, and it retires Vendor's target projection, transport attempts,
   retry/health policy and raw acknowledgement ledger after an explicit
   mirror/seal/activation proof.
6. Compose Brand Profiles' platform plane only after the checked-in Sub-first
   adoption completes. Reversing that order requires an explicit amendment to
   the extraction decision; Vendor will not silently become the first adopter.
7. Record adoption evidence only after each released owner actually runs with
   its former local writer absent.

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

## Amendment — 2026-08-20 (Commercial Agreements target is greenfield)

ADR-0008 records that the designated target was directly observed as
`TARGET_ABSENT`. Step 2's row-migration instruction therefore has no rows to act
on and is superseded for this target by a checked empty-estate switch. Vendor
revision `v015` rechecks the premise under `ACCESS EXCLUSIVE` and refuses a
populated table; it never synthesizes contracts, hashes or history.

## Amendment — 2026-08-20 (Licensing issuer target is greenfield)

ADR-0009 records that the same designated target observation applies to the
issuer estate. Revision `v016` rechecks all five local issuer tables under lock
and refuses any row, because a populated cutover must preserve signed envelopes
byte-for-byte, move only public key material and continue the revocation-list
lineage. Vendor retains its separately owned delivery projection and evidence.
ADR-0010 makes that retention temporary and schedules its retirement after the
Deployment Control cutover and before Brand Profiles.

## Amendment — 2026-08-21 (Deployment Control is a2, and step 4's "greenfield" is half right)

ADR-0011 contracts step 4 and corrects two things.

**The release.** `dotmac-deployment-control` `0.1.0a2` is published and tagged
(Starter PR #308 at `5c87272a`, release run `32471956734`). Step 4 composes a2,
not the a1 it named: a1 returns the raw unique-constraint error instead of the
canonical verdict when two genuinely concurrent first observations race, and
this assembly — receiving arrivals from deployments it does not control over an
at-least-once transport — is where that fires.

**The classification.** Step 4 called this a greenfield composition. That holds
for plans, rollouts, credentials and observations, none of which has ever had a
Vendor owner. It does NOT hold for deployment-target identity:
`register_delivery_target` and `licence_delivery_targets` are a named authority
over that subject today, complete with a customer-binding invariant and two
declared audit codes. A second authority does not stop being one because it was
given a narrower name.

So step 4 is a greenfield composition AND a narrow authority cutover. The
premise for the cutover half is measured, not assumed: `licence_delivery_targets`
and `licence_deliveries` are counted on a target Michael names explicitly, and
the result decides between a sealed empty-estate revision and a backfill with a
writer switch. Either way a forward vendor revision is owed — the earlier
reading, that this slice needed no vendor migration, came from the wrong
classification and is withdrawn.

The module declares one supported plane set, so `ASSEMBLY_MODULE_PLANES` gains
nothing.

## Amendment — 2026-08-21 (steps 2 and 3 have run; step 7 is met for two earlier owners)

Step 7 records adoption only after a released owner runs with its former local
writer absent. That condition was met on 2026-08-17 for Approvals and
Entitlement Allocation: production deploy `32022599873` ran main `f8f8c3fd` at
an immutable image digest with `mod_approvals` and `mod_ealloc` live and the
legacy `public` tables absent. ADR-0005 and ADR-0006 carry the evidence and the
remaining repin action. Commercial Agreements and Licensing remain below
adopted — their switches landed after that deploy.
