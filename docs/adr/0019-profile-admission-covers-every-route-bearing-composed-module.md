# ADR-0019: Profile admission covers every route-bearing composed module

- **Status:** PROPOSED 2026-09-04 by the profile-admission lane. Acceptance is
  Michael's. Nothing here pins a module, and nothing here has run against
  production.
- **Date:** 2026-09-04
- **Amends:** ADR-0015, which introduced `surface_inventory` and checked it for
  completeness against a hand-written roster of VENDOR feature names. That
  roster is the thing this decision replaces; every other part of ADR-0015 —
  the laboratory pairing, the environmental refusal keyed on provider mode, the
  refusal to fall back to `full` in production — stands unchanged.
- **Follows:** `dotmac_starter_mt` ADR-0003, which made a deployment profile a
  surface selector and forbade feature code branching on a profile name.
- **Relates to:** ADR-0011, which composed `dotmac-deployment-control`;
  ADR-0014, which gave the `platform_admin` facet exactly one browser
  authentication owner — the facet a composed module's browser surface joins.

## 1. Context — the profile could not see half of what it composed

`build_spec` read the profile once and applied it once, to
`assembly.VENDOR_SURFACES`. `assembly.STATEFUL_MODULES` was spliced into
`ProductAssemblySpec.modules` RAW:

```python
modules=(
    *STATEFUL_MODULES,                                            # spliced RAW
    *(_profiled_surface(feature, effective) for feature in VENDOR_SURFACES),
),
```

`_profiled_surface` already knew how to withhold a contract-v2 `ModuleManifest`
— it branched on the type and cleared `api_routers`/`web_surfaces`, and its own
docstring warned that clearing the wrong field names "would leave the routes
MOUNTED under a profile that withholds them". It was simply never called with
one. The defect was a missing call, not a missing capability.

The inventory side had the matching hole, and it was the deeper one.
`VendorDeploymentProfile.__post_init__` checked `surface_inventory` against
`VENDOR_SURFACE_CODES - withheld_surfaces`, and `VENDOR_SURFACE_CODES` was
itself a hand-written frozenset of the ten vendor feature names, kept in sync
with `assembly.VENDOR_SURFACES` by a test. So the completeness check compared
**one declaration against another declaration**, and a composed module's code
could not enter the roster's universe at all. "A composed module mounts a
surface no profile declares" was not a case the guard could fail on. It was a
case the guard could not express.

`WITHHOLDABLE_SURFACES` was a second hand list with the same blind spot pointed
the other way: a route-bearing composed module was not on it, so no profile
could have withheld it even if someone had wanted to. The failure mode of a
missing allowlist entry is FORCE-PUBLICATION, which is the harm.

## 2. The measurement — this is a class, not an omission

Measured 2026-09-04 at `main = 172b24c706`.

`dotmac-deployment-control` has shipped an operator browser surface since
**`0.1.0a8`**, not since a11. Peeled commits, tag objects dereferenced first:

| version | peeled commit | `web.py` | `web_surfaces` |
| --- | --- | --- | --- |
| a6 (the pin) | `518711c36e9e5774e11b02c6ab35ec0c9c7b75b9` | no | no |
| a7 | `6b1ce371b07220914696243647aeb0d3947b87cc` | no | no |
| **a8** | `474faf60aee492a4776cdb581f467b11ffcd4964` | **yes** | **yes** |
| a9 | `b8427af26101bde5e9b09aecebe3c9176dd18b36` | yes | yes |
| a10 | `4a56f5836cab48fa2ed7ca00e5affc4364114b31` | yes | yes |
| a11 | `98b2a257f4185ee134b54a0349ad09d76f05286b` | yes | yes |

a11's manifest declares `web_surfaces=(DEPLOYMENT_CONTROL_SURFACE,)`, a
`WebSurfaceContribution(code="deployments", facet="platform_admin", …)` carrying
`GET /deployments`, `GET /deployments/{target_id}`,
`POST /deployments/{target_id}/plans`, `GET /deployment-arrivals` and two
`WebNavItem`s. The paths are facet-relative, so they land under `/platform` in
the **same facet and the same navigation** the console contributes to — and
every production profile publishes the console. Pinning a8 or later would have
mounted an operator deployment UI in `production-composed-v1` with no line in
any inventory and no test able to see it.

**No Control-side change is required.** a11 already declares its surface on its
own manifest, which is exactly the input admission reads. The repair is entirely
this repository's.

**And a11 is not the only one.** `dotmac-release-catalog`,
`dotmac-entitlement-allocation`, `dotmac-commercial-agreements` and
`dotmac-approvals` each say in their own manifest prose that this release ships
no routers and that the guards they declare "land with the routers, in the
release that ships them". Four composed modules are queued against the same
hole, and each would force-publish into `production-composed-v1` on the day it
ships routes. That is why the repair is DERIVATION and not a roster entry: a
roster entry closes one omission, and the omission is a class.

## 3. Decision

1. **Every composed manifest passes through the profile.** `build_spec` builds
   one `COMPOSED_MANIFESTS` tuple — persistence owners then vendor surfaces —
   admits it, and maps `_profiled_surface` over all of it. There is one tuple
   precisely so the filtered set and the admitted set cannot diverge again.
2. **The roster is derived.** `route_bearing_codes(manifests)` returns the codes
   of manifests that actually contribute routes. `bears_routes` is duck-typed
   over five fields — `routers`, `api_routers`, `web_routers`, `nav`,
   `web_surfaces` — because the two manifest generations spell the same thing
   differently. For the kernel this assembly composes that is EXACT rather than
   a proxy: `mount_features` and `mount_web_surfaces` mount from those manifest
   fields and from nothing else. The claim is scoped to this kernel; it would
   stop being exact if a kernel gained a route source outside the manifest.
3. **Withholdability is derived too**, as `route_bearing_codes` minus
   `NEVER_WITHHELD_SURFACES` — the one hand-declared set that remains, holding
   one name. `readiness` is route-bearing, so derivation alone would make it
   withholdable, and a readiness probe with an off switch is not a probe.
4. **Admission is a typed boot refusal.** `admit_surfaces(profile, manifests)`
   raises `SurfaceAdmissionError` carrying an `AdmissionRefusal` member and the
   exact surfaces at fault. Four members, because this module refuses in four
   ways and a test matching prose would pass on the wrong one:
   `SURFACE_NOT_INVENTORIED`, `INVENTORY_NAMES_A_SILENT_SURFACE`,
   `WITHHOLDS_A_MANDATORY_SURFACE`, `WITHHOLDS_A_SILENT_SURFACE`.
5. **Admission runs on the UNPROFILED manifest set.** After filtering, a
   withheld module bears no routes and would read as one that publishes
   nothing — the one conclusion admission must not reach from its own output.
6. **A stateful module's ROUTES may be withheld.** The old rule "no profile may
   name a persistence owner in its withheld set" is removed. See § 4.
7. **The inventory is what a deployment PUBLISHES.** A manifest bearing no route
   publishes nothing and is therefore absent from every inventory.
   `release_evidence` leaves the three declared inventories on that ground, and
   its absence is now derived rather than explained in a paragraph.

## 4. Why the persistence-owner rule had to be relaxed, and what replaces it

The removed rule was a PROXY. Its purpose was that a profile can never leave the
assembly unable to describe its own tables, and it achieved that by keeping
stateful modules out of the withheld set entirely.

That proxy is incompatible with the decision above. A module that ships an
operator screen MUST be withholdable, or it force-publishes into every
production profile — which is precisely the defect being closed.

What replaces it is the property the proxy stood for, asserted directly:

> Withholding clears ROUTE FIELDS and only route fields. A withheld manifest
> keeps its `tables`, `platform_tables`, `requires`, `audit_actions`,
> `capabilities`, `migration_prefix` and `migration_branch` unchanged, so its
> schema and its migration lineage are exactly as composed.

`_profiled_surface` was also widened while this was being written: the
`ModuleManifest` branch cleared two of the four route field names its own
docstring warned about, leaving `web_routers`/`nav` — which a contract-1
`ModuleManifest` may legally carry — mounted under a profile that withheld them.

## 5. Evidence, and which half is live today

**Zero composed modules bear a route at the current pins.** A guard written only
against the real composition would therefore cover nothing at the instant the
old rule is removed. That is a coverage gap with a promise attached, and this
programme keeps finding promises where guards should be. So the two halves are
named separately and must not be read as one:

**The live coverage is the plant.** `_a11_shaped_module()` is the REAL
`deployment_control` manifest as pinned — its real `platform_tables`,
`migration_prefix`, `migration_branch`, `requires` and `audit_actions` — wearing
a `WebSurfaceContribution` on the `platform_admin` facet. Building it with
`dataclasses.replace` on the composed manifest rather than fabricating a
look-alike is what makes every declaration a real value: a fabricated probe
would carry defaults that agree with anything, and the retention comparison
below would pass on emptiness. It is a11's shape on a11's module, and it proves
the property NOW:

- planted and uninventoried, every declared profile refuses it with
  `AdmissionRefusal.SURFACE_NOT_INVENTORIED` naming `deployment_control`;
- the refusal is driven through `assembly.build_spec`, not a helper;
- a legacy `FeatureManifest` plant is refused identically, so the guard is not
  specific to one manifest generation;
- **positive control** — the same plant, in the same composition, under a
  profile whose inventory names it, MOUNTS its route in a really-built
  application, and withholding it takes the route back out. Without this the
  refusal could be firing on an inert object;
- **retention** — withheld, every non-route field compares equal to the
  original, field by field over the whole dataclass, with the named subset
  spelled out and each guarded against being vacuously empty. The named list is
  RATCHETED two-directionally against the pinned kernel's manifest field set:
  `database_catalog` is a11's own declaration and is not a field of
  `ModuleManifest` at the kernel pinned here, so its absence is asserted rather
  than skipped, and the test fails both if that field appears and if a named
  one disappears — an assertion that cannot run is recorded, never dropped;
- **derivation, both directions** — the same module with its surface stripped
  is NOT withholdable, so the assertion is about derivation rather than about
  which modules happen to ship routes today.

**The arriving coverage is the registry+lineage check.** The per-profile
assertion that each `assembly.STATEFUL_MODULES` manifest is still registered in
a `ModuleRegistry` built from that profile's own spec, and that its lineage head
still resolves in the composed Alembic graph, becomes non-vacuous for a
route-bearing composed module on the day one is pinned. It is real coverage; it
is not the coverage that carries § 4 today.

## 6. This change moved no route, and that is asserted

Rule 11 ties a version bump to the EFFECTIVE SURFACE SET. Nothing an operator
can reach changed here: `release_evidence` mounted nothing before and mounts
nothing now, and no composed module bears a route at the current pins. So the
three profile versions are deliberately NOT bumped — a bump signalling a change
nobody made is its own kind of false statement on a host.

"I argue it is surface-neutral" is the same shape as the claim this decision
replaces, so it is asserted instead.
`test_extending_admission_to_composed_modules_mounted_and_removed_no_route`
builds the application under each of the three profiles twice — once from
`build_spec`, once from a local reconstruction of the pre-ADR composition — and
compares the mounted route set by path, methods and route name. It asserts its
own premise FIRST, so when a composed module does start bearing a route the test
fails on the premise with an instruction to DELETE it rather than repair it: the
change it certifies is historical, and a repaired version would be measuring the
new module instead.

## 7. Consequences

- Pinning `dotmac-deployment-control` a8 or later now FAILS every declared
  profile until someone says, per profile, whether that deployment publishes the
  deployment UI. That is the intended cost and the reason this lands first.
- **Admission is not the only thing standing between here and an a11 pin, and
  this decision does not clear the other one.** a11's manifest passes
  `database_catalog=` to `ModuleManifest`, a field the pinned kernel `0.1.0a98`
  does not have — measured, not inferred: the retention assertion for it failed
  in CI against the real installed kernel. a11 declares
  `dotmac-kernel >= 0.1.0a100`, so hard rule 24 makes the pin a kernel move as
  well as a module move, and
  `docs/operations/kernel-a100-assessment-2026-09-01.md` records that a98, a99
  and a100 share a product-owned-driver boundary on `create_app` whose repair is
  a101. That sequencing is not this lane's to resolve; it is recorded here so
  the next reader does not discover it at pin time.
- The same is true for the four modules whose routers are still ahead of them.
- A profile literal is slightly longer-lived than before: `admit_surfaces` runs
  at boot for the profile a host runs, and every DECLARED profile is admitted in
  CI, so the profile nobody has switched to cannot quietly stop describing the
  assembly.
- Nothing here pins a module, adopts a profile, or authorises a deployment.

## 8. What this decision does NOT claim

- It does not claim a11 is safe to pin. It claims that after this change, a pin
  cannot mount an undeclared surface without failing the build.
- It does not claim `bears_routes` is exact for any kernel. It is exact for the
  kernel this assembly composes, and § 3.2 states the condition under which that
  would stop being true.
- It makes no release, registry or production-adoption claim. The peeled commits
  in § 2 are repository-local reads of an external repository's tags, used to
  establish which versions contain a file — not evidence that any of them is
  published, installable or adopted (hard rule 17).
