# Cutover readiness — Deployment Control, delivery, Brand Profiles

**Dated 2026-08-21.** What the remaining ADR-0007 slices need before anyone
writes them, and what is already true. Nothing here takes a pin, composes a
module or moves a writer. The machine-readable half is
`src/vendor_cp/cutover_readiness.py`, held by
`tests/architecture/test_cutover_readiness.py`; where the two disagree, the test
is the one that fails.

## The rule this document is written under

Fleet rule, proposed as `dotmac_governance` ADR 0013 on branch
`feat/repository-local-claims-oracle` (PR #22, `Proposed` — a proposed record is
not yet normative), and checked in here as `AGENTS.md` rule 17:

> Repository-local transition claims must be derived from repository-local facts.
> Release, registry and production-adoption claims require an authoritative
> external oracle.

The local claims — the declared table set, the symbol-level target inventory,
the measured brand absence, the recorded deferral — are derived by
`tests/architecture/test_cutover_readiness.py` from
`src/vendor_cp/cutover_readiness.py`.

### Oracles for the external claims in this document

Each carries immutable coordinates: repository, exact run or peeled commit, and
the source path where a claim is read from a file. "Current Starter `main`" is
not a coordinate and is not used below.

| Claim | Kind | Oracle |
| --- | --- | --- |
| `dotmac-deployment-control` `0.1.0a2` is published and installable | `release_run` | `dotmac_starter_mt` release run `32471956734` — published, installed the wheel back from the private index, registered the manifest, then tagged |
| a2 is pinnable | `peeled_tag` | tag `dotmac-deployment-control-v0.1.0a2`, peeled commit `5c87272a632096850a80e5e9dc1f625a97c3e5d6` (PR #308) |
| `dotmac-brand-profiles` `0.1.0a1` is pinnable | `peeled_tag` | tag `dotmac-brand-profiles-v0.1.0a1`, peeled commit `ed69f9dfdeea493dab7d7ba25c04e940f0870545` |
| `dotmac-approvals` is adopted, this assembly its contract consumer | `adoption_evidence` | `dotmac_starter_mt@20d24703e70e4d361de2f406165df4b36cbee507`, path `packages/dotmac-approvals/EXTRACTION.toml`, fields `status` (`adopted`) and `contract_consumers` |
| `dotmac-entitlement-allocation` is adopted, this assembly its contract consumer | `adoption_evidence` | `dotmac_starter_mt@20d24703e70e4d361de2f406165df4b36cbee507`, path `packages/dotmac-entitlement-allocation/EXTRACTION.toml`, same two fields |
| the deploy that earned both adoptions | `deployment_run` | `dotmac_vendor_control_plane` deploy run `32022599873`, commit `f8f8c3fd636e663e4a17275c19e82fc1667aa52a`, image `sha256:56ec553139c449dc7da46a8873b3c03e95a61e43c970cd1675e28a202b2991cc`, target `vendor-cp-prod` (`vendor.dotmac.io`) |

### The two absence claims, handled differently

An absence describes a moment, so it cannot be cited the way a release can.

**Brand Profiles has no first adopter — restated as a local fact.** This
document does not claim `dotmac_sub` has not finished; that is a temporal
negative about a repository this one cannot see. What it claims is local,
permanent until the decision changes, and derivable here: **Vendor remains
deferred by ADR-0007 § 6.** `DEFERRED_BY_LOCAL_DECISION` holds exactly that.

The dossier state is recorded as background, not as the load-bearing claim: at
`dotmac_starter_mt@20d24703e70e4d361de2f406165df4b36cbee507`,
`packages/dotmac-brand-profiles/EXTRACTION.toml` carries `status =
"audit-complete"` with `contract_consumers` and `adoption_evidence` both empty.
That observation ages; the ADR decision does not, which is why the decision is
what the deferral rests on.

**The delivery-target estate is empty — an as-of observation that does not
exist yet.** No measurement has been taken, so no claim is made. The obligation,
its two tables and its refresh point are in § "The measurement": re-observed on
a target Michael names, immediately before the ADR-0011 slice it gates, by the
operator running it. A measurement taken and then left to age would need the
same treatment.

### The claim this section replaced

An earlier draft asserted that no distribution "awaiting a release tag" was
pinned and called it an executable gate on the tag. It read `pyproject.toml` and
nothing else, so the a2 tag was published and the assertion stayed green. It
proved intent, not availability. That assertion is deleted rather than reworded,
and it is ADR 0013's required known-bad case.

## The programme, and where it stands

ADR-0007 fixes the order and says plainly that reordering it requires an
amendment at the owning source. Six slices, three landed.

| # | Slice | Owner after | State |
| --- | --- | --- | --- |
| 1 | Kernel a61 → a77 | — | landed (#63) |
| 2 | Commercial Agreements | `dotmac-commercial-agreements` | landed (#64), ADR-0008, `v015` |
| 3 | Licensing issuer | `dotmac-licensing` | landed (#65), ADR-0009, `v016` |
| 4 | **Deployment Control** | `dotmac-deployment-control` | **contracted (ADR-0011); release available; execution gated on an estate measurement** |
| 5 | Licence delivery | `dotmac-integration` in Dotmac Integrator | contracted (ADR-0010), blocked on 4 |
| 6 | Brand Profiles, platform plane | `dotmac-brand-profiles` | released; **deferred by local decision** behind another product |

## Pin state

| Distribution | Pinned here | Released | Position |
| --- | --- | --- | --- |
| `dotmac-kernel` | `0.1.0a77` | a85 | current pin satisfies every composed floor |
| `dotmac-approvals` | `0.1.0a4` | a5 | **repin owed** — see below |
| `dotmac-entitlement-allocation` | `0.1.0a4` | a6 | **repin owed** — see below |
| `dotmac-release-catalog` | `0.1.0a4` | a4 | current |
| `dotmac-commercial-agreements` | `0.1.0a1` | a1 | current |
| `dotmac-licensing` | `0.1.0a1` | a1 | current |
| `dotmac-deployment-control` | not pinned | **a2, tagged** (Starter PR #308 at `5c87272a`, release run `32471956734`) | pinned by the ADR-0011 slice that consumes it |
| `dotmac-brand-profiles` | not pinned | a1, tagged | deferred by local decision (ADR-0007 § 6) |

ADR-0007's rule is that a package enters with the coherent slice that consumes
it, so "not pinned" for Deployment Control is sequencing, not a blocker: the
release exists and the slice may be written now.

**a2 rather than a1**, because a1 returns the raw unique-constraint error
instead of the canonical verdict when two genuinely concurrent first
observations race, and this assembly receives arrivals from deployments it does
not control over an at-least-once transport.

## Deployment Control is two differently-shaped halves

Not one greenfield composition. An earlier draft classified it that way on the
grounds that no table here is called `deployments`, which is true and beside the
point.

### Greenfield — plans, rollouts, credentials, observations

No Vendor owner has ever existed for any of these. No revision in this lineage
has created a plan, rollout, attempt, credential or receipt table; `v011` is
`product_identity`, and the V6 line that would have created them was abandoned
unmerged. Nothing to measure, nothing to switch.

### Authority cutover — deployment-target identity

`register_delivery_target` is a named authority over Deployment Control's
subject today. It holds `target_ref`, `customer_ref`, `connection_ref` and
`status`; it refuses to re-point an existing target at another customer; it
writes two declared audit codes. Its own docstring anticipates becoming a
subscriber rather than a parallel source of truth.

Inventoried at symbol level with per-file call-site counts, ratcheted both ways
— a path-level ledger would stay green if `register_delivery_target` were
deleted while `projection.py` remained, which is precisely the transition worth
catching.

| Half | Surface | Fate |
| --- | --- | --- |
| Write authority | `register_delivery_target`, `RegisterTargetCommand`, `RegisterTargetRequest`; `POST /targets`, `GET /targets`; `vendor.licence.delivery_target_registered`, `vendor.licence.delivery_target_updated` | migrated at ADR-0011; the audit codes retire with the writer or ADR-0008's every-declared-code-has-a-consumer rule fails the build |
| Projection | `list_delivery_targets`, `_authorised_target`, `DeliveryTargetResponse`, `LicenceDeliveryTarget`, `TargetStatus` | survives ADR-0011 as a rebuildable projection reconciled from `mod_deploy`; retires at ADR-0010 |

### The measurement, which is an operator obligation

Before ADR-0011 may claim an empty premise, `licence_delivery_targets` **and**
`licence_deliveries` must be measured on a target Michael names explicitly — a
target is never inferred from deployment history. `licence_deliveries` is
included because `target_id` is a foreign key into the registry: an emptiness
claim about targets that ignores the rows depending on them is not a
measurement.

- **Empty** → a forward vendor revision rechecks both under
  `ACCESS EXCLUSIVE` in the same transaction that seals the independent
  registration path, failing closed on any row. The `v013`–`v016` shape.
- **Non-empty** → backfill targets into `mod_deploy` through the module's own
  command, compare, switch the writer, and retain the Vendor table as a
  module-derived projection with no independent write path until ADR-0010.

Either way a forward vendor revision is owed. The earlier draft's claim that
this slice needs no vendor migration came from the wrong classification and is
withdrawn.

## What else retires, and when

| Surface | Retires at | Why |
| --- | --- | --- |
| `licensing/delivery_models.py` | ADR-0010 | the five tables, including `LicenceAckRecord.deployment_id` / `.authenticated_deployment_ref` — a local copy of the claim/proof pair `observation_receipts` owns |
| `licensing/transport.py` | ADR-0010 | attempts, parking, replay generations and terminal-error policy — Integrator's under hard rule 28 |
| `licensing/delivery_ops.py` | ADR-0010 | pipeline health and acknowledgement lag, computed from the attempt ledger that moves with it |
| `docs/design/deployment-credentials.md` | ADR-0011 | the V6 credential-registry brief; `dc_0001` owns what it specified, and a document promising an implementation is how one gets built |

`docs/design/domain-foundation.md` already carries its 2026-08-20 amendment
retiring the `FleetDesiredStateService` and `DeploymentRunner` labels.

### Two things that are not deployment writers

`src/vendor_cp/provisioning/` drives the kernel's `ProvisioningProvider`
contract against a side-effect-free simulator and owns no table (deny case D3).
`src/vendor_cp/deployment_profile.py` selects which vendor SURFACES are mounted
and nothing else (hard rule 11). Neither retires with either cutover; both are
named because the words invite the confusion.

## Local brand writers to retire: none

**Measured.** No model, service, migration or template in this assembly holds a
brand record. `test_this_assembly_holds_no_brand_record` scans `src/` and the
vendor lineage for `BrandProfile`, `brand_profile`, `primary_hex`, `accent_hex`,
`logo_ref` and `custom_css`, and a sensitivity test proves the scan reports a
planted record rather than passing because it matched nothing.

The Brand Profiles extraction dossier reached the same conclusion independently
and recorded the interesting part: it inventoried this repository, compared
`deployment_profile.py` against a brand record because of its name, and rejected
it as ADR-0003 composition rather than presentation.

The only brand-adjacent thing here is a product name in a `<title>` literal in
`console/web.py`. A displayed name is not a stored one, and the test asserts
that file holds a name and no column.

So `BRAND_WRITERS_TO_RETIRE` is empty as a result rather than as an omission.

## Brand Profiles adoption, prepared

No decision is taken here. ADR-0007 § 6 already decided the order; this records
what the slice will be so it is not designed under time pressure on the day the
deferral lifts.

**The deferral.** The extraction dossier names `dotmac_sub` as first adopter,
lists no contract consumer, and sits at `audit-complete`. Vendor is second.
Reversing that needs an amendment at the extraction source. Whether Sub has
finished is not observable from this repository, so
`DEFERRED_BY_LOCAL_DECISION` records the decision Vendor took rather than a
claim about Sub's state, and the entry is removed in the change that takes the
pin.

**What the slice looks like when the deferral lifts.** Thin, for the same reason
as Deployment Control's greenfield half:

- Genuinely dual-plane, and this assembly selects `PLATFORM` alone — the second
  entry `ASSEMBLY_MODULE_PLANES` will have ever held. A real choice, not an
  inference; the kernel fails the composition if it is missing.
- The platform plane is where host bindings live, because a control plane must
  resolve a brand before any tenant exists. This assembly has no tenants at
  all, which is the case the plane was declared for.
- Prerequisites: `module_database_roles.v1` and `idempotency_ledger.v1` are
  COMMON and already bound here; `platform_audit_log.v1` is the platform-plane
  requirement and is also already bound. The TENANT-plane requirement,
  `tenant_scope_catalog.v1`, is bound here as a fact about the database and is
  irrelevant to the selection — the ADR-0028 separation this assembly is the
  reference case for.
- **No migration and no writer retirement**, per the section above. The
  dossier's own next action says the same from the other side.
- One audit action, `platform_brand_profile.changed`, module-owned. Vendor's
  `vendor.*` vocabulary and hard rule 15 are unaffected.
- The assembly — never the module — maps profile values into
  `dotmac_ui.BrandOverride`. The module publishes the allowlist and deliberately
  exposes no override constructor.

**What it must not become.** A brand profile is data, not code: no CSS column,
no token map, no colour parser, no file bytes. `dotmac-files` owns bytes and the
logo/icon columns hold opaque references this assembly never dereferences.

## Approvals and Entitlement Allocation — adoption plan

Both ADRs said "below adopted — nothing has run". That stopped being true on
2026-08-17. The plan is in ADR-0005 § "Adoption plan" and ADR-0006 § "Adoption
plan"; short form:

- Production deploy `32022599873` ran main `f8f8c3fd` at immutable image
  `sha256:56ec5531…` with `mod_approvals` and `mod_ealloc` live, the legacy
  `public` tables absent and `app_user` holding no module privileges. The
  extraction dossiers record both as `adopted` with this assembly as their
  contract consumer.
- **The remaining work is a repin, and it is a declaration gap rather than a
  live fault.** Both are pinned at `0.1.0a4`, and both a4 releases
  under-declare a prerequisite they write at request time: approvals writes the
  outbox tables without declaring `outbox_relay.v1` (fixed in a5), and
  allocation writes the idempotency ledger and platform audit log without
  declaring either (fixed in a6; a5 was never published).
- This assembly is not exposed to the runtime half. It runs the whole kernel
  base lineage, so `public.outbox_events`, `public.platform_outbox_events` and
  both request-time tables exist here. An adopter running only its own lineage
  would take an `UndefinedTable` on the first decision that emitted an event;
  this one will not. What is missing is the proof, not the table.

## Recommended PR sequence

Three changes, in this order, each separately reviewable.

**1. Repin correctness — `version:patch`.** Correct the Approvals and Allocation
adoption documentation; pin approvals `0.1.0a5` and entitlement-allocation
`0.1.0a6` (both tagged); add the `outbox_relay.v1` binding to
`ASSEMBLY_PREREQUISITE_BINDINGS` — expected provider `0012_platform_outbox`, the
descendant completing both planes of the effect, PROVEN by
`test_migration_prerequisite_bindings` rather than asserted; regenerate the
lock; verify `ap_0002`, `ea_0002` and `ea_0003` against the migrated database.
Moves no authority and touches no slice below.

**2. Deployment Control composition — `version:minor`.** Pin `0.1.0a2`; compose
its manifest and `versions_dir()` so `dc_0001` runs; leave
`ASSEMBLY_MODULE_PLANES` unchanged; add the typed adapter; execute the
deployment-target authority transition, in whichever shape the § "The
measurement" result requires. One change, because a composed module beside a
live independent registrar is the state this slice exists to avoid.

**3. Brand Profiles — separate and blocked** until the extraction dossier's
first-adopter evidence changes. Not a Vendor decision to make.

## What this document is not

It is not an authority to compose, and it takes no decision that belongs in an
ADR. ADR-0007 owns the order, ADR-0010 the delivery transfer, ADR-0011 the
Deployment Control composition and target-authority cutover, and the Brand
Profiles order is owned at the extraction source. If this document and one of
those disagree, the ADR wins and this file is the drift.
