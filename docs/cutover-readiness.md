# Cutover readiness — Deployment Control, delivery, Brand Profiles

**Dated 2026-08-21; kernel compatibility and commercial schema-shadow state
updated 2026-08-25.** What the remaining ADR-0007 slices need before anyone
writes them, and what is already true. The composition decision for the Billing
and Subscriptions shadows lives in ADR-0012; this document does not authorise a
runtime or writer cutover. The machine-readable half is
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
| `dotmac-kernel` `0.1.0a94` was published, installed back, verified and tagged | `release_run` + `peeled_tag` | `dotmac_starter_mt` run `32660929576`, commit `9e717eb88603f6ef61bded23b2aa468fe4533a95`: publish and install/verify/tag steps succeeded before the later post-release-record step failed; tag `dotmac-kernel-v0.1.0a94` peels to the same commit |
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
amendment at the owning source. Six slices, four landed.

| # | Slice | Owner after | State |
| --- | --- | --- | --- |
| 1 | Kernel a61 → a77 | — | landed (#63) |
| 2 | Commercial Agreements | `dotmac-commercial-agreements` | landed (#64), ADR-0008, `v015` |
| 3 | Licensing issuer | `dotmac-licensing` | landed (#65), ADR-0009, `v016` |
| 4 | **Deployment Control** | `dotmac-deployment-control` | **LANDED** — a2 composed, `v017` sealed the target registrar (ADR-0011 + its 2026-08-21 amendment) |
| 5 | Licence delivery | `dotmac-integration` in Dotmac Integrator | contracted (ADR-0010); next hand-off slice after 4 |
| 6 | Brand Profiles, platform plane | `dotmac-brand-profiles` | released; **deferred by local decision** behind another product |

## Pin state

| Distribution | Pinned here | Released | Position |
| --- | --- | --- | --- |
| `dotmac-kernel` | `0.1.0a94` | a94 | current compatibility floor |
| `dotmac-approvals` | `0.1.0a5` | a5 | current |
| `dotmac-entitlement-allocation` | `0.1.0a6` | a6 | current (a5 unpublished; never pin it) |
| `dotmac-release-catalog` | `0.1.0a4` | a4 | current |
| `dotmac-commercial-agreements` | `0.1.0a1` | a1 | current |
| `dotmac-licensing` | `0.1.0a1` | a1 | current |
| `dotmac-deployment-control` | `0.1.0a2` | a2 | current |
| `dotmac-billing` | `0.1.0a1` | a1 | PLATFORM schema shadow only; no runtime authority (ADR-0012) |
| `dotmac-subscriptions` | `0.1.0a3` | a3 | PLATFORM schema shadow only; legacy writer unchanged (ADR-0012) |
| `dotmac-brand-profiles` | not pinned | a1, tagged | deferred by local decision (ADR-0007 § 6) |

ADR-0007's rule is that a package enters with the coherent slice that consumes
it. Deployment Control therefore entered at exact a2 with its authority slice;
the Billing and Subscriptions pins enter only as the separately bounded
read-only schema shadows in ADR-0012.

## Billing and Subscriptions — aggregate readiness observation

The incumbent inventory is asymmetric. Vendor has one local immutable priced
offer writer, `vendor_cp.offers.service.publish_offer_version`, whose rows live
in `public.offer_versions`. Commercial contract lifecycle already belongs to
`dotmac-commercial-agreements`; Vendor reaches it through the typed
`vendor_cp.contracts.adapter`, and its lines hold the frozen offer reference and
money terms that a future Subscriptions mapping must reconcile. There is no
Vendor-owned invoice, receivable, settlement, cadence, proration or recurring-
occurrence table in the ratcheted `VENDOR_OWNED_TABLES` inventory and Billing
has no runtime import. That establishes which writers this repository contains;
it is **not** evidence that a named deployed estate has no other Billing
authority.

Run `scripts/report_commercial_shadow_readiness.py` only against the one Vendor
control-plane database. It uses the kernel session boundary and immediately
sets a repeatable-read, read-only transaction. Its aggregate-only JSON separates
source completeness/mapping blockers from target table population and contains
no identifiers, money values, labels or timestamps. It neither selects a
Subscriptions cohort nor claims semantic parity, a sealed watermark, adoption
or cutover readiness. Those remain explicit later gates in ADR-0012.

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

**Taken 2026-08-21. Result: empty.** Michael named `149.102.158.144`, whose
`/etc/dotmac-host-id` marker reads `vendor-cp-prod`. Read-only counts, no
mutation. `licence_deliveries` was measured alongside the targets because
`target_id` is a foreign key into the registry — an emptiness claim about
targets that ignores the rows depending on them is not a measurement.

| | |
| --- | --- |
| Host | `149.102.158.144`, marker `vendor-cp-prod` |
| Database | `vendor_control_plane` |
| Running image | `…@sha256:56ec553139c449dc7da46a8873b3c03e95a61e43c970cd1675e28a202b2991cc` |
| Applied heads | `0023_audit_actor_and_forensics`, `rl_0001_release_artifacts`, `v014_allocations_authority` |
| Observed at | 2026-08-21T12:44:24Z |
| `licence_delivery_targets` | **0 rows** |
| `licence_deliveries` | **0 rows** |
| the other three delivery tables | 0 rows |

Both are ordinary tables (`relkind = 'r'`), so this is an empty table rather
than a missing one — the distinction a bare `count(*)` failing open would hide.

Two things the live database showed that the lineage could not: `mod_deploy`
does not exist and no table matches `%deployment%` or `%rollout%`, so § 1's
greenfield half is observed rather than inferred; and `platform_api` holds
`SELECT, INSERT, UPDATE, DELETE` on `licence_delivery_targets`, which is the
seal's real work.

**Read the premise narrowly — NEVER POPULATED, not "exercised and wrote
nothing".** The rest of the database is empty too: `vendor_accounts` 0,
`offer_versions` 0, `platform_admins` 0, `mod_approvals` 0, `mod_ealloc` 0, and
`platform_audit_events` holds exactly one row whose only action is
`vendor.release_evidence.catalogued`. The two write-path audit codes are absent
from that ledger, but a ledger with one event total is weak evidence — equally
consistent with the writer never being called and with the deployment barely
being used. Zero rows is still zero rows, so the branch is unchanged; what
narrows is what the measurement may be cited FOR. It licenses sealing. It does
not license skipping the recheck, and it is not evidence the registration path
is unreachable.

**Production is behind main and that does not weaken the result.** The applied
vendor head is `v014`, so `v015`/`v016` have not run there — consistent with
Agreements and Licensing remaining below adopted. Neither touches a delivery
table.

**This is a temporal negative and is recorded as one.** Its refresh
responsibility is not prose: the forward revision re-checks both tables under
`ACCESS EXCLUSIVE` in the same transaction that seals the write path and fails
closed on any row. The observation licenses writing that revision; the revision
is what licenses applying it.

### The path this selects — empty, and it has been taken

`v017_deployment_target_authority` implements it: `ACCESS EXCLUSIVE` on all five
delivery tables in a fixed declared order, counts AND relationships re-checked
(dangling `target_id`, dangling `target_ref`, referenced versus unreferenced
targets), abort without change on anything non-zero, then `REVOKE DELETE` on
`licence_delivery_targets` from `platform_api` — inside the same transaction, so
it lands before the locks release — and the effective outcome verified in both
directions.

`INSERT` and `UPDATE` are RETAINED. The reconciler needs them, and an unwritable
projection would make staging permanently impossible, which removes the delivery
path rather than sealing an authority. The single-writer guarantee is therefore
provenance plus a ratchet, not a privilege: `DeploymentTargetFacts` is
constructible only in `vendor_cp.deployment.adapter`, from a record `mod_deploy`
returned. Weaker than a grant, and recorded as weaker. ADR-0011's 2026-08-21
amendment carries the full reasoning.

The table is not dropped — ADR-0010 owns that.

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

- Genuinely dual-plane, and this assembly will add another explicit
  `PLATFORM`-only entry to `ASSEMBLY_MODULE_PLANES`. A real choice, not an
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
- **The repin is done.** Both were pinned at `0.1.0a4`, and both a4 releases
  under-declared a prerequisite they write at request time: approvals wrote the
  outbox tables without declaring `outbox_relay.v1` (a5), and allocation wrote
  the idempotency ledger and platform audit log without declaring either (a6;
  a5 was never published and is refused by a test). Approvals a5 brought the
  `outbox_relay.v1` binding to `0012_platform_outbox`; allocation a6 needed no
  new binding, because Commercial Agreements and Licensing had already bound
  both effects.
- This assembly was never exposed to the runtime half. It runs the whole kernel
  base lineage, so `public.outbox_events`, `public.platform_outbox_events` and
  both request-time tables exist here. An adopter running only its own lineage
  would take an `UndefinedTable` on the first decision that emitted an event;
  this one would not. What was missing was the proof, not the table — and the
  bindings test now DERIVES the required effect set from the composed
  manifests, so the next silently-consumed effect fails here.

## Recommended PR sequence

Three changes, in this order, each separately reviewable.

**1. Repin correctness — `version:patch`. LANDED.** Approvals `0.1.0a5` and
entitlement-allocation `0.1.0a6` are pinned, the `outbox_relay.v1` binding names
`0012_platform_outbox`, the lock is regenerated, and the DDL-free `ap_0002`,
`ea_0002` and `ea_0003` revisions run in the composed migration rehearsal. Moved
no authority and touched no slice below.

**2. Deployment Control composition — `version:minor`. LANDED.** a2 pinned and
composed, `dc_0001` runs, `ASSEMBLY_MODULE_PLANES` unchanged, the typed adapter
added, the write-authority surface retired with its two audit codes, and `v017`
sealing the registrar. The composed lineage count rose, so every document
stating it moved in the same commit — which is what the derived guard in
`test_stale_claims.py` is for.

**One change to the plan, ruled on by Michael:** the seal revokes `DELETE` only.
A full write-revoke would make the projection unwritable, and staging resolves
against a projection row — so it would have removed the delivery path that
ADR-0010 § 1 requires preserved. See ADR-0011's 2026-08-21 amendment.

**3. Brand Profiles — separate and blocked** until the extraction dossier's
first-adopter evidence changes. Not a Vendor decision to make.

## What this document is not

It is not an authority to compose, and it takes no decision that belongs in an
ADR. ADR-0007 owns the order, ADR-0010 the delivery transfer, ADR-0011 the
Deployment Control composition and target-authority cutover, and the Brand
Profiles order is owned at the extraction source. If this document and one of
those disagree, the ADR wins and this file is the drift.
