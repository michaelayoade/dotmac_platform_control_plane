# ADR-0011: Compose Deployment Control, and cut deployment-target authority over to it

- **Status:** Accepted (contract). Execution gated on the estate measurement in
  § 4, which requires a target Michael names explicitly.
- **Date:** 2026-08-21
- **Owner:** Vendor control plane
- **Follows:** ADR-0007 § 4, which sequenced this slice
- **Blocks:** ADR-0010's licence-delivery transfer, which needs an
  authoritative destination before Integrator can route to one

## Context

ADR-0007 § 4 decided that Deployment Control composes here, and hard rule 12
requires the cutover to be contracted before it is composed. This is that
contract. It corrects one classification the earlier decision did not have to
make, and that correction is the substance of this ADR.

**The release is available, and here is the oracle for saying so.** Nothing in
this repository can observe the private index, so per the fleet rule in
`AGENTS.md` rule 17 this claim carries its authority. Two citations, because
they are different facts:

- *published and installable* — `release_run`: `dotmac_starter_mt` release run
  `32471956734`, which published `dotmac-deployment-control` `0.1.0a2`,
  installed the wheel back from the private index, registered its manifest, and
  only then tagged;
- *pinnable* — `peeled_tag`: `dotmac-deployment-control-v0.1.0a2`, peeled commit
  `5c87272a632096850a80e5e9dc1f625a97c3e5d6` (PR #308). The peeled commit rather
  than the tag object's own SHA, because an annotated tag is a distinct object
  and a tag reference is mutable until protected. a2 rather than a1 because a1's observation-admission path returns
the raw unique-constraint error instead of the canonical verdict when two
genuinely concurrent first observations race; a2 runs the receipt insert in a
savepoint, keeps the loser's append-only attempt, points it at the winner and
replays the winner's verdict. This assembly receives arrivals from deployments
it does not control over an at-least-once transport, which is the shape that
produces that race, so the fix is a requirement rather than a preference.

**This slice is NOT wholly greenfield, and an earlier draft of this ADR said it
was.** The reasoning was that no table here is called `deployments`, which is
true and beside the point. `licence_delivery_targets` and
`vendor_cp.licensing.projection.register_delivery_target` are a named authority
over deployment-target identity today: the command holds `target_ref`,
`customer_ref`, `connection_ref` and `status`, refuses to re-point an existing
target at another customer, and writes
`vendor.licence.delivery_target_registered` /
`vendor.licence.delivery_target_updated`. Its own docstring already says it must
become a subscriber rather than a parallel source of truth. A second authority
over the same subject does not stop being one because it was given a narrower
name — that naming choice was made deliberately (see `docs/ARCHITECTURE.md`,
2026-08-02) to stop licensing becoming the de-facto owner, and composing the
real owner is what finally settles it.

## Decision

Compose `dotmac-deployment-control` `0.1.0a2`, and treat the slice as two
differently-shaped halves rather than one.

### 1. Greenfield composition — plans, rollouts, credentials, observations

None of these has ever had a Vendor owner. No revision in this lineage has
created a plan, rollout, attempt, credential or receipt table; the V6 line that
would have was abandoned unmerged, and `v011` here is `product_identity`. For
this half there is no premise to check and no writer to switch, so a
premise-checking revision would be a check with no premise: it would pass
forever and read like evidence.

The composition itself is small, because every prerequisite is already bound.

| Fact | Value | Already true here |
| --- | --- | --- |
| Schema | `mod_deploy` | new; no vendor table collides |
| Lineage root | `dc_0001_deployment_control` | joins the composed lineages |
| Prefix / branch | `dc` / `deployment_control` | reserved in the kernel ledger |
| Kernel floor | `>=0.1.0a77` | this assembly pins a77 exactly |
| `requires` | `idempotency_ledger.v1`, `platform_audit_log.v1` | both already bound, to kernel `0018_idempotency_one_owner` and `0026_platform_audit_log` |
| Planes | platform only, atomic | no `ModulePlaneSelection` is possible; the kernel refuses one |
| Audit actions | four, module-owned `deployment.*` | Vendor's `vendor.*` vocabulary and hard rule 15 are untouched |

`ASSEMBLY_MODULE_PLANES` does not gain an entry. The module declares one
supported plane set, so intent is not selectable, and stating it would be the
a60 mistake in reverse — a declaration that reads like a choice where none
exists.

### 2. Authority cutover — deployment-target identity

`mod_deploy.deployment_targets` becomes the sole authority for what a deployment
target IS. The Vendor write path stops being a source of truth in the same
change, and what survives in `licence_delivery_targets` is a rebuildable
projection reconciled from that owner until ADR-0010 retires it with the rest of
the delivery estate. It may never again be independently registered.

The two halves are inventoried separately in
`src/vendor_cp/cutover_readiness.py`, at SYMBOL level with per-file call-site
counts ratcheted in both directions:

- `TARGET_AUTHORITY_SYMBOLS` — `register_delivery_target`,
  `RegisterTargetCommand`, `RegisterTargetRequest`. Plus
  `TARGET_AUTHORITY_ROUTES` (`POST /targets`, `GET /targets`) and
  `TARGET_AUTHORITY_AUDIT_ACTIONS` (the two declared codes above, which must
  retire with their writer or ADR-0008's every-declared-code-has-a-consumer rule
  fails the build).
- `TARGET_PROJECTION_SYMBOLS` — `list_delivery_targets`, `_authorised_target`,
  `DeliveryTargetResponse`, `LicenceDeliveryTarget`, `TargetStatus`.

A path-level ledger was the earlier draft's instrument and was not sufficient:
deleting `register_delivery_target` while `projection.py` remained would have
left it green while the authority moved. Symbols and call sites are what move.

### 3. What Vendor writes, and what it must not

One typed adapter, `vendor_cp.deployment.adapter`, with no `Any`, following
Approvals, Agreements and Licensing. It translates between the module's commands
and the owners Vendor already composes — the release reference from
`dotmac-release-catalog`, the licence reference from `dotmac-licensing`, and
approval evidence from `dotmac-approvals` through the existing approvals
adapter. The module never calls those owners itself; each coupling is cut at a
value in its `ports.py`, which is what makes it independently releasable.

Unchanged and still forbidden (hard rule 4, deny case D3): Vendor-owned fleet
tables, a Vendor `DeploymentRunner`, provider clients, provider credentials,
connector retries, schedules, leases or backoff. `DeliveryIntent` is a
provider-neutral value the module returns; acting on it is Integrator's, and
this slice does not act on it.

The provisioning laboratory is untouched — it drives the kernel's
`ProvisioningProvider` contract against a side-effect-free simulator and owns no
table — as is `deployment_profile.py`, which selects mounted surfaces and
nothing else. Both are named because the words invite the confusion.

### 4. Measure the estate before claiming it is empty

**This is the gate on execution, and no test in this repository discharges it.**
`licence_delivery_targets` and `licence_deliveries` must be measured on a target
Michael names explicitly. A target is never inferred from deployment history.
`licence_deliveries` is measured with the targets because `target_id` is a
foreign key into the registry: an emptiness claim about targets that ignores the
rows depending on them is not a measurement.

The two branches are different changes, and which one applies is decided by the
result, not in advance:

**Empty.** A forward vendor revision rechecks both tables under
`ACCESS EXCLUSIVE` in the same transaction that seals the independent
registration path, and fails closed if a row exists — the shape `v013`–`v016`
established. The write path is removed, its routes and audit codes with it.

**Non-empty.** The empty path stops. Backfill the existing targets into
`mod_deploy` through the module's own `register_target` command, compare the
backfilled rows against the source, switch the writer, and retain the Vendor
table as a module-derived projection with no independent write path until
ADR-0010. Immutable identities, the customer binding and the audit history are
preserved; synthetic evidence and cross-database SQL are forbidden. ADR-0031
governs a cutover with data.

Either way a forward vendor revision is owed. The earlier draft's claim that
this slice needs no vendor migration was derived from the wrong classification
and is withdrawn.

### 5. Retired with this slice

`docs/design/deployment-credentials.md` — the V6 credential-registry and
applied-state-admission brief. `dc_0001` builds `target_credentials`,
`observation_receipts` and `observation_attempts` and carries the claim/proof
separation, the append-only attempt log, the stable-verdict replay rule and the
half-open eligibility window that brief specified; the module's own dossier
cites this line as their provenance. It is retired as a design to implement, and
the unmerged `feat/v6-slice1-deployment-credentials` and
`feat/v6-slice2-applied-state-admission` branches close with it.

`docs/design/domain-foundation.md` already carries its 2026-08-20 amendment
retiring the `FleetDesiredStateService` and `DeploymentRunner` labels; nothing
further is owed there.

### 6. Brand is not part of this slice

`DesiredDeployment` and `DeliveryIntent` both carry an optional
`brand_profile_ref`. It is an opaque reference and stays `None` here. Composing
Brand Profiles is deferred by ADR-0007 § 6 — a decision this repository holds,
stated in preference to the temporal claim that another product has not yet
adopted the module, which this repository cannot observe. A reference is not a
composition, and populating that field before the owner exists would be the
quiet reordering ADR-0007 forbids.

## Consequences

- The next slice is ADR-0010's, unchanged: Integrator can bind to an
  authoritative destination instead of trusting a projection or inventing a
  second map. That is only true once § 2 has actually run — a composed module
  beside a live independent registrar would leave Integrator the same choice.
- This assembly gains a module schema without gaining a fleet engine. Hard rule
  4's premise is preserved exactly: the prohibition is on a VENDOR-owned fleet
  owner, and composing the independent one is what makes it affordable.
- The composed live-catalogue audit covers `mod_deploy` the moment its migration
  runs; coverage is catalogue-derived, so nothing needs adding to a list.
- The slice is larger than it first looked, and splitting it further would put a
  composed module and a live second writer in production at the same time. It
  stays one change.

## Lifecycle

**Not composed.** Nothing in this ADR pins, installs or migrates anything; it
fixes what the slice must do before anyone writes it, and names the measurement
that decides which shape it takes. Adoption is recorded only after the module
runs in production with the Vendor target-registration authority absent.
