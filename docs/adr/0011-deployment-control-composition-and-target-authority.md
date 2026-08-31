# ADR-0011: Compose Deployment Control, and cut deployment-target authority over to it

- **Status:** Accepted and IMPLEMENTED. The measurement gate was discharged on
  2026-08-21 (§ 4, empty), and the composition plus the target-authority cutover
  landed in one change. See the amendment at the end for the one thing the
  implementation changed.
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
preserved; synthetic evidence and cross-database SQL are forbidden. `dotmac_starter_mt` ADR-0031
governs a cutover with data.

Either way a forward vendor revision is owed. The earlier draft's claim that
this slice needs no vendor migration was derived from the wrong classification
and is withdrawn.

### The measurement, taken 2026-08-21 — EMPTY

Michael named the target: `149.102.158.144`, whose `/etc/dotmac-host-id` marker
reads `vendor-cp-prod`. Read-only counts, no mutation.

**Coordinates** (`deployment_run`, per `AGENTS.md` rule 17):

| | |
| --- | --- |
| Host | `149.102.158.144`, marker `vendor-cp-prod` |
| Database | `vendor_control_plane` in `dotmac_vendor_control_plane-db-1` |
| Running image | `ghcr.io/michaelayoade/dotmac_vendor_control_plane@sha256:56ec553139c449dc7da46a8873b3c03e95a61e43c970cd1675e28a202b2991cc` |
| Applied heads | `0023_audit_actor_and_forensics`, `rl_0001_release_artifacts`, `v014_allocations_authority` |
| Observed at | 2026-08-21T12:44:24Z |

**Result:**

| Table | Rows |
| --- | --- |
| `licence_delivery_targets` | **0** |
| `licence_deliveries` | **0** |
| `licence_delivery_states` | 0 |
| `licence_delivery_attempts` | 0 |
| `licence_ack_records` | 0 |

Both tables under § 4 were confirmed to be ordinary tables (`relkind = 'r'`),
so this is an empty table rather than a missing one — the distinction a bare
`count(*)` failing open would hide. The other three are recorded because
ADR-0010 will need them and reading them cost nothing.

**Two facts the measurement added that the lineage could not.** `mod_deploy`
does not exist on this database, and no table anywhere in it matches
`%deployment%` or `%rollout%` — so the greenfield half of § 1 is now observed
rather than inferred from "no revision created one". And `platform_api` holds
`SELECT, INSERT, UPDATE, DELETE` on `licence_delivery_targets`, which is the
seal's actual work: revoking the three write privileges while keeping `SELECT`
is what makes the projection structurally read-only rather than read-only by
the absence of a caller.

**Read the premise narrowly: NEVER POPULATED, not "exercised and wrote
nothing".** The rest of this database is empty too — `vendor_accounts` 0,
`offer_versions` 0, `platform_admins` 0, `mod_approvals` 0, `mod_ealloc` 0 —
and `platform_audit_events` holds exactly ONE row, whose only action is
`vendor.release_evidence.catalogued`. The two write-path audit codes are absent
from that ledger, but a ledger with one event total is weak evidence: it is
equally consistent with the writer never being called and with the deployment
barely being used at all.

That distinction does not change which branch applies — zero rows is zero rows,
and the sealed path is correct either way. It changes what the measurement may
be cited FOR. It licenses sealing; it does not license skipping the recheck,
and it is not evidence that the registration path is unreachable.

**Production was behind main when this was taken, and has since caught up.** At
12:44Z the applied vendor head was `v014`. Deploy run `32485479666` then took
production to `af9fcf6d3fbd259fbef6b589d37b39d548f7ba8e` at image
`sha256:45715e425dc248d85fe374fa5d347087328a445cf7ead1f8abc29f05f0117b0d`,
applying kernel `0024`–`0026`, `v015`, `v016` and the a5/a6 verification
revisions in one run.

**Re-verified at 2026-08-21T14:17:32Z on the new image and heads
(`ap_0002_outbox_relay`, `ea_0003_platform_audit_log`,
`rl_0001_release_artifacts`, `v016_licensing_authority`): the delivery estate is
still zero, and `mod_deploy` is still absent.** The measurement therefore held
across a deploy that rewrote five other lineages, which is stronger evidence
than the single observation was — and it is the only reason the earlier
observation is still usable. The refresh happened because the state changed, not
because a date passed.

**This is a temporal negative, and it is recorded as one.** An absence describes
a moment. Its refresh responsibility is not prose: the forward revision below
re-checks both tables under `ACCESS EXCLUSIVE` in the same transaction that
seals the write path, and fails closed on any row. The observation licenses
writing that revision; the revision, not this table, is what licenses applying
it.

### The path this selects

The **empty** branch. The forward vendor revision, in ONE transaction:

1. takes `ACCESS EXCLUSIVE` on all five delivery tables in a **fixed, declared
   order** — `licence_deliveries`, `licence_delivery_states`,
   `licence_delivery_targets`, `licence_delivery_attempts`,
   `licence_ack_records`. All five rather than the two under measurement,
   because the seal is only meaningful if nothing in the estate can move under
   it; a fixed order because two concurrent runs taking them in opposite orders
   deadlock;
2. re-counts, and checks the RELATIONSHIPS as well as the tables — deliveries
   with and without `target_id`, referenced versus unreferenced targets,
   dangling `target_id`, dangling `target_ref`. A table-count-only recheck
   passes on a dangling reference, which is exactly the state a half-migrated
   estate would be in;
3. aborts without change if anything is non-zero. The premise is re-proved at
   execution time on the real database, or the revision does nothing;
4. REVOKEs `INSERT`, `UPDATE` and `DELETE` on `licence_delivery_targets` from
   `platform_api`, retaining `SELECT`, and verifies the effective outcome in
   both directions as `v012`/`v013` did;
5. leaves the table in place. It is not dropped here — ADR-0010 owns that, and
   dropping it now would merge two cutovers.

**Step 4 must land before the locks release, and that ordering is the whole
point.** `POST /targets` → `register_delivery_target` is still mounted and
reachable while this runs. Checking emptiness under a lock and then releasing it
with the writer still live preserves precisely the race the check exists to
close: a registration landing between the recheck and the seal. "Empty when
measured" and "cannot become non-empty" are different claims, and only the
second licenses a seal.

No backfill, no comparison, no writer-switch ceremony: there is nothing to
migrate, and building parity machinery against an empty estate is the defect
`dotmac_starter_mt` ADR-0031 seals against and that ADR-0005 already refused once.

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


## Amendment — 2026-08-21 (the seal is DELETE-only, and the writer is reconciled)

§ 4 specified that the forward revision REVOKEs `INSERT`, `UPDATE` and `DELETE`
on `licence_delivery_targets` from `platform_api`. Implementing it surfaced a
contradiction with ADR-0010 § 1, and Michael ruled on the resolution.

**The contradiction.** `projection._authorised_target` resolves a delivery
against a *registered* projection row. If the projection is unwritable and the
registration route is gone, no target can ever exist, `_authorised_target`
always raises `NotFound`, and staging is permanently impossible. That is
removing the delivery path, not sealing an authority — and ADR-0010 § 1 requires
the existing logging and offline-bundle behaviour PRESERVED until its own
cutover, behind mirror/seal/activate gates this slice does not have. The full
revoke reached past ADR-0011's mandate into ADR-0010's.

**The resolution: reconciled, with a DELETE-only revoke.**

- `register_delivery_target` is retired. Its replacement takes no caller-supplied
  identity at all: `vendor_cp.deployment.adapter.resolve_target` reads the
  authoritative record from `mod_deploy` and returns `DeploymentTargetFacts`,
  which is constructible nowhere else. `projection.reconcile_delivery_target`
  accepts only that type. `POST /targets` keeps its path and method — the
  operation is still "make this destination available" — but its body now names
  a target the fleet owner owns instead of describing one.
- `platform_api` KEEPS `INSERT` and `UPDATE`, because the reconciler needs them.
- `DELETE` is revoked, and that one is not a compromise: a projection is rebuilt
  from its authority, never deleted. A role holding `DELETE` on a projection can
  only destroy evidence.

**State the weakness plainly.** The single-writer guarantee is now provenance
plus an architecture ratchet, not a database privilege. A future caller could
reacquire the ability to write arbitrary values by constructing the facts type
outside the adapter; `test_only_the_adapter_constructs_the_provenance_type`
fails if anything but the adapter and the seam's own unit tests does. That is
weaker than a grant, and it is recorded as weaker rather than described as a
seal it is not. ADR-0010 removes the table and the question with it.

**Consequences for the retired vocabulary.** `vendor.licence.delivery_target_registered`
and `_updated` retired with their writer — ADR-0008's every-declared-code-has-a-consumer
rule makes that the same change, not a follow-up. One code replaced them:
`vendor.licence.delivery_target_reconciled`. `registered` versus `updated`
distinguished create from update on a caller's claim, and a reconciliation
against an authority that already decided has no such difference to name.

**What did NOT change.** `_authorised_target` still performs every eligibility
check separately — active status, customer match, bound-deployment match —
because registration was never authorisation and reconciliation is not either.
The customer-repointing refusal is gone, and only that: the customer is no
longer a caller's claim to get wrong, so a change is a correction to project.
