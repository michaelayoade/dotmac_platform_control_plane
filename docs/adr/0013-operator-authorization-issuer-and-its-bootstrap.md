# ADR-0013: The operator authorization issuer, and the one-time bootstrap that starts it

- **Status:** ACCEPTED 2026-08-30 by Michael Ayoade, the owner and only
  approver, with the Control release replacing `0.1.0a4` in § 5's bootstrap evidence —
  now `0.1.0a6`, a5 having been refused in turn (§ 4).
  **Acceptance is not deployment.** Nothing in §§ 5–6 has been executed; § 8
  records what remains and is kept current rather than deleted on acceptance.
- **Date:** 2026-08-30 proposed, 2026-08-30 accepted
- **Owner:** Michael Ayoade
- **Follows:** ADR-0011, which composed `dotmac-deployment-control` and cut
  deployment-target authority over to it
- **Relates to:** `dotmac_governance` ADR 0016 (Accepted 2026-08-30), which
  renames this repository's public identity and states, in its own words, that
  the assembly is "not the owner of every capability it presents"

## 1. Context

ADR-0011 composed `dotmac-deployment-control` and said plainly that "Vendor has
no operator surface for them yet" — `register_target`, `set_desired_state`,
`propose_plan`, `approve_plan` and `request_rollout` are the module's own
commands, and `src/vendor_cp/deployment/adapter.py` is read-only.

The consequence is the thing this ADR exists to fix. The module that owns
deployment authorization is a *library*. A library issues nothing. Until some
deployed assembly presents its commands to an operator, no authorization
receipt can be produced anywhere in the fleet, and every consumer that was told
to bind one is waiting on a record that cannot yet exist.

This assembly is where that surface belongs, because it is already the composed
consumer of the owner. What it must not become is a second owner.

## 2. Decision — the issuer is an operator workflow, and nothing else

This assembly exposes the EXISTING owner. It implements no planner, no approval
model, no deployment engine and no health authority.

Concretely, the issuer is permitted to do exactly four things:

1. call `propose_plan`, which freezes a snapshot and computes its digest;
2. carry an `ApprovalEvidence` produced by `dotmac-approvals` into
   `approve_plan`;
3. call `request_rollout`, and hand the resulting `DeliveryIntent` to the
   Integrator;
4. read `get_plan` / `get_rollout` / `get_target` / `plan_snapshot` for display.

Everything else — what the plan contains, whether the transition is legal,
what the receipt says, how drift is judged — stays in the module. The seam
stays `src/vendor_cp/deployment/adapter.py`, and the ratchet in
`src/vendor_cp/cutover_readiness.py` keeps counting it.

**The test of a design error.** If a change here would require this assembly to
decide *how a target is changed*, the change is wrong and belongs upstream.
That is not a style preference: the module's own docstring says a plan is
frozen precisely so that "editing the desired state mid-rollout would silently
change what is being deployed, and the approval would be for something else". A
second decision-maker on this side reintroduces exactly that.

## 3. What an authorization binds

Ten axes. Six are already columns or command fields upstream; four are the
assembly's own responsibility to supply and are named as such, because a
binding whose source is unnamed is a binding nobody maintains.

| Axis | Where it comes from |
| --- | --- |
| Target identity | `DeploymentPlan.target_id`, resolved through `resolve_target` |
| Canonical descriptor digest | supplied by the assembly, from the product's `DeploymentDescriptorDocumentV1` |
| Exact artifact / image digest | supplied by the assembly, inside the frozen `spec` |
| Normalized plan digest | `snapshot_digest`, upstream — see § 4 |
| Controller identity fingerprint | supplied by the assembly — see § 4's second defect |
| Authorization policy code and version | `ApprovalEvidence.policy_code` / `.policy_version` |
| Immutable approval-decision reference | `ApprovalEvidence.decision_ref` |
| Issued time and expiry | `ApprovalEvidence.decided_at`, plus an assembly-supplied expiry |
| Nonce / replay identity | the rollout's own idempotency key |
| Rollback boundary | the previously-observed spec digest on the target |

**No `approved_by`, and no equivalent.** `ApprovalEvidence` already carries
`approver_refs: tuple[str, ...] = ()`, and it stays empty. Approver identity
lives once, in `dotmac-approvals`, reachable through `decision_ref`. A name
copied alongside a reference is a second copy of an identity that can drift
from the decision it claims to describe, and the module deliberately has no
column for one.

Michael Ayoade is the sole human administrator and approver. A workflow that
appears to need two approvers is reporting a design error, not a staffing gap:
report it. Do not create a placeholder, a service identity, an agent-held
identity or a shared admin account to satisfy a two-reviewer rule.

## 4. Two defects measured in the pinned release, and where they must be fixed

Both were read at the peeled commit of `dotmac-deployment-control-v0.1.0a4`,
`2c61540f74018b7e19d7c5add893e0653cfcdb17`. Neither is repaired here, and the
reason they are recorded here at all is that this assembly is the first caller
positioned to hit them.

**Defect 1 — two sibling functions emit two digest encodings, and one raw `!=`
compares across them.** In `src/dotmac_deployment_control/service.py`:

- `snapshot_digest` (line 305) returns BARE hex — `…hexdigest()`;
- `spec_digest` (line 311) returns PREFIXED — `f"sha256:{…hexdigest()}"`;
- `propose_plan` stores `plan_digest=snapshot_digest(snapshot)` (line 889);
- `approve_plan` compares `command.evidence.content_digest != row.plan_digest`
  (line 974) and, on mismatch, refuses with "the plan changed after approval,
  so a new approval is required".

An approver supplying the canonical `sha256:<hex>` form — the form this same
module uses for `spec_digest`, for the credential fingerprint
(`models.py:328`) and for the raw body digest (`models.py:564`) — is therefore
refused, and the refusal *reads as tamper detection*. That is the worst
available failure mode for a security control: a formatting bug wearing a
security refusal's message.

The repair is a typed parser owned by the module: accept bare 64-hex and
`sha256:<64-hex>` only where compatibility requires it, normalize internally to
algorithm plus bytes, serialize canonically as `sha256:<64-hex>`, and reject
unknown algorithms, uppercase drift, wrong length and malformed values.

**It is not repaired in this assembly, deliberately.** A normalizer here would
be this assembly deciding when two plan digests are the same digest, which is
the § 2 design error exactly. `a4` is immutable and stays immutable; the fix
arrived in `a5`, which carries a Control-owned `PlanDigestV1`.

**a5 was then refused for a third, different reason, and this assembly found
it.** a5 imported `dotmac_kernel.transactions` — first shipped in kernel a98 —
while declaring `dotmac-kernel >=0.1.0a77`. Resolution succeeded, the lock
wrote cleanly, the artifact hashes matched the release evidence, and the
container died at boot on `ModuleNotFoundError`. A hash comparison proves you
got the published bytes; it cannot prove they import. **`a6` is the pinned
release**, carrying `Requires-Dist: dotmac-kernel (>=0.1.0a98)` read out of the
published wheel, and a canary that makes the floor fail in both directions.

Three published Control versions are now refused for three different reasons —
a3 its evidence chain, a4 its behaviour, a5 its declaration — and they are
deliberately not collapsed into "use the latest".

**Both a4 defects were accepted on 2026-08-30 and a4 is UNADOPTABLE.**
It keeps its tag, its artifact and its independently verified identity, and
nothing pins it. This assembly pins `a5`. The exact a5 coordinates are recorded
when that release carries its own `peeled_tag` and `release_run` oracles — not
from this document, which cannot observe a registry.

**Defect 2 — the published `a4` reports itself as `a2`.** At the same peeled
commit, `pyproject.toml` line 3 reads `version = "0.1.0a4"` while
`src/dotmac_deployment_control/__init__.py` line 172 reads
`__version__ = "0.1.0a2"`. Any controller identity fingerprint that reads
`dotmac_deployment_control.__version__` at runtime records the wrong version
into an authorization it is supposed to make auditable. Until `a6`, the
fingerprint must be taken from installed distribution metadata, never from the
module attribute. The fix derives `__version__` from distribution metadata, which
removes the second copy rather than keeping two and correcting one.

## 5. The bootstrap, and why there has to be one

The thing that authorizes deployments cannot authorize its own first
deployment. That is a genuine circularity, not an inconvenience, and it is
discharged once, explicitly, by a human.

- **Issued by Michael**, bound to `platform-cp-01`, bound to the exact artifact
  and descriptor digests, non-reusable, recorded separately from ordinary
  Deployment Control authorizations, and invalid after the first success.
- **Root-owned standalone launcher**, from exact release assets addressed by
  digest. No mutable tag — not `latest`, not a branch name, not a floating
  major.
- **No OpenBao call on the controller path.** The controller applies a signed
  envelope it was handed; it does not resolve secrets to decide anything.
- **Create-only.** The launcher creates the deployment; it has no update, no
  restart and no reconfigure verb.
- **The application does not authorize itself.** Nothing in the deployed
  Platform CP participates in authorizing the deployment that created it.
- It produces a **first-deployment receipt**, marked as a bootstrap receipt and
  not as an ordinary authorization.

Bootstrap evidence binds nine coordinates, and all nine are immutable: Platform
CP source revision; exact image digest; **the Control `0.1.0a6` wheel hash**;
product descriptor digest; database migration heads; launcher hash; workflow
revision; bootstrap authorizer; target `platform-cp-01`.

`a6`, never a refused release. The bootstrap receipt is the first artifact in the fleet to
bind a Control version, so binding an immutable-and-unadoptable release would
put a known-defective digest comparison at the root of the evidence chain.

## 6. Retirement, built in from the start

A temporary path with no retirement mechanism becomes permanent. So retirement
is three interlocking parts, and the load-bearing one is the first, because it
does not depend on anyone remembering.

**6.1 The launcher is structurally single-use.** It refuses to run when the
target already holds any deployment receipt, and its own success creates the
first one. There is no flag to skip the check. A second bootstrap is not a
policy violation to be caught in review; it is a refusal.

**6.2 The bootstrap receipt names its own successor condition.** It is written
with an explicit bootstrap marker and a field naming what retires it: a
second-deployment receipt for `platform-cp-01` whose authorization was issued
by Platform CP itself. Until that receipt exists the bootstrap receipt is a
live compatibility state; once it exists the bootstrap receipt is history.

**6.3 The mutation path is deleted, and the deletion is ratcheted.** The
launcher's call sites are counted in `src/vendor_cp/cutover_readiness.py` at
SYMBOL level, in both directions, alongside the existing entries. The count
goes to zero in the same change that records the second deployment. A
path-level ledger would stay green when the function is deleted and its module
remains — which, per hard rule 18, is exactly the transition that matters.

**The premise check that 6.2 needs, stated honestly.** "A second receipt
exists, self-authorized" is not a repository-local fact. Under AGENTS.md rule
17 it requires an oracle: a `deployment_run` id plus the immutable image digest
that run activated. No test in this repository discharges it, and none will be
written that pretends to. The gate states the condition; the dossier records
the evidence when it exists.

The bootstrap receipt is a one-time compatibility state, not a permanent second
deployment path.

## 7. Ownership, restated because the rename is when it gets blurred

| Owner | Owns |
| --- | --- |
| `dotmac-deployment-control` | plans, approvals, attempts, receipts — authorization STATE |
| Deployment Foundation | target-side rendering and EXECUTION |
| this assembly | the operator WORKFLOW only |
| ERP, Sub | their own runtimes and business decisions |

Do not create another deployment engine.

## 8. Precondition state, kept current

Acceptance did not discharge these; they are the difference between an accepted
design and a running issuer, and they are updated rather than deleted.

**Discharged 2026-08-30.**

- *Pre-rename GHCR evidence.* Captured and committed —
  `docs/operations/pre-rename-ghcr-package-state.json`, with
  `scripts/verify_ghcr_package_state.py` as the post-rename comparison. 23
  versions, 23 distinct digests, package private under a public repository,
  linked to repository id `1317527604`.
- *`platform-cp-01` exists.* Ubuntu 24.04.4 LTS, 4 vCPU, 8 GiB, 80 GiB, private
  address only, no public address and no destination-NAT to it, key-only SSH
  reachable solely through the management jump path. nftables is default-deny on
  input, forward and output, loaded at boot, and its egress allowlist has been
  observed refusing an unapproved destination while permitting an approved one.

**Outstanding.**

- *Egress.* The guest has no outbound path. There is no blanket masquerade for
  its subnet, so it needs one per-host source-NAT rule on the core router. Until
  that exists the approved-destination sets stay empty, which is why they are
  empty rather than pre-populated: an allowlist naming destinations that cannot
  be reached would assert a policy nobody has exercised.
- *PostgreSQL, backups and their restore rehearsal.* Blocked behind egress.
- *The Control `a6` pin.* Landed with verified hashes; it forces kernel
  a77 -> a98, which still owes a migration rehearsal against a RESTORED
  isolated database before it reaches the running deployment.
- *The rename itself*, and the equality checks that follow it.

Nothing above is worked around, and none of it is restated as satisfied
elsewhere in this document.

---

## Amendment, 2026-08-31 — the bootstrap is IN-PLACE, and create-only means an authority

Accepted 2026-08-31 by Michael Ayoade, on review of the first launcher written
against this record. **Nothing above is edited.** The original text stands as
what was accepted on 2026-08-30, and this section states what changed and why —
a record that was quietly rewritten to look as though it always said the right
thing teaches nobody what the mistake was.

### A1. The target is `vendor-cp-prod`, not `platform-cp-01`

§ 5 and § 8 name `platform-cp-01`. That host was cancelled: VMID 125 was
created, proven, and then destroyed, and Platform CP replaces Vendor CP **in
place** on the existing deployment instead. The approved physical target is the
host whose `/etc/dotmac-host-id` reads **`vendor-cp-prod`**, at
`149.102.158.144`, and the marker is what identifies it — an address can be
reassigned, a marker cannot be arrived at by accident.

The repository and product identity is Platform CP. The distribution, import
package, image coordinate, database and migration lineage remain `vendor`, and
that is deliberate rather than debt.

### A2. "Create-only" means creating the AUTHORITY once, not deploying

This is the correction that matters, and the first launcher got it wrong.

That launcher ran `docker compose up -d app` and rewrote `VENDOR_APP_IMAGE` in
`.env` — it **replaced the running application**. That is a general deployment
capability, which is precisely the thing the issuer is supposed to become the
sole owner of. Written to bootstrap an authority, it was a second executor.

So the property is stated exactly:

> The bootstrap CREATES the issuer's authority once, inside the existing
> deployment. It does not replace, restart, update or reconfigure the running
> application, and it exposes no interface that could.

Concretely, the bootstrap may create the issuer's persistence — the module's
schema and tables, through a one-shot migration container — and nothing else.
The running application is replaced for the first time by a deployment
**Platform CP itself authorizes**, and that self-authorized deployment is the
proof the issuer works. A bootstrap that had already replaced the application
would have removed the very thing the proof depends on.

No second issuer, and no general deployment or update interface, at any point.

### A3. The receipt binds all nine coordinates

§ 5's list stands, with the image half made precise. The receipt binds:

1. Platform CP source revision
2. registry image digest
3. transferred image ID
4. RootFS layer-chain digest
5. Control `0.1.0a6` wheel hash
6. product descriptor digest
7. migration heads
8. launcher hash
9. authorizer (Michael Ayoade) and target (`vendor-cp-prod`)

Three and four are both required and neither substitutes for the other.
`docker save`/`load` does not preserve the manifest digest, so an artifact
transferred without a registry credential cannot be identified by digest alone;
the layer chain is what survives the transfer, and the registry digest is what
ties it back to what was verified off-host.

Workflow revision is carried alongside as the tenth field where a workflow
performed the run; a hand-run bootstrap records the operator instead of
inventing one.

### A4. The receipt condition is the ADR's, not the launcher's own

The first launcher checked only for its own dedicated receipt file. A receipt
that exists under another name, or an incompatible receipt from an earlier
attempt, would not have stopped it. The condition is the one this record
describes — **any** receipt asserting the bootstrap has occurred — and an
existing receipt that cannot be parsed or does not match this contract is a
refusal, never an invitation to proceed.

### A5. What remains true from the original

§ 6's retirement mechanism is unchanged and is now load-bearing: the claim is
taken with `O_EXCL` before any work; the receipt names its successor condition;
the launcher's call sites are ratcheted and go to zero when Platform CP
authorizes its own second deployment. § 8's precondition list is superseded
only where A1 replaces the host.

---

## Amendment, 2026-09-01 — A6: the issuer must be able to create the SUBJECT it authorizes

Proposed 2026-09-01, pending Michael Ayoade's acceptance. **Nothing above is
edited**, for the reason A2 already gave: a record quietly rewritten to look as
though it always said the right thing teaches nobody what the mistake was.

### A6.1 The gap, stated as the document's own contradiction

§ 1 names five module commands with no operator surface — `register_target`,
`set_desired_state`, `propose_plan`, `approve_plan`, `request_rollout`. § 2 then
permits the issuer to do "exactly four things", and the two it drops are the
first two.

The consequence is the same one § 1 was written to end, one step earlier in the
chain. `propose_plan` freezes *a target's* desired state. With no command that
registers a target and no command that declares a desired state, there is
nothing to freeze, so `deployment authorize` — the command the whole record
exists to produce — has no reachable path to a plan. A measurement census on
2026-09-01 confirmed it: `cli/owners.py` declared six deployment commands and
none of them wrote a target, and `register_target` / `set_desired_state` were
called only in this repository's own tests. Zero authorization receipts have
been produced anywhere in the fleet, and this was one of three code gaps
blocking the first.

§ 2's four were not wrong about authorization. They were scoped to it, and the
subject of an authorization has to exist before it can be authorized.

### A6.2 The decision

The permitted list becomes six. `register_target` and `set_desired_state` join
it, reached the same way as the other four: through
`src/vendor_cp/deployment/adapter.py`, building the module's own command objects
and returning the module's own `TargetView`.

§ 2's four KEEP their numbers, and the additions are cited as **A6 item 1** and
**A6 item 2**. Renumbering would make every existing citation of "§ 2 item 2"
point at something else, in code comments and in a docstring nobody would think
to re-read.

`dotmac-platform deployment register-target` and `dotmac-platform deployment
set-desired-state` are the operator surface. The complete journey is then
register-target -> set-desired-state -> propose -> `approval open` /
`approval decide` -> authorize.

### A6.3 What is still upstream, named individually

§ 2's test of a design error is unchanged: if a change here would require this
assembly to decide *how a target is changed*, it belongs in the module. Four
decisions sit exactly on that line and none of them is taken here.

- **Idempotency on `target_ref`.** `register_target` returns the existing target
  when the reference is already known. The assembly reports no
  created-versus-already-present flag, because that comparison would be a claim
  the owner never made and a retry of a succeeded command would print a
  different answer for an identical outcome.
- **The unconditional `desired_revision` bump.** The module bumps even when the
  values are unchanged, deliberately, because the revision records that a
  DECISION was taken. There is no local "has anything actually changed?" check —
  the seductive one, which looks like an optimisation and is a second answer to
  whether a plan is worth proposing.
- **The `REGISTERED` -> `ACTIVE` promotion**, and the refusal to declare a
  desired state for a decommissioned target. Both are read out of the returned
  view, never re-derived.
- **Optimistic concurrency.** `--expect-record-version` is carried to the
  module's `expected_version` and compared there. A mismatch is the module's
  refusal (exit `3`), not an assembly mismatch (exit `6`).

**Registration is not authorisation**, and A6 does not weaken that. A registered
target has no desired state, `_STATUS` maps `REGISTERED` onto delivery
`SUSPENDED`, and the command that creates a registration says so in its output.

### A6.4 The one decision the CLI does take, and why it is a transport one

`--spec` is REQUIRED, although `DesiredDeployment.spec` defaults to an empty
mapping upstream. An omitted spec would freeze an empty specification into an
immutable plan digest and the approver would approve it without ever seeing that
it was empty. Refusing to guess an argument is a decision about this surface;
what a spec MEANS is read by nobody here and, deliberately, by nobody upstream
either. An operator who wants an empty spec writes `{}` in a file.

### A6.5 What this does not do

It does not add a suspend, decommission, credential-enrolment or
observation-recording command; those remain module commands with no operator
surface, and each is a separate decision when it is needed. It does not touch
the bootstrap in § 5, the retirement mechanism in § 6, or the kernel pin.

**And it does not carry a brand-profile reference.** `DesiredDeployment` has a
`brand_profile_ref` field; `set-desired-state` has no flag for it and the
adapter does not pass one, so it stays at the module's default. Brand Profiles
is deferred here by ADR-0007 § 6, this assembly composes no brand module, and
`test_this_assembly_holds_no_brand_record` measures the absence rather than
assuming it. An operator flag naming a brand profile would be a surface for
something that is not composed — the flag arrives in the change that composes
the module, not before it.

That ratchet caught the first draft of this lane, which passed the field
through. So did the reconciliation-seam ratchet, on a docstring that merely
NAMED `resolve_target`: the count is over occurrences, and raising a declared
call-site count to accommodate prose would have left room underneath it for a
real new caller. The prose was reworded instead. Both are recorded because the
tempting repair in each case was to edit the ledger.
