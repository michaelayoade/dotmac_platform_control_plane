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

**RATIFIED 2026-09-25 by Michael Ayoade, the owner and only approver, including
the replacement A6.4 recorded on 2026-09-04.** The amendment was originally
proposed 2026-09-01. A6.1, A6.2, A6.3 and A6.5 had already been accepted in
substance; this record now makes that acceptance explicit and ratifies the
replacement A6.4 as part of the complete A6 amendment. Ratification was given
after § A7's separate ratification record, through the owner's instruction to
implement the recommendation that named this exact scope; it does not amend
§ 5's bootstrap or authorize a deployment.

**Nothing above the amendment is edited**, for the reason A2 already gave: a
record quietly rewritten to look as though it always said the right thing
teaches nobody what the mistake was. A6.4 follows the same rule one level down —
it is replaced rather than overwritten, and the clause it replaces is quoted
inside it.

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

### A6.4 Every plan input derives from one immutable reference

**REPLACED 2026-09-04 on Michael's ruling; RATIFIED with the complete A6
amendment 2026-09-25.** A6.1, A6.2, A6.3 and A6.5 are accepted and are not
reopened; A6.4 alone was replaced, and what it used to say is kept below rather
than deleted, for the reason the amendment header already gives.

**Which record this is.** This is `dotmac_platform_control_plane`'s ADR-0013 —
*the operator authorization issuer, and the one-time bootstrap that starts it* —
and its amendment A6. `dotmac_governance` has its own, unrelated ADR 0013
(*Repository-local claims and external oracles*), so a bare "ADR-0013 A6"
resolves to the wrong record and means something else entirely. The Governance
lane hit exactly that ambiguity and parked this ruling in its open decision 47
rather than writing across the boundary. Cite this clause with its repository.

#### The rule

> Target, desired state, profile digest, authorized images and execution-plan
> inputs are derived from one immutable reference. No independently supplied
> value may silently join the plan.

Five values, named individually so a reader cannot discharge the clause by
checking one of them:

1. **target**
2. **desired state**
3. **profile digest**
4. **authorized images**
5. **execution-plan inputs**

Each is DERIVED — resolved from the reference — rather than accepted from
whoever invoked the command. The reference is immutable, so the derivation is
repeatable: the same reference yields the same five values, and a plan digest
computed over them identifies one set of inputs rather than one invocation.

#### What A6.4 said before, and why it was not enough

The clause it replaces read:

> `--spec` is REQUIRED, although `DesiredDeployment.spec` defaults to an empty
> mapping upstream. An omitted spec would freeze an empty specification into an
> immutable plan digest and the approver would approve it without ever seeing
> that it was empty. Refusing to guess an argument is a decision about this
> surface; what a spec MEANS is read by nobody here and, deliberately, by
> nobody upstream either. An operator who wants an empty spec writes `{}` in a
> file.

That was right about the failure it named and too narrow about the class. It
made the operator SUPPLY a specification rather than let one be defaulted, and
then froze whatever was supplied into an immutable plan digest that an approver
approves. Requiring the value does not make it derived. The sentence admits the
gap in its own words — *what a spec MEANS is read by nobody here and,
deliberately, by nobody upstream either* — so an operator mapping travelled into
an authorized, digested, approved plan with no authority having read it. A
required free value and an absent one differ in whether someone typed
something, not in where the value came from.

The replacement closes that: the operator does not submit raw specification,
image or digest values at all. They name a reference, and the five values are
resolved from it.

#### `silently` is the enforceable half

A value that joins the plan **loudly** is a different act from one that arrives
unnoticed, and the clause forbids only the second. Written so a future guard can
tell them apart — this clause will want one, and none exists today:

- **Derived.** The value is resolved from the immutable reference, and the plan
  records that as its provenance. This is the ordinary path.
- **Refused.** An independently supplied value is rejected at the boundary with
  a typed refusal naming which of the five it was. The operator learns
  immediately; nothing reaches the digest.
- **Recorded as an override.** The value is accepted, but only through an
  explicit override that is itself carried into the plan and into the receipt,
  so the plan states which of its inputs did not come from the reference. An
  approver reading the plan sees the exception without having to reconstruct it.

**Silent** is therefore the residue and is defined by what is missing rather
than by intent: a value that was accepted, was used, was covered by the digest,
and appears in neither the refusal path nor the plan's own record of provenance.
An enforceable check follows directly — for each of the five values the plan
carries a provenance, and any provenance that is not the reference must appear
in the plan's declared overrides. A value with no provenance at all is the
violation, and it is detectable without knowing what the value means.

This is deliberately not a ban on overrides. A ceremony with no exception path
grows one that is undeclared, which is the shape this clause exists to end.

#### The profile digest is constrained by two records, and both should say so

The third derived value is also governed upstream. `dotmac_governance`
**ADR 0039 § 8** — *The digest travels, and the read-back compares* — already
requires the profile digest to appear in the Foundation execution plan and in
the signed release receipt, with a read-back after deployment that COMPARES the
running system against the authorized digest and never derives the authority
from it.

The two records constrain the same value from opposite ends. Governance ADR 0039
§ 8 says where the digest must TRAVEL and what compares it; this clause says
where it must COME FROM. They agree, and the agreement is worth stating rather
than leaving to be noticed: an editor of either record who does not know about
the other can weaken this value without appearing to touch anything the other
owns. If this clause is ever narrowed, ADR 0039 § 8 is the record to read first,
and the reverse holds.

#### The downstream consequence, named and not resolved here

This clause is the record behind Michael's step 4, which requires Platform CP to
replace free-text `authorization_ref` with resolution of a standing Control
authorization, and to derive target, desired state, profile digest, image set
and plan input from one immutable reference. **That work is not done here and
this amendment does not do it.**

The current state, measured 2026-09-04 in this repository rather than assumed:
`AUTHORIZATION_REF` is operator input, validated for SHAPE alone against
`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` in `.github/workflows/production-deploy.yml`
and in `scripts/deploy_production.sh`, then carried to the remote command line.
Nothing resolves it, and nothing checks that it names a standing authorization.
Both files say so in their own words — the workflow: *"While the legacy path is
frozen this is validated and carried, never acted on."* A shape check admits any
string of the right alphabet, including one naming an authorization that was
never issued.

That is the gap this clause closes as a DECISION. Closing it in code is separate
work, and stating it here rather than implying it discharged is the point.

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

---

## Amendment, 2026-09-23 — rehearsal issuer source seam only

`src/vendor_cp/deployment/rehearsal_issuer_seam.py` defines an immutable
three-field command and an opaque evidence carrier. It converts only
`command_id`, `plan_id`, and optional `actor_ref` to Control a14's request
mapping. This is source readiness, not operational issuance: the application
stays at its existing kernel a98, Control a6, and Governance schema-9 pins.
This does not install a signer or verifier, close Gate 0 or Gate 1, activate
the issuer, or allocate Foundation. Exact a14 disposable composition is the
next separate gate.

---

## Amendment, 2026-09-24 — disposable a14 rehearsal issuer harness source

`rehearsal_issuer_harness/` is a candidate-independent source and receipt
readiness gate for Control `0.1.0a14`. Its lock identifies exact Control and
Kernel wheels and its explicit test lane requires those installed artifacts,
a real disposable PostgreSQL database, and ephemeral distinct Ed25519 keys.
The harness sends the dependency-light three-field request from the Platform CP
leaf into Control's installed issuer. Control alone derives the signed statement
from its frozen approved plan, records standing, and governs revocation and
single-use consumption. The harness neither launches a deployment nor grants
an application authority over its own creation.

This amendment records local harness source and potential test receipt
readiness only. Protected runner identity, production key custody, and genuine
approval provenance are still open. Gate 0/1, namespace allocation, rehearsal
of an exact Foundation artifact, and Platform CP adoption remain unclosed;
passing this harness alone cannot close any of them or amend § 5's bootstrap.

---

## Amendment, 2026-09-24 — Work Packet A: the Gate 0/2/3 authority contract

**RATIFIED 2026-09-24 by Michael Ayoade, the owner and only approver.**
Proposed 2026-09-24 and merged as Platform CP PR #196
(`c8ead5ac1f35aa2d457fa26f0454051df4ef2ed3`), with its Starter companion PR
#747 (`ead3b8a7ba981533216908ae0c14328a6c48e79f`). Ratification was given
separately, after both merges, in the owner's own words: "a is ratified" —
recorded here because this amendment itself states that a merge is not a
ratification. As originally proposed: this amendment does not implement
anything; it freezes what the next five work packets (B, C1, C2, D, E, tracked
outside this ADR) must be consistent with before any of them may merge. Work
Packet A is now closed, and B, C1, C2, D and E may begin implementation in the
order § A7.7 and the Starter roadmap state.

Only § A7 was ratified by the 2026-09-24 record. A6, including replacement
A6.4, was ratified separately on 2026-09-25 and carries its own provenance at
the head of that amendment.

### A7.1 Why a rehearsal issuer needed its own gate sequence at all

§ 5's bootstrap discharges a circularity for the REAL operator-authorization
issuer once, by hand, outside any automated path. The rehearsal issuer's own
2026-09-23/24 amendments discharged a *different* circularity: Platform CP's
full application cannot adopt Control `0.1.0a14` + Kernel `0.1.0a101` before
Governance schema 11 exists, schema 11 cannot exist truthfully before a
Foundation successor renders real `deployment_artefact_surfaces`, and that
successor cannot be allocated before Gate 0/1 rehearsal readiness is proven —
which was exactly the readiness the full application was blocked from
proving. The dependency-light seam (PR #194) and the disposable Control
a14/Kernel a100 harness (PR #195) broke that cycle by separating MECHANISM
readiness from APPLICATION adoption. Both merged; the mechanism — real
Ed25519 issuance/verification, real migrated PostgreSQL, real
production-matching role privileges, replay/concurrency/rollback/revocation —
is now proven on protected `main` at commit `c80415fa6837b2f2c9ebb4755d5a0b3f9fbf55f3`.

That proof is not the same claim as "a real Foundation candidate may be
rehearsed through Lane 3 today." Proving the mechanism is real is not the
same as authorizing a specific candidate to use it, and folding those two
claims into one step is exactly how the ORIGINAL circularity re-forms one
level up: a Lane-3 receipt issued before a real successor exists would be a
receipt for nothing, and the temptation to backfill its meaning once a
successor is finally allocated is indistinguishable, from the outside, from
manufacturing consent after the fact.

### A7.2 The three gates, and what each one's output actually is

| Gate | Question it answers | Output | Must NOT produce |
| --- | --- | --- | --- |
| **Gate 0** | Can the protected rehearsal issuer genuinely issue, hold standing on, revoke, and single-use-consume authority, under real custody and a real approval chain — with no candidate in the loop? | Work Packet E's immutable, candidate-independent protected issuer-readiness receipt and a reviewed authority graph (this amendment plus B, C1, C2, D, E below) | Any authorization naming a specific Foundation candidate. A candidate does not exist yet; nothing may bind to one. |
| **Gate 2** | Given candidate-independent Gate-0 readiness, what is the one Foundation successor this fleet allocates, builds, and signs? | Exactly one allocated, built, signed Foundation successor artifact | Rehearsal, execution authority, or a change to the rehearsal-issuer mechanism. Gate 2 consumes Gate 0's readiness evidence; it does not renegotiate it. |
| **Gate 3** | Does the exact successor built in Gate 2 pass an authorized, exact-byte Lane 3 rehearsal, using Gate 0's real protected issuer composition? | An issued and validated Foundation `ExecutionGrant` binding the exact candidate and execution inputs, followed by a genuine candidate-bound Lane-3 receipt on the real self-hosted runner | Treating Gate-0 readiness or issuer-operation authority as authority to execute the candidate. |

A Gate cannot be reordered or partially skipped. Gate 2 may begin only from
candidate-independent Gate-0 readiness evidence; Gate 0 authorizes no
candidate. Candidate-specific authority arises only after Gate 2, within Gate
3. Before any executor or Lane-3 action, Gate 3 must obtain and validate
Foundation's candidate-bound `ExecutionGrant` against the exact Gate-2
artifact bytes, rendered plan, target and host, and controller identity. An
absent, invalid, or mismatched grant refuses the run. Only then may Gate 3
execute the Lane-3 rehearsal and produce its receipt.

### A7.3 The document-purpose matrix — five documents, never conflated

This is the concrete failure this section exists to prevent: two of these
five are easy to read as the same kind of thing because they both flow
through Control, and they are not.

| Document | Issued by | Binds | Consumed by | Explicitly NOT |
| --- | --- | --- | --- | --- |
| **Rehearsal-issuer authorization** (`RehearsalIssuerAuthorizationV1`, Control a14) | Control's real `issue_rehearsal_issuer_authorization_for_plan`, against a genuinely approved, standing plan | One lease's authority to OPERATE the protected rehearsal issuer; PR #195's disposable harness proves the mechanism but is not that protected composition | The rehearsal issuer's own consumption/revocation/standing surface | **A grant to deploy, execute, or provoke anything.** It says "this lease may operate the issuer machinery," never "this issuer may act on a target." |
| **Foundation `ExecutionGrant`** (owned by Foundation, C1 selects the real path) | Foundation, against its own execution-authorization semantics — still undecided, C1's exact job | Gate 3's authority for the exact Gate-2 artifact bytes, rendered plan, target and host, and controller identity | Foundation's executor, after Gate 3 obtains and validates it | **Not issued, checked, or implied by the rehearsal-issuer authorization above.** Confusing the two would let "the issuer is allowed to exist" stand in for "this deployment is allowed to run" — the single most consequential document-purpose collapse this matrix exists to refuse. |
| **Harness evidence** (`rehearsal_harness_evidence.py`, Control a14) | The disposable harness uses its own ephemeral signer for mechanism proof; the protected composition must use independently signed evidence bound to the real controller's per-run OpenSSH key fingerprint (§ A7.4) | One lease presentation's authenticity — "this presentation genuinely came from the harness controller for this lease, in this environment, in this window" | Rehearsal-issuer issuance and consumption, as the caller-supplied but independently verified evidence | **Not an approval of anything.** It authenticates a presenter; it does not authorize an action. |
| **`ApprovalEvidence`** (`dotmac-approvals`, via Control's real `approve_plan`) | A human approver, through `dotmac-approvals`'s own real decision flow | That a specific frozen plan snapshot was genuinely reviewed and granted | `approve_plan`, and transitively every later reader of plan standing (including the rehearsal issuer's own `_standing_plan_terms`) | **Not rollout-coupled for a rehearsal act.** CP's existing deployment adapter (ADR-0013 § 2 item 2) carries `ApprovalEvidence` straight into `approve_plan` on the way to `request_rollout` — Work Packet B's protected adapter must reach the identical `approve_plan` call without ever constructing or requesting a `DeliveryIntent`. Approving a rehearsal is not approving a deployment, even though both terminate in the same `approve_plan` call. |
| **Lane-3 receipt** (`RehearsalReceipt.v1`, Starter/Foundation, pre-existing per `docs/inventories/lane3-acceptance-criteria.md`) | The exposure-rehearsal runner, against its own sixteen-item closed vocabulary | That a specific candidate passed real, measured exposure-verification rehearsal | `require_rehearsal.py`'s publication gate | **Not itself an authorization to deploy.** It is evidence a candidate already holding execution authority (from Foundation's `ExecutionGrant`, above) behaved correctly under measured exposure conditions. |

The named Control, Approvals, harness-verification, and receipt-gate paths
already exist (`issue_rehearsal_issuer_authorization_for_plan`, `approve_plan`,
`verify_rehearsal_harness_evidence_signature`, `require_rehearsal.decide`).
The Foundation `ExecutionGrant` issuance and validation path is still C1's
undecided contract; this matrix does not assert that arrow exists today or
propose a sixth document. Among the five downstream packets B, C1, C2, D,
and E, the first four close distinct gaps:
B closes the `ApprovalEvidence` row's rollout-decoupling; C1 closes the
`ExecutionGrant` row's still-undecided semantics; C2 wires B's protected
adapter into the composed assembly; D closes the harness-evidence row's
identity gap (§ A7.4) and the Lane-3 row's protected-runner/environment gap
(§ A7.5). E accepts their candidate-independent operational evidence and
closes Gate 0 (§ A7.7).

### A7.4 Identity and custody — what is real, what remains a test fixture

| Role | PR #195's disposable harness (mechanism proof) | Gate 0's protected issuer composition (Work Packets B, C2, D; operationally accepted by E) |
| --- | --- | --- |
| Rehearsal-issuer signer (`RehearsalIssuerAuthorizationSigner`) | Ephemeral in-memory Ed25519, generated fresh per test session, never persisted | A real key held under OpenBao custody (fleet-standard pattern — see `bao-get` skill), installed once at process start via `install_rehearsal_issuer_security`, never resolved on the per-request path (mirroring `authorization_v3`'s existing "no OpenBao call on the controller path" discipline from § 5) |
| Rehearsal-issuer authorization verifier | The same ephemeral key's own public half | The same real signer's public half; no separate verifier identity |
| Harness-evidence verifier / controller identity | `HarnessSecurity`'s own ephemeral Ed25519 fingerprint — explicitly named in the harness's own README as "test data, not genuine protected-runner approval" | The REAL controller's per-run OpenSSH key fingerprint, derived from the actual key the protected runner (`control-runner-starter-mt`) uses for that run, bound into independently signed harness evidence AND into the lease record. This is a materially different identity shape (OpenSSH host/user key fingerprint, not an ad hoc Ed25519 keypair minted for the occasion) and Work Packet D owns deriving it correctly — it is not a drop-in replacement of the harness's key with a "more real" Ed25519 key. |
| Approval identity | None — the harness's `_seed` helper constructs `ApprovalEvidence` directly as test fixture data | A genuine `dotmac-approvals` decision, reached through Work Packet B's protected (non-rollout) adapter |

No OpenBao path was read, no key was created, and no secret value was
observed while drafting this table. Where this table names a custody
location, it names the PATH convention only (fleet-standard, per the
`bao-get` skill), never a value.

### A7.5 What is independently confirmed absent, as of this amendment

Read directly against the live repository and its GitHub configuration,
2026-09-24, read-only:

- **No protected rehearsal GitHub Environment exists.** `pypi-release` and
  `registry-release` are the only two environments on this repository.
- **`control-runner-starter-mt` is online and idle**, carrying exactly the
  labels `self-hosted, Linux, X64, dotmac-control-runner,
  dotmac-foundation-control`. Its only observed diagnostic run was cancelled
  on 2026-08-31; no successful run is on record.
- **Repository variables are exactly `LANE3_PROBE_HOST` and
  `RELEASE_RECORDER_CLIENT_ID`.** No observer-user, jump-key, or
  inside-vantage variable that `docs/inventories/lane3-acceptance-criteria.md`'s
  own vantage requirements would need exists yet.

Work Packet D owns closing all three. This amendment records their absence
as a precondition Gate 0 has not yet met, not as a defect in anything merged
so far — PRs #194/#195 never claimed to close them.

### A7.6 Ownership, restated for the rehearsal issuer the way § 7 states it for the real one

| Owner | Owns |
| --- | --- |
| `dotmac-deployment-control` | Rehearsal-issuer authorization state — issuance, standing, revocation, single-use consumption (already real, per PR #61's merged `rehearsal_issuer_issuance.py`) |
| `dotmac-approvals` | The approval DECISION an `ApprovalEvidence` carries — Platform CP constructs no approval logic of its own, exactly as § 2 already holds for the real issuer |
| Deployment Foundation | Execution semantics and the `ExecutionGrant` boundary (Work Packet C1) — Control's rehearsal-issuer envelope never substitutes for this |
| Platform CP (this assembly) | The protected rehearsal-issuer OPERATOR WORKFLOW (Work Packets B/C2) and the single writer of Gate-0's candidate-independent readiness receipt (Work Packet E); it decides nothing about plan legality, execution authority, Lane-3 receipt content, or drift, exactly as § 2's test of a design error already states |
| Starter / Foundation infrastructure | The protected runner, its GitHub Environment, OIDC, and the Lane-3 vantage configuration (Work Packet D) |

Do not create a second rehearsal-issuer state owner, a second approval
model, or a second execution-authorization path. The test of a design error
from § 2 applies here unchanged: if a change to any of B, C1, C2, D, or E
would require deciding *whether a plan is standing, whether a signature is
valid, or whether a deployment may execute*, the change belongs to the module
that already owns that decision, not to the workflow composing it.

### A7.7 Work Packet E — operational Gate-0 acceptance and closeout

Platform CP owns this packet and is the single writer of the immutable
protected issuer-readiness receipt. E begins only after Michael ratifies this
amendment and B, C1, C2, and D are each accepted. It consumes D's protected
workflow evidence and the accepted, immutable revision and test coordinates
from B, C1, and C2. Using a candidate-independent issuer-operation test plan,
the protected run must show a genuine human approval through
`dotmac-approvals`, real issuer signing custody, and the actual
controller's per-run identity in independently verified harness evidence. It
exercises issuance and standing, then single-use consumption with replay
refused; a separate lease exercises revocation with later use refused. Missing
approval or custody, an absent or mismatched controller identity, invalid
evidence, a stale or revoked lease, or a second consumption is a refusal, not
a readiness pass.

E records the protected environment and run identity, exact source revisions,
evidence digests, and pass/refusal outcomes in a candidate-independent receipt.
The receipt names no Foundation successor, artifact, rendered deployment plan,
or candidate-bound authority. A disposable-harness result cannot substitute
for the protected run. Gate 0 closes only when this receipt passes after B,
C1, C2, and D close. E does not allocate, build, sign, or rehearse a Foundation
candidate, produce an `ExecutionGrant`, or authorize deployment. Gate 3 alone
obtains candidate-specific execution authority after Gate 2 builds its artifact.

### A7.8 What this amendment does not do

It does not install a signer, create a GitHub Environment, provision a key,
read an OpenBao path, allocate a Foundation successor, or authorize any
candidate. It does not amend § 5's bootstrap or A6's plan-input decisions. It
is the ratified reference with which B, C1, C2, D, and E must be consistent. Gate 0 does not close until B, C1, C2, and D each close
against it and E produces its passing protected issuer-readiness receipt.
