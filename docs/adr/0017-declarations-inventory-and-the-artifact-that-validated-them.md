# ADR-0017: Declarations, inventory, and knowing which artifact validated them

- **Status:** Proposed. Michael Ayoade is the owner and only approver.
- **Date:** 2026-08-31
- **Owner:** Platform Control Plane
- **Follows:** ADR-0013 (the issuer and its bootstrap), whose receipt is the
  first artifact this record's promotion rule governs

## 1. Three artifacts, not one file

A deployment descriptor is doing three jobs at once today, and they have
different lifetimes. Separating them is the substance of this record.

**The source contract** — stable rules. What roles exist, what each may bind,
what the database contract requires, which invariants must hold. It changes when
the product's shape changes, and it is reviewed as a design.

**The candidate descriptor** — an immutable build artifact naming an exact
future image, exact migration heads and an exact manifest digest. It is produced
once and never edited; a change means a new candidate.

**The accepted descriptor** — the current deployed truth. This is the one
`dotmac-deploy drift` compares a running deployment against.

## 2. The migration rule, which is the load-bearing part

> **The accepted descriptor always describes the deployment that currently
> exists.**

From which everything else follows:

- the candidate **never** replaces the accepted descriptor before migrations
  and runtime have succeeded;
- a successful deployment promotes candidate to accepted **atomically**;
- a **failed migration leaves the accepted descriptor unchanged**.

This is not theoretical here. `deploy/product.toml` describes a deployment that
exists — pre-bootstrap image `sha256:45715e42…`, revision `af9fcf6d…` — while a
bootstrap receipt on the same host records that `mod_deploy` was created and six
migration heads applied. The descriptor must not advance to describe the
application that will exist until that application is the one running. A
descriptor that ran ahead would make every drift check report a deployment
nobody performed.

> **Amended 2026-08-31 — see § 8.** Read literally, the paragraph above treats
> the descriptor as one unit, and that reading is wrong in the half it does not
> mention. The bootstrap advanced the DATABASE without deploying anything, so
> holding the whole descriptor still left it declaring a database that no longer
> existed. The image half must not run ahead; the database half must not fall
> behind.

The reverse ordering is the one that breaks by accident, because writing a file
succeeds more reliably than a migration does. A descriptor advanced while
migrations rolled back claims objects the database does not have, and the next
recovery run then fails against a database that is perfectly fine.

## 3. A check scoped to the known defect proves nothing about the next one

`deploy/product.toml` declared `environment = "production"` while carrying an
all-zero `assembly.manifest_digest`. The value is a syntactically perfect digest
naming nothing, so the descriptor parsed and any gate checking only parsing
reported green.

The fix carries a property worth naming, because it generalises: **the
placeholder check covers BOTH digests, not only the one that was wrong.** The
image reference was already real while the manifest digest was not, so a check
written for the failing field would have passed the day before and taught
nothing.

This is the same shape as a guard that enumerated five stateful modules while
six were composed. A check written against the defect in front of you proves the
defect is gone; it says nothing about the next one, and it is indistinguishable
from a check that works until the day it matters.

## 4. Two copies of a version is a defect class, not an incident

Generating the real manifest surfaced this: `dotmac-deployment-control` declares
`0.1.0a2` on its `ModuleManifest` while the installed distribution is `0.1.0a6`.
Every other composed module agrees.

It is the **third instance in one day**:

1. Deployment Control `a4` shipped self-reporting `__version__ = "0.1.0a2"`.
2. Starter's kernel `main` diverged from published `a99` under one version
   string.
3. A module manifest disagreeing with its own distribution.

**The rule this settles:** where a version exists in two places, the
DISTRIBUTION is artifact identity — it is what the lockfile pins, what the hash
covers, and what decides which code runs. A manifest built from the other copy
would be a truthful hash of an untruthful document, which is worse than no
digest at all. So `deploy/product-manifest.json` records the distribution
version and keeps the declared one beside it where they differ, rather than
resolving the disagreement silently.

The Control defect is filed against **that package's own repository**. It is not
fixed from here.

## 5. Which artifact validated the recovery bundle — established, not assumed

`dotmac_deployment_foundation.recovery` exists in **no published version**
(`0.2.0a1` and `0.2.0a2` both lack it, measured). So the bundle that earned
PROVED on 2026-08-30 was validated by bytes whose identity nothing recorded.

**Established.** The run imported a `git archive` extraction of Starter
`d6b9aae5` on `PYTHONPATH`, a bare source tree with **no distribution
metadata at all** — no `.dist-info`, no `PKG-INFO`. Its receipt recorded
`foundation_version: 0.3.0a1`, and **`0.3.0a1` was never published and never
tagged**; published tags are `0.1.0a1`, `0.2.0a1`, `0.2.0a2`. The receipt named
a version whose bytes nobody can retrieve.

**Reproduced.** The candidate artifact was downloaded (run `33339810583`,
artifact `9740182233`), its wheel digest verified as
`sha256:2a6e0ccd040b05ab602be4b439e48dd61188b3b71ed6e80ecc8a482e70d57443`
BEFORE installing — a download that is not digest-checked is not a pin — and the
identical retained evidence re-verified against it:

| | original | reproduced |
| --- | --- | --- |
| bundle digest | `sha256:f282bbc9…` | `sha256:f282bbc9…` |
| findings | 0 | 0 |
| roles restored | 5 | 5 |
| verdict | PROVED | PROVED |

The receipts differ in **exactly one field**: `foundation_version`, `0.3.0a1` →
`0.3.0a2`. Every other field is identical.

**PROVED stands, and now has provenance.** The recovery verdict did not depend
on the unrecorded bytes; only the receipt's claim about its own validator did.
Note the source trees are NOT identical — the candidate adds `ancestry.py`,
`authorization.py` and `evidence.py` and changes five more files — so
reproduction was a real check rather than a formality. `recovery.py` and
`errors.py` are byte-identical across both; `spec.py` differs, which is why the
comparison had to be run rather than reasoned about.

## 6. The pin is to the candidate, and it EXPIRES

`0.3.0a2` is held: publishing before rehearsal would recreate the deadlock the
candidate lane exists to break. So `scripts/recovery/build_bundle.py` binds to
the candidate coordinate the way Lane 3 does — digest-verified download of run
`33339810583`, artifact `9740182233` — and not to a published version, because
no published version contains the module it imports.

**That artifact expires 2026-11-28.** The pin is therefore a dated obligation,
not a permanent arrangement: either `0.3` publishes before then and the pin
moves to it, or Platform CP loses its recovery-bundle capability. A pin that
expires is a forcing function; an unpinned import has no deadline at all.

The declaration itself is owned by the Wave 4 CLI lane, which is the single
writer of `pyproject.toml` and the lockfile here.

## 7. The conformance gate is an accepted gap with a retirement condition

There is no `deployment-conformance.yml`, and it is not added yet. Under
`0.2.0a2`, `dotmac-deploy validate` refuses this descriptor:

```
error: unknown key(s) ['database']
```

`[database]` is the contract the recovery proof was checked against. The three
available moves were each refused, deliberately: arming a gate that fails on the
product's own descriptor; stripping `[database]` and discarding the contract;
pinning the held candidate.

**Retirement condition:** the gate arms — with `require-real-digests` left at
its default of `true` — when `0.3` publishes. ERP's is switched off while its
descriptor holds a real digest, which is the unarmed-gate mistake and is not
copied here.

Stating the condition is what makes this a monitored absence rather than an
oversight. Until then nothing checks the descriptor, and that is the gap.

## 8. One file, two halves, two different events — amendment, 2026-08-31

§ 2 says the accepted descriptor always describes the deployment that currently
exists, and then reasons about that deployment as a single thing that advances
at a single moment. It does not. `deploy/product.toml` describes two things:

* the **application half** — `[image]`, `[assembly]`, `[roles]` — which advances
  when a deployment replaces the running container;
* the **database half** — `[migration]`, `[database]` — which advances when
  migrations commit.

A normal deployment moves both in one step, which is why the distinction stayed
invisible. The create-only issuer bootstrap moved exactly one: it ran the
composed lineage in a short-lived `ops` container and deliberately did not
replace, restart or repin the application. § 2's refusal was therefore correct
for the image half and wrong for the database half, and the descriptor spent a
day declaring five module schemas and four heads against a database holding
seven and six.

**The rule, restated per half.** The accepted descriptor's image half must never
describe an application that is not running. Its database half must never
describe a database that is not there — in EITHER direction: not ahead of a
migration that has not committed, and not behind one that has.

**A promotion may move one half.** The 2026-08-31 reconciliation
(`docs/operations/descriptor-reconciliation-2026-08-31.md`) advances the
database half and carries the application half across unchanged, and
`deploy/descriptor-promotions.json` records which sections moved and which
values were carried, so a promotion that quietly advances the image fails rather
than passing as a database repair.

**What this amendment does NOT claim to fix.** § 2's atomicity — migrations and
declarations landing together — was violated by the bootstrap before this record
existed, and no promotion made afterwards restores it. The reconciliation is a
repair of a state that already broke the rule. The contract that would prevent
the next one — an operation that advances the database carries a candidate and
promotes it atomically, or refuses to run, and its receipt binds BOTH descriptors
— is being ratified in `dotmac_governance` and is not implemented here; the
`DatabaseContract` that would express it lives in the Foundation `0.3.0a2`
candidate this record holds unpublished (§ 6).

**And the reason none of it was noticed**, stated narrowly because the broad
version is false. `classify_invariant_breaches` in the Foundation does compare a
descriptor's declared `[[database.isolation]]` invariants against a catalogue
captured from live production. It could not have caught this: it runs inside a
recovery rehearsal, and it is scoped to the invariants the descriptor DECLARES,
and this descriptor declared no DELETE invariant. What had no live comparison at
all was `expected_schemas` and `expected_heads` — parsed, consumed by nothing,
so being wrong about them cost nothing.

§ 3's lesson applies twice over. A comparison scoped to what was declared cannot
report what was never declared, which is the present-but-undeclared problem
living in the checker rather than in the database. Every declared schema still
existed that day, so a declared-but-absent check was green on a database that
had moved. `dotmac-platform admin descriptor-drift` reports both directions,
against a catalogue capture from the target, connects to nothing, and is the
first live consumer those two declarations have ever had.

---

## Amendment — 2026-09-20 (a render candidate, distinct from § 1's three artifacts)

Proposed 2026-09-20, pending Michael Ayoade's acceptance. **Nothing above is
edited.** § 1 through § 8 stand exactly as written above; this section names
a gap between what Governance now requires and what this record currently
distinguishes, and proposes a fourth artifact to close it. It does not close
the gap itself.

### Why § 1's candidate descriptor is not the thing Governance's gate wants

Governance introduced a `deployment_artefact_surfaces` declaration at
`schema_version: 10`: a product must render its deployment assets and
byte-compare the rendered output against a committed copy, in CI, before
merge. `schema_version: 11` additionally requires `compatibility_retirements`
and `retirement_history`. Protected `main`'s `.dotmac/standards-profile.json`
is pinned to an older accepted Governance revision
(`a19259b10568d29dc0a9617347498fea7f1e7a97`, predating schema 10) and is not
exposed to either requirement. It is draft PR #187 specifically that repins
`governance_model.revision` to the newest accepted revision
(`7cb563d38d8f64f8019581a912a64ac466cd9fbd`, schema 11) while its own
`schema_version` field is still `9` — that mismatch, not anything on `main`,
is what fails the `Dotmac engineering standards` check.

§ 1 names a source contract, a candidate descriptor and an accepted
descriptor. The files under `deploy/candidates/*.toml` are instances of that
one candidate-descriptor kind; `deploy/descriptor-promotions.json` records
which one became `deploy/product.toml`, whose header says "THIS FILE IS A
PROMOTED CANDIDATE. IT IS NEVER HAND-EDITED." The ledger includes
`contract_change` and `composition_change` promotions that deploy nothing.
The latter explicitly declares what a deployment **will** run, not a process
role already running. The distinction here is therefore not past versus
future: the descriptor candidate and promotion ledger record a declared
contract and its promotion authority. They do not define a Foundation render
input and committed output that CI byte-compares with the asset production
consumes.

The deployment-artefact requirement instead needs a render input and
committed rendered output checked before merge. § 1 through § 8 name no such
artifact; reusing a descriptor candidate would silently couple its promotion
lifecycle to a different job.

### The proposed fourth artifact: the deployment render candidate — concept named, concrete shape DEFERRED

This amendment names the gap and proposes naming a fourth artifact —
distinct from all three § 1 names — as the **deployment render candidate**.
It does NOT yet propose the concrete file shape (an independent
`deploy/render-candidates/<date>-<slug>.toml` was an earlier draft of this
amendment's own text; that specific shape is DEFERRED below, not accepted).

The name is chosen to avoid exactly the collision Governance's schema
change would otherwise create with existing vocabulary: `deploy/candidates/
*.toml` already means "a pre-promotion draft of the accepted descriptor,"
per § 1 and the ledger's own `note` field. A deployment render candidate is
not a draft of the accepted descriptor and is never a promotion input. It
answers a different question — "what would Foundation's renderer produce
right now, from this input, and does the committed copy still match?" —
never "is this what the product will run next."

**The render candidate does not itself authorize descriptor promotion.**
§ 2's migration rule is untouched: the accepted descriptor still advances
only from a descriptor candidate under `deploy/candidates/*.toml`, and only
through `deploy/descriptor-promotions.json`'s append-only ledger exactly as it
operates today — whether the promoted state is a deployment or, as the
ledger's own `contract_change`/`composition_change` entries record, a
narrower fact that "deploys nothing." A deployment render candidate reaching
CI green says Foundation can render this input byte-for-byte; it says
nothing about whether that input has been, or ever will be, promoted or
deployed, and it may never stand in for a descriptor candidate in the
ledger's `candidate` field.

### Why an independent `[image]` field is refused, not deferred as a detail

An earlier draft of this amendment let the render candidate declare its own
`[image]`, matching or diverging from the accepted descriptor's. That is not
a detail to fill in later — it is a second image authority, and this
repository already has one, on purpose. `src/vendor_cp/deployment/
candidate.py` derives the ONLY image a Foundation execution plan may name:

    accepted descriptor + accepted release receipt
            -> candidate spec (two fields replaced, nothing else)
            -> canonical document
            -> FoundationExecutionPlanV1

`CandidateImage` (same file) carries a private witness only
`admit_candidate_image` holds, specifically so "the override must come from
a verified receipt" is a TYPE, not a convention an operator or a second
document could route around. A render candidate with its own typed or
string `[image]` field is exactly the raw reference that module's own
docstring says "has nowhere to go" — regardless of whether its Compose
output happens to byte-compare cleanly in CI. Two mechanisms that usually
agree are not one mechanism; the day they diverge is the day this
distinction was load-bearing.

**Correction: `admit_candidate_image` does not admit an image "for the
current authorized plan" — it runs BEFORE any authorization exists.**
`CandidateRefused`'s own docstring says so directly: "nothing has been asked
of Deployment Control at this point." The real sequence has three stages,
not two, and pre-merge CI sits BEFORE the first one that touches a real
image:

1. **Pre-merge (this amendment's render candidate, in CI): NON-AUTHORIZING
   and receipt-free.** No `production-image.yml` release receipt exists yet
   for a change still under review, so nothing here may call
   `admit_candidate_image` and expect it to succeed. The render candidate
   declares no deployable `[image]` or independent desired-image value. A
   non-deployable, late-bound image slot in rendered Compose bytes may be a
   way to prove the render before publication — today's production Compose
   uses `${VENDOR_APP_IMAGE:?…}` — but only a later design can establish
   whether Foundation preserves that slot and execution fills it without
   changing the checked bytes. This amendment approves no such file shape.
2. **Later, once a real release receipt exists:** `admit_candidate_image`
   derives the actual image from the accepted descriptor plus that VERIFIED
   RECEIPT and a registry readback — never from a plan, authorized or
   otherwise, because at this point still nothing has been asked of Control.
3. **Only after that derivation: Control binds the exact deployment
   inputs**, the derived image among them, as part of authorizing the
   deployment. Authorization consumes the derived image; it does not
   precede or produce it.

A render candidate implementation must not conflate stage 1 with stages 2–3
by treating its pre-merge render as if it carried, or needed to carry, an
authorized or receipt-derived image. Whatever it does carry pre-merge has no
bearing on what `admit_candidate_image` later derives, and reaching stage 2
by any other path (a typed or string `[image]` an operator or a second
document could set) is exactly the raw reference `candidate.py`'s own
docstring says "has nowhere to go."

**Satisfying schema 11's byte-compare does not satisfy Governance ADR-0014
§ 6.** ADR-0014 requires ONE document binding release digest, private-
inventory digest, rendered-configuration digest, exact container image
digest, target, approver and rationale together — its own stated argument
is that any three of those agreeing proves nothing about the fourth. A CI
job that renders and byte-compares Compose output answers schema 11's
question and none of ADR-0014's; an implementation that stops at the byte-
compare has closed one gate and left the other exactly as open as before
this amendment. Both gates apply; neither substitutes for the other.

**Disposition: the render-candidate CONCEPT is proposed; the concrete
`deploy/render-candidates/*.toml` file shape is DEFERRED** until a design
demonstrates it introduces no image authority independent of
`admit_candidate_image`, and separately addresses ADR-0014 § 6's full
binding rather than schema 11's byte-compare alone. Implementation must not
proceed from the concept alone.

### The invariant

> A deployment render candidate MUST NOT declare a deployable `[image]` or
> any independent desired-image value. Its pre-merge render is receipt-free
> and non-authorizing; a late-bound image slot, if the eventual design can
> prove one, is not an image admission. After publication, the image used for
> execution MUST come from `admit_candidate_image`
> (`src/vendor_cp/deployment/candidate.py`), never from the render candidate.
> No field of the render candidate may retroactively alter
> `deploy/product.toml` or `deploy/descriptor-promotions.json`.

These artifacts retain independent lifecycles.
Concretely: no test, script, or CI step reads a deployment render candidate
to decide what the accepted descriptor says; no promotion in the ledger may
cite a deployment render candidate as its `candidate` field (that field
names an existing pre-promotion descriptor candidate, and only that). The
image derived after publication may enter the accepted descriptor only
AFTER successful deployment, through an ordinary candidate under
`deploy/candidates/*.toml` and a ledger promotion, as §§ 2 and 8 require;
the pre-merge render candidate never pre-authorizes or promotes that image.
The render candidate answers Governance's question; it never answers
`dotmac-deploy drift`'s.

### The second invariant: rendered bytes must be the bytes production runs

A render candidate satisfying Governance in isolation is not enough. Today,
`.github/workflows/production-deploy.yml` `rsync`s
`docker-compose.production.yml` to the production host verbatim.
`scripts/deploy_production.sh` uses that file by default, but its
`COMPOSE_FILE` environment override can select a different path. Naming a
separate, CI-only render candidate does not bind either the copied file or
the effective Compose path to the bytes CI compared.

A conforming implementation MUST prove that the exact rendered bytes its CI
job byte-compares are the bytes the production executor consumes at its
effective Compose path. The render candidate may produce
`docker-compose.production.yml` itself, provided the production invocation
pins that path or refuses an override; otherwise the implementation must
verify the effective file's digest against the retained rendered asset before
execution. Hand-edits to the retained output must fail the CI byte-compare.
An implementation that renders a file production never consumes has
satisfied Governance's letter while leaving its actual purpose — proving
what CI checked is what runs — unmet.

### What this amendment does not resolve

Three prerequisites remain open and are not resolved by naming the concept
above — the first two found by a bounded read-only architecture review of
Governance's schema-11 requirement against Platform CP's actual deployment
surface, the third by review of this amendment's own draft against
`candidate.py` and Governance ADR-0014:

1. **No published Foundation release can render Platform CP's complete
   topology.** The published `dotmac_deployment_foundation` release
   (`0.2.0a2`, the version this record's § 5 and § 7 already establish as
   what is actually installable) cannot parse Platform CP's `[database]`
   contract at all — § 7 already records the exact refusal,
   `error: unknown key(s) ['database']`. The unpublished `0.3.0a3`
   candidate understands more of the shape but still cannot reproduce
   Platform CP's actual database bootstrap sequence, the `manifest-init`
   ownership boundary, volume permission requirements, or Host-header-aware
   readiness checks. A renderer that cannot represent these cannot be the
   thing CI byte-compares against, because a rendered file missing them
   would be compared and pass while describing a deployment nobody could
   run.
2. **Platform CP is not the party permitted to close that gap.** This
   repository's own `AGENTS.md` rule 21 states it directly: "Render, apply,
   observe and rollback are the published Foundation CLI's," reached only
   through a verbatim passthrough, because re-growing any of them here would
   be a second deployment engine. That forbids Platform CP writing its own
   renderer to work around Foundation's gap. Only a Foundation release with
   full topology support closes this; a local renderer would create the
   exact second-writer problem the rule exists to prevent, and it would be
   invisible to every other product pinned to the same Foundation contract.
3. **No design yet proves the render candidate introduces no second image
   authority, or satisfies ADR-0014 § 6's full binding.** See "Why an
   independent `[image]` field is refused, not deferred as a detail" above.
   This is not a detail to fill in during implementation — it is a
   precondition implementation must arrive already satisfying, because a
   render candidate built first and reconciled with `candidate.py` second
   would spend real effort on a shape this amendment has already refused.

**This amendment does not authorize implementation.** No
`deploy/render-candidates/` path, renderer invocation, CI byte-compare step,
or `.dotmac/standards-profile.json` change follows from accepting the
concept above. Implementation waits for BOTH a published
`dotmac-deployment-foundation` release with full topology support for
Platform CP's `[database]` contract, bootstrap sequence, `manifest-init`
ownership boundary, volume permissions and readiness checks, AND Michael
Ayoade's explicit go-ahead on this exact amendment, separately from his
acceptance of the concept it proposes.

**Status: Proposed.** Michael Ayoade is the owner and only approver, per
this record's own header. Nothing in this amendment is accepted until he
rules on it.
