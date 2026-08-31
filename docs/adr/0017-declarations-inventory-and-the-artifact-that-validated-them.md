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
