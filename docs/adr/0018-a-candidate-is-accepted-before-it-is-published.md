# ADR-0018: A candidate is accepted before it is published

- **Status:** PROPOSED 2026-08-31 by the release-pipeline lane. Acceptance is
  Michael's; nothing here has run against production.
- **Date:** 2026-08-31
- **Relates to:** ADR-0015 (production surface policy) and ADR-0016 (API
  documentation exposure), whose assertions this pipeline moves onto the
  ARTIFACT; ADR-0013, whose issuer must run from an accepted image; ADR-0017,
  which declares what an artifact contains where this declares how one earns
  the right to exist.

## 1. Context — the ordering was the defect

`production-image.yml` built an image, **pushed it**, pulled it back, and then
smoked it. Every individual step was reasonable. The order was not.

A failing smoke left published bytes in GHCR that nothing had accepted. There is
no mechanism for unpublishing them: the tag exists, the digest is immutable and
resolvable, and any consumer is free to pin it. The registry therefore recorded
what had been BUILT, not what had PASSED, and the difference was invisible to
anyone reading a digest.

That is not a hypothetical. The GHCR package already carries 29 versions against
a frozen preservation set of 23, and nothing in the pipeline distinguished an
accepted publication from a rejected one after the fact.

## 2. Decision — nine steps, and the order is the contract

1. Select an exact protected-main revision.
2. Verify required CI succeeded **on that revision**.
3. Build **one** local OCI candidate. Nothing is pushed.
4. Record its identity: config digest, layer digests, RootFS chain, source
   revision, lock digest, Dockerfile digest.
5. Test **those exact bytes**.
6. Publish the same config and layers.
7. Read the immutable registry digest back.
8. Prove the registry holds what was accepted.
9. Emit a release receipt.

The registry can then only ever hold something that already passed. That is the
entire claim, and it is a claim about ORDER rather than about coverage — a step
list containing every correct step can still be wrong.

**The read-back must leave the runner.** Comparing a local tag with itself
passes without the registry being consulted at all, so the local references are
removed and their absence asserted before the pull. A tautology that reads
exactly like a proof is worse than no proof.

**`docker tag` renames; it does not rebuild.** That is what makes step 6 able to
publish the accepted bytes rather than equivalent ones, and what makes step 8's
comparison meaningful rather than a re-measurement of a second build.

## 3. What a candidate must demonstrate

Twelve properties, each tested against the artifact rather than the checkout,
because the whole class of defect this exists to catch is an artifact that
disagrees with its source:

installed CLI; application import; fresh zero-to-head migration;
**restored-production migration**; database ownership, role, grant and
isolation; **dependency-aware readiness** rather than liveness alone;
a browser/API/CLI journey; wrong-credential and wrong-standing refusal; exact UI
assets; production documentation routes absent or protected; no fake
provisioning surface; no checkout dependency.

Two are reused rather than rebuilt. `diagnose self --strict` already proves the
no-checkout property in both directions, and ADR-0015's profile refusals are
exercised in the artifact rather than restated.

### 3.1 The restored-production migration is the one that cannot be faked

CI's empty database is the path that **cannot** fail. A restored copy is the one
that can, and the 2026-08-31 rehearsal proved exactly how: production is owned
by `app_admin`, while a copy created by `initdb` through `POSTGRES_DB` is owned
by `postgres`, so the first `CREATE SCHEMA` is refused with `permission denied
for database`. A recovery bundle can be **PROVED** and still restore into a
differently-owned database, because `CatalogEvidence.ownership` covers schema,
table and sequence ownership and not DATABASE ownership.

So the battery runs both lanes. Lane A restores into a correctly-owned copy and
requires the upgrade to succeed. Lane B plants the exact defect and requires the
failure — **and requires it to be the right failure**, by matching the message
rather than accepting any non-zero exit. Lane A alone is compatible with a world
where the trap has silently stopped being detectable.

**The lanes must differ in exactly one variable, and the first construction did
not.** It left `public` owned by `postgres` in lane B as well, so `app_admin`
could create nothing, the restore landed zero tables, and the "upgrade" would
have been a fresh install. The non-empty guard caught it on the first real
run — but had that guard not existed, lane B would have failed with precisely
the expected message for entirely the wrong reason, and the battery would have
gone on reporting a trap it was no longer testing. A two-variable experiment
cannot attribute its own result.

Both copies therefore carry `public` owned by `app_admin` and their objects
restored as `app_admin`, exactly as production has them; only `datdba` differs.
The script asserts both halves — `app_admin|app_admin` against
`postgres|app_admin` — and additionally refuses a lane-B failure that mentions
TABLE privileges, because that is the failure mode the single-variable setup
exists to exclude.

### 3.2 Readiness, and why liveness was not enough

The kernel owns `/health` and its docstring is explicit: *liveness — does not
touch DB*. That is correct for a liveness probe. It is also what
`docker compose up -d app --wait` was waiting on, so a container whose database
was unreachable reported healthy, `scripts/deploy_production.sh` declared the
deploy successful, and the first request an operator made was what found out.

This assembly therefore owns `/health/ready`, which asks the one dependency it has.
The kernel does not, and should not: liveness is generic and means the same
thing everywhere, while readiness is the question *are MY dependencies
reachable* and only the assembly knows what those are.

It answers on `/health/ready`, and that path is the kernel's rather than a
preference. `dotmac_kernel.middleware.tenant` resolves a tenant by QUERYING THE
DATABASE before every route, and short-circuits only for the two paths in
`_HEALTH_PATHS` — with the kernel's own comment saying liveness and readiness
probes "run before a DB may even be reachable".

The first draft of this route answered on `/readyz`. It therefore went through
tenant resolution, so with the database unreachable the middleware raised first
and the probe returned **500** — the opposite of a readiness answer, and exactly
when readiness matters most. CI found it; the candidate battery would have too,
since it asserts 503. The kernel had already reserved the right path and left it
for the assembly to implement.

The exemption and the route are compatible, and the distinction is worth being
precise about: the MIDDLEWARE must not touch the database on this path, while
the ROUTE deliberately does. The exemption is what lets a probe answer at all
when the database is gone — which is what lets this one answer 503 rather than
500.

It is published under every profile and withheld by none. A readiness probe a
deployment can switch off is a deployment that can return to reporting healthy
while unable to serve.

The battery runs the **negative case first**. A probe that returned 200
unconditionally would pass a positive-only test, so the unreachable-database
case is asserted before the reachable one, with liveness alongside as a positive
control — otherwise "not ready" and "not answering at all" are the same
observation.

## 4. Admission — a pasted identifier is not evidence

Manual dispatch takes an exact CI run id and verifies seven things, each with a
failure the others do not catch: the run belongs to this repository; it is the
workflow we mean; it reached a successful **terminal** conclusion; it ran on
protected main and not from a fork; its head is a full 40-character SHA; that
SHA is still current main; and **every required gate actually ran and passed**.

The seventh is the one that matters most and the easiest to omit. **A workflow
reports success at the run level when one of its jobs skipped**, so a required
gate that never ran is indistinguishable from one that passed unless something
asks. `skipped` is refused by name, alongside `neutral`, `cancelled`,
`timed_out`, `action_required` and `stale` — enumerated rather than expressed as
"anything but success", so a new conclusion kind arrives as a visible decision.

Check 7 reads **check-runs at the SHA** rather than jobs within the named run,
because the required set spans several workflows; verifying only that run's own
jobs would silently exempt every gate produced by another one.

**And a pasted image digest is not deployment evidence either.** The deploy path
now requires the release receipt that binds those exact bytes to that exact
revision. A digest an operator retyped proves only that it could be retyped.

## 5. What this does NOT claim

- Nothing here has run against `vendor-cp-prod`, and this ADR authorizes no
  production action.
- The receipt is a repository-local artifact. Under hard rule 17 it is evidence
  that a candidate was accepted by this pipeline; it is not an adoption claim,
  and it does not assert that any deployment consumed it.
- The twelve properties are what this pipeline can check on a runner. They are
  not a statement that the artifact is correct — only that these specific ways
  of being wrong have been ruled out.
- The UI asset expectation is exact and therefore brittle by design. A
  design-system bump is meant to show up as a reviewed diff, because an image
  built against a different one serves different bytes at the same URLs and
  every page still renders.

## 5.1 One dependency deliberately NOT added here

ADR-0017 § owns the `dotmac-deployment-foundation` candidate pin as a dated
obligation. It is restated here only to record why this change does not
discharge it — not as a second copy of the obligation, which would be the
two-copies-of-a-version defect that ADR one file over is about.

The coordinates it is owed against:

| field | value |
| --- | --- |
| candidate run | `33339810583` |
| artifact id | `9740182233` |
| wheel sha256 | `2a6e0ccd040b05ab602be4b439e48dd61188b3b71ed6e80ecc8a482e70d57443` |
| artifact lease expires | **2026-11-28** |

It is not added in this change, for two reasons that are worth stating rather
than leaving to be rediscovered. That version is deliberately unpublished, so it
cannot be a Poetry dependency at all — it installs by digest-verified download,
which is a different mechanism with a different failure mode. And adding it here
would change the lockfile and therefore the image contents in the same change
that first asserts what the image contains, which is the wrong order for exactly
the reason this ADR is about.

The expiry is a **lease, not a note**, and ADR-0017 holds it.
`vendor_cp.recovery.bundle` already treats the package's absence as
`evidence.tool_absent` (exit 4) rather than pretending it is installed, so
nothing in this pipeline depends on the pin landing first.

## 6. Consequences

`production-image.yml` becomes the acceptance gate rather than a build-and-hope
step, and `.github/candidate/` holds the battery, the verifier, the declared
gate set and the asset expectation. The battery deliberately does **not** live
under `scripts/`: that directory holds production instructions and is being
retired into the installed console script, and a CI harness there would be the
first new occurrence of the shape `vendor_cp.installed_surface` refuses.

`tests/architecture/test_candidate_before_publication.py` holds the ORDER, not
merely the presence of the steps — including the single assertion that would
have caught the previous design: no `docker push` may appear before acceptance,
and the registry credential may not even be acquired before it.
