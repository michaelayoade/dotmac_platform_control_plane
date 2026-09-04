# Platform CP's thirteen `ApplicationFoundationProfile` concerns — measured 2026-09-04

Measured against `main` at `e9485ad`, and against the composed distributions the
**lock** pins rather than against intent. This is the content half of the
profile; the document's schema is `dotmac-deployment-foundation`'s and is not
settled here.

**Michael's gate, verbatim:** *"Missing or inert concerns block the candidate.
No placeholders and no unjustified inapplicable."* And: *"Either identify and
bind the real worker-execution owner or keep that concern — and therefore
cutover — red."*

So three of the thirteen are recorded RED below. That is the finding, not a
shortfall: a concern with no real owner does not get a placeholder, and the
candidate stays blocked until it has one.

## How a concern was judged bound

A binding needs an implementation, an exact version and an **immutable
coordinate** — `<name>@sha256:<64 hex>`, `sha256:<64 hex>` or a peeled 40-char
commit. It also needs a **real runtime consumer**: a provider nothing discovers
is inert, and a binding whose only consumer is a test is absent.

Coordinates come from `poetry.lock`'s recorded wheel hashes, which are the
checked-in immutable record and are derivable offline. Assembly-owned providers
are bindable too, coordinated by this repository's own peeled commit.

## Ten that bind

| concern | provider | version | coordinate source | runtime consumer |
| --- | --- | --- | --- | --- |
| `identity_session` | `dotmac_kernel.platform_auth` + `platform_web` | 0.1.0a98 | kernel wheel hash | 8 source files; every platform route and the console facet |
| `authorization` | `dotmac_kernel.platform_auth.require_platform_admin` | 0.1.0a98 | kernel wheel hash | 12 source files |
| `persistence_migrations` | `dotmac_kernel.migrations` + composed lineages | 0.1.0a98 | kernel wheel hash | 7 source files; `dotmac-platform admin migrate` |
| `settings_secrets` | `vendor_cp.config` + `vendor_cp.production_secrets` | assembly | peeled commit | boot config; the OpenBao materializer |
| `audit_telemetry` | `dotmac_kernel.audit.write_platform_audit_event` | 0.1.0a98 | kernel wheel hash | 7 source files |
| `health_runtime_admission` | `vendor_cp.readiness` + kernel `/health` + profile admission | assembly + 0.1.0a98 | peeled commit | `/health/ready` under every profile |
| `worker_execution` | `dotmac_kernel.messaging.platform_worker` | 0.1.0a98 | kernel wheel hash | `vendor_cp.relay.runner` — see below |
| `edge_security` | kernel CSRF / security-headers / rate-limit middleware | 0.1.0a98 | kernel wheel hash | `require_csrf` on browser routes |
| `api_web_interaction` | kernel `app_factory` + `web_surfaces` | 0.1.0a98 | kernel wheel hash | 9 router modules |
| `deployment_recovery` | `dotmac-deployment-control` + `vendor_cp.recovery` | 0.1.0a6 | control wheel hash | 15 source files; the recovery bundle path |

Kernel wheel: `sha256:27405c57c4af395224cdd2f4366c0144207e9df2eab4ca8a8ed1142c1d0859fa`
Control wheel: `sha256:9b02cf33f954b6562858af320b518c10f9e93aa92fbc3873e4a83fdf117b8fc0`

### `worker_execution` — the one that just became bindable

`WorkerContract` is **not** the provider, and the Foundation lane reached that
independently through ADR 0039 § 3's own test: *if two correct deployments of
the same artifacts could hold different values for it, it is not a binding*.
`heartbeat_max_age_seconds` and `max_backlog` are thresholds, and staging and
production hold them differently from identical artifacts.

The real provider is the worker distribution the image carries:
`dotmac_kernel.messaging.platform_worker`, at the kernel's exact pinned version,
coordinated by the wheel hash and therefore checkable against the image's
installed inventory.

Its runtime consumer is `vendor_cp.relay.runner`, which arrived in #150. Before
that, this concern had a provider in the image and **nothing that discovered
it** — inert by the gate's own definition. It is the one concern this
programme's relay work moved from red to bound.

## Three that are RED, and stay red

### `request_evidence_context`

**No provider and no consumer.** Nothing under `src/vendor_cp` references the
kernel's observability middleware or a correlation identifier; the only
`correlation_id` in play is the outbox column, written by module owners and read
by nobody here.

The kernel ships `dotmac_kernel.middleware.observability`, so this is a
composition gap rather than a missing capability — but binding it while nothing
mounts it would be exactly the inert slot the gate refuses.

### `data_governance` — RED, and `inapplicable` is refused as a route

**Ruled 2026-09-04:** this requires a real `ConcernBinding`, not an
inapplicable, and *"the binding must resolve to an implementation that actually
enforces the platform-data rules."* So the argument I declined to make on my own
reading — that a control plane holding no tenant data has none to govern — is
closed off. It does not need a better proof; it needs an implementation.

There is no such implementation here. Measured against `main` at `dde5c3c`:

| primitive | references under `src/vendor_cp` |
| --- | --- |
| retention | 0 |
| residency | 0 |
| erasure / data subject | 0 |
| anonymisation / pseudonymisation | 0 |
| purge | 0 |
| consent (`dotmac_kernel.consent`) | 0 |
| classification | 3, none of them about data — secret custody and backfill row classification |

**And the tenant data path is not used at all.** `get_platform_db` appears in 10
files and `platform_session` in 4; `get_db`, `tenant_session` and `set_tenant`
appear in **none**, and the single `tenant_scope` hit is a docstring. The
kernel's RLS machinery is composed and live — 17 tables carry `tenant_id` and
force row security — but nothing in this assembly reads or writes through a
tenant-scoped session. It is machinery with no runtime consumer here, which is
the inert slot the gate refuses.

#### The two adjacent mechanisms, and why neither is the owner

Both were measured before being set aside, because the reason they are adjacent
is the thing that stops the next reader binding one of them.

**The plane separation.** 16 vendor revisions contain a `REVOKE`, 14 of them
`REVOKE ALL`, and PostgreSQL enforces it on every statement the tenant app role
makes. It is real enforcement, driven by refusals in the Postgres tier rather
than described. But what it enforces is **which principal may touch which
table** — access control, whose concern is `authorization`, already bound. It
says nothing about how long data may be kept, where it may live, or what may be
erased.

**The append-only audit trail.** Kernel `0026` makes `platform_audit_events`
immutable, which is a genuine rule about data. It is the integrity half of
`audit_telemetry`, already bound, and binding it here would put one mechanism
under two concerns while retention, residency and erasure remained unenforced.

Binding either would make the slot look filled while nothing enforces the
platform-data rules — the exact outcome *"actually enforces"* rules out. So the
concern stays **red**, and the finding is that this assembly has no data
lifecycle owner at all: not one that describes the rules without enforcing them,
but one that does neither.

### `integration` — RED, and the repair is Foundation's

**No provider.** `dotmac-integration` is not composed; ADR-0007 § 6 defers
Integrator, and the Governance external-connector ratchet stands at zero.

I recorded this as the strongest candidate for a justified `InapplicableConcern`
while saying that whether the ratchet satisfies `AbsenceProof` was the
Foundation lane's call on its own type. **Ruled 2026-09-04:** the current
worker-specific `AbsenceProof` *cannot represent* integration at all, and the
repair is a discriminated, concern-specific proof — an
`IntegrationSurfaceAbsenceProofV1` with a closed inventory and installed-image
evidence.

That is a change to Foundation's type, so nothing here can close it. The
concern stays red and the obligation sits with the Foundation lane.

## What this does not decide

The profile **document** — its schema, its serialisation and its digest — is
`dotmac-deployment-foundation`'s, and `verify_profile_against_candidate` must be
owned by an independent verifier rather than the candidate builder. Neither is
settled here, and the Foundation candidate does not yet exist.

The resolver already refuses `profile_digest` by name
(`plan_input.profile_digest_underivable`). When these bindings land it starts
resolving with no change to its shape — and until then the refusal is the
correct answer rather than a gap, which is what keeps the empty-string default
from reappearing one layer up.


## Addendum, 2026-09-04 — a refusal-code collision to resolve

Two codes now spell `PURPOSE_MISMATCH` across the signing plane:

* `vendor_cp.deployment.evidence_producer.EvidenceRefusal.PURPOSE_MISMATCH` —
  raised when the **producer** is handed an identity of another purpose;
* Foundation's machine-readable `PURPOSE_MISMATCH` on the **verifying** side.

They describe the same class of mistake at opposite ends of one signature, which
is precisely when one name for two things is worst: an operator branching on the
string cannot tell whether signing was refused or verification was. Whichever
way it resolves, one side moves — and this side is willing to be the one that
does, since the producing refusal is the newer of the two.

`RELEASE_EVIDENCE_PURPOSE` is declared once here for the same reason, so if
Foundation's canonical purpose string differs from `platform_release_evidence`,
exactly one constant moves rather than every call site.

---

## Addendum, 2026-09-04 (second) — two counts, and where the three red concerns now stand

### The count, stated as two numbers because it is two claims

| what is being counted | figure |
| --- | --- |
| **concerns bound in something a deployment executes** | **0 of 13** |
| **concerns with an implementation present in the assembly** | **10 of 13** |

These are different claims and the programme has already confounded them once.
The second is what the table above this addendum measures: ten providers exist in
the composed distributions, with real runtime consumers. The first is zero, and
each of the three reasons is independent:

* **no profile document exists** — nothing writes
  `/app/application_foundation_profile.json`, so `verify_embedded_profile`
  returns `DOCUMENT_ABSENT` against a real Platform image;
* **no `ApplicationFoundationProfile` type exists under `src/`** — the document
  has no producer here;
* **the merged verifier has test callers only** — no workflow, script or
  runtime path calls it.

A field, a module, a test fixture or a package pin is none of these. The route
from ten to thirteen is a different route from the route from zero to thirteen,
and only the second one is about a deployment.

The accepted ordering is unchanged: **readback refusal → embed the canonical
document → wire image admission, and the last only once `DOCUMENT_ABSENT` has
become a verified admission.** Step 1 is merged in code (#165) and has **never
run against a real image** — its refusal is asserted only against `tmp_path`
fixtures.

### `integration` — the Foundation repair landed, and this side now consumes it

`IntegrationSurfaceAbsenceProofV1` merged in Starter #625 (`908f3c70`), and
`profile_readback` now accepts a proven absence as SATISFYING `integration` —
**bound to the exact installed artifact and to the closed surface inventory**.

Ruled 2026-09-04: *"This is not a general 'nothing applies' escape hatch."* Four
things stop it becoming one, and the fourth is the one that is usually left out:

1. a closed schema-to-concern map with **one** entry, so a proof of this schema
   naming another concern is REFUSED rather than ignored;
2. `observed_inventory_digest` must equal a digest this repository derives from
   `distributions.json` — the builder stage's independent per-file record. A
   caller may write any string; it cannot make that string equal one derived
   from the image;
3. `source_revision` and the installed-artifact digest, checked against the
   caller's release-receipt expectation rather than against the document;
4. **the producing type's own refusals, re-checked here.**
   `IntegrationSurfaceAbsenceProofV1.__post_init__` enforces complete
   enumeration, emptiness and a positive control *in the producing process*.
   What arrives is JSON, and **a constructor's refusals do not travel in a
   document**. A verifier trusting the `schema` string would accept a two-key
   object with no families at all.

This does **not** move the concern to satisfied. There is still no document, so
there is still no proof in one. It means the seam is ready and the refusal is
specific.

**No release → pin → consume chain exists for this type, and that is not an
oversight.** `profile_readback.py` imports no Foundation type — it is
stdlib-only and reads the profile as a document. The seam is the emitted
document, and `IntegrationSurfaceAbsenceProofV1.as_document()` carries
`source_revision`, `image_digest`, `observed_inventory_digest`, `families`,
`positive_control` and `state`, which is every field checked above. Verified by
reading both sides rather than assumed.

**One inference is recorded as an inference.** The proof's `image_digest` is
compared against the caller's `wheel_sha256` — the INSTALLED ARTIFACT. That
reading is forced rather than chosen: the proof travels inside the profile
document, the profile document is baked into the container image, and a
container digest computed over layers that include the document cannot appear in
the document. The two alternatives are self-contradictory. If Foundation settles
on a different meaning the check fails LOUDLY rather than admitting wrongly,
which is the safe direction for an inference about another repository's type —
but it is Foundation's field and this is not a shared contract until Foundation
says so.

**A new local specification, published rather than assumed.**
`canonical_inventory_digest` defines what `observed_inventory_digest` must equal:
the `(filename, sha256)` pairs of every distribution the builder stage recorded,
sorted, as UTF-8 JSON with no insignificant whitespace. Foundation defines no
computation for it — `satisfies()` takes whatever the verifier supplies — so a
producer must implement this separately. Sharing an encoder would make the
comparison a statement that one function agrees with itself.

### `data_governance` — still RED, and this lane did not build it

**Ruled 2026-09-04:** control-plane data still needs retention/disposition
governance; *"no tenant data"* is insufficient, `inapplicable` was already
refused by an earlier ruling, and an absence proof does not repair it either —
the schema-to-concern map above closes that route by construction.

`PlatformDataGovernanceV1` is **not implemented here, and this lane declined to
invent it.** What the ruling settles is *that* it must exist and *what it is
about*. What it does not settle is the substance, and the substance is not an
engineering choice:

* **the retention periods and dispositions themselves** — how long a platform
  audit event, a rotation record, an outbox row or a recovery bundle may be
  kept, and what happens at the end. These are business, contractual and legal
  determinations. Picking "365 days" to make a slot go green is exactly the
  placeholder the gate refuses, wearing a type;
* **what enforcement means** — a declaration checked at admission, a reconciler
  that disposes, or a refusal that blocks a deploy. These are three different
  owners with three different failure modes;
* **where it is composed.** This document's own rule is that a binding whose
  only consumer is a test is absent. A new module with no runtime consumer would
  be the inert slot the gate refuses, and creating that consumer touches the
  deployment path that the accepted ordering puts LAST.

`table_inventory.py` is honest about being an **input** to a future owner rather
than an owner, and that remains true: a cardinality per table informs retirement
decisions and is not a retention rule. It is a starting point, not the
implementation.

So the concern stays red, and what it is now blocked on is a decision rather
than a keystroke.

### `request_evidence_context` — an owner exists, and it is not this repository

**Ruled 2026-09-04:** implementation ownership goes to **`dotmac-kernel`**,
extracted **product-first from ERP's trusted-proxy behaviour**. **Foundation
owns the profile/verifier contract; ERP is the first adopter and Sub follows.**

That work is not dispatched and is not this lane's. What is this lane's is that
the profile can express the binding and this verifier can judge it the day it
arrives — the concern is an ordinary slot in `FOUNDATION_CONCERNS`, blocked by
name when unbound and satisfied when declared, and unreachable by the absence
route. Both are held by
`tests/unit/test_profile_readback.py::test_request_evidence_context_is_a_slot_this_verifier_already_judges`
and `::test_request_evidence_context_cannot_be_reached_by_the_absence_route`.

---

## Addendum, 2026-09-04 (third) — `data_governance` has an implementation

Michael ruled the substance the previous addendum said was blocked on a decision
rather than a keystroke:

> *"Data governance: for first production, explicitly classify every table.
> Authoritative control/evidence records use enforced retain: no automated hard
> deletion and no `DELETE` for online roles. Any transient table that does not
> fit must receive an explicit policy rather than inheriting this one. New
> unclassified tables fail admission."*

`vendor_cp.data_governance` implements it. `AGENTS.md` rule 25 is the normative
statement; this records what was measured.

### The classification — 58 tables, four dispositions

Every table the eight composed lineages build, held against the live catalogue
by `tests/migration/test_data_governance_catalogue.py` in BOTH directions — and
against the real composed database by `dotmac-platform admin migrate`, which is
where the first draft was found wrong.

**The first attempt derived the list from the migration SOURCES and got three
names wrong**, because kernel `0018_idempotency_one_owner` and
`0022_party_role_grants` RENAME tables rather than recreating them: the database
holds `idempotency_records`, `platform_idempotency_records` and
`party_role_grants`, not the names their creating revisions used. CI's deploy
step refused, named all six discrepancies in both directions, and committed
nothing. That is the mechanism working, and it is recorded here rather than
quietly corrected — a classification read out of the revision that created a
table is exactly the reading this enforcement exists to stop anyone trusting.

| disposition | count | what it means |
| --- | --- | --- |
| `ENFORCED_RETAIN` | 54 | an authoritative control or evidence record. No automated hard deletion; no `DELETE`/`TRUNCATE` for `platform_api` or `app_user` |
| `SUPERSEDED_IN_PLACE` | 2 | `public.domain_settings`, `public.relay_heartbeats` — a current-state value replaced by `UPDATE`. Not a record, so not RETAINED; the same grant by a stated route |
| `LIFECYCLE_DELETE` | 1 | `public.feature_flag_overrides` — the online role KEEPS `DELETE` |
| `MIGRATION_BOOKKEEPING` | 1 | `public.alembic_version` — not a record this deployment governs |

Requirement 3 is what the second and third rows are for. Retain is not applied
by default: the criterion is measured — *does a composed, mounted code path
delete rows from this table as an online role?* — and exactly one table answers
yes. `dotmac_kernel.platform_web.set_flag` clears a flag override by deleting
the row, `PLATFORM_WEB_SURFACE` is mounted because this assembly composes with
`web_enabled=True`, and absence is what "no override" means. So it is classified
`LIFECYCLE_DELETE`, with its deleting owner and its trigger named, and the
enforcement PROVES the online role can still act on it.

### Which enforcement is code and which is a grant

**A grant.** `enforce_retention` issues `REVOKE DELETE, TRUNCATE ... FROM
platform_api, app_user` on all 57 non-transient tables and reads the outcome back
through `has_table_privilege` — never `information_schema`, which misses a
privilege reached through role membership. PostgreSQL refuses the statement; that
is the enforcement. Two escapes a table grant does not close are checked on the
live catalogue rather than assumed: an `ON DELETE CASCADE` executes with the
referencing table's owner's privileges, and a `SECURITY DEFINER` function runs
as its owner (the kernel's outbox claim/settle pair are exactly that shape).

**Code, and weaker.** "No automated hard deletion" is a claim about call sites.
`DELETION_SITES` enumerates all eight row-deletion sites in this repository and
in the seven composed distributions; the scan derives its own coverage from 328
files and is held to the ledger two-directionally, so a kernel repin adding a
deletion fails the build. Seven of the eight are `NOT_COMPOSED` or
`REHEARSAL_ONLY` with a premise that is itself checked; the eighth is the
`set_flag` site above. This is recorded as the weaker half deliberately: it
cannot see a `psql` session.

### What happens on a new unclassified table — measured

At CI, `test_every_table_the_composed_database_holds_is_classified` fails.

At deploy, `enforce_retention` runs inside the composed upgrade's single
transaction — `alembic/env.py`, guarded by the deploy path's
`require_composed_heads` attribute — and raises `DataGovernanceRefusal` naming
the table and naming the file to classify it in. Nothing commits.
`test_a_new_unclassified_table_refuses_the_deploy` creates a table after
composition, exactly as a repinned module's lineage would, and drives that
refusal. The reverse direction is driven too: a classified table the database no
longer has refuses as well, because a policy describing nothing is how a dropped
table stops being noticed.

The deploy path being the consumer is proved rather than asserted. The same
scratch database is composed twice: once with `make_alembic_config` (no
post-condition), where at least 15 `(role, table)` pairs still hold `DELETE`;
then with `deploy_config`, where every lineage is already at heads so no DDL
runs at all — and the only pairs left holding `DELETE` are the two on
`public.feature_flag_overrides`. CI's Postgres job already runs
`dotmac-platform admin migrate` against a real composed database before the test
suite, so the enforcement executes there on every run.

### The count, restated — and it did not move

| what is being counted | figure |
| --- | --- |
| **concerns bound in something a deployment executes** | **0 of 13** |
| **concerns with an implementation present in the assembly** | **11 of 13** |

The second moves from ten to eleven: `data_governance` now has a provider
(`vendor_cp.data_governance`, assembly-owned, coordinated by this repository's
peeled commit) and a runtime consumer that is not a test (`alembic/env.py` on
the `dotmac-platform admin migrate` path).

**The first is still zero and this change does not move it.** All three reasons
stand unchanged: no profile document is written, no `ApplicationFoundationProfile`
type exists under `src/`, and the merged verifier has no caller outside its own
module and tests. A module, a migration hook, a ledger and three test files are
none of those things. The route from eleven to thirteen is a different route from
the route from zero to thirteen.

`request_evidence_context` and `integration` are unchanged: the first is
`dotmac-kernel`'s to extract product-first from ERP, the second is Foundation's
`IntegrationSurfaceAbsenceProofV1`, already consumed here.

### `table_inventory` now has a caller

`vendor_cp.deployment.table_inventory` said it was an INPUT to a future owner. It
was, and it had no caller in the source tree at all — which by this document's
own rule made it absent. `govern_observation` is that owner's consumption of it:
a production census judged against the classification, where an `UNKNOWN` table
becomes `GovernanceVerdict.UNESTABLISHED` rather than a clean verdict, because a
retention decision may not rest on a partial inventory.

Stated precisely, because the distinction is this document's own: the census now
has a non-test caller in `src/`, and `govern_observation` itself does not yet
have one — no operator command runs a production census. `enforce_retention` is
what a deployment executes. The savepoint discipline the census needed does not
apply to the live reads here: each asks ONE set-returning statement, so a
per-table refusal cannot abort the transaction, and copying the fix where its
premise does not hold would look like diligence and mean nothing.

### One thing this change did NOT do, and it is a decision rather than an omission

`deploy/product.toml` already carries `[[database.isolation]]` claims — the
ADR-0011 `DELETE` seal on `public.licence_delivery_targets`, in both directions —
and those are compared against a live capture by `admin descriptor-drift` and by
the candidate acceptance script. Publishing the other 56 `DELETE` denials there
is the obvious next step and was deliberately not taken: `drift._isolation_findings`
records an UNOBSERVED role/object pair as `DECLARED_ABSENT` rather than as a
quiet pass, so declaring them without the capture producing readings for them
would turn one green descriptor into ~112 findings. Whether the descriptor
publishes the whole retention seal — and therefore what a capture must probe — is
a deployment-contract decision, not an implementation detail, and it needs
Michael.

---

## Addendum, 2026-09-04 (fourth) — the document is BUILT, and what each slot needs to BIND

Michael's blocker, verbatim: *"Ten providers are implemented, but zero of
thirteen concerns are bound into an executable profile. … Nothing builds,
embeds, admission-checks and reads back the complete document."* Four verbs.
This addendum records the first and the fourth, the wiring for the second and
third, and the inventory nobody had.

### A concern is bound because a provider ANSWERED

`vendor_cp.deployment.profile` builds the document. Nothing in it writes a
concern because a literal said so: for every slot it RESOLVES the providers in
the environment the image actually has — `importlib.import_module` plus
`getattr` against the installed distributions — and refuses to emit anything if
a symbol is missing. A kernel repin that removed
`write_platform_audit_event` does not produce a profile claiming
`audit_telemetry`; it fails the image build, by name.

Three facts per provider and none of them typed in: the **version** from
`importlib.metadata` (what the INSTALLER recorded — the rule
`vendor_cp.identity` already holds this assembly to), the **coordinate** from
`poetry.lock`'s recorded wheel hash or the peeled commit the image was built at,
and a **cross-check** between them. A distribution whose installed version
disagrees with the lock is refused, because the coordinate would then name a
wheel that is not in this image.

It runs as `python -m vendor_cp.deployment.profile` inside the builder stage,
from the INSTALLED wheel, so the document is produced by the same bytes it
describes. A Dockerfile heredoc would have made the whole thing a literal in a
build file — the exact shape this replaces — and nothing would lint, type-check
or be testable.

### What each of the thirteen needs to BIND, as opposed to be present

This is the inventory that did not exist. "Present" is a fact about the source
tree; "bound" is a fact about a document an artifact carries.

| concern | present? | what BINDING additionally required | state |
| --- | --- | --- | --- |
| `identity_session` | yes | three kernel symbols resolving in the installed env; kernel wheel hash from the lock | **bound** |
| `authorization` | yes | both platform guards resolving | **bound** |
| `persistence_migrations` | yes | kernel `versions_dir` + this assembly's composed config and locations | **bound** |
| `settings_secrets` | yes | assembly settings + secret materializer importing; assembly coordinate = peeled commit | **bound** |
| `audit_telemetry` | yes | `write_platform_audit_event` resolving | **bound** |
| `health_runtime_admission` | yes | readiness service, surface admission and `create_app` all resolving | **bound** |
| `worker_execution` | yes | the kernel worker AND `vendor_cp.relay.runner` — the consumer that made it non-inert in #150 | **bound** |
| `edge_security` | yes | CSRF, security-headers and rate-limit middleware all importing | **bound** |
| `api_web_interaction` | yes | `create_app`, `web_surfaces` and the composed `vendor_cp.main:app` | **bound** |
| `deployment_recovery` | yes | the control module's lineage + manifest, and the assembly's bundle/capture | **bound** |
| `data_governance` | yes (#167) | `enforce_retention`, `GOVERNED_TABLES`, `CONTRACT` resolving | **bound** |
| `request_evidence_context` | **in `dotmac-kernel`, not here** | an installed artifact and real assembly wiring that CONSUME it | **declared unbound** |
| `integration` | proof type exists, in Foundation | a producible `IntegrationSurfaceAbsenceProofV1` | **declared unbound** |

So the emitted document binds **eleven**, and names the other two with their
reasons rather than merely being short. `verify_embedded_profile` returns
`CONCERNS_INCOMPLETE` naming exactly those two — the correct verdict for this
artifact.

### `integration` cannot be filled from this side, and that is a finding

The previous addendum recorded the seam as ready. Building the producer showed
what "ready" did not cover: `IntegrationSurfaceAbsenceProofV1` lives in
`dotmac-deployment-foundation`, which this assembly deliberately does not depend
on and which the acceptance battery's **step 17** proves is absent from the
image. So the proof cannot be CONSTRUCTED here.

Hand-writing its JSON is not the workaround it looks like. The whole value of
that type is the refusals its constructor performs — complete enumeration,
emptiness, a positive control — and `profile_readback`'s own docstring is that
*"a constructor's refusals do not travel in a document."* Re-implementing them
from this side would produce a second, drifting copy of another repository's
type in the one place where drift is unobservable.

Installing Foundation as a BUILD-ONLY tool in the builder stage would work
(only the emitted JSON would travel to runtime, leaving step 17 intact), but
pinning it at all is a composition decision this repository has not taken —
`pyproject.toml` says so explicitly. **Flagged, not invented.**

`canonical_inventory_digest` is consequently NOT used by the builder: the only
thing that needed it was that proof. No second implementation was written and
the local one was not hardened further. Its ownership stays routed to
Foundation, and it has to be settled before a proof is ever produced here.

### The readback, run against real bytes for the first time

Acceptance step 18 runs `verify_embedded_profile` INSIDE the candidate, against
`/app/application_foundation_profile.json` and `/app/distributions.json` as the
image carries them. One script, two callers: the PR rehearsal and the
publication path, so this cannot drift.

The probe asserts a NAMED verdict, and
`tests/architecture/test_profile_embedding.py::EXPECTED_CANDIDATE_VERDICT` must
agree with it. It is `DOCUMENT_ABSENT` in the commit that adds the probe and
`CONCERNS_INCOMPLETE` in the commit that embeds the document, and both move
together or the build fails. A probe that accepted any answer would have passed
straight through the embed and proved nothing about it.

**Two honest limitations, named rather than papered over.**
`CANDIDATE_SOURCE_REVISION` is supplied by the CALLER — the workflow's own SHA
in the rehearsal, the selected source SHA on the publication path — so the
revision expectation genuinely comes from outside the image. The WHEEL
expectation does not: there is no external source for it today, because the
release receipt itself reads the wheel digest out of `/app/distributions.json`
(step 13). The verifier's three-witness design therefore collapses to two on
this path — the document's claim against the image's independent per-file
record — and the "expectation from a receipt" leg is not exercised until a
receipt exists to hold it.

### The count, restated — and the first figure has NOT moved

| what is being counted | figure |
| --- | --- |
| **concerns bound in something a deployment executes** | **0 of 13** |
| **concerns with an implementation present in the assembly** | **11 of 13** |

A builder is not a deployment. What is now true that was not: a document exists,
it is produced from providers that answered, it is embedded in the image, and
the candidate-acceptance battery reads it back. What is still not true: nothing
ADMITS on it. The readback returns `CONCERNS_INCOMPLETE`, no deploy gates on the
verdict, and image admission is not wired — which is correct, because two
concerns are genuinely unsatisfied and wiring admission now would either block
every deployment or be softened into accepting anything.

The route from eleven to thirteen runs through `dotmac-kernel`
(`request_evidence_context`) and a Foundation composition decision
(`integration`). The route from zero to thirteen additionally requires a deploy
path that refuses on the verdict. They are still different routes.
