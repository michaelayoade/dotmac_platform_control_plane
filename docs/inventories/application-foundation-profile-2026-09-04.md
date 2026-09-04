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
