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

### `data_governance`

**No provider.** No consent ledger, no retention policy and no residency rule is
composed: `dotmac_kernel.consent` has zero references here. The licensing
delivery tables hold data but govern none of it.

There is a plausible argument that a control plane holding no tenant or
subscriber data has no data to govern — but that argument needs an
`InapplicableConcern` with an **executable `AbsenceProof`**, not prose, and I
have not established one. Recorded red rather than marked inapplicable on my own
reading, because "no unjustified inapplicable" is the gate.

### `integration`

**No provider.** `dotmac-integration` is not composed; ADR-0007 § 6 defers
Integrator, and the Governance external-connector ratchet stands at zero.

This is the strongest candidate of the three for a justified
`InapplicableConcern`: the deferral is a checked-in decision and the ratchet at
zero is close to an executable absence proof. Whether that ratchet satisfies
`AbsenceProof`'s contract is the Foundation lane's call on its own type, not
mine to assert.

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
