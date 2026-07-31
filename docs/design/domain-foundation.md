# Vendor Control Plane — Domain Foundation Design (Lane B)

> **📍 Authoritative home (moved 2026-07-31).** This is the source-of-truth
> vendor-control-plane domain-foundation design, now owned by this repository
> (ruling C5 — a separate repo consuming the pinned kernel, not the reference
> assembly). It originated as "Lane B" design in `dotmac_starter_mt`
> (`docs/superpowers/plans/2026-07-30-vendor-control-plane-domain-foundation.md`),
> which now retains only a versioned pointer here. The as-built foundation lives
> in `docs/ARCHITECTURE.md` + `docs/adr/` (slices 1–3; the D1–D5 boundary tests;
> fake-only providers).
>
> **Cross-repo references:** kernel contracts, the kernel-boundary/program
> directives, and the deployment-profiles plan referenced below live in the
> `dotmac_starter_mt` repository under `docs/superpowers/` and `docs/adr/` —
> relative links in this document point at those starter-repo paths.

> **Status:** Design only. No application code is authorized by this document. It is the
> domain foundation for Lane B of
> [`2026-07-18-deployment-profiles-commercial-platform.md`](2026-07-18-deployment-profiles-commercial-platform.md)
> (vendor control-plane product assembly), under the accepted decision
> [`ADR-0003`](../../adr/0003-unified-deployment-profiles.md) and the program directive
> [`2026-07-18-kernel-program-directive.md`](../reviews/2026-07-18-kernel-program-directive.md).
> Nothing here may be represented in README/ARCHITECTURE as current runtime behavior.
> Scope recorded from Michael's directive of 2026-07-30.

> **Kernel-contract rule for this document:** every kernel contract is referenced **by name
> only**, with a pointer to
> [`2026-07-18-kernel-boundary.md`](2026-07-18-kernel-boundary.md) or the owning workstream.
> Restating a kernel contract's fields anywhere in this document is a defect, not a
> convenience — see § "Kernel contract dependencies". Where a contract is not yet published,
> the dependency is marked **blocked on kernel alpha**.

## Goal

Give the vendor control plane a domain foundation with one named owner per business decision
and state transition, so that Lane B can be delivered vertically (Deployment plan § Lane B,
steps 1–6) without inventing competing authorities, without copying kernel contracts, and
without reaching into any product data plane.

Domains in scope (verbatim from the 2026-07-30 directive):

1. Vendor customer accounts and commercial contracts
2. Licence and entitlement allocation
3. Fleet/deployment desired state
4. Release channels and immutable artifact selection
5. Deployment lifecycle and audit timeline
6. Support consent and time-bounded break-glass access
7. Observed application health
8. Typed APIs, events, state machines, and acceptance tests for all of the above

## Hard boundaries

The control plane **owns** fleet desired state, release channels/artifact selection, licence
and entitlement allocation, commercial contracts, and support access.

The control plane **must not**:

| Prohibition | Technical expression in this design |
|---|---|
| Own Sub/ERP business data | No subscriber, invoice-of-record, device, ticket, or product-party aggregate exists here. Product identifiers are opaque external IDs on control-plane rows. |
| Access product databases | Exactly one database engine (the control plane's own). No product DSN in config, no product ORM import, no cross-database join. Governance test in § "Acceptance tests" (deny case D2). |
| Maintain permanent SSH | Every support credential is issued with a TTL bounded by policy and expires at the credential itself; there is no "standing access" state in the support-access machine. Deny case D1. |
| Silently modify deployments | Every mutation is a change request → immutable preview (`plan_hash`) → named approval of *that hash* → serialized, audited run. A stale plan is refused, not applied. Deny case D3. |

Two further standing constraints inherited from the program:

- **Transport, not authority.** Data planes are reached through their own versioned APIs,
  webhooks, signed licence documents, or offline bundles — never a shared table, ORM model,
  or database credential (ADR-0003 § Cross-project reuse; adoption plan § Deployment topology).
- **Allocation is not evaluation.** The control plane decides *what a customer is entitled
  to*; the data plane's kernel entitlement evaluator decides *whether a request is allowed*.
  These are different decisions with different owners and must never merge.

## Domain map and module layout

The control plane is a thin `ProductAssemblySpec` over the kernel (name referenced only —
kernel-boundary plan Task 3). Its own modules:

```text
vendor_control_plane assembly
  ├── accounts          CommercialAccount, AccountContact, LegalEntityRef, AccountStatus
  ├── contracts         CommercialContract, ContractLine, ContractAmendment, ApprovalRecord
  ├── allocation        EntitlementAllocation, AllocationLine, LicenceIssuance, ProjectionRun
  ├── releases          Product, ReleaseArtifact, ReleaseChannel, ChannelPin, ArtifactSelection
  ├── fleet             Deployment, DeploymentDesiredState, DeploymentBinding, InfraResourceRef
  ├── provisioning      DeploymentChangeRequest, DeploymentPlan, DeploymentRun, RunStep, Evidence
  ├── support_access    SupportAccessRequest, ConsentRecord, BreakGlassApproval, AccessGrant, Session
  └── observed_health   DeploymentHeartbeat, HealthSnapshot, HealthFreshness, FleetHealthRollup
```

Every one of those names is control-plane-owned. None of them is proposed for the kernel; a
later promotion to the kernel requires its own architecture decision.

## Ownership table

Mirrors `docs/ARCHITECTURE.md`'s authority/ownership style: one named owner per decision,
plus what that owner must never degrade into.

| Decision / state transition | Owner (the only writer) | Reads | Must not become |
|---|---|---|---|
| Vendor customer identity and account status | `AccountService` | account contacts, legal entity refs | a copy of a product's customer record |
| Contract shape (lines, term, currency, offer versions) | `ContractService` | immutable offer versions, jurisdiction policy | an editable price list mutated in place |
| Contract lifecycle transition | `ContractService` + `ContractTransitionPolicy` (versioned) | approval records, activation rule, clock | a status field written by a billing webhook |
| Two-person approval satisfaction | `ApprovalPolicyService` | actor identity, policy version | a UI-only confirmation dialog |
| What a contract entitles (capability codes, limits, term) | `AllocationService` | contract lines, product capability catalogue | a second entitlement authority competing with the data-plane evaluator |
| Whether an allocated capability code is legal | `CapabilityCatalogueReader` (reads the product's manifest-declared codes) | ModuleManifest catalogue | a place where new capability codes are invented |
| Licence document issuance and signing | `LicenceIssuanceService` (via kernel licence-signer provider) | allocation snapshot, deployment binding, key custody | a service that holds the signing key inside a deployment |
| Licence delivery to a data plane | `EntitlementProjectionService` | issued licence, deployment API endpoint | a writer of the data plane's `tenant_entitlement_grants` |
| Licence/allocation lifecycle transition | `AllocationService` | contract events, clock, revocation decisions | a side effect of a payment webhook |
| Deployment existence and desired state | `FleetDesiredStateService` | account, contract, profile code, region | infrastructure inventory scraped from a cloud API |
| Which exact immutable artifact a deployment must run | `ArtifactSelectionService` (pure, explainable function) | channel pin, compatibility range, current digest | a mutable tag such as `:latest` |
| Release channel membership and pins | `ReleaseCatalogService` | attested artifacts, provenance/SBOM refs | a channel that can repoint an already-approved plan |
| Change request, plan preview, and `plan_hash` | `DeploymentChangeService` | desired state, artifact selection, allocation snapshot | an implicit plan recomputed at apply time |
| Approval of a specific plan hash | `DeploymentApprovalService` | plan preview, approver identity, policy | an approval that survives an input change |
| Execution of an approved plan | `DeploymentRunner` (restricted worker, provider-only) | approved plan, provider protocols, short-lived credentials | an HTTP request handler, or a worker with standing cloud credentials |
| Deployment lifecycle transition | `DeploymentRunner` + `FleetDesiredStateService` (transition table) | run outcomes, verification gates | an operator editing state to "unstick" a run |
| Deployment audit timeline | `DeploymentTimelineProjector` (single writer, rebuildable) | audit events + lifecycle history | the only copy of what happened |
| Support access request admissibility | `SupportAccessPolicy` (versioned) | case/incident ref, requested scope, TTL ceiling | a checkbox on a support console |
| Customer consent | `SupportConsentService` (customer-authorized actor is the deciding party) | access request, notification record | a vendor-side default-on setting |
| Break-glass authorization | `BreakGlassService` | named incident, approvers, TTL ceiling, notification | a quieter path to the same access |
| Support credential issuance and expiry | `SupportSessionService` (via kernel secret/identity provider) | active grant, least-privilege scope | a permanent key, shared password, or hidden account |
| Observed health of a deployment | `ObservedHealthIngestService` (single writer of the projection) | authenticated deployment heartbeat | desired state, or an automatic mutation trigger |
| Fleet health rollup | `FleetHealthRollupProjector` (rebuildable) | health snapshots, freshness | a place where raw tenant data becomes queryable |

### Mutable-resource ownership list

| Resource | Single writer | Repair / rebuild path |
|---|---|---|
| `CommercialAccount`, `AccountContact` | `AccountService` | none needed (source record) |
| `CommercialContract`, `ContractLine`, `ApprovalRecord` | `ContractService` | none (append-only amendments; lines immutable after approval) |
| `EntitlementAllocation`, `AllocationLine` | `AllocationService` | recompute from contract + policy version; drift reported, never auto-applied |
| `LicenceIssuance` | `LicenceIssuanceService` | reissue as a new document version; never edit an issued document |
| `Deployment`, `DeploymentDesiredState` | `FleetDesiredStateService` | none (source record) |
| `InfraResourceRef` | `DeploymentRunner` | reconcile from provider observed state; refs are evidence, not authority |
| `ChannelPin` | `ReleaseCatalogService` | none (append-only pin history) |
| `ArtifactSelection` (recorded in a plan) | `DeploymentChangeService` | recompute — pure function of pinned inputs |
| `DeploymentRun`, `RunStep`, `Evidence` | `DeploymentRunner` | append-only; resume, never rewrite |
| `DeploymentTimelineEntry` | `DeploymentTimelineProjector` | full rebuild from the event/audit log |
| `AccessGrant`, `Session` | `SupportSessionService` | none (append-only; revocation is a new fact) |
| `DeploymentHeartbeat`, `HealthSnapshot` | `ObservedHealthIngestService` | rebuild from retained heartbeats; safe to drop and re-derive |
| `FleetHealthRollup` | `FleetHealthRollupProjector` | full rebuild from snapshots |

## State machines

Notation per transition: **from → to · actor · guard · audit event**. Every audit event is
written by the owning service inside the same transaction as the state change, and every
transition is refused when the guard fails (fail closed, never "log and continue").

### 1. Commercial contract lifecycle

```text
draft -> pending_approval -> approved -> active -> expired | terminated | superseded
   \-> cancelled            \-> draft (rejected)   \-> suspended -> active
```

| From → To | Actor | Guard | Audit event |
|---|---|---|---|
| `draft` → `pending_approval` | vendor commercial admin | ≥1 contract line; legal entity, currency, and term set; every line pins an immutable offer version | `contract.submitted` |
| `pending_approval` → `draft` | approver | rejection reason recorded | `contract.rejected` |
| `pending_approval` → `approved` | approver ≠ submitter when two-person policy applies | `ApprovalPolicyService` satisfied at the recorded policy version; all pinned offer versions still exist | `contract.approved` |
| `approved` → `active` | `ContractService` (rule-driven) | the contracted **activation rule** is satisfied (countersignature date, manual confirmation, or first deployment activation) — never "a form was submitted" | `contract.activated` |
| `active` → `suspended` | commercial admin | named reason; suspension projects to allocation restriction only, never to data deletion | `contract.suspended` |
| `suspended` → `active` | commercial admin | reinstatement reason; allocation re-projection queued | `contract.reinstated` |
| `active` → `superseded` | `ContractService` | an approved amendment reaches its effective date; successor contract id recorded | `contract.superseded` |
| `active` → `expired` | `ContractService` (clock) | term end passed with no renewal; grace policy already applied at the allocation layer | `contract.expired` |
| `active` → `terminated` | commercial admin | effective date + notice policy + impact preview acknowledged | `contract.terminated` |
| `draft` \| `pending_approval` → `cancelled` | submitter or admin | no downstream allocation exists | `contract.cancelled` |

**Invariant:** no contract transition writes deployment state, entitlement grants, or product
data. It emits an event; `AllocationService` and `FleetDesiredStateService` react through the
inbox.

### 2. Licence / entitlement-allocation lifecycle

```text
draft -> staged -> issued -> delivered -> active -> grace -> expired
                     \-> revoked (any state)      \-> superseded
```

| From → To | Actor | Guard | Audit event |
|---|---|---|---|
| `draft` → `staged` | `AllocationService` (on `contract.activated`) | contract active; every allocation line names a capability code declared by the target product's manifest catalogue; limits declare their combine strategy | `allocation.staged` |
| `staged` → `issued` | `LicenceIssuanceService` | signing performed by the kernel licence-signer provider **outside** any deployment; deployment binding present when contracted; issuer/key id recorded | `licence.issued` |
| `issued` → `delivered` | `EntitlementProjectionService` | delivery is an authenticated data-plane **API call, webhook, or offline bundle** — a database write is structurally impossible | `licence.delivered` |
| `delivered` → `active` | data-plane acknowledgement (inbound, authenticated) | the data plane reports successful verification and local projection; ack carries the licence document id + version | `licence.activated` |
| `active` → `grace` | `AllocationService` (clock) | grace behavior comes from the versioned commercial policy, never from an evaluator guess | `licence.grace_entered` |
| `grace` \| `active` → `expired` | `AllocationService` (clock) | validity end passed | `licence.expired` |
| any → `revoked` | commercial admin or `ContractService` | named reason; revocation entry published to the revocation list consumed by connected and air-gapped deployments | `licence.revoked` |
| `active` → `superseded` | `LicenceIssuanceService` | renewal/amendment issued a successor document; predecessor id recorded | `licence.superseded` |

**Invariant:** the control plane never writes `tenant_entitlement_grants` (deployment plan
Workstream 2, kernel-owned, data-plane-resident). It delivers a signed document or an API
call; the data plane's own module decides to accept it and owns the row.

### 3. Deployment lifecycle

```text
intent_recorded -> plan_ready -> approved -> applying -> applied -> active
        ^              |             |          |  \-> failed_retryable -> applying
        |              |             |          \-> failed_terminal
        +--------------+-------------+
        (plan invalidated / approval expired)
active -> plan_ready (change)   active <-> suspended
active | suspended -> decommissioning -> decommissioned
```

| From → To | Actor | Guard | Audit event |
|---|---|---|---|
| `—` → `intent_recorded` | fleet operator | account exists; contract active or explicitly marked internal/non-billable | `deployment.intent_recorded` |
| `intent_recorded` \| `active` → `plan_ready` | `DeploymentChangeService` | artifact selection resolves to exactly **one** immutable digest; allocation snapshot resolvable; profile code valid; `plan_hash` computed over every input | `deployment.plan_ready` |
| `plan_ready` → `intent_recorded` \| `active` (revert) | `DeploymentChangeService` | any plan input changed → plan invalidated, not silently recomputed | `deployment.plan_invalidated` |
| `plan_ready` → `approved` | named approver (≠ requester when policy requires) | the approval request carries the exact `plan_hash` the approver was shown; approval TTL set | `deployment.plan_approved` |
| `approved` → `applying` | `DeploymentRunner` (worker) | idempotency key unused; per-deployment serialization lock acquired; approval unexpired; `plan_hash` still current | `deployment.run_started` |
| `applying` → `applied` | `DeploymentRunner` | every step reported success with evidence | `deployment.run_succeeded` |
| `applying` → `failed_retryable` | `DeploymentRunner` | classified retryable provider error; observed state + last error + next retry recorded | `deployment.run_failed` |
| `failed_retryable` → `applying` | `DeploymentRunner` | resume **the same run** — a replay never creates a second deployment or duplicate infrastructure | `deployment.run_resumed` |
| `applying` → `failed_terminal` | `DeploymentRunner` | non-retryable; compensation plan recorded for any partial external work | `deployment.run_failed_terminal` |
| `applied` → `active` | `DeploymentRunner` | verification gates pass: health observed fresh, licence/entitlement acknowledged, contracted activation condition met | `deployment.activated` |
| `active` → `suspended` | fleet operator | named reason; suspension never deletes data | `deployment.suspended` |
| `suspended` → `active` | fleet operator | reinstatement reason | `deployment.resumed` |
| `active` \| `suspended` → `decommissioning` | fleet operator | impact preview acknowledged; two-person approval; retention/legal-hold check | `deployment.decommission_started` |
| `decommissioning` → `decommissioned` | `DeploymentRunner` | provider cleanup evidence retained; external resource refs closed out | `deployment.decommissioned` |

**Invariants:** `applying` is the only state in which infrastructure is touched; nothing
outside `DeploymentRunner` writes observed infrastructure refs; there is no transition that
lets an operator edit lifecycle state by hand to bypass a failed gate.

### 4. Release artifact / channel state (supporting)

```text
built -> attested -> published -> pinned(channel) -> superseded | withdrawn
```

| From → To | Actor | Guard | Audit event |
|---|---|---|---|
| `built` → `attested` | release CI (external) | signature, provenance, and SBOM present | `artifact.attested` |
| `attested` → `published` | `ReleaseCatalogService` | digest is immutable and unique; compatibility range declared | `artifact.published` |
| `published` → `pinned` | release manager | channel exists; pin names the exact digest, never a moving tag | `channel.pinned` |
| `pinned` → `superseded` | `ReleaseCatalogService` | a newer pin exists on that channel; **already-approved plans keep their digest** | `channel.pin_superseded` |
| any → `withdrawn` | release manager | security withdrawal reason; deployments running it are flagged in the fleet view, not auto-mutated | `artifact.withdrawn` |

Artifact selection itself is a **pure, explainable function**, not a state:
`select(deployment) -> (digest, channel, pin_id, compatibility_window, reason)`. Where a
deployment's update authority is `customer_approved` or `offline_bundle` (ADR-0003 axis), the
selection result is an **offer** that cannot enter `plan_ready` without the customer approval
record.

### 5. Support access lifecycle (consent + break-glass)

One grant object, two admission bases (`consent`, `break_glass`), never a third quiet path.

```text
requested -> awaiting_consent -> consent_granted --\
        \-> break_glass_approved ------------------+-> active -> expired | revoked -> closed
         \-> denied | lapsed
```

| From → To | Actor | Guard | Audit event |
|---|---|---|---|
| `—` → `requested` | support engineer | case/incident ref, purpose, requested scope, and TTL ≤ policy ceiling; application-impersonation and infrastructure grants are **separate** requests | `support.access_requested` |
| `requested` → `awaiting_consent` | `SupportAccessPolicy` | scope is least-privilege for the stated purpose; customer notified | `support.consent_requested` |
| `awaiting_consent` → `consent_granted` | customer-authorized actor | consent names the same scope + TTL as the request | `support.consent_granted` |
| `awaiting_consent` → `denied` | customer-authorized actor | — | `support.consent_denied` |
| `awaiting_consent` → `lapsed` | clock | consent window elapsed | `support.consent_lapsed` |
| `requested` → `break_glass_approved` | break-glass approvers | named incident; two-person approval where practicable (single-approver fallback records why); TTL ≤ break-glass ceiling (strictly shorter than consent ceiling); customer notification emitted immediately unless a recorded legal restriction applies | `support.break_glass_approved` |
| `consent_granted` \| `break_glass_approved` → `active` | `SupportSessionService` | credential issued with an enforced expiry at the credential itself; for customer-controlled deployments the channel is **initiated outbound by the deployment**; active-session indicator visible to the customer | `support.session_opened` |
| `active` → `revoked` | customer kill switch or vendor revoke | takes effect immediately at the credential, not at the next poll | `support.access_revoked` |
| `active` → `expired` | clock/credential TTL | no renewal — extension requires a **new** request through the same machine | `support.access_expired` |
| `expired` \| `revoked` → `closed` | `SupportSessionService` | full session/command audit sealed; customer-facing closure summary published | `support.access_closed` |

**Invariants:** no state issues a credential without an expiry; no state grants standing
host access; there is no "renew in place" transition; break-glass is louder than consent
(more approvers, shorter TTL, mandatory notification), never quieter.

### 6. Observed application health (deliberately not a state machine)

Observed health is a **rebuildable projection with a freshness classification**, owned by
`ObservedHealthIngestService`:

```text
freshness: fresh (heartbeat within window) | stale (window exceeded) | missing (never seen)
```

It has no transitions an operator can drive, no authority over desired state, and — in the
first executable slice — **no automatic consequence**. A stale or unhealthy deployment is
surfaced in the read-only fleet view and may raise an alert; it never triggers a deployment
mutation, a suspension, or an entitlement change without a human going through the change
request → preview → approval path. Heartbeat scope (product, deployment, environment,
version, region) is derived from the authenticated deployment identity server-side, never
from caller-supplied labels.

## Typed API surface sketch

Resource · verb · request type → response type. **Type names only** — field-level shapes for
anything kernel-owned live in the kernel contract, not here. All routes sit behind the
kernel's platform-admin guard except the deployment-authenticated ingest route and the
customer-actor consent routes, which carry their own identities.

### Accounts and contracts

| Verb + resource | Request → Response |
|---|---|
| `POST /accounts` | `CreateAccountRequest` → `AccountResponse` |
| `GET /accounts/{id}` | — → `AccountDetailResponse` |
| `POST /accounts/{id}/contracts` | `DraftContractRequest` → `ContractResponse` |
| `POST /contracts/{id}/submit` | `SubmitContractRequest` → `ContractResponse` |
| `POST /contracts/{id}/approve` | `ApproveContractRequest` → `ContractResponse` |
| `POST /contracts/{id}/activate` | `ActivateContractRequest` → `ContractResponse` |
| `POST /contracts/{id}/terminate` | `TerminateContractRequest` → `ContractTerminationPreview` then `ContractResponse` |
| `GET /contracts/{id}/timeline` | — → `ContractTimelineResponse` |

### Allocation and licences

| Verb + resource | Request → Response |
|---|---|
| `GET /contracts/{id}/allocation` | — → `AllocationSnapshotResponse` |
| `POST /allocations/{id}/issue` | `IssueLicenceRequest` → `LicenceIssuanceResponse` |
| `GET /licences/{id}` | — → `LicenceResponse` (metadata + status; never key material) |
| `POST /licences/{id}/revoke` | `RevokeLicenceRequest` → `LicenceResponse` |
| `GET /deployments/{id}/projection` | — → `EntitlementProjectionStatusResponse` |

### Releases

| Verb + resource | Request → Response |
|---|---|
| `GET /products/{code}/artifacts` | — → `ArtifactListResponse` |
| `POST /channels/{code}/pins` | `PinArtifactRequest` → `ChannelPinResponse` |
| `GET /deployments/{id}/artifact-selection` | — → `ArtifactSelectionResponse` (digest + channel + pin + reason) |

### Fleet and deployment lifecycle

| Verb + resource | Request → Response |
|---|---|
| `POST /accounts/{id}/deployments` | `RecordDeploymentIntentRequest` → `DeploymentResponse` |
| `GET /deployments` | `FleetQuery` → `FleetListResponse` (read-only fleet view) |
| `GET /deployments/{id}` | — → `DeploymentDetailResponse` |
| `POST /deployments/{id}/change-requests` | `DesiredStateChangeRequest` → `ChangeRequestResponse` |
| `POST /change-requests/{id}/plan` | `PlanRequest` → `DeploymentPlanPreview` (carries `plan_hash`) |
| `POST /change-requests/{id}/approve` | `ApprovePlanRequest` (**must** echo `plan_hash`) → `ChangeRequestResponse` |
| `POST /change-requests/{id}/runs` | `StartRunRequest` (idempotency key) → `DeploymentRunResponse` |
| `GET /runs/{id}` | — → `DeploymentRunResponse` (steps + evidence refs) |
| `GET /deployments/{id}/timeline` | — → `DeploymentTimelineResponse` |

There is deliberately **no** `PUT /deployments/{id}` and no direct desired-state write route.
Desired state changes only through a change request.

### Support access

| Verb + resource | Request → Response |
|---|---|
| `POST /support/access-requests` | `SupportAccessRequest` → `SupportAccessGrantResponse` |
| `POST /support/access-requests/{id}/consent` | `ConsentDecisionRequest` (customer actor) → `SupportAccessGrantResponse` |
| `POST /support/access-requests/{id}/break-glass` | `BreakGlassApprovalRequest` → `SupportAccessGrantResponse` |
| `POST /support/grants/{id}/revoke` | `RevokeGrantRequest` → `SupportAccessGrantResponse` |
| `GET /deployments/{id}/support-grants` | — → `SupportGrantListResponse` (active-session indicator) |

### Observed health

| Verb + resource | Request → Response |
|---|---|
| `POST /ingest/heartbeats` | `HeartbeatEnvelope` (deployment-authenticated) → `HeartbeatAck` |
| `GET /deployments/{id}/health` | — → `ObservedHealthResponse` |
| `GET /fleet/health` | `FleetHealthQuery` → `FleetHealthRollupResponse` |

## Event catalogue

Producer → consumers, with delivery semantics. All events leave through the kernel's
transactional outbox contract (named only; deployment plan Workstream 3 / program workstream
4) and are consumed through an idempotent inbox. Ordering is guaranteed **per aggregate**
only; no consumer may assume global ordering.

| Event | Producer | Consumers | Delivery |
|---|---|---|---|
| `contract.approved` | `ContractService` | audit timeline | at-least-once, idempotent |
| `contract.activated` | `ContractService` | `AllocationService`, `FleetDesiredStateService`, timeline | at-least-once, ordered per contract |
| `contract.suspended` / `.terminated` / `.expired` | `ContractService` | `AllocationService`, fleet view, timeline | at-least-once, ordered per contract |
| `allocation.staged` | `AllocationService` | `LicenceIssuanceService`, timeline | at-least-once, ordered per allocation |
| `licence.issued` / `.delivered` / `.revoked` | `LicenceIssuanceService` / `EntitlementProjectionService` | data-plane delivery adapter, timeline, fleet view | at-least-once; natural key `(allocation_id, document_version)` prevents duplicate issuance |
| `licence.activated` | inbound data-plane acknowledgement | `AllocationService`, deployment verification gate | at-least-once inbound; deduplicated by document id + version |
| `channel.pinned` / `artifact.withdrawn` | `ReleaseCatalogService` | `DeploymentChangeService` (plan invalidation), fleet view | at-least-once |
| `deployment.intent_recorded` | `FleetDesiredStateService` | timeline, fleet view | at-least-once |
| `deployment.plan_ready` / `.plan_invalidated` | `DeploymentChangeService` | approval surface, timeline | at-least-once, ordered per deployment |
| `deployment.plan_approved` | `DeploymentApprovalService` | `DeploymentRunner`, timeline | at-least-once, ordered per deployment |
| `deployment.run_started` / `.run_succeeded` / `.run_failed` / `.run_resumed` | `DeploymentRunner` | timeline, fleet view, alerting | at-least-once, ordered per run |
| `deployment.activated` / `.suspended` / `.decommissioned` | `DeploymentRunner` / `FleetDesiredStateService` | `AllocationService` (billing-start signal), timeline | at-least-once, ordered per deployment |
| `support.access_requested` / `.consent_granted` / `.break_glass_approved` | `SupportAccessPolicy` / `SupportConsentService` / `BreakGlassService` | notification adapter, timeline, customer surface | at-least-once; customer notification is a required consumer for break-glass |
| `support.session_opened` / `.access_revoked` / `.access_expired` / `.access_closed` | `SupportSessionService` | timeline, customer surface, audit export | at-least-once |
| `health.heartbeat_received` (internal) | `ObservedHealthIngestService` | `FleetHealthRollupProjector` | at-least-once, last-write-wins per deployment |
| `health.freshness_changed` | `FleetHealthRollupProjector` | alerting, fleet view | at-least-once; **no** deployment-mutating consumer |

### Idempotency, outbox, and concurrency notes

- **Command envelope.** Every mutating command carries actor identity, account id, target
  aggregate id, correlation id, causation id, and an idempotency key. Replaying a command
  with the same key returns the original result and emits nothing new.
- **Transactional outbox.** State change and outbox row commit in one transaction owned by
  the kernel's session/transaction authority. The relay is at-least-once; every consumer
  keeps an inbox keyed `(event_id, consumer)`.
- **Per-deployment serialization.** A run claim takes a per-deployment lock and performs a
  compare-and-set on `(plan_hash, approval_id)`. Two concurrent runs on one deployment are
  structurally impossible; a replayed start resumes the existing run.
- **`plan_hash` as the anti-silent-mutation control.** The hash covers desired state, the
  selected artifact digest, the allocation snapshot, and the profile/provider set. Approval
  binds to that hash. If any input changed, the run is refused with a `plan_stale` error and
  the deployment stays where it was.
- **Issuance idempotency.** Licence issuance is keyed on `(allocation_id, document_version)`
  so a redelivered `contract.activated` cannot mint a second licence.
- **Optimistic concurrency.** Contract, allocation, and desired-state writes carry a version;
  a stale write is rejected with a conflict, never merged.
- **Compensation.** Partially completed external work records an explicit compensation entry;
  compensation is itself an audited, idempotent run step.

## Acceptance-test outline

Given/when/then per domain. Every domain's suite runs against the kernel's fake-provider test
kit (named only — kernel-boundary plan Task 5); no suite requires a cloud, payment, DNS,
licence-signing, or telemetry credential.

### Accounts and contracts

- Given a draft contract with no lines, when it is submitted, then submission is refused and
  no `contract.submitted` event is emitted.
- Given a contract pending approval and a two-person policy, when the submitter approves it,
  then approval is refused naming the policy version.
- Given an approved contract whose activation rule is "countersigned", when the countersign
  date is recorded, then it becomes `active` and exactly one `contract.activated` is emitted.
- Given an active contract, when it is terminated, then a termination preview is produced
  first and no allocation, deployment, or product data is deleted as a side effect.

### Licence and entitlement allocation

- Given an activated contract, when allocation is staged, then every allocation line
  references a capability code that exists in the target product's manifest catalogue.
- Given an allocation line naming an undeclared capability code, when staging runs, then it
  fails loudly and names the offending code.
- Given `contract.activated` delivered twice, when the inbox processes both, then exactly one
  licence document exists.
- Given an issued licence, when delivery runs, then the only egress is an authenticated API
  call, webhook, or exported bundle — asserted by a transport-inspection test.
- Given a revoked licence, when the revocation list is published, then a connected data plane
  and an offline bundle consumer both receive it.

### Fleet desired state

- Given an account with no active contract, when a billable deployment intent is recorded,
  then it is refused unless explicitly flagged internal/non-billable.
- Given a deployment, when any caller attempts a direct desired-state write, then no such
  route exists (route-inventory assertion) and the change must go through a change request.

### Release channels and artifact selection

- Given a channel pin, when artifact selection runs twice with unchanged inputs, then it
  returns the identical immutable digest and an identical explanation.
- Given a mutable tag supplied as a pin, when the pin is created, then it is refused — pins
  are digests.
- Given an approved plan and a subsequent newer channel pin, when the run starts, then the
  run still applies the digest the approver saw.
- Given a deployment whose update authority is `customer_approved`, when a new pin appears,
  then the selection is an offer and cannot reach `plan_ready` without a customer approval
  record.

### Deployment lifecycle and audit timeline

- Given a plan preview, when an approver approves the exact `plan_hash`, then the run applies
  precisely that plan.
- Given an approved plan and a changed input, when the runner starts, then it refuses with
  `plan_stale`, the deployment stays in its prior state, and the refusal is on the timeline.
- Given a forced failure at every step in turn, when the run resumes, then it never creates
  duplicate infrastructure, never activates prematurely, and never emits a billing-start
  signal.
- Given a completed run, when the timeline projection is dropped and rebuilt from the event
  log, then it reproduces byte-identical entries.

### Support consent and break-glass

- Given an access request with a TTL above the policy ceiling, when it is submitted, then it
  is refused.
- Given a consent-based grant, when the customer revokes it mid-session, then the credential
  stops working immediately and `support.access_revoked` is on the timeline.
- Given a break-glass approval, when it is created, then a customer notification event is
  emitted in the same transaction unless a recorded legal restriction applies, and the TTL is
  strictly shorter than the consent ceiling.
- Given an expired grant, when the engineer retries, then access is denied and only a new
  request can restore it — there is no renew-in-place path.
- Given a customer-controlled deployment, when a session opens, then the channel is initiated
  outbound by the deployment and the deployment can terminate it.

### Observed health

- Given no heartbeat within the window, when the fleet view is read, then the deployment
  shows `stale` and **no** mutation is triggered.
- Given a heartbeat carrying caller-supplied tenant/deployment labels, when it is ingested,
  then the labels are discarded and scope is derived from the authenticated identity.
- Given a heartbeat payload containing subscriber identifiers or secrets, when it is
  ingested, then it is rejected/redacted by the allowlist before storage.
- Given the health projection is deleted, when it is rebuilt from retained heartbeats, then
  the fleet view is restored without contacting any deployment.

### Deny cases (the hard boundaries, tested as first-class requirements)

- **D1 — no permanent SSH.** Given the full support-access suite, when every issued
  credential is enumerated, then each has a finite expiry ≤ the policy ceiling; and given a
  request for a non-expiring or shared credential, then issuance is refused. A governance
  test asserts no code path can construct a credential without an expiry argument.
- **D2 — no product-DB access.** Given the control-plane assembly, when its configuration and
  import graph are inspected, then it declares exactly one database engine (its own), no
  product DSN, and no import of a product ORM package (`dotmac_sub`, `dotmac_erp`, or any
  product models module). Sensitivity-proved with a temporary violating import.
- **D3 — no silent deployment mutation.** Given any path that reaches a provider, when it is
  traced, then it originates from an approved `plan_hash` and a claimed run; and given a
  direct provider call attempted outside `DeploymentRunner`, then a governance test fails.
- **D4 — no real infrastructure in the first slice.** Given the control-plane development
  profile, when the provider registry resolves, then only fake providers are available and
  any real-cloud provider reference fails startup validation.
- **D5 — no second entitlement authority.** Given the control plane, when its schema and
  services are inspected, then no table or evaluator duplicates the data-plane
  `tenant_entitlement_grants` store or the kernel entitlement evaluator.

## Kernel contract dependencies

Referenced by name only. "Blocked on kernel alpha" means Lane B cannot implement the
dependent behavior until the contract publishes as a tagged pre-release; it may design and
test around a locally-declared *port* that the kernel contract will satisfy, but it may not
define a competing public contract.

| Kernel contract (by name) | Source | Used here for | Status |
|---|---|---|---|
| `ProductAssemblySpec` | kernel-boundary plan, Task 3 | declaring the control plane as an assembly | **blocked on kernel alpha** |
| `create_app(spec)` | kernel-boundary plan, Task 3 | assembly bootstrap | **blocked on kernel alpha** |
| `dotmac_kernel.testing` harness + fake providers + contract suites | kernel-boundary plan, Task 5 | every acceptance suite above | **blocked on kernel alpha** |
| `ModuleManifest` / `ModuleRegistry` and declared capability codes | module control-plane directive steps 2–3; deployment plan WS1 | validating allocation lines against real capability codes | **blocked on kernel alpha** |
| Entitlement evaluator, `tenant_entitlement_grants`, `EntitlementDecision`, `QuotaDecision` | deployment plan WS2 | the *data-plane* side of projection; the control plane allocates only | **blocked on kernel alpha** |
| `DeploymentProfile` / `DeploymentProfileSpec` / `DeploymentProfileRegistry` | ADR-0003 § Profile contract; deployment plan WS1 | the profile code carried by desired state and the plan | **blocked on kernel alpha** |
| Provider protocols: `ProvisioningProvider`/`ProvisioningAuthority`, `CommercialAuthority`, `TelemetryProvider`, `IngressProvider`, `DnsVerificationProvider`, `TlsProvider`, secret/identity provider | ADR-0003 § Provider interfaces; deployment plan WS1/WS10/WS11 | every outbound effect the runner performs | **blocked on kernel alpha** — see Conflict C6 |
| Signed licence issuer/verifier contract | deployment plan WS8 | `LicenceIssuanceService`, revocation list, offline bundles | **blocked on kernel alpha** |
| Transactional outbox + idempotent inbox + idempotent command envelope + lifecycle history | deployment plan WS3; program workstream 4 | every event in the catalogue | **blocked on kernel alpha** |
| Support-access grant contract + diagnostic bundle contract | program workstream 5; deployment plan WS11 | the enforcement seam in the data plane; the control plane owns the workflow | **blocked on kernel alpha** — see Conflict C2 |
| Health/readiness contract, OpenTelemetry instrumentation, heartbeat envelope | program workstream 5; deployment plan WS11 | `POST /ingest/heartbeats` schema and freshness windows | **blocked on kernel alpha** |
| Canonical permissions + audit actions | program workstream 3 | every audit event named in the state machines | **blocked on kernel alpha** |
| Platform-admin identity + `require_platform_admin` + exact-host platform routing | [`2026-07-18-control-plane-security.md`](2026-07-18-control-plane-security.md), Task 1 | actor authentication on every vendor API route | prerequisite, not kernel-alpha-blocked — lands with that plan |
| Money / FX snapshot / jurisdiction policy primitives | deployment plan WS4 | contract amounts, currency, legal entity | **blocked on kernel alpha**; contract lines reference the types by name only |
| Common API/error conventions, versioned OpenAPI policy | program workstream 5; deployment plan WS13 | the typed API surface above | **blocked on kernel alpha** |

## Sequencing — the first executable slice

> **Amendment 2026-07-30 (D0 reconciliation — reconciles this 0–7 table with the 0–6 revised
> sequence below).** The `0.1.0a1` kernel alpha is the **focused** alpha defined by the
> kernel-boundary plan's Tasks 2–6 (+ ruling C6): `ProductAssemblySpec`, `create_app`,
> `dotmac_kernel.testing` (harness + fakes), and the `ProvisioningProvider` protocol +
> `FakeProvisioningProvider` + contract suite. It does **not** ship a module/capability
> registry, outbox/inbox, deployment-profile registry, money/FX, signed-licence,
> entitlement-evaluator, or health/heartbeat contract. **Therefore prerequisite 2 below
> overstated the alpha** where it names "module registry/capability catalogue, outbox/inbox" as
> part of it — those are later workstreams (deployment plan WS1 / WS3), not the alpha, and the
> alpha must not be silently expanded to include them. **Canonical alpha-era step count is
> 0–6** (see the revised sequence below); **step 7 (observed health) is deferred** until the
> health/heartbeat-envelope contract (program WS5 / deployment plan WS11) publishes. Against the
> focused alpha, only **steps 0 and 1 are unlocked end-to-end**, plus **step 6's
> `ProvisioningProvider` execution seam** (exercisable in isolation against the fake); steps 2–5
> and 7 remain design-only pending their named workstreams. Per-step contract mapping and the
> full ruling:
> [`../reviews/2026-07-30-vendor-dependency-reconciliation.md`](../reviews/2026-07-30-vendor-dependency-reconciliation.md).
> Read the 0–7 table below as the fuller domain enumeration, not the alpha-era build order.

Prerequisites (none of this slice starts before all three hold):

1. Control-plane security plan merged (platform identity, exact-host routing, RLS-active dev).
2. Kernel alpha published as a tagged pre-release: `ProductAssemblySpec`, `create_app`,
   `dotmac_kernel.testing`, module registry/capability catalogue, outbox/inbox, and — for
   step 6 — a published `ProvisioningProvider` protocol (Conflict C6).
3. The Lane B home is decided (assembly package vs separate repository — Conflict C5).

Then, fake infrastructure provider only:

| # | Step | Owner | Machine transition | API | Event | Gate |
|---|---|---|---|---|---|---|
| 0 | Assembly scaffold pinning kernel alpha; platform-admin surface; dev profile with fakes only | assembly | — | — | — | empty-assembly boot + D4 |
| 1 | Customer account | `AccountService` | — | `POST /accounts` | — | Foundation gate |
| 2 | Commercial contract: draft → submit → approve → activate | `ContractService` | contract SM | `POST /contracts/*` | `contract.activated` | Manual commercial gate |
| 3 | Deployment intent | `FleetDesiredStateService` | `→ intent_recorded` | `POST /accounts/{id}/deployments` | `deployment.intent_recorded` | Manual commercial gate |
| 4 | Exact release + entitlement selection | `ArtifactSelectionService` + `AllocationService` | `allocation.staged`; selection is pure | `GET /deployments/{id}/artifact-selection`, `GET /contracts/{id}/allocation` | `allocation.staged` | determinism + digest-only tests |
| 5 | Reviewed preview | `DeploymentChangeService` + `DeploymentApprovalService` | `→ plan_ready → approved` | `POST /change-requests/{id}/plan`, `/approve` | `deployment.plan_ready`, `.plan_approved` | D3 (`plan_stale`) |
| 6 | Audited fake-provider provisioning | `DeploymentRunner` | `→ applying → applied → active` | `POST /change-requests/{id}/runs` | `deployment.run_*`, `.activated` | Provisioning-simulation gate (forced failure at every step) |
| 7 | Observed health in a read-only fleet view | `ObservedHealthIngestService` + `FleetHealthRollupProjector` | freshness only | `POST /ingest/heartbeats`, `GET /deployments`, `GET /fleet/health` | `health.*` | no mutating consumer of health |

Explicitly **out** of the first slice, in this order afterwards: real signed licence issuance
(needs the kernel licence contract), real cloud provisioning providers, DNS/TLS
reconciliation, support access against a real deployment, maintenance waves/rollout rings,
vendor invoicing, public signup, and any production fleet mutation. Support access and
licensing are designed here so their state machines are settled before their first
implementation — designing them late is what produces backdoors.

## Ownership rulings (Michael, 2026-07-30 — C1–C7 resolved)

The seven ownership ambiguities this design surfaced were ruled on by Michael on
2026-07-30. They are now **decisions**, not open assumptions; the design above is written to
them. Each ruling also amends the checked-in document it touches (ADR-0003, the
deployment-profiles plan, and kernel-boundary Tasks 3/5) — this section is the discovery
record, those documents remain authoritative for their scope.

- **C1 — Fleet tables → vendor control plane.** The **kernel** owns reusable protocols and
  primitives only. The **vendor control plane** owns `Deployment`, provisioning requests,
  steps, approvals, desired/observed state, and fleet history. (Resolves the Workstream-11
  lane ambiguity: tables + workflow are Lane B; the starter/kernel owns no fleet deployments.)
- **C2 — Support grants → split by concern.** The **vendor control plane** owns the canonical
  request, consent, grant, revocation, and session **workflow**. The **kernel** owns grant
  **claims, verification, enforcement decisions, and audit hooks** (the enforcement contract a
  data plane consumes). The design's two-home split is ratified as-is.
- **C3 — Channels never authorize deployment.** `ReleaseChannel`/`RolloutWave` never authorize
  a deployment by themselves. Under **vendor-automatic** authority a deployment may advance
  through policy gates; **customer-approved** requires an exact approval; **offline** produces
  a signed bundle and observes acknowledgement. A channel pin is desired state ONLY under
  vendor-automatic authority — otherwise it is an offer.
- **C4 — Entitlements: control plane delivers, data plane writes.** The **control plane
  initiates** signed/versioned delivery. The **product data plane verifies it and is the ONLY
  writer of `tenant_entitlement_grants`**, then acknowledges the applied version/digest.
  (Consistent with the Dotmac app-independence standard; a checked-in delivery contract is
  still required before implementation.)
- **C5 — Separate repository.** Lane B lives in its **own maintained repository —
  `dotmac_vendor_control_plane`** (recommended name). ADR-0003's topology diagram expresses
  **logical composition, not a monorepo requirement**. This resolves the step-0 blocker.
- **C6 — `ProvisioningProvider` → kernel alpha (approved with correction).** Pull a
  **product-neutral `ProvisioningProvider` protocol, typed plan/apply/observe results, stable
  errors, a fake, and a parametrized contract suite into the kernel alpha**. Keep fleet
  workflows and cloud-specific operations OUT of the kernel. **Correction to the design's
  original recommendation:** Lane B must **not** define a local replacement, and executable
  slice steps 0–5 **cannot** run "in the meantime" — step 0 requires the published kernel
  alpha. Domain design, contract examples, and acceptance scenarios may continue meanwhile.
  (See the revised sequencing below.)
- **C7 — Fleet/support admin surfaces → vendor-control-plane portal.** Fleet, support,
  maintenance, and incident pages belong to the **vendor-control-plane portal**. The kernel
  supplies authentication and portal-composition machinery only. (Resolves the Workstream-12
  "Platform administration" ambiguity in favor of the Lane B assembly's own portal.)

## Revised program sequence (per the C6 correction)

> **Amendment 2026-07-30 (D0 reconciliation).** "Implement executable slice steps 0–6" (step 5
> below) fixes the canonical alpha-era **step count** at 0–6 (step 7 / observed health deferred
> — see the amendment on the first-slice table above). It does **not** mean all of steps 0–6
> build immediately on the focused alpha: the focused `0.1.0a1` (`ProductAssemblySpec`,
> `create_app`, `dotmac_kernel.testing`, `ProvisioningProvider` protocol+fake+suite) genuinely
> unlocks only **steps 0 and 1**, plus **step 6's `ProvisioningProvider` execution seam** (the
> one thing C6 pulled forward for step 6). Steps 2–5 stay design-only until their named
> workstreams publish — most universally the transactional outbox/inbox (deployment plan WS3)
> and the capability catalogue + deployment-profile registry (WS1); step 2 additionally the
> money/FX primitives (WS4). Do not expand `0.1.0a1` to unblock them. Step-to-contract matrix
> and ruling:
> [`../reviews/2026-07-30-vendor-dependency-reconciliation.md`](../reviews/2026-07-30-vendor-dependency-reconciliation.md).

1. Finish and merge the control-plane security work (v0.8.0).
2. Amend ADR-0003, the deployment-profiles plan, kernel-boundary Tasks 3/5, and this design
   with the C1–C7 rulings.
3. Build and publish the kernel alpha containing `ProductAssemblySpec` AND `ProvisioningProvider`
   (protocol + typed results + stable errors + fake + contract suite).
4. Create the `dotmac_vendor_control_plane` repository.
5. Implement executable slice steps 0–6 against that pinned kernel alpha and its fake provider.

Until step 3 ships, Lane B is **design-only** — domain modelling, contract examples, and
acceptance scenarios. No executable slice step (including step 0) runs before the kernel alpha
is published.
