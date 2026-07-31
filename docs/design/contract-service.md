# ContractService — design (state machine + acceptance cases)

> **Status:** Implementation AUTHORIZED (2026-07-31). Every kernel dependency
> ContractService needs has published: WS1 (a3), WS4 (a2), WS2 (a4), the vendor
> OfferVersion + ApprovalPolicy owners (merged), and — the last blocker — the
> **platform outbox** channel (kernel **0.1.0a6**, resolving
> `starter-platform-outbox-channel-fork`). ContractService lands **state +
> platform audit + platform outbox event atomically** (never audit-only).
> AllocationService follows as **immutable staging only**; the signed/versioned
> cross-plane delivery + ack (WS8/C4) stays design-only. This document fixes the
> owner, states, transitions, and tests; the code lands one guarded slice at a time.

## Owner and scope

`ContractService` is the **one owner** of commercial-contract shape and lifecycle
in the vendor control plane. It owns:

- **Contract shape** — the contract, its lines, currency, term, and the immutable
  offer/price versions each line references.
- **Lifecycle transitions** — the state machine below, each transition named,
  guarded, audited, and idempotent.

It does **not** own: entitlement *evaluation* (kernel WS2 — data-plane), fleet
desired state, licence signing, or payment. It is a decision owner, and routes/
jobs/webhooks are thin adapters around it (Dotmac source-of-truth standard).

`AllocationService` is a **separate** owner that reacts to `contract.activated`
(via `process_once_platform`) and **stages an immutable allocation** — it derives
*what a tenant is entitled to* from the active contract's lines. **Implemented
(staging only):** `src/vendor_cp/allocations/` — the `ContractEventConsumer`
(`PlatformDeliveryTransport`) dispatches `contract.activated` to `stage_allocation`,
which writes an immutable `Allocation` (unique per `(contract_id, content_hash)`,
idempotent on the source event id). Delivery of that allocation is out of scope
here. It **does NOT write
`tenant_entitlement_grants`** — the vendor control plane never writes a product
data plane's WS2 grants (ruling C4 / `domain-foundation.md` § "Licence /
entitlement-allocation lifecycle"). Delivery is a **signed, versioned document or
authenticated API/webhook/offline-bundle envelope**; the **product data plane
verifies it, writes its own local WS2 grant, and acknowledges the applied
version/digest**. Kernel `0.1.0a4` supplies only the *local* evaluator + storage
(`TenantEntitlementGrant`, `is_entitled`) — **not** the cross-plane signed
delivery/ack contract, which is design-only until WS8/C4 publishes.

**Allocation is not evaluation:** `ContractService`/`AllocationService` decide
*what* a tenant is entitled to; `dotmac_kernel.is_entitled` (WS2, data-plane)
decides *whether a request is allowed*. **The authoritative lifecycle is
`docs/design/domain-foundation.md` §§ "Commercial contract lifecycle" +
"Licence / entitlement-allocation lifecycle";** this document is the focused
ContractService view and defers to it on any conflict.

## State machine

**Commercial approval and operational activation are DIFFERENT decisions** and are
separate states — `approved` is not `active`. This mirrors the authoritative
`domain-foundation.md` lifecycle (the full state set incl. `suspended`,
`superseded`, `cancelled` lives there; reproduced here for the ContractService
view):

```
draft → pending_approval → approved → active → expired | terminated | superseded
   \→ cancelled            \→ draft (rejected)   \→ suspended → active
```

- **`approved`** records that the *commercial* approval policy is satisfied. It
  does NOT make the contract operative.
- **`approved → active`** is a *separate* rule-driven command: the contracted
  **activation rule** must be satisfied (countersignature date, manual
  confirmation, or first deployment activation) — never "a form was submitted".

An amendment produces a new immutable contract *version* (never an in-place
edit); when its approved amendment reaches its effective date the predecessor
goes `active → superseded` with the successor id recorded.

### Transition rules (each = one named, guarded, audited command)

| Transition | Guard | Effects |
|---|---|---|
| `draft → pending_approval` (submit) | ≥1 line; every line's `capability_code` **declared** (WS1 `CapabilityCatalogue.require`); legal entity, currency, term set; each line pins an immutable offer version | snapshot the priced contract; emit `contract.submitted` |
| `pending_approval → approved` (approve) | `ApprovalPolicyService` satisfied **at the recorded policy version**; approver ≠ submitter when two-person applies; approval bound to *this* content hash; pinned offer versions still exist | emit `contract.approved` |
| `pending_approval → draft` (reject) | approver | reason recorded | emit `contract.rejected` |
| `approved → active` (activate) | the contracted **activation rule** is satisfied (rule-driven, not "form submitted") | set `activated_at`; emit `contract.activated` |
| `active → suspended` / `suspended → active` | commercial admin | named reason; projects to allocation restriction only, never data deletion | `contract.suspended` / `contract.reinstated` |
| `active → superseded` | `ContractService` | an approved amendment reaches its effective date; successor id recorded | `contract.superseded` |
| `active → expired` (clock) | term end passed, no renewal | emit `contract.expired` |
| `active → terminated` | commercial admin | effective date + notice policy + impact preview acknowledged | emit `contract.terminated` |
| `draft`\|`pending_approval → cancelled` | submitter/admin | no downstream allocation exists | emit `contract.cancelled` |

**ContractService only changes contract state and enqueues events.** It does NOT
synchronously mutate allocation, deployment, or entitlement state — each transition
commits its state change, its **platform audit event**, and its **platform outbox
event** (`enqueue_platform_event`, kernel 0.1.0a6) in ONE transaction (never
audit-only). `contract.*` events are consumed through `process_once_platform` by
`AllocationService` / `FleetDesiredStateService`, which own those transitions.

### Invariants

- **Immutable pricing.** Lines reference immutable offer/price versions and exact
  `Money` (kernel WS4 — never float); an FX conversion uses an immutable,
  timestamped `ExchangeRate` snapshot. A contract's priced snapshot is frozen at
  submit; re-pricing is a new version.
- **Idempotent, atomic transitions.** Each transition is a
  `process_once`-style idempotent command (kernel messaging), atomic with its
  outbox event, so a decision and its emitted consequence commit together.
- **Two-person approval is content-bound.** Approvals are against a content hash
  of the exact version; changing the contract invalidates prior approvals.
- **No deployment-mode / plan-name branching.** Contract logic reads explainable
  local values, never a profile/plan string (kernel ADR-0003 ban).
- **Capability codes are declared, never invented.** Every line code is validated
  against the WS1 catalogue at submit; allocation projects only declared codes.

## Relationship to the kernel contracts

| Uses | Kernel contract | For |
|---|---|---|
| WS1 capability catalogue | `CapabilityCatalogue.require` | reject a contract line naming an undeclared capability |
| WS2 entitlements (data-plane) | `TenantEntitlementGrant` / `is_entitled` | the *product* data plane writes its own local grant + evaluates. The vendor CP NEVER writes these; it stages an allocation and delivers a signed/versioned envelope (cross-plane delivery/ack = WS8/C4, design-only) |
| WS4 money/FX | `Money`, `ExchangeRate` | exact pricing + immutable FX snapshots |
| WS3 platform messaging | `process_once_platform` + `enqueue_platform_event` (kernel **0.1.0a6**) | idempotent transitions emitted atomically into the **platform outbox** (`platform_outbox_events`, no tenant/RLS); the platform relay delivers. Contract events are platform-level, NOT tenant-data-plane — so they use the platform channel, never the tenant outbox (resolved fork `starter-platform-outbox-channel-fork`) |
| Deployment profiles (WS1) | `DeploymentProfileRegistry.is_valid_code` | a contract that pins a deployment profile validates the profile code |

## Acceptance cases (the tests the future implementation must pass)

1. **Submit rejects an undeclared capability code** on any line (WS1 `require`).
2. **Submit freezes an immutable priced snapshot**; a later offer-version change
   does not mutate the submitted contract.
3. **Approval is separate from activation.** `pending_approval → approved`
   requires the approval policy satisfied at its recorded version (two distinct
   approvers of *this* content hash when applicable) and emits `contract.approved`
   — it does NOT make the contract `active`.
4. **Activation is a separate rule-driven command.** `approved → active` requires
   the contracted activation rule (not "a form was submitted"); it emits
   `contract.activated` and mutates NO allocation/entitlement/deployment state.
5. **ContractService writes no cross-plane state.** Activation emits an event;
   `AllocationService` reacts (inbox) and STAGES an immutable allocation. The
   vendor CP writes **no** `tenant_entitlement_grants`; the product-local WS2 grant
   is written by the data plane only after it verifies a signed/versioned delivery
   envelope and acks the version/digest (WS8/C4 — design-only).
6. **Amendment creates a new version**; the prior version stays `active` until the
   amendment's effective date, then goes `superseded` (no gap, no in-place edit).
7. **Suspend/terminate project to allocation restriction, never data deletion**;
   `is_entitled` on the data plane reflects the projected change only after the
   data plane applies it.
8. **Transitions are idempotent and atomic with their outbox event** (a retried
   approve/activate does not double-emit or double-transition).
9. **Money is exact; FX uses an immutable timestamped snapshot** (no float, no
   live-rate lookup at read time).
10. **No transition branches on a profile/plan string** (architecture test).

## Dependencies — what must publish before implementation

| Dependency | Status | Needed for |
|---|---|---|
| WS1 capability catalogue + profile registry | **published** (kernel 0.1.0a3) | line-code + profile validity |
| WS4 money/FX | **published** (0.1.0a2) | pricing |
| WS3 messaging (outbox/inbox) | **published** (0.1.0a2); relay slice 2 = **implementation brief**, targeting 0.1.0a5 | atomic transitions + eventual delivery |
| WS2 entitlements (data-plane evaluator/storage) | **published** (0.1.0a4) | the *product* verifies + writes its own local grant |
| Immutable **OfferVersion** owner + versioned **ApprovalPolicy** owner (vendor) | **not yet** (vendor slices, next lane) | pinned pricing + separated approval |
| Signed/versioned cross-plane **delivery + ack** contract (WS8 / C4) | **not yet** (design-only) | allocation *delivery* → product-local WS2 grant |

**Corrected dependency chain** (per the 2026-07-31 reconciliation):

```
WS3 relay ─────────────┐
OfferVersion owner ────┼─▶ ContractService ─▶ allocation staging ─▶ signed
ApprovalPolicy owner ──┘   (state + events)   (immutable, no grant)   delivery/ack
                                                                          │
                                                                          ▼
                                                          product-local WS2 projection
```

**Do not implement** until: WS2 published (**done, 0.1.0a4**) *and* the vendor's
OfferVersion + ApprovalPolicy owners exist. Then implement **ContractService**
(state + events only). Implement **AllocationService staging only** with its
boundary explicitly limited to an immutable allocation; **licence
issuance/delivery/ack stays design-only** until the signed/versioned cross-plane
contract (WS8/C4) publishes. Vendor slices require migrations, typed
commands/outcomes, platform audit, idempotency, thin routes, and Postgres
rehearsals.
