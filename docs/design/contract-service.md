# ContractService — design (state machine + acceptance cases)

> **Status:** Design only (2026-07-31). No implementation is authorized. Per the
> standing constraint, the vendor CP may DESIGN the contract state machine and
> acceptance cases now, but must NOT implement commercial/deployment records
> until the kernel contracts they depend on publish (see § Dependencies). This
> document fixes the owner, the states, the transitions, and the tests; the code
> lands later, one guarded slice at a time.

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

`AllocationService` is a **separate** owner: it derives *what a tenant is
entitled to* from an active contract's lines and projects that into the kernel's
WS2 entitlement grants (via API/webhook — never a shared table). **Allocation is
not evaluation**: `ContractService`/`AllocationService` decide entitlement;
`dotmac_kernel.is_entitled` (WS2) decides whether a request is allowed.

## State machine

```
             submit                approve (2-person)
  draft ───────────────▶ pending_approval ───────────────▶ active
    ▲  │                      │  reject                        │
    │  │ withdraw             ▼                                │ amend
    │  └──────────────── draft                                 ▼
    │                                               pending_approval (amendment)
    │                                                          │ approve
    │                                                          ▼
    └────────────────────────────────────────────────────── active'
                                                              │
                              expire (term end) / terminate   ▼
                                                    expired | terminated
```

States: `draft`, `pending_approval`, `active`, `expired`, `terminated`. An
amendment re-enters `pending_approval` from `active` and returns to `active` (a
new immutable contract *version*, never an in-place edit). Terminal states
(`expired`, `terminated`) are immutable.

### Transition rules (each = one named, guarded, audited command)

| Transition | Guard | Effects |
|---|---|---|
| `draft → pending_approval` (submit) | contract has ≥1 line; every line's `capability_code` is **declared** (kernel WS1 `CapabilityCatalogue.require`); currency ∈ allowed set; offer versions pinned (immutable) | snapshot the priced contract; emit `contract.submitted` (outbox) |
| `pending_approval → active` (approve) | **two distinct approvers** (`ApprovalPolicyService`), each approving *this* content hash; not self-approval; clock-based activation rule met | set `activated_at`; emit `contract.activated`; trigger `AllocationService` to project entitlements |
| `pending_approval → draft` (reject/withdraw) | approver or owner | record reason; emit `contract.rejected` |
| `active → pending_approval` (amend) | amendment references the active version; delta re-priced | new version in `pending_approval`; old stays `active` until the amendment activates |
| `active → expired` (expire) | term end reached (clock) | emit `contract.expired`; `AllocationService` revokes derived grants |
| `active → terminated` (terminate) | authorized termination + reason | emit `contract.terminated`; grants revoked |

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
| WS2 entitlements | `TenantEntitlementGrant` / `grant_entitlement` | AllocationService projects an active contract's derived entitlements (data-plane owns evaluation via `is_entitled`) |
| WS4 money/FX | `Money`, `ExchangeRate` | exact pricing + immutable FX snapshots |
| WS3 messaging | `process_once` + outbox `enqueue_event` | idempotent transitions emitted atomically; the relay (slice 2, design fixed) delivers |
| Deployment profiles (WS1) | `DeploymentProfileRegistry.is_valid_code` | a contract that pins a deployment profile validates the profile code |

## Acceptance cases (the tests the future implementation must pass)

1. **Submit rejects an undeclared capability code** on any line (WS1 `require`).
2. **Submit freezes an immutable priced snapshot**; a later offer-version change
   does not mutate the submitted contract.
3. **Activation needs two distinct approvers of the same content hash**; a single
   approver, a self-approval, or an approval of a stale hash does not activate.
4. **Activation projects entitlements** via `AllocationService` → WS2 grants; the
   data-plane `is_entitled` then returns allowed for the granted codes.
5. **Amendment creates a new version** in `pending_approval`; the prior version
   stays `active` until the amendment activates (no gap, no in-place edit).
6. **Expiry/termination revokes derived grants**; `is_entitled` then returns not
   allowed.
7. **Transitions are idempotent and atomic with their outbox event** (a retried
   approve does not double-activate or double-emit).
8. **Money is exact; FX uses an immutable timestamped snapshot** (no float, no
   live-rate lookup at read time).
9. **No transition branches on a profile/plan string** (architecture test).

## Dependencies — what must publish before implementation

| Dependency | Status | Needed for |
|---|---|---|
| WS1 capability catalogue + profile registry | **published** (kernel 0.1.0a3) | line-code + profile validity |
| WS4 money/FX | **published** (0.1.0a2) | pricing |
| WS3 messaging (outbox/inbox) | **published** (0.1.0a2); relay slice 2 **design fixed**, unimplemented | atomic transitions + delivery |
| WS2 entitlements | **merged, pending publish** (0.1.0a4) | allocation → grants |
| Immutable offer/price + approval-policy contracts | **not yet** (vendor-owned, later slice) | shape + two-person approval |

**Do not implement** contract/allocation records until WS2 publishes and the
vendor's own offer-version + approval-policy owners exist. This design is the
contract those slices must satisfy.
