# ADR-0008: deployment plans bind exact releases and exact approvals

- **Status:** Accepted
- **Date:** 2026-08-17
- **Follows:** ADR-0007

## Context

ADR-0007 gives Vendor CP authority over provider-neutral managed-service
profiles and deployment desired state while reserving every external call for
Integrator connector plugins. Desired state alone cannot safely authorize a
change: a mutable image tag, a newly selected connector, a changed
configuration revision, or an expired approval could otherwise be substituted
between preview and execution.

The release catalogue records one immutable artifact and its attestations. A
commercial contract deliberately names one commercial product. Neither is a
multi-component deployment bundle, and third-party Mailcow or Nextcloud
artifacts must not be relabelled as Dotmac product releases merely to fit a
manifest shape.

`dotmac-approvals` is already the only approval authority in this assembly. A
deployment service may decide what approval means for its own transition, but
it may not count votes or maintain a second approval ledger.

## Decision

### 1. Bundle manifests are immutable local composition records

Vendor CP owns `DeploymentBundleManifestVersion`. It binds a managed profile to
exact component artifact ids, digest-pinned references, exact selected
attestation row ids/digests and compatible predecessor bundle versions.

The loaded Release Catalog artifact row, not the caller, declares exactly one
origin class:

- `dotmac_product` requires the catalogue's product-manifest, provenance, SBOM
  and signature attestations;
- `upstream_third_party` requires provenance, SBOM, signature and separate
  governed vulnerability-policy-result and compatibility-result attestations,
  and MUST NOT fabricate a Dotmac product-manifest attestation.

Ambiguous, absent or unrecognised origin evidence fails closed. A caller cannot
submit `source_class` or invented evidence locator/digest pairs. This requires
the Release Catalog a5 origin/admission contract; the currently pinned a4 does
not satisfy that prerequisite and is not silently treated as equivalent.

The manifest stores catalogue facts. It neither downloads bytes nor invokes a
registry.

### 2. Integrator selects concrete bindings; Vendor records the selection

Desired state contains exact immutable snapshots of externally owned,
provider-neutral capability contracts. A capability id names the reusable owner
contract; a canonical `capability_instance_ref` names one stable node inside a
deployment. During planning, Integrator supplies one opaque installation and
UUID binding identity for every required capability instance,
plus the exact owner-contract schema/attestation, Integrator connector
configuration revision, connector key/version, manifest/artifact/configuration
digests and module-owned execution-policy digest.
Vendor CP records that returned selection as a plan input. It does not choose a
provider, read connector credentials or call a connector.

### 3. A plan is an immutable deterministic DAG

`DeploymentPlan` is a write-once canonical document over:

- deployment and exact desired-state revision/hash;
- managed profile and bundle manifest hashes;
- the exact selected component artifacts and admission evidence;
- the exact commercial allocation snapshot, or an explicit internal source;
- every versioned capability, stable deployment-local instance and concrete
  binding selection;
- configuration and lifecycle policy versions;
- the exact owner-shaped desired APPLY document for each selected instance,
  already validated against its held schema, with only approved composition
  targets absent; and
- the ordered global step graph; and
- one static command template per capability binding, containing only the exact
  deployment reference, capability, instance and binding, connector artifact/config
  digests, same-binding steps, sorted symbolic prerequisite binding ids and
  value-free prerequisite-evidence mappings.

Each mapping originates in a held, Dotmac-only `capability_composition`
attestation. It pins source binding, source step, exact APPLY-output schema and
public/non-secret JSON pointer, plus target step, exact APPLY-input schema and
JSON pointer. Vendor resolves abstract capability identities to the plan's UUID
bindings and step keys. It neither invents a product field nor carries a
concrete runtime value in desired state, the plan or approval.

The immutable profile retains the abstract owner rule. Fleet resolves it only
from explicit source/target instance selections after validating selector
applicability and the rule's exact-one coverage axis; the concrete edge set is
part of desired-state and plan hashes. Duplicate writes to one target
instance/pointer are refused.

The planner rehydrates and revalidates the held APPLY input schema before it
saves the plan. `ProvisionStep.input` is that exact desired document—not a
generic component/configuration wrapper. Connector configuration, secret
references and orchestrator-owned identities remain separate signed envelope
fields. Integrator may add only the approved composition target values after it
has verified the exact prerequisite receipts.

`plan_hash` is SHA-256 over that complete canonical document. Replanning never
updates a plan. It creates a new revision and changes the deployment's current
plan pointer. A separate canonical `plan_input_hash` refuses a concurrent or
immediate duplicate of the current inputs; it deliberately excludes the
revision-specific saved-plan identity. Reverting inputs after an intervening
change creates another plan revision, so an older approval cannot silently
revive.

Each command-template digest excludes `plan_hash`, approval and dynamic receipt
pins, avoiding a temporal/self-reference cycle while making every approved
static command input part of the global plan hash.

### 4. Approval is a separate exact, expiring binding

Vendor first signs one minimal PLAN command per binding and records its exact
body digest. A held-key verifier admits only Integrator receipts for commands
Vendor actually signed, with exact deployment/plan/config identity and a
continuous module receipt projection. Requesting approval then requires a
canonical receipt set that exactly covers every planned binding. The
`dotmac-approvals` request binds the saved `plan_hash`; Vendor's immutable
request/grant binding additionally commits the receipt ids, signed transport
digests, request-body digests, PLAN command ids and module PLAN receipt hashes.

A grant is usable only while all of these still match:

- deployment current plan id;
- exact saved plan hash;
- approval request and grant ids;
- approval grant digest; and
- exact approved command-template digest; and
- an unexpired timestamp.

Any changed desired state, bundle, artifact, allocation, binding,
configuration, policy or step graph produces a different plan or a new current
plan revision and therefore invalidates the old grant structurally.

### 5. Dispatch builds the exact Integrator envelope, but performs no execution

Vendor CP may derive one signed APPLY command per exact capability binding from
the immutable current plan and grant. The wire contract is
`integrator.provisioning-command.v1`: nonce equals command id; the canonical
header binds audience, lifetime and SHA-256 of the exact body; an Ed25519 signer
is injected through a command-purpose port and must not reuse licence/session
key identity or public material.

The instance reference is part of the PLAN body, approved APPLY template,
APPLY/OBSERVE/CANCEL body, command replay fingerprint and immutable receipt
projection. A receipt that changes it is not evidence for the dispatched node.

Same-binding `depends_on` contains only local step keys. Cross-binding edges are
the template's sorted prerequisite binding ids. At dispatch, a read-only
resolver selects exact already-ingested successful Integrator terminal receipts
for those ids. The resulting UUID-sorted receipt pins include operation id,
binding id, terminal sequence/digest and required `succeeded` status. They are
signed and replay-fingerprinted but excluded from plan/template hashes; they
must exactly cover the approved static prerequisites. Vendor accepts neither
caller-authored steps nor caller-authored receipt pins.

Dispatch proceeds in evidence-gated waves. A command whose static prerequisites
do not yet have exact successful receipts is not emitted; after receipt ingress
it becomes eligible, while a binding with an already-ingested successful APPLY
receipt is not emitted again.

Where a static prerequisite-evidence mapping exists, Integrator corroborates
the source schema against the pinned upstream APPLY receipt, extracts only the
approved public/non-secret pointer, validates the target schema and injects a
copy into the downstream request immediately before plugin I/O. Concrete
values remain outside plan/template hashes and are never accepted from the
Vendor caller.

OBSERVE and CANCEL are equally derived, not caller-shaped. Vendor selects the
latest held-key-verified receipt for the exact plan, grant, binding, connector
artifact and configuration. It reads `step_key` and `provider_operation_ref`
only from the signed module-receipt projection's typed top level, never from
free-form connector evidence. Owner-declared verification steps determine which
bindings require OBSERVE. CANCEL additionally carries a non-empty Vendor-authored
compensation reason; the connector cannot decide that policy transition.

Vendor may persist bundle, plan, approval-request and approval-grant rows and
emit local outbox facts. It may not apply a step, reach a provider, materialize
a connector secret or accept arbitrary shell. Operation claiming, receipt
locking and provider execution remain Integrator-owned.

## Consequences

- A plan preview is stable evidence rather than a calculation repeated at
  apply time.
- Approval authority remains in `dotmac-approvals`; deployment transition
  authority remains in Vendor CP.
- Integrator remains the sole owner of connector identity resolution and
  provider I/O, while Vendor obtains an exact record suitable for approval.
- Cross-repository golden JSON fixes the canonical APPLY template, body hash and
  signature bytes without importing the deployable Integrator assembly.
- PLAN, APPLY, OBSERVE and CANCEL command identities plus their signed receipts
  are immutable and exact replay converges; a digest or command id reused for
  different content is a conflict.
- These tables and passing tests are implementation evidence, not production
  adoption or permission to mutate an external system.

## Acceptance

1. Input order is canonical within a prospective revision; a later revision,
   including a semantic revert, receives a new saved-plan identity so it cannot
   revive an older grant.
2. Changing every material input in turn yields a new plan or invalidates the
   current-plan comparison.
3. A missing, mutable or evidence-mismatched artifact is refused before a plan
   exists.
4. A third-party artifact reaches a bundle without a fabricated product
   manifest and cannot omit its own admission evidence.
5. Approval with a different hash, an expired request/grant, or a non-current
   plan is refused.
6. Two concurrent creates cannot leak `IntegrityError` or mint competing
   current plan revisions.
7. Static cross-binding dependencies are plan-hashed; dynamic receipt pins
   exactly cover them and cannot be caller supplied. Static evidence mappings
   are also plan/template-hashed while their later concrete values are not.
8. Vendor and Integrator produce byte-identical canonical template/body/header
   material for the checked golden APPLY fixture.
9. The fleet package's transitive no-external-I/O guard continues to pass.
10. OBSERVE/CANCEL select only signed typed module step/provider pins; a free-form
    evidence decoy and a detached pin pair cannot influence a command.
