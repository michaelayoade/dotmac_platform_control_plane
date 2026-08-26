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
exact component artifact ids, digest-pinned references, exact attestation
digests, vulnerability-policy evidence and compatible predecessor bundle
versions.

Every component declares one of two provenance classes:

- `dotmac_product` requires the catalogue's product-manifest, provenance, SBOM
  and signature attestations;
- `upstream_third_party` requires provenance, SBOM, signature and separate
  vulnerability-policy evidence, and MUST NOT fabricate a Dotmac
  product-manifest attestation.

The manifest stores catalogue facts. It neither downloads bytes nor invokes a
registry.

### 2. Integrator selects concrete bindings; Vendor records the selection

Desired state contains only provider-neutral capability requirements and schema
versions. During planning, Integrator supplies one opaque installation and
binding identity for every required capability, plus exact connector version,
manifest/artifact/configuration digests and execution-policy version. Vendor CP
records that returned selection as a plan input. It does not choose a provider,
read connector credentials or call a connector.

### 3. A plan is an immutable deterministic DAG

`DeploymentPlan` is a write-once canonical document over:

- deployment and exact desired-state revision/hash;
- managed profile and bundle manifest hashes;
- the exact selected component artifacts and admission evidence;
- the exact commercial allocation snapshot, or an explicit internal source;
- every versioned capability and concrete binding selection;
- configuration and lifecycle policy versions; and
- the ordered step graph, including stable operation keys, typed command schema,
  retry classification and compensation contract.

`plan_hash` is SHA-256 over that complete canonical document. Replanning never
updates a plan. It creates a new revision and changes the deployment's current
plan pointer. Reverting inputs after an intervening change creates another plan
revision, so an older approval cannot silently revive.

### 4. Approval is a separate exact, expiring binding

Requesting approval opens a `dotmac-approvals` request whose content digest is
the saved `plan_hash`. Vendor records an immutable request binding containing
its expiry. Once the module reports the request satisfied, Vendor records an
immutable grant digest over the plan, authority request and expiry.

A grant is usable only while all of these still match:

- deployment current plan id;
- exact saved plan hash;
- approval request and grant ids;
- approval grant digest; and
- an unexpired timestamp.

Any changed desired state, bundle, artifact, allocation, binding,
configuration, policy or step graph produces a different plan or a new current
plan revision and therefore invalidates the old grant structurally.

### 5. This decision authorizes no execution

Vendor CP may persist bundle, plan, approval-request and approval-grant rows and
emit local outbox facts. It may not apply a step, reach a provider, materialize
a connector secret or accept arbitrary shell. Approval-bound command intake,
run serialization and signed receipts remain the next Integrator-owned slice.

## Consequences

- A plan preview is stable evidence rather than a calculation repeated at
  apply time.
- Approval authority remains in `dotmac-approvals`; deployment transition
  authority remains in Vendor CP.
- Integrator remains the sole owner of connector identity resolution and
  provider I/O, while Vendor obtains an exact record suitable for approval.
- These tables and passing tests are implementation evidence, not production
  adoption or permission to mutate an external system.

## Acceptance

1. Reordering equivalent inputs yields the same plan hash and step graph.
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
7. The fleet package's transitive no-external-I/O guard continues to pass.
