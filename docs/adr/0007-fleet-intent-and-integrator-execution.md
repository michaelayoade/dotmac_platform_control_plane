# ADR-0007 — Vendor owns fleet intent; Integrator owns external execution

- **Status:** Accepted
- **Date:** 2026-08-16
- **Scope:** managed Identity, ERP, Mailcow, Nextcloud, Academy and Workspace
- **Supersedes:** the active-document claim that fleet tables are categorically
  forbidden. Historical ADRs remain historical.

## Context

Dotmac sells managed email and collaboration as a service, and must be able to
deliver the same governed suite for customer domains such as NHIA without
forking a deployment script per customer. The existing Vendor Control Plane
already owns commercial contracts, approval subjects, allocations, licences and
immutable release evidence. It also contains a fake-only provisioning-contract
laboratory. That laboratory proves a protocol shape; it is not a fleet owner and
must never grow into a production runner.

The independently deployed Dotmac Integrator is already the fleet-wide external
connector control plane. Its stateful integration module owns installations,
bindings, secret references, inbox/outbox, retries, checkpoints, health and
repair evidence. Connector plugins own provider wire translation and I/O. If
Vendor also selected providers, opened network clients, dereferenced secrets or
ran host commands, the fleet would acquire two execution owners and no stable
place to repair drift.

Products remain independently deployed applications. ERP, Mailcow, Nextcloud,
Academy, Workspace and the identity provider each own their runtime, database,
migrations, sessions and domain decisions. Vendor may decide what should exist;
Integrator may transport that decision; neither may write a product database.

## Decision

### 1. Vendor owns provider-neutral fleet intent

Vendor owns these control-plane entities in its one database:

- **Managed profile** — immutable/versioned required and allowed-optional
  component policy, externally owned capability requirements and dependency
  graph. Product owners define the capability's configuration fields,
  operations, endpoint roles and verification checks. Publication resolves and
  snapshots each exact product/business-owner capability contract through an
  injected read-only registry. Vendor defines no capability endpoint or schema.
  The profile contains no customer configuration and does not make a
  deployment's optional selection.
- **Deployment target** — the customer/account-owned logical destination. It is
  not a hostname credential, SSH endpoint, connector binding or provider id.
- **Deployment** — the stable lifecycle identity linking one target to one
  managed profile and exactly one active product-qualified contract or named
  internal source. An internal source is for Dotmac-owned non-commercial estate;
  it is not a customer entitlement escape hatch.
- **Desired-state snapshot** — content-addressed selected components, typed
  connector-configuration references, required provider-neutral capabilities,
  exact product-owned desired APPLY documents, update authority and
  verification contract, and explicit deployment-instance edges selected from
  owner-authored composition definitions. Each desired document is validated
  against the held owner input schema, including declared formats, before
  persistence. Selector applicability and exact-one coverage come only from the
  held composition; callers choose instances, never coverage. Only a target pointer declared by an
  approved composition may be absent, and the caller may not pre-fill it.

The desired-state content hash covers every decision-bearing field. Publishing
a new snapshot never edits an older one. Compatibility with a predecessor is
checked against the exact persisted product and hash, not against caller prose.
The target belongs to the same Vendor account as the deployment; database
constraints enforce that parity.

A reusable capability is not a singleton node. The stable
`capability_instance_ref` supplies multiplicity while the commercial requirement
continues to name the same owner capability id. Configuration, desired document,
composition edge, Integrator binding and plan node exact-cover that instance.

Vendor does **not** persist a chosen provider, connector package, installation
id or binding id in desired state. It requests versioned capabilities. Connector
selection and binding identity are execution-plan facts owned at the Integrator
boundary.

### 2. External I/O belongs only to Integrator connector plugins

Vendor fleet/profile services, their transitive local imports and every script,
job or worker that imports them must not:

- import network/process clients or provider SDKs;
- issue HTTP, DNS, SSH, subprocess, container or infrastructure calls;
- dereference a secret reference;
- branch on a provider/product implementation;
- mutate an external product or its database.

They publish intent and later consume typed receipts/observations. Integrator
selects one compatible active plugin per requested capability, executes an
immutable plan through its durable engine, and returns signed/content-addressed
evidence. Products expose versioned APIs/webhooks; they never share a database
with Vendor or Integrator.

The local `LaboratoryProvisioningProvider` remains side-effect-free and
fake-only. It is not an exception authorising a real Vendor runner.

### 3. Managed-suite composition does not replace product contracts

The reusable managed suite closes dependencies across:

- Identity / OIDC
- ERP
- Mailcow email
- Nextcloud collaboration
- Academy LMS
- optional Workspace launcher surfaces

That profile is operational composition, not a new commercial entitlement
owner. Each immutable offer, contract and allocation remains qualified by one
product. A fleet deployment references those authoritative facts. Vendor must
not manufacture a capability or entitlement that its product/business owner and
allocation do not declare. The component graph may select an exact capability
id; the injected `CapabilityContractRegistry` supplies its semantic owner,
contract reference, content hash, schema versions and endpoint roles. There is
no production default and no caller-supplied contract document.

### 4. Configuration is typed; artifact evidence is a plan input

Connector configuration is constrained by owner-declared field type (for
example a DNS name or list). Sensitive values are named, versioned secret
references; their material is held only by Integrator at installation/runtime.
Vendor never accepts or stores a raw secret value. This configuration snapshot
is distinct from the product-owned desired APPLY document: the latter contains
only the provider-neutral operation fields declared by its held schema and
never connector config/secret refs, a plan hash or other orchestrator metadata.

Stack 1 does not pretend a managed profile is an artifact catalogue. ADR-0008's
immutable bundle manifest records exact artifacts and the origin class owned by
their Release Catalog rows:

- a Dotmac-built product is evidenced by an exact Release Catalog association
  and product manifest;
- a pinned third-party image/package is evidenced by exact upstream artifact
  digest plus separately governed vulnerability-policy and compatibility
  result attestations;
- customer/external services are observations from a versioned connector and
  never become entitlement authority.

Evidence identifies what was observed and how; it cannot decide the desired
state it is meant to verify. Adding that evidence to a bundle/plan changes the
plan hash; it does not rewrite this Stack 1 desired-state snapshot.

### 5. Approval binds exact immutable execution content

The next execution slice must build a deterministic plan from one desired-state
snapshot, exact artifact digests, connector installation/binding identities,
policy versions and configuration snapshot. Approval binds the exact plan hash
and expiry. Any changed input produces a different hash and invalidates approval.
Execution is compare-and-set and idempotent; receipts bind plan, step, attempt,
plugin and observed artifact identity.

This ADR authorises Stack 1 intent state. It does not authorise a Vendor runner
or weaken the approval requirement for later stacks.

## Enforced invariants

- `tests/architecture/test_fleet_intent_boundary.py` traces local imports from
  fleet/profile domains and importing entry-point families and refuses external
  I/O transitively. Sensitivity probes include direct HTTP/process usage,
  delegated helpers and an unresolved relative `from .. import
  provider_transport` escape.
- All fleet/profile routes are guarded by the kernel's
  `require_platform_admin`.
- Profile publication fails closed without externally owned immutable
  capability snapshots. Test registries are fixtures, not a production
  capability catalogue.
- `tests/architecture/test_deny_cases.py` continues to ban provider SDKs across
  all Vendor runtime and entry-point code.
- The fleet migration creates only control-plane intent tables. No credential,
  execution-step, remote command or provider result table is authorised here.

## Delivery roadmap

1. **Stack 1 — Fleet intent:** this ADR, managed profiles, deployment targets,
   deployments, immutable desired-state snapshots and no-I/O guards.
2. **Stack 2 — Plan and approval (ADR-0008):** deterministic immutable plan,
   exact artifact and connector-binding selection, plan hash, expiry and
   invalidation.
3. **Stack 3 — Integrator execution:** durable command/receipt contract,
   compare-and-set run ownership, connector SPI and fake executor.
4. **Stack 4 — Product connectors/adoption:** Identity, ERP, Mailcow, Nextcloud
   and Academy connectors plus product-owned typed ports.
5. **Stack 5 — Operations and acceptance:** backup/restore, upgrade/rollback,
   drift/repair, alerting and an isolated cross-domain acceptance harness.

Each stack is independently reviewable. No stack may smuggle the next stack's
authority into its own database because doing so would make the eventual owner a
second writer rather than a composed service.

## Consequences

Vendor can sell and govern a repeatable suite for many customer domains without
becoming a deployment script warehouse. The cost is an explicit asynchronous
boundary: desired state, plan, execution and observed state are different
records owned by different services. That separation is intentional; it makes
approval exact, execution retryable and drift repairable.
