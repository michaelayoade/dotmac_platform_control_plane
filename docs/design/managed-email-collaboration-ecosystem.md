# Managed email, collaboration and academy ecosystem

**Status:** requirements source for ADR-0007's five-stack programme. This file
defines acceptance; `docs/ARCHITECTURE.md` remains the as-built source of truth.

## Outcome

For any authorised customer account and domain, an operator can select a
versioned managed profile and obtain a repeatable deployment containing:

- a customer identity realm and OIDC clients;
- ERP;
- Mailcow email;
- Nextcloud collaboration;
- Academy LMS;
- optionally the Workspace launcher.

Every component shares customer identity without sharing application sessions
or databases. Each product owns its runtime and domain state. Vendor owns the
commercial contract and desired fleet state. Integrator alone performs external
I/O through plugins. The system must be able to explain which exact inputs were
approved, what ran, what was observed, what drifted and how it was repaired.

## Ownership map

| Decision/state | Sole owner | Consumers / boundary |
|---|---|---|
| offers, contracts, customer account | Vendor CP | product-qualified, immutable commercial facts |
| approval policy/request/decision | `dotmac-approvals` | Vendor supplies subject and exact content hash |
| entitlement allocation | `dotmac-entitlement-allocation` | Vendor typed adapter; never duplicated in fleet tables |
| artifact and attestation identity | `dotmac-release-catalog` | exact Dotmac artifacts and held manifest bytes |
| managed profile and desired state | Vendor fleet service | provider-neutral, immutable, content addressed |
| plan and approval binding | Vendor planning service | exact desired state plus Integrator-selected bindings |
| installations, bindings, secret materialisation, inbox/outbox, retry, checkpoints, health and repair | Starter's `dotmac-integration` module | one stateful external-integration owner |
| provider protocol and I/O | versioned Integrator connector plugin | discovered through the connector SPI |
| execution assembly | `dotmac_integrator` | thin assembly; no second execution engine |
| customer users and external identity binding | customer product/kernel identity owner | issuer+subject+tenant binding; no shared app sessions |
| ERP business decisions | ERP | API/webhook only |
| Mailcow mailbox/domain decisions | Mailcow connector translating to Mailcow | Vendor never calls Mailcow |
| Nextcloud collaboration decisions | Nextcloud connector translating to Nextcloud | Vendor never calls Nextcloud |
| Academy enrolment/course decisions | Academy | connector records observations; Academy remains owner |
| DNS records and TLS observations | DNS connector / certificate connector | typed evidence, not desired-state authority |

No application reads another application's database. No connector writes a
product database. A product receives a typed command through its public API,
decides locally and emits an observation/event. Integrator records transport
evidence and requests reconciliation; it does not decide product status.

## Commercial and profile rules

1. Every offer, contract and allocation is qualified by exactly one
   `product_code`. The suite does not introduce a cross-product entitlement.
2. A managed profile is immutable once published. A new version is a new row and
   has a new content hash.
3. A profile declares required components, allowed optional components and the
   dependency graph; it contains no customer configuration and makes no optional
   choice for a deployment. The deployment selects an allowed optional set and
   the fleet service closes dependencies. Selecting Nextcloud/Mailcow/ERP/Academy
   requires Identity. Workspace is optional and may be omitted without weakening
   the selected products' requirements.
4. A component declares the provider-neutral capabilities it needs, its
   configuration field definitions and its verification checks. A profile may
   narrow/require the schema; the deployment supplies customer values. Neither
   may invent product entitlements.
5. A sold customer deployment references an active product-qualified contract
   and cannot accept a different caller-supplied product identity. A deployment
   may instead name an explicit internal source for Dotmac-owned
   non-commercial estate; exactly one source is required, and the internal path
   is not a customer entitlement escape hatch.
6. Update authority is one of `vendor_automatic`, `customer_approved`, or
   `offline`. The value governs who may open/approve later plan revisions; it
   does not execute an update.

## Component requirements

### Identity

- Permanent issuer under the customer-authorised domain.
- Exact realm/client configuration with confidential clients, S256 PKCE where
  applicable and RS256 at both provider and relying-party boundary.
- Exact redirect URIs, no wildcards unless a product contract explicitly
  declares one.
- Named secret references for admin/bootstrap and each client; no shared session
  JWT secret and no secret material in Vendor.
- Discovery, JWKS, issuer, algorithm, client and real-login verification.
- Backup/restore evidence must preserve the issuer and signing keys; a restore
  that changes issuer is a failed recovery.

### ERP

- Exact Release Catalog artifact and product manifest for Dotmac ERP.
- Provider-neutral product installation/configuration port.
- OIDC client registration and ERP-side issuer/audience/redirect configuration.
- Health, migration, login, backup/restore, upgrade and rollback checks.
- ERP remains the sole owner of its business data and authorization.

### Mailcow

- Exact third-party upstream image/component digests and a Dotmac-authored
  compatibility profile.
- Customer mail domains, MX, SPF, DKIM, DMARC and autoconfiguration DNS.
- OIDC/auth integration supported by the pinned compatibility profile; where a
  protocol cannot consume OIDC directly, a connector-owned supported bridge is
  explicit evidence rather than a Vendor special case.
- Send/receive, app-password/client, quarantine/admin and TLS verification.
- Mail data backup/restore plus a real delivery rehearsal.

### Nextcloud

- Exact third-party image digest and compatibility profile.
- OIDC client configuration, trusted domain/proxy settings, cron/background-job
  mode and database/cache/storage dependencies.
- Login, file upload/download/share, WebDAV, background-job, health and
  backup/restore verification.
- Nextcloud groups/files/shares remain Nextcloud decisions.

### Academy

- Exact Dotmac Academy Release Catalog artifact (or explicitly classified
  third-party evidence if the selected implementation is not Dotmac-built).
- OIDC client configuration with exact issuer/audience/redirect URI.
- Health, login, course access, enrolment boundary, job/worker and database
  migration checks.
- Academy owns course, cohort, enrolment and completion state. An importer may
  record an external fact but may not assign those authoritative fields.
- Backup/restore, upgrade and rollback evidence is mandatory, not deferred
  because Academy was added after the collaboration pair.

### Workspace (optional)

- Exact Dotmac release evidence and OIDC configuration.
- Launcher shows only applications authorised by declared kernel permissions.
- Login uses the published OIDC adapter and kernel external-login finalizer;
  Workspace owns its session.
- Omission removes its own fields/checks without removing any selected
  component dependency.

## Configuration contract

Configuration fields are declared by component and type. The initial vocabulary
includes DNS names/lists and opaque references. A sensitive value must be a
versioned named secret reference, for example a reference shaped like
`secret-name@v3`; it is never the value itself. Ordinary configuration cannot be
an arbitrary string escape hatch. The profile service rejects:

- undeclared fields;
- fields owned by an unselected component;
- missing required fields after dependency closure;
- raw tokens/passwords/private keys;
- unused capabilities or verification checks;
- a predecessor hash/product not matching the persisted predecessor.

Configuration snapshots are canonicalised and hashed. A plan names the exact
snapshot hash; edits create another snapshot and invalidate prior approval.

## Artifact and source classes

Every component declares one source class and evidence shape:

1. **Dotmac release:** exact OCI/package digest, source revision, canonical
   product manifest and manifest digest associated by Release Catalog.
2. **Pinned third-party release:** exact upstream digest, provenance locator and
   immutable Dotmac compatibility-profile version defining configuration and
   verification. “Latest” is not an artifact identity.
3. **External/customer service:** versioned connector observation containing the
   remote immutable identifier where one exists. It is operational evidence,
   never a product entitlement or desired-state decision.

Evidence is content-addressed and records its producer/version/time. A passing
health endpoint alone does not prove configuration, identity, backup or domain
correctness.

## Stack 1 — provider-neutral fleet intent

Required deliverables:

- managed profile version and component/dependency closure;
- account-owned deployment target;
- deployment linked to target/profile and exactly one active product-qualified
  contract or named internal source;
- immutable configuration and desired-state snapshots;
- exact capability/configuration-schema/verification declarations;
- two-session race canaries for profile/deployment identities;
- platform-admin-only routes;
- transitive no-external-I/O guard covering source plus scripts/jobs/workers.

Stack 1 contains no provider/connector binding, execution step, remote command,
credential material, receipt or observed-state authority.

## Stack 2 — deterministic plan and exact approval (ADR-0008)

ADR-0008 owns this downstream contract. The planner resolves one desired state
into a deterministic DAG. Canonical plan
content includes:

- desired-state and configuration hashes;
- exact artifact digests/source-class admission evidence;
- exact policy versions;
- exact Integrator installation and binding identities selected for every
  requested capability;
- dependency/ordering graph and expected verification checks;
- allocation/contract/deployment identity and update authority.

The plan hash covers canonical inputs and step graph. An approval request binds
that hash and an expiry. Any changed field, compatible-plugin result or policy
version makes the prior approval inapplicable. Approval evaluation remains in
`dotmac-approvals`; Vendor stores only the plan-to-request binding and expiry.

## Stack 3 — approval-bound Integrator execution

Vendor emits a typed command containing plan hash, immutable plan locator,
approval evidence and idempotency key. Integrator performs compare-and-set run
claiming and rejects:

- unknown/expired/not-approved content;
- content whose recomputed hash differs;
- a binding/plugin version different from the plan;
- two active runners for the same plan/deployment;
- an idempotency key reused for different content.

Each step receipt binds plan hash, step id, attempt, connector distribution and
version, installation/binding id, timestamps, result class and content-addressed
evidence. Retry and repair remain Integrator decisions. Fake connectors exercise
the exact production SPI; no separate fake engine is permitted.

## Stack 4 — connector and product adoption

Connector distributions are independent plugins discovered from package
metadata. Initial capabilities cover identity, DNS/TLS, host/container,
Mailcow, Nextcloud, ERP, Academy, Workspace and backup object storage. Products
expose provider-neutral versioned ports; provider names, URLs, wire schemas and
secret references remain in connectors.

For each component, adoption requires:

- exact connector config schema and capability version;
- held-secret installation with redaction proofs;
- idempotent apply/observe/repair/cancel semantics;
- typed product-side command/observation boundary;
- contract test plus isolated real-product rehearsal;
- no provider branch in Vendor, integration module or Integrator assembly.

## Stack 5 — operational evidence and acceptance

The acceptance harness creates an isolated test customer/domain and proves:

1. profile → deployment → immutable desired state;
2. deterministic plan → exact approval → Integrator run;
3. multi-component provisioning including Academy;
4. OIDC login into every selected application with separate sessions;
5. mail DNS and real send/receive;
6. Nextcloud file/WebDAV operation;
7. ERP login/health and a non-destructive public API probe;
8. Academy login/course-boundary probe;
9. backup validation, restore into isolation and issuer/data invariants;
10. compatible upgrade, deliberately failed upgrade, bounded rollback;
11. drift detection followed by idempotent repair;
12. receipt/evidence completeness and secret redaction.

The test uses only explicitly named test infrastructure (Seabone is the current
named test host). Production topology, credentials and customer domains are not
inferred from test success. Teardown removes only resources tagged with the
acceptance run id and proves their absence.

## Completion criteria

The ecosystem is complete only when all five stacks are landed through their
own repositories, CI is green, published packages are consumed by exact pins,
and the isolated acceptance harness produces durable evidence for every selected
component. A locally green Vendor branch, a fake provider run or an endpoint
returning 200 is not end-to-end completion.
