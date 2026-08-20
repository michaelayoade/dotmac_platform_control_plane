# Architecture (as-built + boundaries)

The Vendor Control Plane composes the **pinned `dotmac-kernel`** into a
vendor/product-lifecycle assembly. This document is the source-of-truth for what
it owns and — just as importantly — what it must never become.

## Composition

- `assembly.build_spec()` returns a `dotmac_kernel.assembly.ProductAssemblySpec`;
  `main.py` boots it via `dotmac_kernel.create_app`. The kernel supplies config,
  the single RLS database + transaction authority, platform-admin auth, the
  middleware stack, error handling, and feature mounting. The vendor supplies
  only its own feature modules.
- The kernel is `dotmac-kernel==0.1.0a77` (extras `testing` and `licensing`),
  resolved **only**
  from the private Forgejo registry (ADR-0005 in `dotmac_starter_mt`). It is a
  dependency, never vendored source.
- The a61 → a77 compatibility uplift moves no domain writer and composes no new
  module. It does cross kernel a68's platform-audit registry enforcement, so
  every Vendor-owned platform audit action is now declared on exactly one
  installed feature manifest and swept by
  `tests/architecture/test_platform_audit_actions.py`. The a74–a77 releases
  themselves add only the four published module namespace allocations used by
  the cutovers sequenced in ADR-0007.
- **Two composition declarations, deliberately separate** (ADR-0028). Both are
  checked in at `src/vendor_cp/migration_bindings.py` and both are installed
  from `alembic/env.py` before Alembic builds the revision map:

  - `ASSEMBLY_PREREQUISITE_BINDINGS` answers *where does an effect come from*.
    Kernel `0001_initial_tenant_schema` supplies **both**
    `module_database_roles.v1` and `tenant_scope_catalog.v1`, and both are
    bound, because that is simply true: this assembly runs the whole kernel base
    lineage, so `public.tenants`, `public.tenant_domains` and
    `public.app_current_tenant_id()` all exist here.
  - `ASSEMBLY_MODULE_PLANES` answers *what does this product install*. It
    selects `ModulePlane.PLATFORM` for `approvals`, the one selectable module
    composed here; Release Catalog and Entitlement Allocation each declare a
    single supported plane set, so their contract is atomic and the kernel
    refuses a selection for them.

  Kernel `0.1.0a60` briefly let the first imply the second, and this assembly is
  the case that broke it: binding the tenant catalogue truthfully would have
  installed a dual-plane module's tenant tables in a control plane that has no
  tenants, and the only escape was to lie by withholding a binding whose effect
  the database plainly provides. Availability is not intent.

  Both are mirrored into `DOTMAC_MIGRATION_BINDINGS` /
  `DOTMAC_MODULE_PLANE_SELECTIONS`, so `alembic heads|history|show` — which
  never run `env.py` — inspect the same graph an upgrade applies.

  `tests/migration/test_selected_planes.py` proves the half of ADR-0028 that is
  assertable without a selectable module — the catalogue exists, is bound, and
  no module schema holds a tenant-scoped table — and says plainly that the full
  four-fact proof (platform tables built, tenant tables absent, *because of the
  selection*) lands with the first shadow composition.
- `dotmac-approvals==0.1.0a4` is the **approval authority** (ADR-0005). Pinned,
  its public `versions_dir()` locator composed, `ModulePlane.PLATFORM` selected,
  and `platform_api` holding DML on `mod_approvals` — restored by vendor
  migration `v013`, which reverses v012's shadow revoke as a forward revision and
  verifies the effective outcome in both directions.

  **The switch was greenfield, and valid only because the legacy estate was
  empty.** That is an observation, not an assumption: a direct authorized
  Docker-boundary check against the designated sole target found `TARGET_ABSENT`
  — no Compose `db` service, no data volume — so there was no approval history to
  seal, compare or migrate. (The read-only inventory tool never ran; its
  contribution was refusing to report an absence it had not observed. See
  ADR-0005.) `v013` re-checks emptiness under `ACCESS EXCLUSIVE` in the same
  transaction that drops the tables, and fails closed if a row exists. ADR-0004's
  sealed cutover is superseded and must not be built.

  **`vendor_cp.approvals.adapter` is the only seam.** Typed, no `Any`, and it
  uses the eligibility mapping (`PLATFORM_ADMIN_ROLE_ID`) and digest translation
  declared during the contract phase before any code used them. Contracts open an
  approval request at submit — the subject's owner knows the digest to bind it
  to — carry `approval_request_id`, and evaluate it at approve. The legacy
  writer, its models and its tables are gone, and the ratchet on its call sites
  is held at zero.

  **Vendor owned the shadow restriction, and still does not ask the module to
  weaken its grants.** `ModulePlane.PLATFORM` selects storage shape — which of a
  dual-plane module's tables get built — and says nothing about whether the
  composing assembly has acquired write authority. That distinction is what let
  v012 hold the module read-only and v013 hand it authority, both from this
  assembly, without the module knowing either phase existed.

  **Retired with the switch:** the sealed-cutover implementation
  (`approvals_cutover.py` and its test) and the read-only inventory tool. Both
  queried `approval_policies` / `approval_records`, which `v013` drops, so
  retaining them would preserve the appearance of a reference implementation
  rather than one. They remain readable at `c3a0d1b`; a later cutover implements
  locally from ADR-0031's protocol and its own current inventory, and the
  extraction bar is unchanged at two CURRENT consumers. See ADR-0005 § "Retired
  artifacts".

  **Lifecycle: below adopted.** Composed and authoritative in code is not
  adopted; the new owner has not run in production, because nothing has.
- `dotmac-release-catalog==0.1.0a4` is the permanent owner of immutable release
  artifacts and attestations. The assembly composes its `ModuleManifest` and
  its public `versions_dir()` alongside the kernel and vendor migration
  lineages. Its `mod_rel` tables are platform catalogues: `platform_api` may
  use the published grants and `app_user` is denied.

  a4 is a floor, not a courtesy bump. Through a3 the module declared those
  tables in `ModuleManifest.tables` — the TENANT contract, meaning `tenant_id
  NOT NULL` plus FORCEd RLS — while its migration built platform-shaped tables.
  The declaration and the database disagreed, and nothing here looked because
  nothing audited the live catalogue. a4 moves them to `platform_tables`
  (ADR-0023), which is what makes the declaration true.
- `dotmac-entitlement-allocation==0.1.0a4` is installed and its manifest and
  public migration lineage are composed. This is deliberately a **shadow
  installation**, not adoption: `vendor_cp.allocations` remains the sole
  authoritative writer and there is no dual-write. Vendor migration v011 makes
  new immutable offers and contracts product-qualified, binds that identity into
  the contract content hash, and emits it on contract events. Historical rows
  remain explicitly unclassified until an operator supplies evidence; the
  independent module therefore still receives no `ContractSnapshot`.

## The composed database is audited whole

`tests/migration/test_composed_live_catalog.py` audits the database this
assembly actually produces — kernel lineage, both module lineages, vendor
lineage — rather than the tables someone remembered to name.

- The module schemas (`mod_rel`, `mod_ealloc`) go through the kernel's own
  canonical gate, `dotmac_kernel.migrations.catalog.audit_live_schemas`. A rule
  the kernel tightens tightens here in the release that ships it, and the
  expected table set derives from this assembly's plane selection rather than
  from prerequisite availability.
- `public` is not walked by that gate (the compatibility namespace has
  exceptions a module schema does not get), so this repository owns the policy
  for it. Every table is classified from the live catalogue: `tenant_id NOT
  NULL` and the kernel's no-column subtype tables are the tenant plane and must
  FORCE RLS with a policy; everything with neither is the platform plane and
  must hold **no** privilege for `app_user`, across all seven PostgreSQL table
  privileges and their column-level forms.
- The tenant CATALOGUE (`tenants`, `tenant_domains`) is a third category, not an
  allowlisted exception: it is what tenancy is defined by, so kernel 0001 leaves
  it outside RLS and grants it read-only to the tenant role. It is held to that
  contract explicitly — no RLS, and no privilege beyond `SELECT`. `tenant_domains`
  carries `tenant_id NOT NULL` as a parent FK rather than a scoping
  discriminator, so classifying on that column alone wrongly demands FORCEd RLS
  on it.
- Nullable-`tenant_id` tables belong to neither plane. The three kernel tables
  in that state are named as **unmonitored**, not exempt, and the set is
  asserted exactly, so a fourth cannot appear quietly.
- The vendor lineage's own tables are derived by diffing `public` across
  `kernel@head` and `heads`. This replaced a hand-written ten-name licence-table
  list that could only ever prove what someone remembered; a future `v012` table
  is swept the moment its migration runs.

## Allocation authority (ADR-0006)

`dotmac-entitlement-allocation` owns allocations. `v014` transferred the
authority: `platform_api` holds DML on `mod_ealloc`, and the legacy
`public.allocations` / `public.allocation_entries` tables are dropped along with
the writer that owned them.

**Greenfield, on the same observation as approvals.** A direct authorized check
against the designated sole target found `TARGET_ABSENT` — no Compose `db`
service, no data volume — so there was no allocation estate to seal, compare or
migrate. `v014` re-checks emptiness under `ACCESS EXCLUSIVE` in the same
transaction that drops the tables and fails closed if a row exists.

**`vendor_cp.allocations.adapter` is the only seam**, typed with no `Any`. The
division of rules is deliberate: Vendor keeps the checks about VENDOR'S contract
(it is `ACTIVE`, and the activation event's digest still matches the current
version), because only Vendor can say what "stale" means about its own aggregate;
the module keeps every rule about what a valid allocation IS. Contract activation
stages through the adapter via `ContractEventConsumer`; licensing reads through
it and takes the product from the module's `allocation_product()` — and there is
no way to supply one instead. `IssueLicenceCommand` has no `product` field, and
`IssueLicenceRequest` REJECTS the retired HTTP field rather than ignoring it, so
a caller cannot select a licence lineage the allocation does not name. That one
value flows to all four consequences: lineage, signed payload, audit record and
outbox event.

**The shadow-overlap exemption is gone.** It waived two host-squatter violations
while the legacy tables shadowed `mod_ealloc`; `v014` dropped those tables, so
its premise evaporated and it was REMOVED rather than lowered — an exemption
describing nothing silently widens what the gate permits (ADR-0018). The composed
audit now consumes the kernel gate with no subtraction, which is strictly
stronger, and a guard fails the build if a subtraction helper returns.

**Retired with the switch, beyond the runtime writer:** the allocation cutover
preflight (`allocations/preflight.py` and its test), which audited legacy rows
for a sealed cutover that is not happening and read tables that no longer exist;
and `shadow_overlaps.py` with its architecture test. Both remain readable at
`b76f5fa`. A later cutover implements locally from ADR-0031's protocol and its
own current inventory, and the extraction bar is unchanged at two CURRENT
consumers.

**Lifecycle: below adopted.** Vendor CP now has no local writer for release
artifacts, approvals or allocations — but adoption is earned by running in
production with the local writer proven absent, not by landing code, and nothing
has run.

## In-place module recomposition (ADR-0007)

This repository, runtime and control-plane database remain the Vendor product
assembly. There is no replacement repository and no second control plane. The
remaining local owners move through separately reviewable expand/migrate/
contract slices: Commercial Agreements first, then the Licensing issuer, then
greenfield Deployment Control. Brand Profiles' platform plane follows its
checked-in Sub-first adoption unless that extraction decision is explicitly
amended at the source.

Each authority-moving slice must pin and compose one released module, install
its lineage and platform-plane intent, migrate or prove the absence of rows,
switch one writer, and retire the replaced local owner in the same coherent
change. Merely pinning kernel a77 does none of those things. External provider
I/O, credentials, retries and connector scheduling remain owned by the separate
Dotmac Integrator; module-owned desired state in `mod_deploy` is not permission
to build a second Vendor-local fleet or connector engine.

## Deployment profiles

`src/vendor_cp/deployment_profile.py` declares which vendor SURFACES a
deployment publishes. It is read in exactly one place — `build_spec()` — and a
test fails the build if a second module imports the loader, because ADR-0003
forbids feature code branching on a profile name.

`production-bootstrap` (required by `scripts/deploy_production.sh` in the host
env file) composes and runs everything and simply does not mount the `licensing`
and `offers` routers. Those two features' domain owners are still vendor-local
and reusable-looking; publishing their routes would make an external caller a
constraint on deciding the owner. A withheld surface is not a disabled
subsystem: licence key custody still loads at boot, and a test asserts it.

A profile may never withhold a persistence owner. All three module manifests carry a
migration lineage and own schemas the database already contains, so an assembly
missing one would no longer describe its own tables.

## Production topology

The first production assembly is `vendor.dotmac.io` on the explicitly named
`vendor-cp-prod` host (`149.102.158.144`). It is isolated from Marketing's
Compose project and from every product data plane:

- a GitHub-hosted workflow builds the application once, publishes it to GHCR,
  and emits the immutable registry digest; the production host only pulls;
- nginx terminates TLS and proxies to the loopback-only application port;
- container and deploy health probes call the loopback endpoint with the
  canonical `vendor.dotmac.io` host identity; trusted-host rejection remains
  active for raw IP host headers;
- the deploy owner reconciles the named product-manifest volume to UID/GID
  10001 and mode `0750` through a networkless, read-only-root initializer with
  only `CHOWN`/`FOWNER`; the app mounts it read-only and only one-off ops mounts
  it read-write;
- PostgreSQL has no published port and its volume belongs only to the Vendor
  Compose project;
- the application runs as UID/GID 10001 on a read-only filesystem, with all
  Linux capabilities dropped;
- `app_user`, `platform_api`, and `app_admin` remain distinct. The official
  Postgres image bootstraps a new cluster through a separate `postgres`
  superuser with an ephemeral verifier. Its first-cluster initializer creates
  permanent `app_admin` directly as `NOSUPERUSER NOCREATEROLE BYPASSRLS`,
  creates the kernel's two narrow dispatcher login roles, transfers database
  and `public` schema ownership to the migrator, and removes the bootstrap
  verifier before the temporary server stops. The deploy owner verifies that
  final contract before backup or composed migration; the bootstrap role never
  owns or runs application migrations and `app_admin` never gains cluster-wide
  role-creation authority;
- the licence primary key is held from OpenBao path
  `secret/dotmac/licensing/signing-key`, mounted read-only, loaded at assembly
  boot, and retained in process memory. Production refuses an ephemeral issuer
  before mounting routes;
- the host retains no GHCR credential. Each approved deploy pipes the
  same-repository Actions token over SSH stdin into a temporary Docker config
  under `/run`, then logs out and removes that config;
- `vendor_cp.production_secrets` owns the exact four-record OpenBao schema,
  create-only seeding, validation, and per-file atomic host materialization.
  `scripts/materialize_production_secrets.py` is its thin operator adapter.

`scripts/deploy_production.sh` is the only production migration/deploy owner.
It verifies the host markers, pulls an exact digest, takes a pre-migration
backup, runs the five-lineage `scripts/migrate.py`, and only then replaces the
application. The complete operator contract and rollback boundary are in
`docs/operations/production-deployment.md`.

`scripts/bootstrap_production_host.sh` alone owns `/etc/dotmac-host-id`. The
marker is its final atomic write after the held signing key, Certbot account,
hostname-valid certificate, final nginx configuration, and host environment
have all been verified. An existing Certbot account may be reused without
restating its contact; a new registration still requires an explicit contact.
The deployment path never creates or repairs the marker itself.

## Ownership (what this control plane owns)

- **Production secret materialization** — `vendor_cp.production_secrets` is the
  sole schema, generation, validation, and host-projection owner for Vendor's
  four canonical OpenBao records. The service creates only absent records with
  KV v2 CAS, and the script is a thin operator adapter. Runtime settings never
  read OpenBao, and GHCR authentication remains a per-deploy Actions token
  rather than a fifth persistent record.
  The dependency-free `vendor_cp.product_release_pins` contract is shared by
  runtime configuration and the host operator. `pin-product-release` therefore
  cannot accept a declaration the process later rejects, and changes one
  operator-owned pin without re-rendering or exposing the secret-bearing host
  environment.
- **Vendor accounts** (slice 3) — the vendor-owned `AccountService`: typed
  commands + outcomes, atomic transaction ownership, idempotency, audit,
  platform-admin-only adapters.
- **Commercial lifecycle (as-built)** — immutable product-qualified offers,
  versioned approvals, product-qualified contracts, the legacy allocation
  projection, and signed licence issuance and delivery. Offer and contract
  services consume `dotmac-entitlement-allocation`'s product-scoped
  `CapabilityCatalogueReader` port. The assembly config names only exact
  artifact and product-manifest digests per product. The adapter requires the
  digest-addressed container row and its matching `product_manifest`
  attestation, reads the held canonical bytes through a local document-reader
  port, and delegates digest/canonical/product/version verification to kernel
  a50 before deriving capabilities. The old raw capability-list configuration
  is rejected. These commercial features remain vendor-local owners until each
  approved independent-module cutover explicitly retires its corresponding
  local writer.
- **Allocation cutover gate** — Entitlement Allocation can become authoritative
  only after one coherent change proves all of the following:

  1. **expand delivered for new writes:** the commercial-contract owner persists,
     hashes, and emits an explicit product identity; historical offers and
     contracts must still be mapped from evidence before the v011 checks can be
     validated;
  2. **typed boundary delivered:** commercial services and the cutover preflight
     consume the allocation module's product-scoped catalogue port rather than
     owning a duplicate protocol. Release-bound, digest-verified product-manifest
     snapshots now supply that port;
  3. every live legacy allocation entry validates against its product's
     manifest and duplicate capability codes are normalized before switching;
  4. the activation adapter constructs the module's `ContractSnapshot`, the
     consumer switches once, licence issuance reads `allocation_product()`, and
     the legacy models, service, FK and writer path are retired after parity.

  `preflight_allocation_cutover` is the read-only proof for steps 1–3. It scans
  offers, contracts, allocations, and entries; reports every known divergence;
  and accepts only immutable, evidence-referenced mapping proposals. It never
  changes a legacy row. Separate canonical digests bind the exact operator
  classification set and every relevant persisted fact the report observed;
  neither digest makes a proposal authoritative. Shadow runs may observe normal
  traffic, but the final cutover proof must run after the legacy writer is
  quiesced, so a passing observation cannot move before the writer switch.
  Until all four gates pass, the module tables are empty and non-authoritative.
  A partial switch would either invent product identity or create two writers.
- **Release artifacts and attestations** — owned by the independently published
  `dotmac-release-catalog`, not by a vendor-local feature or table. Vendor's
  `release_evidence` service is the thin ingestion adapter: it holds exact
  product-emitted manifest bytes by digest, calls the module's public write
  seam, spends every delivery key through kernel idempotency, and emits one
  platform audit event per new association. It owns no table or capability
  vocabulary. `scripts/catalogue_product_release.py` is the operator boundary;
  no publish HTTP surface exists. Product identity and capability declarations
  originate in each product assembly; the catalogue binds their snapshot
  attestation to exact artifact bytes, while Vendor only consumes that evidence.
- **Provisioning contracts** (slice 4, delivered) — the `provisioning` feature
  (`src/vendor_cp/provisioning/`): a platform-admin-only API that drives the
  kernel's `ProvisioningProvider` contract (plan → apply → observe → cancel)
  against the Vendor-owned `LaboratoryProvisioningProvider`, plus test-only
  conformance via the kernel's `check_provisioning_provider_contract`. A
  **laboratory** — simulation only, no Vendor-owned fleet tables, no runner, no real
  infrastructure, no SSH; the only state is the provider's in-memory operation
  ledger. Runtime code never imports `dotmac_kernel.testing`. The real runner +
  activation contracts are a later, design-gated slice.
- **Administration shell** — a platform-admin-only console surface
  (`src/vendor_cp/console/`). The initial identity is created or rotated by the
  assembly's `vendor_cp.platform_admin` service. The prompt-only
  `scripts/create_platform_admin.py` adapter supplies the kernel's
  `platform_session`; there is no HTTP self-registration path and no second
  engine/session owner.

## Boundaries (deny-cases D1–D5)

The control plane is defined as much by what it refuses as what it does. Each is
a build-failing architecture test (`tests/architecture/test_deny_cases.py`):

| # | Boundary | Why |
|---|---|---|
| **D1** | One control-plane database; the kernel owns the engine. No `create_engine`/`sessionmaker`, no product DSNs. | A cache or a product DB must never become a parallel authority; the vendor CP has exactly one datastore. |
| **D2** | No product data-plane imports (`dotmac_sub`/`crm`/`erp`/`app`). | ERP/ISP/CRM remain separate data planes; collaboration is API/webhook only. An ISP operator is a *tenant*, its subscribers are the product's parties — never the vendor CP's. |
| **D3** | Vendor-owned simulation provider only; real config fails startup; no real-provider SDKs or runtime testing-kit imports. | A request-time access check never calls a payment/cloud provider; future module-owned desired state still leaves connector execution in Integrator. |
| **D4** | Platform-admin auth through the kernel (`require_platform_admin`). | One authority for platform-actor identity; no re-implemented auth to drift. |
| **D5** | Only the kernel's public surface; no private/internal/copied code. | Products compose a pinned kernel and improve it via declared extension points — never fork or copy it. |

## Still design-only (do NOT implement outside its contracted slice)

Deployment Control is released but not yet composed here. Until its own cutover
lands, fleet desired state, update authority, support access and observed fleet
health remain absent. The permitted future persistence owner is the module's
`mod_deploy` lineage, never a Vendor-local set of fleet tables; the full provider
runner remains outside this application behind Dotmac Integrator. Commercial
Agreements, Licensing and Brand Profiles likewise move only through the ordered
ADR-0007 cutovers; existing Vendor-local code is not evidence that extraction or
adoption already happened.

## Migrating existing products

ERP and ISP adopt through assemblies, adapters, contract/shadow tests,
expand/contract migrations, reconciliation, and one-writer cutovers — never a
big-bang rewrite, and never by this control plane reaching into their databases.


## Licence delivery targets vs. the Deployment entity (2026-08-02)

`licence_delivery_targets` is a **licensing-owned projection** of where a
licence may be delivered, written only by
`EntitlementProjectionService.register_delivery_target`. It is deliberately NOT
the authoritative `Deployment` entity. The historical
`docs/design/domain-foundation.md` names `FleetDesiredStateService`; ADR-0007
supersedes that local-owner label with the independent Deployment Control
module, which is released but not yet composed here. Naming the licensing table
`deployments` would have made licensing
the de-facto owner of an entity another service is specified to own — a
source-of-truth violation dressed as a convenience. When the module cutover
lands, this projection is rebuilt from its desired state rather than competing
with it.
