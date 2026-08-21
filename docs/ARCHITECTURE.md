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
    `public.app_current_tenant_id()` all exist here. Kernel
    `0018_idempotency_one_owner` and `0026_platform_audit_log` supply the two
    request-time effects Commercial Agreements and Licensing declare; those
    effects are bound explicitly rather than inferred from composition order.
  - `ASSEMBLY_MODULE_PLANES` answers *what does this product install*. It
    selects `ModulePlane.PLATFORM` for `approvals`, the one selectable module
    composed here; Release Catalog, Entitlement Allocation, Commercial
    Agreements and Licensing each declare a single supported plane set, so
    their contract is atomic and the kernel refuses a selection for them.

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
- `dotmac-approvals==0.1.0a5` is the **approval authority** (ADR-0005). Pinned,
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

  **Lifecycle: adopted since 2026-08-17.** Production deploy `32022599873`
  runs `mod_approvals` live with the legacy `public` tables absent and
  `app_user` holding no module privilege; the extraction dossier records this
  assembly as the contract consumer. The one item that survived adoption is now
  closed: a4 wrote the outbox relay without declaring `outbox_relay.v1`, and the
  repin to `0.1.0a5` composes `ap_0002_outbox_relay` — a DDL-free revision whose
  entire `upgrade()` is `require_prerequisites` — against the
  `outbox_relay.v1` binding added beside it.
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
- `dotmac-entitlement-allocation==0.1.0a6` is the allocation authority under
  ADR-0006. Its manifest and public lineage are composed, `v014` retired the
  empty legacy tables and local writer, and Vendor retains one typed adapter.
  a6 declares the two kernel effects `stage_allocation` writes at request time
  and composes the DDL-free `ea_0002`/`ea_0003` verification revisions; both
  effects were already bound. `0.1.0a5` carried only half of that and was never
  published — do not pin it.
- `dotmac-commercial-agreements==0.1.0a1` is the commercial-agreement authority
  under ADR-0008. Its platform-only manifest and `cg_0001_agreements` lineage
  are composed. `v015` checks the greenfield premise under lock, drops the empty
  `public.contracts` / `public.contract_lines` estate, and leaves
  `mod_agreements` as the sole lifecycle, history, audit and outbox writer.
  Vendor retains one typed adapter that resolves immutable offers, supplies the
  product capability catalogue, and converts the authoritative Approvals
  request into content-bound evidence.
- `dotmac-licensing==0.1.0a1` is the Licensing issuer authority under ADR-0009.
  Its platform-only manifest and `li_0001_licensing` lineage are composed.
  `v016` rechecks the greenfield premise under lock, drops the five empty local
  issuer tables, and leaves `mod_licensing` as the sole lineage, issuance,
  public-key registry, lifecycle, acknowledgement and revocation writer.
  Vendor retains one typed grant/signer adapter and product-held private-key
  custody. Its delivery projection/transport tables are a temporary owner under
  ADR-0009, frozen pending ADR-0010's post-Deployment-Control Integrator
  cutover.

## The composed database is audited whole

`tests/migration/test_composed_live_catalog.py` audits the database this
assembly actually produces — all seven lineages: kernel, the five module owners,
and Vendor — rather than the tables someone remembered to name.

- The module schemas (`mod_rel`, `mod_ealloc`, `mod_approvals`,
  `mod_agreements`, `mod_licensing`) go through the kernel's own
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

**`vendor_cp.allocations.adapter` is the only seam**, typed with no `Any`.
Commercial Agreements answers whether the agreement is `ACTIVE` and whether the
versioned activation fact still matches its frozen digest; Vendor does not read
or reconstruct that owner's state. Entitlement Allocation keeps every rule
about what a valid allocation IS. Agreement activation stages through the
adapter via `ContractEventConsumer`; the Licensing adapter reads that typed
allocation snapshot and takes the product from it — and there is no way to
supply one instead. `IssueLicenceCommand` has no `product` field, and
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

**Lifecycle: split, and the split is the point.** Vendor CP now has no local
writer for release artifacts, approvals, allocations, agreements or licensing
issuance. Adoption is earned per owner, by running in production with the local
writer proven absent — not by landing code, and not by a neighbouring owner
having done it.

Approvals and Entitlement Allocation cleared that bar on 2026-08-17 with
production deploy `32022599873` (ADR-0005 and ADR-0006 § "Adoption plan" carry
the evidence and the repins each still owes). Commercial Agreements and
Licensing switched AFTER that deploy and remain below adopted until the next
one runs them.

## In-place module recomposition (ADR-0007)

This repository, runtime and control-plane database remain the Vendor product
assembly. There is no replacement repository and no second control plane.
Commercial Agreements moved first under ADR-0008 and Licensing followed under
ADR-0009. The remaining local owners move through separately reviewable
expand/migrate/contract slices: greenfield Deployment Control next, then the
ADR-0010 licence-delivery cutover to Dotmac Integrator, then Brand Profiles'
platform plane after its checked-in Sub-first adoption. Reordering those steps
requires an explicit amendment at the owning source.

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
and `offers` routers. Licensing's issuer is composed; Vendor still owns its
route adapter, key custody and delivery. A withheld surface is not a disabled
subsystem: licence key custody still loads at boot, and a test asserts it.

A profile may never withhold a persistence owner. All five stateful module
manifests carry a migration lineage and own schemas the database already
contains, so an assembly missing one would no longer describe its own tables.

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
backup, runs the seven-lineage `scripts/migrate.py`, and only then replaces the
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
  Commercial Agreements, Approvals, Entitlement Allocation, signed licence
  issuance, and delivery. `dotmac-commercial-agreements` owns agreement shape,
  lifecycle, append-only history, audit and versioned transition facts;
  `dotmac-approvals` owns the content-bound decision; and
  `dotmac-entitlement-allocation` owns the immutable allocation, and
  `dotmac-licensing` owns the issuer lifecycle, public-key registry,
  acknowledgements and revocation. Vendor adapters translate between those
  owners and the local OfferVersion catalogue without
  reading another owner's ORM or maintaining a parallel status path. The
  assembly config names only exact
  artifact and product-manifest digests per product. The adapter requires the
  digest-addressed container row and its matching `product_manifest`
  attestation, reads the held canonical bytes through a local document-reader
  port, and delegates digest/canonical/product/version verification to kernel
  a50 before deriving capabilities. The old raw capability-list configuration
  is rejected. Agreements, Approvals, Allocation and Licensing have no local
  writer; Vendor retains key custody and temporarily retains delivery under
  ADR-0009. ADR-0010 freezes that path and schedules its transfer to Integrator
  immediately after Deployment Control.
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

Deployment Control is released (`0.1.0a2`, tagged) and CONTRACTED here
(ADR-0011) but not composed. Until that slice lands, fleet desired state, update
authority, support access and observed fleet health remain absent. The permitted
persistence owner is the module's `mod_deploy` lineage, never a Vendor-local set
of fleet tables; the full provider runner remains outside this application
behind Dotmac Integrator.

**That slice is two differently-shaped halves.** Greenfield for plans,
rollouts, credentials and observations — no Vendor owner has ever existed for
any of them. A narrow AUTHORITY CUTOVER for deployment-target identity:
`register_delivery_target` and `licence_delivery_targets` are a named authority
over that subject today, and a second authority does not stop being one because
it was given a narrower name. `src/vendor_cp/cutover_readiness.py` inventories
both halves at symbol level with per-file call-site counts, ratcheted in both
directions.

Execution is gated on measuring `licence_delivery_targets` and
`licence_deliveries` on a target Michael names explicitly — never one inferred
from deployment history. An empty result permits a sealed empty-estate revision
in the `v013`–`v016` shape; a non-empty result requires backfill into
`mod_deploy`, comparison, a writer switch, and retention of the Vendor table as
a module-derived projection until ADR-0010. Either way a forward vendor revision
is owed.

ADR-0010's licence-delivery transfer is the next slice after Deployment Control
and must land before Brand Profiles. Until then the current logging/offline path
is frozen and no connected Vendor transport or additional retry policy may be
added.

Brand Profiles is released (`0.1.0a1`, peeled commit
`ed69f9dfdeea493dab7d7ba25c04e940f0870545`) and its platform-plane composition
is PREPARED (`docs/cutover-readiness.md`). It is not composed, and the reason
stated here is a LOCAL one: **this assembly is deferred by ADR-0007 § 6.** That
is a decision this repository holds and can be held to. Whether `dotmac_sub` has
finished adopting is a temporal claim about a repository this one cannot
observe, so it is background rather than the load-bearing reason — as of
`dotmac_starter_mt@20d24703e70e4d361de2f406165df4b36cbee507`,
`packages/dotmac-brand-profiles/EXTRACTION.toml` carried `status =
"audit-complete"` with no contract consumer. There is nothing to retire when the
deferral lifts: no model, service, migration or template in this assembly holds
a brand record, which is measured rather than assumed.

Commercial Agreements and Licensing are composed and authoritative under
ADR-0008/0009, but remain below adopted until they actually run.

## Migrating existing products

ERP and ISP adopt through assemblies, adapters, contract/shadow tests,
expand/contract migrations, reconciliation, and one-writer cutovers — never a
big-bang rewrite, and never by this control plane reaching into their databases.


## Licence delivery targets vs. the Deployment entity (2026-08-02)

`licence_delivery_targets` is a **temporary Vendor delivery projection** of
where a licence may be delivered, written only by
`EntitlementProjectionService.register_delivery_target`. It is deliberately NOT
the authoritative `Deployment` entity. The historical
`docs/design/domain-foundation.md` names `FleetDesiredStateService`; ADR-0007
supersedes that local-owner label with the independent Deployment Control
module, which is released but not yet composed here. Naming the licensing table
`deployments` would have made licensing
the de-facto owner of an entity another service is specified to own — a
source-of-truth violation dressed as a convenience. When the Deployment Control
cutover lands, this projection may only be reconciled from its desired state.
**It is nevertheless a second authority over Deployment Control's subject, and
ADR-0011 treats it as one.** `register_delivery_target` holds the ref, customer,
connection and status, refuses to re-point a target at another customer, and
writes two declared audit codes — the narrower name avoided the wrong OWNER
label, not the ownership. ADR-0011 migrates that write path once
`mod_deploy.deployment_targets` exists, after measuring the estate on a named
target; what survives here may only be reconciled from that owner. ADR-0010 then
retires the projection when delivery execution moves to Integrator; it must not
become a permanent cache or a second destination registry.
