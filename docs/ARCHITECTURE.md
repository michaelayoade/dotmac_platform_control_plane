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
- The kernel is `dotmac-kernel==0.1.0a45` (extras `testing` and `licensing`),
  resolved **only**
  from the private Forgejo registry (ADR-0005 in `dotmac_starter_mt`). It is a
  dependency, never vendored source.
- `dotmac-release-catalog==0.1.0a2` is the permanent owner of immutable release
  artifacts and attestations. The assembly composes its `ModuleManifest` and
  its public `versions_dir()` alongside the kernel and vendor migration
  lineages. Its `mod_rel` tables are platform catalogues: `platform_api` may
  use the published grants and `app_user` is denied.
- `dotmac-entitlement-allocation==0.1.0a3` is installed and its manifest and
  public migration lineage are composed. This is deliberately a **shadow
  installation**, not adoption: `vendor_cp.allocations` remains the sole
  authoritative writer and there is no dual-write. Vendor migration v011 makes
  new immutable offers and contracts product-qualified, binds that identity into
  the contract content hash, and emits it on contract events. Historical rows
  remain explicitly unclassified until an operator supplies evidence; the
  independent module therefore still receives no `ContractSnapshot`.

## Ownership (what this control plane owns)

- **Vendor accounts** (slice 3) — the vendor-owned `AccountService`: typed
  commands + outcomes, atomic transaction ownership, idempotency, audit,
  platform-admin-only adapters.
- **Commercial lifecycle (as-built)** — immutable product-qualified offers,
  versioned approvals, product-qualified contracts, the legacy allocation
  projection, and signed licence issuance and delivery. Offer and contract
  services consume `dotmac-entitlement-allocation`'s product-scoped
  `CapabilityCatalogueReader` port. The current assembly adapter is populated
  from `VENDOR_PRODUCT_MANIFEST_CAPABILITIES_JSON`; this is temporary shadow
  input, not a verified publication contract and not authority for product
  identity. After `dotmac-kernel`'s release-bound product-manifest snapshot and
  `dotmac-release-catalog`'s `product_manifest` attestation kind are published,
  that adapter must verify the canonical snapshot digest associated with the
  exact product artifact and reject the raw JSON configuration. These
  commercial features remain vendor-local owners until each approved
  independent-module cutover explicitly retires its corresponding local writer.
- **Allocation cutover gate** — Entitlement Allocation can become authoritative
  only after one coherent change proves all of the following:

  1. **expand delivered for new writes:** the commercial-contract owner persists,
     hashes, and emits an explicit product identity; historical offers and
     contracts must still be mapped from evidence before the v011 checks can be
     validated;
  2. **typed boundary delivered:** commercial services and the cutover preflight
     consume the allocation module's product-scoped catalogue port rather than
     owning a duplicate protocol. Promotion still needs the temporary configured
     capabilities replaced by release-bound, digest-verified product-manifest
     snapshots;
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
  `dotmac-release-catalog`, not by a vendor-local feature or table. This change
  composes the owner; it does not yet add a publish HTTP adapter or claim a
  production cutover. Product identity and capability declarations originate in
  each product assembly; the release catalogue binds their snapshot attestation
  to exact artifact bytes, while Vendor only consumes that evidence.
- **Provisioning contracts** (slice 4, delivered) — the `provisioning` feature
  (`src/vendor_cp/provisioning/`): a platform-admin-only API that drives the
  kernel's `ProvisioningProvider` contract (plan → apply → observe → cancel)
  against the Vendor-owned `LaboratoryProvisioningProvider`, plus test-only
  conformance via the kernel's `check_provisioning_provider_contract`. A
  **laboratory** — simulation only, no fleet tables, no runner, no real
  infrastructure, no SSH; the only state is the provider's in-memory operation
  ledger. Runtime code never imports `dotmac_kernel.testing`. The real runner +
  activation contracts are a later, design-gated slice.
- **Administration shell** — a platform-admin-only console surface
  (`src/vendor_cp/console/`).

## Boundaries (deny-cases D1–D5)

The control plane is defined as much by what it refuses as what it does. Each is
a build-failing architecture test (`tests/architecture/test_deny_cases.py`):

| # | Boundary | Why |
|---|---|---|
| **D1** | One control-plane database; the kernel owns the engine. No `create_engine`/`sessionmaker`, no product DSNs. | A cache or a product DB must never become a parallel authority; the vendor CP has exactly one datastore. |
| **D2** | No product data-plane imports (`dotmac_sub`/`crm`/`erp`/`app`). | ERP/ISP/CRM remain separate data planes; collaboration is API/webhook only. An ISP operator is a *tenant*, its subscribers are the product's parties — never the vendor CP's. |
| **D3** | Vendor-owned simulation provider only; real config fails startup; no real-provider SDKs or runtime testing-kit imports. | A request-time access check never calls a payment/cloud provider; the runner + activation contracts are a later, design-gated slice. |
| **D4** | Platform-admin auth through the kernel (`require_platform_admin`). | One authority for platform-actor identity; no re-implemented auth to drift. |
| **D5** | Only the kernel's public surface; no private/internal/copied code. | Products compose a pinned kernel and improve it via declared extension points — never fork or copy it. |

## Still design-only (do NOT implement yet)

Fleet desired state, update authority, support access, the full provisioning
runner, and observed fleet health. Independent-module extraction of the
existing approvals, contracts, allocation and licensing implementations follows
their adjudication/cutover dossiers; their existing vendor-local code is not
evidence that those extractions already happened.

## Migrating existing products

ERP and ISP adopt through assemblies, adapters, contract/shadow tests,
expand/contract migrations, reconciliation, and one-writer cutovers — never a
big-bang rewrite, and never by this control plane reaching into their databases.


## Licence delivery targets vs. the Deployment entity (2026-08-02)

`licence_delivery_targets` is a **licensing-owned projection** of where a
licence may be delivered, written only by
`EntitlementProjectionService.register_delivery_target`. It is deliberately NOT
the authoritative `Deployment` entity: `docs/design/domain-foundation.md`
assigns that to `FleetDesiredStateService`, and deployment intent remains
design-only. Naming the licensing table `deployments` would have made licensing
the de-facto owner of an entity another service is specified to own — a
source-of-truth violation dressed as a convenience. When the fleet slice lands,
this projection is rebuilt from it rather than competing with it.
