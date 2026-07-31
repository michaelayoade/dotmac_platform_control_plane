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
- The kernel is `dotmac-kernel==0.1.0a1` (extras `testing`), resolved **only**
  from the private Forgejo registry (ADR-0005 in `dotmac_starter_mt`). It is a
  dependency, never vendored source.

## Ownership (what this control plane owns)

- **Vendor accounts** (slice 3) — the vendor-owned `AccountService`: typed
  commands + outcomes, atomic transaction ownership, idempotency, audit,
  platform-admin-only adapters.
- **Provisioning contracts** (slice 4, delivered) — the `provisioning` feature
  (`src/vendor_cp/provisioning/`): a platform-admin-only API that drives the
  kernel's `ProvisioningProvider` contract (plan → apply → observe → cancel)
  against the FAKE provider, plus conformance via the kernel's
  `check_provisioning_provider_contract`. A **laboratory** — fakes only, no fleet
  tables, no runner, no real infrastructure, no SSH; the only state is the fake's
  in-memory operation ledger. The real runner + activation contracts are a later,
  design-gated slice.
- **Administration shell** — a platform-admin-only console surface
  (`src/vendor_cp/console/`).

## Boundaries (deny-cases D1–D5)

The control plane is defined as much by what it refuses as what it does. Each is
a build-failing architecture test (`tests/architecture/test_deny_cases.py`):

| # | Boundary | Why |
|---|---|---|
| **D1** | One control-plane database; the kernel owns the engine. No `create_engine`/`sessionmaker`, no product DSNs. | A cache or a product DB must never become a parallel authority; the vendor CP has exactly one datastore. |
| **D2** | No product data-plane imports (`dotmac_sub`/`crm`/`erp`/`app`). | ERP/ISP/CRM remain separate data planes; collaboration is API/webhook only. An ISP operator is a *tenant*, its subscribers are the product's parties — never the vendor CP's. |
| **D3** | Fake providers only; real config fails startup; no real-provider SDKs. | A request-time access check never calls a payment/cloud provider; the runner + activation contracts are a later, design-gated slice. |
| **D4** | Platform-admin auth through the kernel (`require_platform_admin`). | One authority for platform-actor identity; no re-implemented auth to drift. |
| **D5** | Only the kernel's public surface; no private/internal/copied code. | Products compose a pinned kernel and improve it via declared extension points — never fork or copy it. |

## Still design-only (do NOT implement yet)

Commercial contracts (blocked on money/FX + outbox/inbox), deployment intent
(outbox + deployment profiles), allocation (capability catalogue + outbox),
plan/approval (profiles + allocation + outbox), the full provisioning runner
(preceding workflows + activation contracts), observed health (health/heartbeat
contract + outbox). Each unblocks only when its kernel primitive lands.

## Migrating existing products

ERP and ISP adopt through assemblies, adapters, contract/shadow tests,
expand/contract migrations, reconciliation, and one-writer cutovers — never a
big-bang rewrite, and never by this control plane reaching into their databases.
