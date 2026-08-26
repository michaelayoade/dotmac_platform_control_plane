# dotmac_vendor_control_plane

The DotMac **Vendor Control Plane** — a vendor/product/fleet-intent **assembly**
composed from the pinned `dotmac-kernel`. It is **not** a product data plane: it
owns vendor-side accounts, commercial state and provider-neutral deployment
intent — never a product's tenants, subscribers, customer data, credentials or
provider execution.

- **Hard rules:** `AGENTS.md` (canonical). **As-built + boundaries:**
  `docs/ARCHITECTURE.md`. **Decisions:** `docs/adr/`.
- **Kernel:** consumed at the exact version pinned in `pyproject.toml`, resolved
  **only** from the private Forgejo registry (ADR-0005 in `dotmac_starter_mt`).
  The testing extra supports tests only; runtime code never imports it. No
  copied kernel code or private imports (deny-case D5).
- **Release Catalog:** `dotmac-release-catalog==0.1.0a4`, exact-pinned from the
  same registry. The assembly composes its manifest and public Alembic lineage;
  its `mod_rel` platform-catalog tables remain inaccessible to `app_user`.
  Stack 2's origin/admission path deliberately remains unusable until the
  catalogue a5 contract is published and pinned: origin class and upstream
  vulnerability/compatibility results must come from catalogue rows, never a
  Vendor request.
- **Entitlement Allocation:** exact-pinned at the version in `pyproject.toml` and
  authoritative after ADR-0006/v014. Vendor stages and reads allocations only
  through its typed adapter; the legacy tables and writer are retired.
- **Approvals:** exact-pinned at the version in `pyproject.toml` and
  authoritative after ADR-0005/v013. Vendor owns the subject and content hash;
  the module owns approval policy, requests, decisions and evaluation.
- **Product capability evidence:** a product/business-owner catalogue adapter
  injects exact immutable capability contracts, held operation schemas and
  product-owned cross-capability composition snapshots. Vendor may compose
  commercial requirements but cannot mint endpoints, fields, checks, schemas
  or dataflow semantics. A deployment supplies the exact desired APPLY document
  for every selected capability; Vendor validates it against those held schemas
  (including declared formats) and persists it immutably. The deployment also
  selects exact source/target capability instances for applicable owner-authored
  composition rules; selectors and coverage remain owner evidence. Approved
  composition targets remain absent
  until Integrator injects signed public evidence. Artifact origin and every
  admission row are selected independently from Release Catalog evidence.
- **Release-evidence ingestion:** `scripts/catalogue_product_release.py` accepts
  one product build's exact OCI digest, source revision, canonical manifest and
  manifest digest. It holds the document content-addressably and writes through
  Release Catalog's immutable service seam using kernel-owned idempotency.

## Layout

- `src/vendor_cp/assembly.py` — the vendor `ProductAssemblySpec`.
- `src/vendor_cp/main.py` — `app = create_app(build_spec())` (`uvicorn
  vendor_cp.main:app`).
- `src/vendor_cp/console/` — the platform-admin-only administration shell.
- `src/vendor_cp/managed_profiles/` — reusable provider-neutral suite profiles,
  component dependency closure and exact configuration/verification contracts.
- `src/vendor_cp/fleet/` — deployment targets, deployments and content-addressed
  desired-state snapshots. It records intent only and performs no external I/O.
- `src/vendor_cp/planning/` — immutable exact-artifact bundles, deterministic
  plan/command templates, expiring approval bindings and exact signed Integrator
  PLAN/APPLY/OBSERVE/CANCEL command envelopes plus held-key-verified receipt
  evidence. It does not execute them.

The mounted Fleet/Profile/Planning HTTP adapters are platform-admin only.
Account-scoped customer administration and explicit support-consent are a
separate control-plane stack and are not claimed here.
- `src/vendor_cp/providers.py` — legacy provisioning-contract laboratory wiring
  (**simulation only**; never a fleet execution path).
- `src/vendor_cp/provisioning/laboratory.py` — the side-effect-free runtime
  simulation of the kernel's public provisioning contract.
- `docs/design/managed-email-collaboration-ecosystem.md` — end-to-end ownership,
  managed-suite requirements and the five-stack delivery roadmap.
- `tests/architecture/test_deny_cases.py` — the D1–D5 boundary guards.
- `tests/architecture/test_fleet_intent_boundary.py` — transitive proof that
  fleet/profile code and importing entry points cannot perform provider I/O.

## Boundaries (D1–D5)

| # | Deny case |
|---|---|
| D1 | One control-plane database; the kernel owns the engine (no `create_engine`, no product DSNs). |
| D2 | No product data-plane imports (`dotmac_sub`/`crm`/`erp`/`app`). |
| D3 | Vendor owns intent, never execution. External I/O belongs only to Integrator connector plugins; the local provider is a contract simulator and real mode fails startup. |
| D4 | Platform-admin auth **through the kernel** (`require_platform_admin`), never re-implemented. |
| D5 | Only the kernel's **public** surface (`SUPPORTED_MODULES` + top-level `__all__`); no private/internal/copied code. |

## Develop

The kernel resolves from Forgejo, so the installer needs a read credential:

```bash
export POETRY_HTTP_BASIC_FORGEJO_USERNAME=<forgejo-user>
export POETRY_HTTP_BASIC_FORGEJO_PASSWORD=<forgejo-token>   # from OpenBao; never commit
make install    # poetry install
make check      # ruff + mypy + import-linter
make test       # pytest
```

## Production

Production is built once on a GitHub-hosted runner and deployed only by an
immutable GHCR digest. The host does not build the repository, expose
PostgreSQL, or run migrations from the container command. See
[`docs/operations/production-deployment.md`](docs/operations/production-deployment.md)
for the host contract, secret pointers, ordered first deploy, current Sub
release-evidence ingestion, and rollback boundary.

## Managed-services boundary

The assembly owns vendor accounts, immutable product-qualified offers and
contracts, approvals, allocation orchestration, licence issuance/delivery,
managed profiles, deployment targets, deployments and immutable desired-state
snapshots. A managed suite may require Identity, Mailcow email, Nextcloud
collaboration, ERP, Academy LMS and optional Workspace surfaces, but it does not
turn them into one commercial product: each offer, contract and allocation stays
qualified by one product and profile dependency closure composes those facts.

Vendor never contacts a host, identity provider, DNS provider, Mailcow,
Nextcloud, ERP or Academy. The separately deployed Dotmac Integrator selects
versioned connector plugins, materialises named secret references, applies an
exact approved plan and returns receipts and verification evidence. See ADR-0007
and `docs/design/managed-email-collaboration-ecosystem.md`.
