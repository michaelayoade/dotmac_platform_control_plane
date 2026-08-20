# dotmac_vendor_control_plane

The DotMac **Vendor Control Plane** — a vendor/product-lifecycle **assembly**
composed from the pinned `dotmac-kernel`. It is **not** a product data plane: it
owns vendor-side accounts, provisioning contracts, and (later) deployment
lifecycle — never a product's tenants, subscribers, or customer data.

- **Hard rules:** `AGENTS.md` (canonical). **As-built + boundaries:**
  `docs/ARCHITECTURE.md`. **Decisions:** `docs/adr/`.
- **Kernel:** consumed at the exact version pinned in `pyproject.toml`, resolved
  **only** from the private Forgejo registry (ADR-0005 in `dotmac_starter_mt`).
  The testing extra supports tests only; runtime code never imports it. No
  copied kernel code or private imports (deny-case D5).
- **Release Catalog:** `dotmac-release-catalog==0.1.0a4`, exact-pinned from the
  same registry. The assembly composes its manifest and public Alembic lineage;
  its `mod_rel` platform-catalog tables remain inaccessible to `app_user`.
- **Entitlement Allocation:** `dotmac-entitlement-allocation==0.1.0a4`, also
  exact-pinned and composed through its public manifest and Alembic locator.
  It is the allocation authority under ADR-0006; the retired Vendor-local
  writer and tables are absent.
- **Approvals:** `dotmac-approvals==0.1.0a4`, platform-plane only and the
  authority under ADR-0005. Vendor retains the typed route/identity adapter,
  not a second policy engine.
- **Commercial Agreements:** `dotmac-commercial-agreements==0.1.0a1`,
  platform-only and the agreement authority under ADR-0008. Vendor retains one
  typed offer/catalogue/approval-evidence adapter; the local lifecycle writer
  and tables are absent.
- **Product capability evidence:** Vendor config pins exact product OCI and
  manifest digests; the adapter verifies their Release Catalog association and
  derives capabilities only from held kernel-canonical document bytes.
- **Release-evidence ingestion:** `scripts/catalogue_product_release.py` accepts
  one product build's exact OCI digest, source revision, canonical manifest and
  manifest digest. It holds the document content-addressably and writes through
  Release Catalog's immutable service seam using kernel-owned idempotency.

## Layout

- `src/vendor_cp/assembly.py` — the vendor `ProductAssemblySpec`.
- `src/vendor_cp/main.py` — `app = create_app(build_spec())` (`uvicorn
  vendor_cp.main:app`).
- `src/vendor_cp/console/` — the platform-admin-only administration shell.
- `src/vendor_cp/providers.py` — provisioning provider wiring (**Vendor-owned
  simulation only** this phase; a real provider fails startup).
- `src/vendor_cp/provisioning/laboratory.py` — the side-effect-free runtime
  simulation of the kernel's public provisioning contract.
- `tests/architecture/test_deny_cases.py` — the D1–D5 boundary guards.

## Boundaries (D1–D5)

| # | Deny case |
|---|---|
| D1 | One control-plane database; the kernel owns the engine (no `create_engine`, no product DSNs). |
| D2 | No product data-plane imports (`dotmac_sub`/`crm`/`erp`/`app`). |
| D3 | Vendor-owned simulation provider only; real config **fails startup**; no real-provider SDKs or runtime testing-kit imports. |
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

## Scope this phase

The assembly owns vendor accounts, immutable offers, licence issuance/delivery,
and the provisioning laboratory. It composes Release Catalog, Entitlement
Allocation, Approvals and Commercial Agreements as their authoritative owners.
ADR-0007 keeps this repository and database while Licensing, Deployment Control
and Brand Profiles replace the remaining local owners one contracted slice at a
time. External connector execution remains in Dotmac Integrator.
