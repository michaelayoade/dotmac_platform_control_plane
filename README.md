# dotmac_vendor_control_plane

The DotMac **Vendor Control Plane** — a vendor/product-lifecycle **assembly**
composed from the pinned `dotmac-kernel`. It is **not** a product data plane: it
owns vendor-side accounts, provisioning contracts, and (later) deployment
lifecycle — never a product's tenants, subscribers, or customer data.

- **Hard rules:** `AGENTS.md` (canonical). **As-built + boundaries:**
  `docs/ARCHITECTURE.md`. **Decisions:** `docs/adr/`.
- **Kernel:** consumed as `dotmac-kernel==0.1.0a1` (extras `testing`) resolved
  **only** from the private Forgejo registry (ADR-0005 in `dotmac_starter_mt`).
  No copied kernel code, no private imports (deny-case D5).

## Layout

- `src/vendor_cp/assembly.py` — the vendor `ProductAssemblySpec`.
- `src/vendor_cp/main.py` — `app = create_app(build_spec())` (`uvicorn
  vendor_cp.main:app`).
- `src/vendor_cp/console/` — the platform-admin-only administration shell.
- `src/vendor_cp/providers.py` — provisioning provider wiring (**fake only** this
  phase; a real provider fails startup).
- `tests/architecture/test_deny_cases.py` — the D1–D5 boundary guards.

## Boundaries (D1–D5)

| # | Deny case |
|---|---|
| D1 | One control-plane database; the kernel owns the engine (no `create_engine`, no product DSNs). |
| D2 | No product data-plane imports (`dotmac_sub`/`crm`/`erp`/`app`). |
| D3 | Fake providers only; a real-provider config **fails startup**; no real-provider SDKs. |
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

## Scope this phase

Slices **1 (foundation)** and **2 (assembly that boots via `create_app`)** are in
place. **Accounts** (slice 3) and the **provisioning laboratory** (slice 4) build
on this. Commercial contracts, deployment intent, allocation, plan/approval, the
full provisioning runner, and observed health remain **design-only** until their
blocking primitives (outbox, money/FX, capability catalogue, deployment profiles)
land in the kernel.
