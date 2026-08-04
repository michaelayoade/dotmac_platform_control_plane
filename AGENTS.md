# AGENTS.md — hard rules (canonical)

The Vendor Control Plane is an **assembly** over the pinned `dotmac-kernel`. It
owns **vendor/product lifecycle** (accounts, provisioning contracts, later
deployment lifecycle). It is **not** a product data plane and never holds a
product's tenants, subscribers, or customer records.

Each rule names the test/contract that enforces it. If a rule here and a test
disagree, fix the drift.

1. **Kernel is a pinned dependency, consumed public-surface-only.** Import only
   the kernel's public API — `SUPPORTED_MODULES` + top-level `__all__`. No copied
   kernel files, no private/internal names, no import-path shims
   (`tests/architecture/test_deny_cases.py::test_d5_*`, **D5**).
2. **One control-plane database; the kernel owns the engine.** No `create_engine`
   / `sessionmaker` in vendor code, no product database DSNs (**D1**).
3. **No product data-plane imports.** Never import `dotmac_sub`/`crm`/`erp`/`app`
   (**D2**). Cross-system collaboration is via APIs/webhooks only, per the
   Dotmac app-independence standard.
4. **Fake providers only, this phase.** A non-`fake` `VENDOR_PROVIDER_MODE` FAILS
   STARTUP; no real-provider SDKs are imported (**D3**). No fleet tables, no
   `DeploymentRunner` yet.
5. **Platform-admin auth through the kernel.** Vendor admin surfaces depend on
   `dotmac_kernel.platform_auth.require_platform_admin`; auth is never
   re-implemented (**D4**).
6. **Vendor logic lives in services; routes/web are thin adapters.** Business
   decisions have one named owner; adapters validate-authorise-delegate.
7. **Atomic, idempotent, audited mutations.** Account/lifecycle commands are
   typed, own their transaction, are idempotent, and write audit — reusing the
   kernel's transaction authority (`get_db`/`conflict_savepoint`) and audit
   write-side.
8. **Branch before committing; merge only on green.** Protected `main`. Pin the
   kernel exactly (`==0.1.0a9`); bump deliberately when a new alpha ships.
9. **Cross-repository engineering governance is pinned and required.**
   `.dotmac/standards-profile.json` names the enrolled authority and fully typed
   contract surface, and pins the accepted Governance source by exact commit.
   The `Dotmac engineering standards` CI job must execute that same immutable
   revision. Mutable tags/branches, copied rules, candidate mode, or a missing
   required check are not substitutes.

## Validation before any commit

```
make check   # ruff (lint+format) + mypy --strict
make test    # pytest: boot, provisioning contract, D1–D5 deny cases
```

The kernel resolves from the private Forgejo registry — set
`POETRY_HTTP_BASIC_FORGEJO_USERNAME` / `_PASSWORD` from OpenBao (never commit a
token). See `docs/ARCHITECTURE.md` for the boundary rationale and
`docs/adr/0001-vendor-control-plane-foundation.md` for the founding decision.
