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
4. **Vendor-owned simulation provider only, this phase.** A non-`fake`
   `VENDOR_PROVIDER_MODE` FAILS STARTUP; no real-provider SDKs are imported
   (**D3**). Runtime code implements the side-effect-free laboratory provider
   locally and never imports `dotmac_kernel.testing`; the kernel test kit is
   test-only. No fleet tables, no `DeploymentRunner` yet.
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
   kernel to an EXACT version (`==`, never a range or caret); bump deliberately
   when a new alpha ships. **`pyproject.toml` is the authority for which
   version that is** — this file deliberately does not repeat the number. A
   second copy of a version literal is a second thing to forget, which is
   exactly how this line came to say `a8` while the pin said `a9`.
9. **Bindings state facts; plane selections state intent.** A
   `PrerequisiteBinding` says where an effect comes from, and this assembly
   binds BOTH kernel effects — including `tenant_scope_catalog.v1`, because
   kernel `0001` really does create `public.tenants` here. A
   `ModulePlaneSelection` says what this product installs, and it is EMPTY
   until a selectable module is composed — which happens only behind a cutover
   contract, never as a side effect of a version bump. Never reintroduce the a60
   model in which an absent binding selected a plane, and never create a tenants
   table, a sentinel tenant, or a nullable tenant column to satisfy a module
   (ADR-0028; `tests/architecture/test_migration_prerequisite_bindings.py`,
   `tests/migration/test_selected_planes.py`).
10. **Every composed table is audited, none by name.** The module schemas go
    through the kernel's `audit_live_schemas`; `public` is classified from the
    live catalogue, and the vendor-owned subset is derived by diffing the
    lineages. A privilege proof that names tables in a literal list is a
    regression — it only ever covers what someone remembered
    (`tests/migration/test_composed_live_catalog.py`).
11. **A deployment profile selects surfaces and nothing else.** Read it once, in
    `build_spec()`. It may not withhold a persistence owner and may not change
    behaviour; feature code never branches on a profile name (ADR-0003, deny
    case D6; `tests/architecture/test_deployment_profile.py`).
12. **Cross-repository engineering governance is pinned and required.**
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
