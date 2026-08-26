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
   binds every required kernel effect — database roles and the tenant catalogue
   from kernel `0001`, the outbox relay from `0012`, and the idempotency ledger
   from `0018`. The tenant catalogue remains bound because kernel `0001` really
   does create `public.tenants` here. A
   `ModulePlaneSelection` says what this product installs, and it selects
   `PLATFORM` alone for `approvals` — never as a side effect of a version bump,
   and only behind the cutover contract that authorised it. Never reintroduce
   the a60
   model in which an absent binding selected a plane, and never create a tenants
   table, a sentinel tenant, or a nullable tenant column to satisfy a module
   (ADR-0028; `tests/architecture/test_migration_prerequisite_bindings.py`,
   `tests/migration/test_selected_planes.py`).
10. **Coverage is catalogue-derived; exceptions are named and ratcheted.** Two
    halves, and the distinction between them is the rule. WHICH tables get
    audited is never a literal list: module schemas go through the kernel's
    `audit_live_schemas`, `public` is classified from the live catalogue, and
    the vendor-owned subset is derived by diffing the lineages — so a table
    added tomorrow is covered the moment its migration runs. WHAT an exceptional
    category contains IS named exactly — `TENANT_CATALOGUE`,
    `UNMONITORED_SPLIT_SCOPE` — and every such set is
    ratcheted in both directions, so it cannot grow quietly or shrink without
    the declaration being lowered in the same change. A privilege proof over a
    hand-listed set of TABLES is the regression; a hand-listed set of
    EXCEPTIONS, each justified and dated, is the contract
    (`tests/migration/test_composed_live_catalog.py`,
    `tests/architecture/test_shadow_overlaps.py`).
11. **A deployment profile selects surfaces and nothing else.** Read it once, in
    `build_spec()`. It may not withhold a persistence owner and may not change
    behaviour; feature code never branches on a profile name (ADR-0003, deny
    case D6; `tests/architecture/test_deployment_profile.py`).
12. **An authority cutover is contracted before it is composed, and its premise
    is checked.** ADR-0005 records the Approvals switch: the estate was MEASURED
    (`TARGET_ABSENT`), not assumed, and `v013` re-checks emptiness under
    `ACCESS EXCLUSIVE` in the same transaction that drops the legacy tables,
    failing closed if a row exists. `dotmac-approvals` is the authority;
    `vendor_cp.approvals.adapter` is the ONLY seam and is typed with no `Any`.
    The retired local writer's call sites are ratcheted at ZERO. Do not build
    parity, backfill, synthesized requests or sealed evidence against an empty
    estate — ADR-0031 governs a cutover WITH data, and this was not one. Composed
    and authoritative in code is NOT adopted
    (`tests/architecture/test_approvals_authority.py`,
    `tests/migration/test_authority_switch.py`).
13. **A guard exemption dies with its premise.** The assembly-local waiver for
    the legacy allocation tables shadowing `mod_ealloc` was REMOVED when `v014`
    dropped those tables, not lowered and not left describing nothing: an
    exemption whose premise has evaporated keeps widening a gate for facts nobody
    has examined (ADR-0018). The composed live-catalogue audit now consumes the
    kernel gate raw, with no subtraction at all. When you retire an exemption,
    delete its prose in the same change — `test_stale_claims.py` fails if a
    document still describes a retired exemption as live.
14. **Cross-repository engineering governance is pinned and required.**
    `.dotmac/standards-profile.json` names the enrolled authority and fully typed
    contract surface, and pins the accepted Governance source by exact commit.
    The `Dotmac engineering standards` CI job must execute that same immutable
    revision. Mutable tags/branches, copied rules, candidate mode, or a missing
    required check are not substitutes. The schema-9 external-connector ratchet
    is Governance-owned and transitional: this assembly records its measured
    baseline in `docs/external-connector-surface.md`, but never copies the
    detector or treats the ratchet as runtime isolation.

## Validation before any commit

```
make check   # ruff (lint+format) + mypy --strict
make test    # pytest: boot, provisioning contract, D1–D5 deny cases
```

The kernel resolves from the private Forgejo registry — set
`POETRY_HTTP_BASIC_FORGEJO_USERNAME` / `_PASSWORD` from OpenBao (never commit a
token). See `docs/ARCHITECTURE.md` for the boundary rationale and
`docs/adr/0001-vendor-control-plane-foundation.md` for the founding decision.
