# ADR-0001: Vendor Control Plane foundation

- **Status:** Accepted (2026-07-30).
- **Context:** Ruling C5 (recorded in `dotmac_starter_mt`) placed the vendor
  fleet/support/lifecycle workflows in a **separate repository** consuming the
  kernel, not inside the reference assembly or any product data plane. The kernel
  alpha `dotmac-kernel==0.1.0a1` (with `ProductAssemblySpec`, `create_app`, the
  `ProvisioningProvider` contract, and the `testing` kit) is published to the
  private Forgejo registry, which unblocks this repository.

## Decision

Create `dotmac_vendor_control_plane` as an assembly over the pinned kernel, with
these founding constraints (the D1–D5 deny-cases):

1. **Pinned, public-surface-only kernel dependency** (`==0.1.0a1`, extras
   `testing`), from Forgejo only. No copied kernel code, no private imports.
2. **One control-plane database**, engine owned by the kernel. No product DSNs,
   no cross-database access.
3. **Fake providers only** this phase; a real-provider mode fails startup. This
   is a provisioning-contract **laboratory**, not a fleet driver — no fleet
   tables, no `DeploymentRunner`.
4. **Platform-admin auth through the kernel.**
5. Move the authoritative vendor domain design into this repository; leave a
   versioned pointer in `dotmac_starter_mt`.

## Scope delivered

- **Slice 1 (foundation):** repo, pinned kernel, AGENTS/ARCHITECTURE/ADR, CI,
  protected main, D1–D5 deny-case tests.
- **Slice 2 (assembly):** the vendor `ProductAssemblySpec` booting via
  `create_app`, the platform-admin console shell, and the kernel empty-consumer +
  testing-kit contracts running green.

## Not in scope (later slices / design-only)

Accounts (slice 3) and the provisioning laboratory (slice 4) build on this.
Commercial contracts, deployment intent, allocation, plan/approval, the full
provisioning runner, and observed health remain design-only until their kernel
primitives (outbox/inbox, money/FX, capability catalogue, deployment profiles)
land. See `docs/ARCHITECTURE.md`.

## Consequences

The vendor CP evolves independently of product data planes and of the kernel's
release cadence (it pins an exact kernel and bumps deliberately). Its boundaries
are enforced by tests, not convention, so drift fails the build.

## Implementation clarification — 2026-08-11

"Fake providers only" describes the admitted runtime effect: the laboratory may
simulate the public provisioning contract and may not reach real
infrastructure. It does not make the kernel's test fake a runtime provider.
`LaboratoryProvisioningProvider` is the Vendor-owned, side-effect-free runtime
implementation; `dotmac_kernel.testing` is consumed only by tests that run the
kernel's conformance suite. This preserves D3 while keeping test-only session
factories, fake signing helpers, and provider fakes out of shipped execution
paths.
