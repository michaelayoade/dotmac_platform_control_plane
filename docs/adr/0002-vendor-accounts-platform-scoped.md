# ADR-0002: Vendor accounts are platform-scoped (option A)

- **Status:** Accepted (2026-07-31).
- **Context:** Slice 3 introduces vendor accounts. Two models were spiked
  (rulings "a" and "c" of the slice-3 exploration): **(A)** platform-level
  accounts owned by the control plane itself, and **(C)** tenant-scoped accounts
  living under RLS. This ADR records the chosen model; option C is kept on a
  parallel spike branch (`slice3-accounts-tenant`) for comparison only.

## Decision

Vendor accounts are **platform-level**: no `tenant_id`, no RLS. A vendor account
belongs to the vendor control plane and is operated by a **platform admin**, not
by any product tenant — the control plane is not a tenant of itself. Accordingly
the `AccountService` builds on the kernel's **PLATFORM-scoped** primitives
(`dotmac-kernel==0.1.0a2`):

- **Idempotency** — `dotmac_kernel.messaging.process_once_platform`, keyed on
  `command_id` alone (globally unique; there is no tenant to scope by). A retried
  create replays the recorded result instead of creating a second account.
- **Audit** — `dotmac_kernel.write_platform_audit_event`, recording the action
  against the acting `PlatformAdmin` in the platform audit trail.
- **Auth** — every route depends on `require_platform_admin` (deny-case D4).
- **Persistence** — `vendor_accounts` follows the kernel platform-catalog
  pattern (`PlatformAdmin`, `platform_audit_events`): a plain table with no
  tenant column and no RLS. In production a vendor-lineage migration GRANTs it to
  `platform_api`/`app_admin` and REVOKEs `app_user`.

The service is the single owner of account state transitions; routes are thin
platform-admin-only adapters that build a typed command and delegate. It honours
the kernel transaction-authority contract: it RECEIVES a `Session` (via
`get_platform_db`) and only `add`/`flush` — it never commits.

## Why not tenant-scoped (option C)

Tenant-scoping (C) would force a synthetic "vendor tenant" to hang accounts off,
re-introducing exactly the fabricated-tenant problem the kernel's platform
identity model (ADR-0004 in `dotmac_starter_mt`) was created to avoid, and it
would make every account query carry a tenant filter for a dimension that does
not exist here. C remains a documented spike for the record, not the design.

## Consequences

- Vendor accounts get the same exactly-once + audited guarantees the tenant
  surface has, without inventing a tenant.
- The kernel's platform-scoped primitives (added in `0.1.0a2`, option b) get
  their first real consumer, validating that surface.
- A vendor-lineage Alembic migration for `vendor_accounts` (with the platform
  grants) is a follow-up; unit tests build the schema via the kernel testing
  kit's `create_all`.
