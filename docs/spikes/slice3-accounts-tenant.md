# Spike: tenant-scoped vendor accounts (slice 3, option C)

**Status:** spike / rejected alternative. Kept on branch
`slice3-accounts-tenant` for comparison against **option A** (platform-level,
merged to `main`). Not intended to merge.

## What this branch does

Models vendor accounts as **tenant-scoped**: every `vendor_accounts` row carries
a `tenant_id` (NOT NULL, FK to `tenants`, RLS in production), `external_ref` is
unique only WITHIN a tenant, and the `AccountService` uses the kernel's
**tenant-scoped** primitives:

- `CommandEnvelope` + `process_once` — idempotency keyed on `(tenant_id,
  command_id)`.
- `write_audit_event` — audit rows scoped to `(tenant_id, actor_party_id)`.
- Routes use tenant auth (`require_user_auth` → `Party`) + tenant context
  (`require_tenant` → `Tenant`) + the tenant/`app_user` session (`get_db`).

The distinguishing behaviour is captured in a test: the same `external_ref` may
exist in two different tenants.

## Why it was NOT chosen

A vendor account has **no natural tenant**. It belongs to the vendor control
plane itself, operated by a platform admin. Forcing a `tenant_id` onto it means
inventing a synthetic "vendor tenant" to own every account — re-introducing
exactly the fabricated-tenant problem the kernel's platform identity model
(ADR-0004 in `dotmac_starter_mt`) was created to avoid. It also:

- makes every query, uniqueness constraint, and RLS policy carry a dimension
  that does not vary in practice (there is only ever the one synthetic tenant);
- routes account management through tenant auth (`require_user_auth`) instead of
  the platform-admin authority that actually governs the control plane;
- couples account lifecycle to a `tenants` row whose deletion would cascade the
  accounts — an accident waiting to happen for platform-owned data.

## Outcome

Option **A** (platform-level, on `main`, ADR-0002) is the design. This spike
exists so the trade-off is on the record and reproducible: compare the diff of
this branch vs `main~1` against the diff of option A vs the same base.
