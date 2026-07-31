"""Vendor accounts (slice 3, option C — TENANT-scoped SPIKE).

⚠️ This is the *rejected-alternative* spike kept for comparison against option A
(platform-level, on `main`). Here a vendor account is modelled as a
**tenant-scoped** row (RLS, `tenant_id` on every row) and the service uses the
kernel's TENANT-scoped primitives (`CommandEnvelope` + `process_once` +
`write_audit_event`). See `docs/spikes/slice3-accounts-tenant.md` for why this
forces a fabricated "vendor tenant" and was not chosen.
"""
