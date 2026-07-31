"""Vendor accounts (slice 3, option A — PLATFORM-level).

A vendor account is a platform-level resource with NO tenant context: it belongs
to the vendor control plane itself, operated by a platform admin, not to any one
product tenant. So it uses the kernel's PLATFORM-scoped primitives
(`process_once_platform`, `write_platform_audit_event`) rather than the
tenant-scoped ones. See `docs/adr/0002-vendor-accounts-platform-scoped.md`.
"""
