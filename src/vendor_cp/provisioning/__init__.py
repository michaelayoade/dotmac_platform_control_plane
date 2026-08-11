"""Provisioning contract laboratory (slice 4).

A platform-admin-only surface for exercising the kernel's `ProvisioningProvider`
contract (plan → apply → observe → cancel) against the Vendor-owned laboratory
simulation. It is a LABORATORY, not a fleet driver: simulation only (deny-case
D3), no fleet tables, no `DeploymentRunner`, no persistence beyond the
provider's in-memory operation state. The provisioning runner + activation
contracts are a later, design-gated slice (see `docs/ARCHITECTURE.md`).
"""
