"""Provisioning contract laboratory (slice 4).

A platform-admin-only surface for exercising the kernel's `ProvisioningProvider`
contract (plan → apply → observe → cancel) against the FAKE provider. It is a
LABORATORY, not a fleet driver: fakes only (deny-case D3), no fleet tables, no
`DeploymentRunner`, no persistence beyond the fake's own in-memory operation
state. The provisioning runner + activation contracts are a later, design-gated
slice (see `docs/ARCHITECTURE.md`).
"""
