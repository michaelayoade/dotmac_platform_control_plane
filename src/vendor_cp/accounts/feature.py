"""The `accounts` feature manifest — vendor-account management.

Registered in the vendor `ProductAssemblySpec.modules`. Contributes a JSON API
(`routers`) only — no web surface yet. `core=True`: vendor accounts are
foundational to the control plane, not a deletable shell.
"""

from __future__ import annotations

from dotmac_kernel.features import FeatureManifest

from vendor_cp.accounts.router import router

feature = FeatureManifest(
    name="accounts",
    routers=[router],
    core=True,
    enabled_by_default=True,
    audit_actions=("vendor.account.created",),
)
