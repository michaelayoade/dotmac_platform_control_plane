"""The `accounts` feature manifest — vendor-account management.

Registered in the vendor `ProductAssemblySpec.modules`. Contributes a JSON API
(`routers`) only — no web surface yet. `core=True`: vendor accounts are
foundational to the control plane, not a deletable shell.
"""

from __future__ import annotations

from dataclasses import replace

from vendor_cp.accounts.declaration import declaration
from vendor_cp.accounts.router import router

feature = replace(declaration, routers=[router])
