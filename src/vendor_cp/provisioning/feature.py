"""The `provisioning` feature manifest — the provisioning contract laboratory.

Contributes a JSON API (`routers`) only. `core=False`: the lab is a deletable
surface for exercising the provider contract, not part of the minimum viable
control plane.
"""

from __future__ import annotations

from dataclasses import replace

from vendor_cp.provisioning.declaration import declaration
from vendor_cp.provisioning.router import router

feature = replace(declaration, routers=[router])
