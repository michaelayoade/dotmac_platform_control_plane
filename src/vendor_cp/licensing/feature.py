"""Vendor's retained WS8 licence route and delivery surface.

`core=True`: signed delivery is the contracted hand-off from the vendor control
plane to a product data plane, not an optional add-on. Issuer persistence and
lifecycle declarations belong to the separately composed `licensing` module.
"""

from __future__ import annotations

from dataclasses import replace

from vendor_cp.licensing.declaration import declaration
from vendor_cp.licensing.router import router

feature = replace(declaration, routers=[router])
