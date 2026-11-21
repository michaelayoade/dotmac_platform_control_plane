"""The `offers` feature manifest — immutable priced offer versions.

JSON API only (`routers`). `core=True`: offer versions are foundational to the
commercial domain (the Commercial Agreements adapter pins them).
"""

from __future__ import annotations

from dataclasses import replace

from vendor_cp.offers.declaration import declaration
from vendor_cp.offers.router import router

feature = replace(declaration, routers=[router])
