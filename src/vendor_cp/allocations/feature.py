"""The `allocations` feature manifest — staged allocation projection (read API).

The staging itself is event-driven (`ContractEventConsumer`), not route-driven; the
router is read-only. `core=True`: allocation is the projection the WS8 signed
delivery will later consume.
"""

from __future__ import annotations

from dataclasses import replace

from vendor_cp.allocations.declaration import declaration
from vendor_cp.allocations.router import router

feature = replace(declaration, routers=[router])
