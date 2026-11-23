"""Vendor's HTTP surface over the Commercial Agreements module authority."""

from __future__ import annotations

from dataclasses import replace

from vendor_cp.contracts.declaration import declaration
from vendor_cp.contracts.router import router

feature = replace(declaration, routers=[router])
