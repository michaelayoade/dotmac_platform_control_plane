"""The vendor-owned administration portal shell.

A platform-admin-only surface (deny-case D4: auth goes THROUGH the kernel — this
route depends on `dotmac_kernel.platform_auth.require_platform_admin`, it does not
re-implement authentication). This is a slice-2 placeholder shell; the real
fleet/support/lifecycle screens belong to later slices and must never live in a
product data plane.
"""

from __future__ import annotations

from dotmac_kernel.platform_auth import require_platform_admin
from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse

router = APIRouter()

_SHELL = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>DotMac Vendor Control Plane</title></head>
<body>
  <h1>DotMac Vendor Control Plane</h1>
  <p>Administration console shell (platform-admin only).</p>
</body></html>"""


@router.get("/admin", response_class=HTMLResponse)
def console_shell(_admin: object = Depends(require_platform_admin)) -> str:
    """Render the console shell for an authenticated platform admin."""
    return _SHELL
