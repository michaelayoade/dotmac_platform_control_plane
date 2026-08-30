"""The vendor-owned administration portal shell.

A platform-admin-only surface (deny-case D4: auth goes THROUGH the kernel — this
route depends on `dotmac_kernel.platform_auth.require_platform_admin`, it does not
re-implement authentication). This is a slice-2 placeholder shell; the real
fleet/support/lifecycle screens belong to later slices and must never live in a
product data plane.

## The route no longer authors its own prefix

It used to answer on `/admin`, which this module chose for itself. Under the
kernel's facet composition the FACET owns the prefix — `platform_admin` mounts
at `/platform` — and a module that also spells a prefix is declaring a second,
competing opinion about where its pages live. The path here is therefore
relative, and the mount point is the facet's business.
"""

from __future__ import annotations

from dotmac_kernel.platform_auth import require_platform_admin
from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse

router = APIRouter()

_SHELL = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>DotMac Platform Control Plane</title></head>
<body>
  <h1>DotMac Platform Control Plane</h1>
  <p>Administration console shell (platform-admin only).</p>
</body></html>"""


@router.get("/console", response_class=HTMLResponse, name="console_shell")
def console_shell(_admin: object = Depends(require_platform_admin)) -> str:
    """Render the console shell for an authenticated platform admin.

    `require_platform_admin` is UNCHANGED by the contract-v2 conversion. The
    composition mechanism moved; the authorization did not. That separation is
    the point — a migration that quietly altered who may reach this page while
    claiming to change how it is mounted would be the dangerous shape.
    """
    return _SHELL
