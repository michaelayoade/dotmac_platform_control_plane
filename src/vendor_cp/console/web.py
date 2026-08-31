"""The vendor-owned administration portal shell.

A platform-admin-only surface (deny-case D4: auth goes THROUGH the kernel —
this module re-implements no authentication and, since the browser-auth repair
below, declares none either). This is a slice-2 placeholder shell; the real
fleet/support/lifecycle screens belong to later slices and must never live in a
product data plane.

## The route no longer authors its own prefix

It used to answer on `/admin`, which this module chose for itself. Under the
kernel's facet composition the FACET owns the prefix — `platform_admin` mounts
at `/platform` — and a module that also spells a prefix is declaring a second,
competing opinion about where its pages live. The path here is therefore
relative, and the mount point is the facet's business.

## The route no longer authors its own authentication either

The same sentence is true of the guard, and for a while it was not. This
handler carried `Depends(require_platform_admin)` — the kernel's BEARER guard,
correct for the JSON API and wrong here — while the composed `platform_admin`
facet was already authenticating the request through its declared
`kernel_platform_session` profile, whose provider is
`require_platform_web_auth` (the platform session COOKIE). Two authentication
owners on one route, in this order:

    require_csrf → facet cookie authentication → handler → require_platform_admin

A browser holding a valid platform session therefore passed the facet and then
failed the handler for want of an `Authorization` header: `/platform/console`
was unreachable with exactly the credential it is meant to accept.

The repair is to DELETE the second owner, not to widen it. Nothing here now
depends on any authentication dependency; the facet is the sole browser
authentication authority for this surface, and the two credential populations
stay apart — a cookie never reaches the JSON API's `require_platform_admin`,
and a bearer token never becomes a browser session. Weakening the handler guard
until it accepted a cookie would have produced the same 200 while leaving two
authorities to drift, which is the worse shape and is why the composed
dependency graph — not this docstring, and not a grep — is what the tests
assert against.

**When a screen needs the administrator object.** Do not add a guard back to
get at it. `require_platform_web_auth` already resolved a `PlatformAdmin` for
this request; the answer is a kernel-supported request-scoped principal
projection to read it from, and re-authenticating inside a route would restore
the defect under a different name.
"""

from __future__ import annotations

from fastapi import APIRouter
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
def console_shell() -> str:
    """Render the console shell for an authenticated platform admin.

    Takes no authentication dependency BY DESIGN. The `platform_admin` facet
    this surface contributes to authenticates every non-entry route it mounts
    through its declared authentication profile, so a request that reaches this
    function has already been proven to hold a live platform session. Declaring
    a guard here as well would not be defence in depth — it would be a second
    authentication authority, which is precisely the defect this shape fixes.
    """
    return _SHELL
