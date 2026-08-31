"""The `console` module manifest — the vendor admin shell, on contract v2.

Declares a typed `WebSurfaceContribution` against the kernel's existing
`platform_admin` facet. Carries no JSON `routers` yet. `core=False` — a
deletable surface, not part of the control plane's minimum viable core.

## Why this is not a legacy `web_routers` manifest any more

Kernel a98 refuses to compose an assembly whose modules contribute legacy
`web_routers` unless a `staff_admin` facet is declared carrying BOTH an
authentication profile and an `admission_permission`, because the compatibility
adapter will not infer an authorization policy.

That permission cannot exist here, and not for want of choosing one. Admission
is evaluated with `authorize_party(db, tenant, party, code)`, which needs a
tenant-scoped Party; the same kernel therefore REFUSES an `admission_permission`
on any facet whose profile enters the platform plane, where the principal is a
`PlatformAdmin` and no Party exists. A legacy staff surface in a
platform-plane assembly is required to declare something it is simultaneously
forbidden to declare.

The way through is not a permission. It is to stop being a legacy surface: a
contract-v2 contribution targets `platform_admin`, whose profile
(`kernel_platform_session`) is the platform-admin identity boundary the console
already used. Manufacturing a tenant and a Party to satisfy the type would have
produced a sentinel tenant — the exact shape the dual-plane rule refuses, and
the same one already declined when scoping the provisioning laboratory.

**The audience is unchanged, and the facet now owns the guard.** The
contribution targets the platform-admin identity boundary the console always
sat behind; what moved is that the FACET authenticates the request, through the
`kernel_platform_session` profile whose provider is the kernel's
`require_platform_web_auth`. The routes stopped declaring
`require_platform_admin` — the kernel's BEARER guard — because carrying it as
well made a valid browser session fail the handler after passing the facet, and
because two authentication owners on one route is a boundary with no single
authority. The JSON API keeps `require_platform_admin`; the browser surface
keeps the cookie; neither credential population reaches the other.
"""

from __future__ import annotations

from dotmac_kernel import (
    LocalizedText,
    ModuleManifest,
    WebNavItem,
    WebSurfaceContribution,
)

from vendor_cp.console.web import router

CONSOLE_SURFACE = WebSurfaceContribution(
    code="console",
    # The kernel's own platform facet. It owns the `/platform` prefix, the
    # shell template and the session policy; this module supplies routes and
    # navigation and authors none of those things.
    facet="platform_admin",
    routers=(router,),
    navigation=(
        WebNavItem(
            code="console.shell",
            region="primary",
            label=LocalizedText("console.shell", "Vendor Console"),
            route_name="console_shell",
            order=10,
        ),
    ),
    supported_ui_contract_versions=frozenset({1}),
)

feature = ModuleManifest(
    code="console",
    version="0.1.0",
    contract_version=2,
    web_surfaces=(CONSOLE_SURFACE,),
    core=False,
    enabled_by_default=True,
)
