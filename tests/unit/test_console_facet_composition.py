"""The console's contract-v2 composition, and the permission that cannot exist.

Kernel a98 refuses a legacy `web_routers` contribution unless a `staff_admin`
facet declares BOTH an authentication profile and an `admission_permission` —
and refuses an `admission_permission` on any facet whose profile enters the
platform plane, because admission is evaluated with
`authorize_party(db, tenant, party, code)` and a platform profile resolves a
`PlatformAdmin`, never a tenant-scoped Party.

For a platform-plane assembly those two rules are jointly unsatisfiable. The
resolution is not to find the right permission; it is that no such permission
can exist, so the console stops being a legacy surface.

The last test here is the one that matters. "We declared no admission
permission" is otherwise an absence nobody has tested — it would keep passing
if a later kernel quietly started accepting one, and it would keep passing if
the refusal were removed altogether.
"""

from __future__ import annotations

import pytest
from dotmac_kernel import (
    AuthenticationProfileBinding,
    BrowserSecurityPlane,
    TemplateRef,
    WebFacetMount,
    create_app,
)
from dotmac_kernel.web_surfaces import WebSurfaceError, WebSurfaceRegistry

from vendor_cp.assembly import build_spec
from vendor_cp.console.feature import CONSOLE_SURFACE, feature as console_manifest


def test_the_console_contributes_a_v2_surface_not_legacy_routers() -> None:
    """Contract 2, `web_surfaces`, and no legacy fields at all."""
    assert console_manifest.contract_version == 2
    assert console_manifest.web_surfaces == (CONSOLE_SURFACE,)
    assert not console_manifest.web_routers
    assert not console_manifest.nav


def test_the_surface_targets_the_kernel_platform_facet() -> None:
    """It joins the EXISTING platform facet rather than declaring a new one.

    The facet owns the prefix, the shell and the session policy. A module that
    declared its own would be inventing a second audience boundary next to the
    platform-admin one it already sits behind.
    """
    assert CONSOLE_SURFACE.facet == "platform_admin"


def test_the_surface_declares_no_admission_permission_anywhere() -> None:
    """The contribution carries no admission permission, by construction.

    `WebSurfaceContribution` has no such field — admission belongs to the
    facet — so this asserts the shape rather than a value: nothing the module
    declares can carry one.
    """
    assert not hasattr(CONSOLE_SURFACE, "admission_permission")


def test_the_assembly_boots_and_the_console_is_reachable_by_path() -> None:
    """Startup on a98 with the console composed under the facet prefix."""
    app = create_app(build_spec())
    paths = {getattr(route, "path", "") for route in app.routes}
    console = {path for path in paths if path.endswith("/console")}
    assert console, paths
    assert all(path.startswith("/platform") for path in console), console


def test_a_planted_platform_admission_permission_is_REFUSED() -> None:
    """SENSITIVITY. Without this, "we declared none" is an untested absence.

    Plant exactly what the console is forbidden to declare — an
    `admission_permission` on a facet whose profile enters the PLATFORM plane —
    and require the kernel to refuse it. If a future kernel starts accepting
    this, or drops the check, this test fails and the reasoning in
    `console/feature.py` stops being true silently.
    """
    profile = AuthenticationProfileBinding(
        code="planted_platform_profile",
        security_plane=BrowserSecurityPlane.PLATFORM,
    )
    facet = WebFacetMount(
        code="planted_admin",
        url_prefix="/planted",
        shell=TemplateRef("layouts/platform.html"),  # nosec B604 - Jinja ref
        authentication_profile=profile.code,
        admission_permission="planted.admission",
    )
    with pytest.raises(WebSurfaceError, match="plane"):
        WebSurfaceRegistry(
            manifests=(),
            facets=(facet,),
            authentication_profiles=(profile,),
        )
