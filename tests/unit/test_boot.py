"""The vendor assembly boots through the kernel and serves the expected surface.

Uses the kernel's SUPPORTED testing kit (`dotmac_kernel.testing`) — proving the
assembly composes and runs against the published contract, not a copied harness.
"""

from __future__ import annotations

from dotmac_kernel import create_app
from dotmac_kernel.testing import (
    assembly_test_client,
    create_test_engine,
    isolated_session,
)

from vendor_cp.assembly import build_spec


def test_vendor_assembly_boots_and_serves_health() -> None:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as session:
            app = create_app(build_spec())
            with assembly_test_client(app, session=session) as client:
                resp = client.get("/health")
                assert resp.status_code == 200
                assert resp.json() == {"status": "ok"}
    finally:
        engine.dispose()


def test_platform_auth_surface_is_mounted() -> None:
    """Platform-admin auth comes from the kernel (a `/platform/auth/*` route)."""
    app = create_app(build_spec())
    paths = {getattr(r, "path", "") for r in app.routes}
    assert any(p.startswith("/platform/auth") for p in paths), paths


def test_console_is_mounted_under_the_platform_facet() -> None:
    """The console shell now answers under the facet's `/platform` prefix.

    `/admin` was a coordinate this module chose for itself; under facet
    composition the facet owns the prefix. The assertion is on the FACET prefix
    rather than the exact string the module used to author, so a module that
    starts spelling its own prefix again fails here.
    """
    app = create_app(build_spec())
    paths = {getattr(r, "path", "") for r in app.routes}
    console = {p for p in paths if p.endswith("/console")}
    assert console, paths
    assert all(p.startswith("/platform") for p in console), console


def test_the_retired_admin_coordinate_is_gone() -> None:
    """`/admin` is RETIRED, not redirected.

    The inventory was small enough to retire outright: one test, no nginx
    location (the vhost proxies `/` wholesale), no deploy script and no
    external consumer. The alternative — widening the platform cookie path to
    keep `/admin` reachable — would have traded a routing convenience for a
    real authentication-scope change, which is not a trade worth making for a
    coordinate nothing depends on.
    """
    app = create_app(build_spec())
    paths = {getattr(r, "path", "") for r in app.routes}
    assert "/admin" not in paths, paths
