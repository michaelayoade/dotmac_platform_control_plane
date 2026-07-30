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


def test_console_admin_route_is_mounted() -> None:
    """The vendor console shell is mounted at /admin. That it is platform-admin
    guarded (kernel auth, deny-case D4) is proven statically in
    `test_deny_cases.py`; a live unauthenticated request is an integration
    concern (the kernel tenant-resolver middleware needs a real DB for a
    tenant-scoped route), out of scope for this unit boot check."""
    app = create_app(build_spec())
    assert "/admin" in {getattr(r, "path", "") for r in app.routes}
