"""One browser authentication owner per composed route — proven on the graph.

The defect this file exists to prevent had a valid platform session reach
`/platform/console` and be refused, because the route ran TWO authentication
owners in sequence:

    require_csrf → facet cookie authentication → handler → require_platform_admin

The facet authenticated the browser cookie; the handler then demanded a bearer
`Authorization` header the browser had no reason to send. Either owner alone is
defensible. Together they are a boundary with no single authority, and the
symptom — a 403/401 on a valid session — is the *mild* form. The dangerous form
is the two drifting apart.

**Why none of these assertions read source text.** A regex over `console/web.py`
proves a string is absent from one file. It cannot see a dependency the ROUTER
attached, it cannot see a dependency nested inside another dependency (which is
exactly where the facet's authentication lives), and it would keep passing if
the guard came back through either of those doors. So every assertion here
builds the real application and walks `route.dependant` — see
`route_dependency_graph.py`, and see the sensitivity test at the bottom, which
plants the exact two-owner shape and requires the detector to report it.
"""

from __future__ import annotations

from dotmac_kernel import create_app
from dotmac_kernel.platform_auth import (
    require_platform_admin,
    require_platform_web_auth,
)
from fastapi import Depends, FastAPI
from fastapi.routing import APIRoute
from route_dependency_graph import (
    UNSAFE_METHODS,
    api_routes,
    authentication_owners,
    bearer_authentication_owners,
    browser_authentication_owners,
    carries_csrf,
    composed_browser_routes,
    describe,
    distinct_authentication_owners,
    route_identity,
)

from vendor_cp.assembly import build_spec
from vendor_cp.deployment_profile import FULL, deployment_profile

CONSOLE_OWNER = "console"


def _app() -> FastAPI:
    """The FULL profile, explicitly.

    `console` is a WITHHOLDABLE surface (`deployment_profile.py`), so a test
    that took the ambient profile could pass by composing no console at all.
    """
    return create_app(build_spec(deployment_profile(FULL)))


def _console_routes(app: FastAPI) -> list[APIRoute]:
    return [
        route
        for route in composed_browser_routes(app)
        if route_identity(route)[1] == CONSOLE_OWNER
    ]


def test_the_console_is_composed_at_all() -> None:
    """Non-vacuity. Every assertion below quantifies over the console's routes,
    and a loop over an empty list passes for the wrong reason."""
    assert _console_routes(_app())


def test_the_console_has_exactly_one_browser_authentication_owner() -> None:
    """THE regression test. One owner — not zero, not two."""
    app = _app()
    for route in _console_routes(app):
        owners = browser_authentication_owners(route)
        assert owners == (require_platform_web_auth,), (
            f"{describe(route)} must be authenticated once, by the facet's "
            f"declared browser profile; the graph carries {owners!r}"
        )


def test_no_console_route_also_carries_the_bearer_guard() -> None:
    """The abort condition, stated as its own assertion.

    A change that left `require_platform_admin` on the route and merely made it
    return something friendlier would satisfy a status-code test and fail this
    one. That ordering is deliberate: a 200 obtained by loosening a guard is
    worse than the 403 it replaced.
    """
    app = _app()
    for route in _console_routes(app):
        assert bearer_authentication_owners(route) == (), (
            f"{describe(route)} still carries a bearer authentication owner; "
            "the facet is the sole browser authentication authority"
        )


def test_every_composed_browser_route_has_exactly_one_authentication_owner() -> None:
    """The rule generalised over the whole browser surface, entry routes aside.

    A facet's declared entry routes (the login form and its submission) are
    pre-authentication by construction — they are where a session comes FROM —
    so they must carry zero owners. Everything else answers to exactly one. The
    entry set is read off the registry rather than hardcoded, so a facet that
    later declares another entry route does not need this test edited, and a
    route quietly BECOMING an entry route is visible in the diff that does it.

    Counted as DISTINCT authorities, not as graph nodes. The kernel's own
    platform screens name `require_platform_web_auth` on the handler while the
    facet composes it too; FastAPI's dependency cache resolves that to one
    execution and one verdict, so it is one authority. The console's defect was
    categorically different — two DIFFERENT owners reading two different
    credentials, able to disagree, and they did.
    """
    app = _app()
    registry = app.state.web_surface_registry
    seen_entry = 0
    seen_authenticated = 0
    for route in composed_browser_routes(app):
        facet, owner, surface, local = route_identity(route)
        owners = distinct_authentication_owners(route)
        if registry.is_entry_route(
            facet=facet, owner=owner, surface=surface, route_name=local
        ):
            seen_entry += 1
            assert owners == frozenset(), (
                f"{describe(route)} is a declared entry route and must not "
                f"authenticate; the graph carries {sorted(map(repr, owners))}"
            )
        else:
            seen_authenticated += 1
            assert len(owners) == 1, (
                f"{describe(route)} must answer to exactly one authentication "
                f"authority; the graph carries {sorted(map(repr, owners))}"
            )
    assert seen_entry, "no entry route was examined"
    assert seen_authenticated, "no authenticated browser route was examined"


def test_no_composed_browser_route_authenticates_a_bearer_credential() -> None:
    """API bearer credentials never become browser sessions.

    Stated structurally rather than only behaviourally: the browser plane has no
    dependency that reads an `Authorization` header, so there is no code path
    that could mint a browser session from an API credential.
    """
    app = _app()
    offenders = [
        describe(route)
        for route in composed_browser_routes(app)
        if bearer_authentication_owners(route)
    ]
    assert not offenders, offenders


def test_no_api_route_authenticates_a_browser_cookie() -> None:
    """And the converse: a browser cookie never authenticates the JSON API.

    The JSON routers are mounted by `mount_features`, outside the facet, so they
    reach no cookie dependency at all. This is the assertion that would fail if
    someone "fixed" a browser 401 by teaching an API route to read the session
    cookie.
    """
    app = _app()
    offenders = [
        describe(route)
        for route in api_routes(app)
        if browser_authentication_owners(route)
    ]
    assert not offenders, offenders


def test_every_vendor_api_route_is_guarded_by_the_kernel_bearer_owner() -> None:
    """D4's JSON half, on the graph: the vendor API keeps `require_platform_admin`.

    The repair removed a guard, and a guard removal is exactly the change that
    can go one route too far. This is the counterweight.
    """
    app = _app()
    vendor = [
        route for route in api_routes(app) if route.path.startswith("/platform/vendor/")
    ]
    assert vendor, "no vendor API route was examined"
    for route in vendor:
        assert require_platform_admin in bearer_authentication_owners(
            route
        ), f"{describe(route)} must depend on the kernel's require_platform_admin"


def test_every_unsafe_composed_browser_route_carries_csrf() -> None:
    """CSRF survives the repair, on every unsafe browser route.

    Removing an authentication dependency from a browser handler is precisely
    the kind of edit that can take a transport control with it, so the CSRF
    contract is asserted here rather than assumed from the kernel's runtime.
    """
    app = _app()
    unsafe = [
        route
        for route in composed_browser_routes(app)
        if route.methods & UNSAFE_METHODS
    ]
    assert unsafe, "no unsafe browser route was examined"
    for route in unsafe:
        assert carries_csrf(route), f"{describe(route)} is missing require_csrf"


def test_no_api_route_is_classified_as_a_browser_route_by_csrf() -> None:
    """CSRF applicability is declared, never guessed from a URL prefix.

    The vendor API lives under `/platform/vendor/...` — the same prefix the
    browser facet mounts under — so a prefix-based CSRF rule would wrongly
    protect contract clients that send no cookie and no token.
    """
    app = _app()
    offenders = [describe(route) for route in api_routes(app) if carries_csrf(route)]
    assert not offenders, offenders


# ── SENSITIVITY ──────────────────────────────────────────────────────────────
def test_the_detector_reports_a_planted_second_authentication_owner() -> None:
    """Without this, "exactly one owner" is an assertion over an unproven detector.

    The probe reproduces the original defect's exact shape — a route-level
    browser authentication dependency plus a handler-declared bearer guard —
    across BOTH doors the old signature scan was blind to. If `dependency_calls`
    ever stopped walking route-level dependencies, or stopped recursing, this
    fails and every "exactly one" above stops being meaningful.
    """
    probe = FastAPI()

    @probe.get(
        "/planted",
        name="planted",
        dependencies=[Depends(require_platform_web_auth)],
    )
    def planted(_admin: object = Depends(require_platform_admin)) -> str:
        return "planted"

    route = next(
        r for r in probe.routes if isinstance(r, APIRoute) and r.name == "planted"
    )
    assert browser_authentication_owners(route) == (require_platform_web_auth,)
    assert bearer_authentication_owners(route) == (require_platform_admin,)
    assert len(authentication_owners(route)) == 2


def test_the_detector_reports_an_owner_nested_two_levels_deep() -> None:
    """The facet reaches its authentication through a context dependency, so a
    walker that only looked one level down would report ZERO owners on every
    console route and the suite would pass while the surface was wide open."""
    probe = FastAPI()

    def middle(_admin: object = Depends(require_platform_web_auth)) -> None:
        return None

    def outer(_ctx: None = Depends(middle)) -> None:
        return None

    @probe.get("/nested", name="nested", dependencies=[Depends(outer)])
    def nested() -> str:
        return "nested"

    route = next(
        r for r in probe.routes if isinstance(r, APIRoute) and r.name == "nested"
    )
    assert browser_authentication_owners(route) == (require_platform_web_auth,)
