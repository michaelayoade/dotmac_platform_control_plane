"""Walk the CONSTRUCTED FastAPI dependency graph of a composed application.

Every authentication guard in this repository used to be checked by reading
`inspect.signature(endpoint)` — which sees only what a handler spells in its own
parameter list. That is the wrong instrument twice over.

It is blind UPWARD: a route-level dependency (`include_router(...,
dependencies=[...])`), which is how the kernel's browser-surface runtime
attaches CSRF and the facet's authentication, appears in no endpoint signature
at all. So a surface could be authenticated, or not authenticated, and a
signature scan would report the same thing either way.

It is blind DOWNWARD: a dependency's own dependencies are invisible to it. The
platform facet reaches its authentication two levels down — a composed context
dependency that itself `Depends(require_platform_web_auth)` — and a scan of the
handler's parameters cannot see it.

A regex over the source has both blindnesses plus a third: it proves a string is
absent from one file, never that a callable is absent from the graph FastAPI
will actually execute. So these helpers walk `route.dependant`, the tree
FastAPI itself solves per request, and report the callables it will invoke.

`tests/architecture/test_browser_authentication_ownership.py` carries the
sensitivity proof: a probe route declaring two authentication owners must be
REPORTED as two, or "exactly one owner" is an assertion over a detector that
sees nothing.
"""

from __future__ import annotations

from collections.abc import Iterator

from dotmac_kernel.middleware.csrf import require_csrf
from dotmac_kernel.platform_auth import (
    require_platform_admin,
    require_platform_web_auth,
)
from dotmac_kernel.web_deps import require_web_auth, require_web_party
from fastapi import FastAPI
from fastapi.routing import APIRoute

#: Every callable in the pinned kernel that turns a CREDENTIAL into a principal,
#: with the transport it reads. Named exhaustively rather than matched by a
#: `require_*` prefix: `require_platform_host` and `require_tenant` also start
#: that way and decide no identity, so a prefix match would count them and make
#: "exactly one authentication owner" mean nothing.
AUTHENTICATION_OWNERS: dict[object, str] = {
    require_platform_web_auth: "browser",
    require_web_party: "browser",
    require_web_auth: "browser",
    require_platform_admin: "bearer",
}

BROWSER_AUTHENTICATION_OWNERS = frozenset(
    call for call, transport in AUTHENTICATION_OWNERS.items() if transport == "browser"
)
BEARER_AUTHENTICATION_OWNERS = frozenset(
    call for call, transport in AUTHENTICATION_OWNERS.items() if transport == "bearer"
)

#: Composed browser routes are named `web:<facet>:<owner>:<surface>:<local>` by
#: `dotmac_kernel.web_surfaces.qualified_route_name`. The prefix is the kernel's
#: own contract for "this route was mounted through a web facet".
COMPOSED_ROUTE_PREFIX = "web:"

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def api_routes(app: FastAPI) -> Iterator[APIRoute]:
    """Every mounted route that is NOT a composed browser route."""

    for route in app.routes:
        if isinstance(route, APIRoute) and not route.name.startswith(
            COMPOSED_ROUTE_PREFIX
        ):
            yield route


def composed_browser_routes(app: FastAPI) -> Iterator[APIRoute]:
    """Every route the kernel mounted through a web facet."""

    for route in app.routes:
        if isinstance(route, APIRoute) and route.name.startswith(COMPOSED_ROUTE_PREFIX):
            yield route


def route_identity(route: APIRoute) -> tuple[str, str, str, str]:
    """(facet, owner, surface, local name) for a composed browser route."""

    prefix, facet, owner, surface, local = route.name.split(":", 4)
    if prefix != COMPOSED_ROUTE_PREFIX.rstrip(":"):
        raise ValueError(f"{route.name!r} is not a composed browser route")
    return facet, owner, surface, local


def dependency_calls(route: APIRoute) -> tuple[object, ...]:
    """Every callable FastAPI will invoke for `route`, sub-dependencies first.

    This is the whole point of the module: it reads `route.dependant`, the tree
    FastAPI builds at include time and solves on every request, so a dependency
    attached by the router — or nested inside another dependency — is counted
    exactly like one the handler spelled itself. The endpoint is included, as
    the last entry, because it is a node of that same tree.
    """

    found: list[object] = []

    def walk(dependant: object) -> None:
        for child in getattr(dependant, "dependencies", ()):
            walk(child)
        call = getattr(dependant, "call", None)
        if call is not None:
            found.append(call)

    walk(route.dependant)
    return tuple(found)


def authentication_owners(route: APIRoute) -> tuple[object, ...]:
    """Occurrences — not distinct members — of an authentication owner.

    Occurrences, because the defect being guarded against is TWO owners on one
    route, and a set would happily report a route carrying the same owner twice
    as carrying one.
    """

    return tuple(
        call for call in dependency_calls(route) if call in AUTHENTICATION_OWNERS
    )


def distinct_authentication_owners(route: APIRoute) -> frozenset[object]:
    """How many AUTHORITIES decide identity for this route.

    The distinction from `authentication_owners` is the whole subtlety. One
    owner reached twice — the kernel's own platform screens declare
    `require_platform_web_auth` on the handler while the facet also composes it,
    and FastAPI's dependency cache runs it once — is one authority with one
    decision. TWO DIFFERENT owners is the defect: two decisions, in sequence,
    that can disagree and did.
    """

    return frozenset(authentication_owners(route))


def browser_authentication_owners(route: APIRoute) -> tuple[object, ...]:
    return tuple(
        call
        for call in dependency_calls(route)
        if call in BROWSER_AUTHENTICATION_OWNERS
    )


def bearer_authentication_owners(route: APIRoute) -> tuple[object, ...]:
    return tuple(
        call for call in dependency_calls(route) if call in BEARER_AUTHENTICATION_OWNERS
    )


def carries_csrf(route: APIRoute) -> bool:
    return require_csrf in dependency_calls(route)


def describe(route: APIRoute) -> str:
    """A failure message a reader can act on without re-deriving the route."""

    methods = ",".join(sorted(route.methods or ()))
    return f"{methods} {route.path} ({route.name})"


__all__ = [
    "AUTHENTICATION_OWNERS",
    "BEARER_AUTHENTICATION_OWNERS",
    "BROWSER_AUTHENTICATION_OWNERS",
    "COMPOSED_ROUTE_PREFIX",
    "UNSAFE_METHODS",
    "api_routes",
    "authentication_owners",
    "bearer_authentication_owners",
    "browser_authentication_owners",
    "carries_csrf",
    "composed_browser_routes",
    "dependency_calls",
    "describe",
    "distinct_authentication_owners",
    "route_identity",
]
