"""Architecture guards for the target API router (DESIGN-rev3 section 2.6).

The router is the ONE entrance for target principals. These tests pin its shape
on the CONSTRUCTED route table and on the source, so that a later change cannot
add a route that skips the authentication, define its own message bytes, or let a
bearer token or session cookie authenticate a target call.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.routing import APIRoute
from route_dependency_graph import (
    AUTHENTICATION_OWNERS,
    authentication_owners,
    dependency_calls,
)

from vendor_cp.deployment.target_api import contract as c
from vendor_cp.deployment.target_api.router import build_router

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "src" / "vendor_cp" / "deployment" / "target_api"


def _routes() -> list[APIRoute]:
    app = FastAPI()
    app.include_router(build_router(lambda: (_ for _ in ()).throw(RuntimeError())))
    return [r for r in app.routes if isinstance(r, APIRoute)]


def test_the_target_router_is_one_catch_all_so_no_route_can_skip_authentication() -> (
    None
):
    routes = _routes()
    assert [r.path for r in routes] == [f"{c.BASE_PATH}/{{rest:path}}"]
    (route,) = routes
    assert route.methods == {"GET", "POST", "PUT", "PATCH", "DELETE"}
    # Authentication happens inside the one handler, through the authenticator.
    # No kernel bearer or session owner is on the graph: a target call is
    # authenticated by its signature and by nothing else.
    assert authentication_owners(route) == ()
    assert not [c_ for c_ in dependency_calls(route) if c_ in AUTHENTICATION_OWNERS]


def test_the_authenticator_calls_the_contract_check_and_never_builds_a_message() -> (
    None
):
    """The lint Control ships for a consumer's router (`audit_router_source`)."""
    source = (PACKAGE / "auth.py").read_text(encoding="utf-8")
    assert c.audit_router_source(source) == []


def test_no_module_but_the_mirror_defines_a_signed_message_or_a_header_name() -> None:
    literals = {c.REQUEST_PURPOSE, c.RESPONSE_PURPOSE, "x-dotmac-"}
    for path in sorted(PACKAGE.glob("*.py")):
        if path.name in {"contract.py", "response_signing.py"}:
            continue
        text = path.read_text(encoding="utf-8").lower()
        for literal in literals:
            assert literal.lower() not in text, (path.name, literal)


def test_the_target_api_has_no_database_dsn_engine_or_foundation_import() -> None:
    for path in sorted(PACKAGE.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        for forbidden in (
            "create_engine",
            "sessionmaker",
            "dotmac_deployment_foundation",
        ):
            assert forbidden not in text, (path.name, forbidden)
        # `client.py` NAMES the database settings (it is the tripwire that refuses
        # them); no other module may mention one.
        if path.name != "client.py":
            assert "DATABASE_URL" not in text, path.name


def test_lane_5b_does_not_compose_the_router_into_any_profile() -> None:
    """Mounting is lane 5a's (the M4 profile); until then nothing is reachable."""
    assembly = (ROOT / "src" / "vendor_cp" / "assembly.py").read_text(encoding="utf-8")
    # only the route-less declarations (`target_api.feature`) are composed
    assert "target_api.router" not in assembly
    assert "target_api.runtime" not in assembly
    from vendor_cp.deployment.target_api.feature import feature

    assert not feature.routers
    assert not feature.web_routers


def _control_pin() -> int:
    import re

    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(
        r'^dotmac-deployment-control\s*=\s*\{\s*version\s*=\s*"0\.1\.0a(\d+)"',
        pyproject,
        re.MULTILINE,
    )
    assert match, "the Control pin is no longer an exact 0.1.0aN pin"
    return int(match.group(1))


def test_the_contract_mirror_lives_exactly_while_control_is_pinned_below_a18() -> None:
    """Two-way ratchet (review ruling 6).

    `target_api/contract.py` mirrors `dotmac_deployment_control.target_api`, which
    ships with a18. While a17 is pinned the mirror must exist (nothing else
    defines the bytes); once a18 or later is pinned it must be GONE, so two
    definitions of the wire can never coexist.
    """
    mirror = PACKAGE / "contract.py"
    if _control_pin() >= 18:
        assert not mirror.exists(), (
            "Control a18+ is pinned: delete target_api/contract.py and import "
            "dotmac_deployment_control.target_api"
        )
    else:
        assert mirror.exists(), "the mirror is gone while Control a17 is pinned"


def test_the_response_key_has_two_named_settings_and_is_never_logged() -> None:
    from vendor_cp.deployment.target_api.response_signing import (
        RESPONSE_KEY_FILE_ENV,
        RESPONSE_KEY_ID_ENV,
        Ed25519ResponseSigner,
    )

    for path in sorted(PACKAGE.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        assert "print(" not in text and "logging" not in text, path.name
        if path.name != "response_signing.py":
            assert "os.environ" not in text.replace("os.environ if", ""), path.name
            assert RESPONSE_KEY_FILE_ENV not in text, path.name
            assert "VENDOR_TARGET_API_RESPONSE_KEY" not in text, path.name
    assert {RESPONSE_KEY_FILE_ENV, RESPONSE_KEY_ID_ENV} == {
        "VENDOR_TARGET_API_RESPONSE_KEY_FILE",
        "VENDOR_TARGET_API_RESPONSE_KEY_ID",
    }
    seed = bytes(range(64, 96))
    signer = Ed25519ResponseSigner(seed, key_id="k")
    assert seed.hex() not in repr(signer) and seed.hex() not in str(vars(signer))
