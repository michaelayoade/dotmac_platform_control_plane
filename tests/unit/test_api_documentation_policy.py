"""The API documentation of a control plane is not public by default.

`dotmac_kernel.create_app` builds `FastAPI(title=..., lifespan=...)` and passes
none of the four documentation-suppression arguments, so `/docs`,
`/docs/oauth2-redirect`, `/redoc` and `/openapi.json` exist unless an assembly
takes them away. The vhost proxies `/` wholesale, so on the production host that
default was the whole endpoint inventory, every request/response schema and every
enum vocabulary, readable without a credential.

The test that matters here is
`test_a_planted_default_fastapi_configuration_fails_the_production_gate`. Every
other assertion checks that today's assembly is correct; that one checks that an
assembly which simply FORGETS the policy is caught, which is the only way this
stays true after the next composition change. It is planted twice — on a bare
`FastAPI()` and on this assembly's own `create_app(build_spec())` — because a
gate proven only against a toy has not been proven against the product.
"""

from __future__ import annotations

import pytest
from dotmac_kernel import create_app, settings
from dotmac_kernel.deps import get_platform_db
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from vendor_cp.api_documentation import (
    BEARER_PLANE_GUARD,
    COOKIE_PLANE_GUARDS,
    DEVELOPMENT,
    OPENAPI_PATH,
    PRODUCTION,
    REDOC_PATH,
    SWAGGER_OAUTH2_REDIRECT_PATH,
    SWAGGER_PATH,
    TEST,
    ApiDocumentationPolicy,
    ApiDocumentationPolicyError,
    ApiDocumentationPolicyViolation,
    DocumentationExposure,
    DocumentationPlane,
    api_documentation_policy,
    apply_api_documentation_policy,
    audit_api_documentation,
    classify_environment,
    documentation_routes,
    install_api_documentation_policy,
)
from vendor_cp.assembly import build_spec

#: The three paths named in the defect, plus the Swagger OAuth2 redirect FastAPI
#: mounts alongside `/docs` — omitting it would leave a documentation route the
#: policy never considered.
DOCUMENTATION_PATHS = (
    SWAGGER_PATH,
    SWAGGER_OAUTH2_REDIRECT_PATH,
    REDOC_PATH,
    OPENAPI_PATH,
)


def _production_app() -> FastAPI:
    return install_api_documentation_policy(
        create_app(build_spec()), environment=PRODUCTION
    )


def _development_app() -> FastAPI:
    return install_api_documentation_policy(
        create_app(build_spec()), environment=DEVELOPMENT
    )


# ── the production route set ─────────────────────────────────────────────────
def test_the_production_route_set_excludes_or_protects_all_three_paths() -> None:
    app = _production_app()
    served = {route.path: route for route in documentation_routes(app)}

    assert SWAGGER_PATH not in served, served
    assert SWAGGER_OAUTH2_REDIRECT_PATH not in served, served
    assert REDOC_PATH not in served, served

    # The document plane is PROTECTED rather than absent: an API client holding a
    # platform-admin bearer token is the audience an OpenAPI document has.
    assert OPENAPI_PATH in served, served
    assert BEARER_PLANE_GUARD in served[OPENAPI_PATH].guards


def test_the_production_openapi_document_refuses_an_unauthenticated_reader() -> None:
    """The live answer, not just the inventory.

    Driven against a bare `FastAPI()` carrying FastAPI's defaults and then
    policed, rather than against `create_app(build_spec())`: the composed
    application's `TenantResolverMiddleware` resolves a tenant from the request
    host through the real engine on every non-health path, which a SQLite unit
    lane has no way to answer. The route set of the composed assembly is asserted
    above; what is proven here is what the policed routes actually DO.

    `require_platform_admin` checks the host BEFORE it checks the credential, so
    there are two refusals to see: 404 off the platform root (the surface does
    not exist there) and 401 on it without a bearer token.
    """
    app = FastAPI()
    apply_api_documentation_policy(app, api_documentation_policy(PRODUCTION))
    app.dependency_overrides[get_platform_db] = lambda: None

    with TestClient(app) as elsewhere:
        for path in (SWAGGER_PATH, SWAGGER_OAUTH2_REDIRECT_PATH, REDOC_PATH):
            assert elsewhere.get(path).status_code == 404, path
        off_host = elsewhere.get(OPENAPI_PATH)
        assert off_host.status_code == 404, off_host.text

    platform_root = f"http://{settings.platform_root_domain}"
    with TestClient(app, base_url=platform_root) as client:
        for path in (SWAGGER_PATH, SWAGGER_OAUTH2_REDIRECT_PATH, REDOC_PATH):
            assert client.get(path).status_code == 404, path

        anonymous = client.get(OPENAPI_PATH)
        assert anonymous.status_code == 401, anonymous.text
        assert '"paths"' not in anonymous.text

        # The credential is at least CONSULTED rather than the header ignored:
        # an unparseable token still fails, but through the credential path.
        bearer = client.get(
            OPENAPI_PATH, headers={"Authorization": "Bearer not-a-real-token"}
        )
        assert bearer.status_code == 401, bearer.text
        assert '"paths"' not in bearer.text


# ── the development route set ────────────────────────────────────────────────
def test_development_retains_the_expected_documentation() -> None:
    app = _development_app()
    served = {route.path for route in documentation_routes(app)}
    assert served == set(DOCUMENTATION_PATHS), served
    assert all(not route.guards for route in documentation_routes(app))


def test_applying_the_development_policy_leaves_the_documentation_serving() -> None:
    """Applying a PUBLIC policy must not disturb the routes it publishes."""
    app = FastAPI()
    apply_api_documentation_policy(app, api_documentation_policy(DEVELOPMENT))

    with TestClient(app) as client:
        schema = client.get(OPENAPI_PATH)
        assert schema.status_code == 200
        assert "paths" in schema.json()
        assert client.get(SWAGGER_PATH).status_code == 200
        assert client.get(REDOC_PATH).status_code == 200


# ── the sensitivity proof ────────────────────────────────────────────────────
def test_a_planted_default_fastapi_configuration_fails_the_production_gate() -> None:
    """A future assembly that forgets the policy must fail LOUDLY.

    FastAPI enables documentation by default, so "did nothing" and "decided to
    publish" are the same bytes. The gate has to be able to tell them apart by
    reading the route inventory, which is why it does.
    """
    planted = FastAPI()
    production = api_documentation_policy(PRODUCTION)

    violations = audit_api_documentation(planted, production)
    assert violations, "a default FastAPI app must not satisfy the production gate"
    assert any(SWAGGER_PATH in violation for violation in violations), violations
    assert any(REDOC_PATH in violation for violation in violations), violations
    assert any(OPENAPI_PATH in violation for violation in violations), violations


def test_the_planted_default_fails_on_this_assembly_too() -> None:
    """The same plant, on the real product rather than a bare `FastAPI()`.

    `create_app(build_spec())` is what `vendor_cp.main` starts from. Auditing it
    BEFORE the policy is applied is the exact state the production host was in.
    """
    unpoliced = create_app(build_spec())
    violations = audit_api_documentation(
        unpoliced, api_documentation_policy(PRODUCTION)
    )
    assert violations, "the composed assembly inherits FastAPI's public docs"
    assert {route.path for route in documentation_routes(unpoliced)} == set(
        DOCUMENTATION_PATHS
    )


def test_the_gate_is_not_vacuous_for_the_development_policy_either() -> None:
    """The mirror case: an app with no documentation fails the DEVELOPMENT gate.

    Without this, a gate that only ever complains about routes being PRESENT
    would pass on an application that serves nothing at all — which would make
    the development assertion above prove nothing about the gate.
    """
    stripped = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    violations = audit_api_documentation(
        stripped, api_documentation_policy(DEVELOPMENT)
    )
    assert violations, violations
    assert all("no route is mounted" in violation for violation in violations)


def test_applying_a_policy_it_cannot_satisfy_raises_rather_than_returning() -> None:
    """Apply is apply-then-audit, in one fail-closed step.

    Removing routes is something this module can do; CREATING a documentation
    surface an app was built without is not, so the development policy over a
    stripped app must raise rather than hand back an application that quietly
    disagrees with its own declaration.
    """
    stripped = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    with pytest.raises(ApiDocumentationPolicyViolation, match="no route is mounted"):
        apply_api_documentation_policy(stripped, api_documentation_policy(DEVELOPMENT))

    planted = FastAPI()
    production = api_documentation_policy(PRODUCTION)
    assert audit_api_documentation(planted, production)
    apply_api_documentation_policy(planted, production)
    assert not audit_api_documentation(planted, production)


def test_applying_the_production_policy_twice_is_idempotent() -> None:
    app = _production_app()
    before = documentation_routes(app)
    apply_api_documentation_policy(app, api_documentation_policy(PRODUCTION))
    assert documentation_routes(app) == before


# ── the cookie/bearer plane rule ─────────────────────────────────────────────
def test_the_openapi_document_is_never_reachable_through_a_browser_cookie() -> None:
    """Mixing the planes is refused by the gate, not merely avoided by taste.

    A cookie-guarded `/openapi.json` is reachable by any page a logged-in
    operator's browser is induced to load. The document authenticates by bearer
    token or it is not served.
    """
    app = _production_app()
    for route in documentation_routes(app):
        assert not set(route.guards) & COOKIE_PLANE_GUARDS, route

    planted = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    def require_platform_web_auth() -> None:  # the kernel's cookie guard, by name
        return None

    @planted.get(OPENAPI_PATH, dependencies=[Depends(require_platform_web_auth)])
    def _cookie_guarded_schema() -> dict[str, str]:
        return {}

    violations = audit_api_documentation(planted, api_documentation_policy(PRODUCTION))
    assert any("cookie plane" in violation for violation in violations), violations


def test_interactive_documentation_may_not_be_declared_bearer_protected() -> None:
    """A browser page cannot carry an `Authorization` header to itself.

    Declaring one bearer-protected is how a cookie fallback gets added later, so
    the policy type refuses to express it at all.
    """
    with pytest.raises(ApiDocumentationPolicyError, match="Authorization header"):
        ApiDocumentationPolicy(
            environment=PRODUCTION,
            interactive=DocumentationExposure.PLATFORM_BEARER,
            document=DocumentationExposure.PLATFORM_BEARER,
            rationale="x",
        )


# ── the declared policies themselves ─────────────────────────────────────────
def test_production_may_not_declare_public_documentation() -> None:
    with pytest.raises(ApiDocumentationPolicyError, match="may not publish"):
        ApiDocumentationPolicy(
            environment=PRODUCTION,
            interactive=DocumentationExposure.DISABLED,
            document=DocumentationExposure.PUBLIC,
            rationale="x",
        )


def test_a_policy_needs_a_rationale() -> None:
    with pytest.raises(ApiDocumentationPolicyError, match="rationale"):
        ApiDocumentationPolicy(
            environment=DEVELOPMENT,
            interactive=DocumentationExposure.PUBLIC,
            document=DocumentationExposure.PUBLIC,
            rationale="   ",
        )


def test_public_interactive_documentation_needs_its_document() -> None:
    with pytest.raises(ApiDocumentationPolicyError, match="cannot load its own"):
        ApiDocumentationPolicy(
            environment=DEVELOPMENT,
            interactive=DocumentationExposure.PUBLIC,
            document=DocumentationExposure.DISABLED,
            rationale="x",
        )


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # Publishing is opt-in BY NAME. An unset or blank ENVIRONMENT is not a
        # development host, it is a host nobody declared.
        (None, PRODUCTION),
        ("", PRODUCTION),
        ("   ", PRODUCTION),
        ("dev", DEVELOPMENT),
        ("  Development ", DEVELOPMENT),
        ("test", TEST),
        ("ci", TEST),
        ("production", PRODUCTION),
        ("prod", PRODUCTION),
        # Fail closed. None of these is a declared publishing environment, and a
        # deployment that mistypes ENVIRONMENT must not publish its API.
        ("staging", PRODUCTION),
        ("prodction", PRODUCTION),
        ("productionn", PRODUCTION),
    ],
)
def test_environment_classification_fails_closed(
    raw: str | None, expected: str
) -> None:
    assert classify_environment(raw) == expected


def test_the_strict_reading_of_environment_diverges_only_towards_withholding() -> None:
    """The rest of the assembly reads an unset `ENVIRONMENT` as development.

    `assembly.build_spec()` passes `os.getenv("ENVIRONMENT", "development")` and
    the kernel's `Settings.environment` defaults to `"dev"`. This module refuses
    that default. The divergence is only safe in one direction, so assert the
    direction rather than the mere fact: every value the looser reading would
    call non-production and this one calls production must end up with LESS
    exposure, never more.
    """
    for raw in (None, "", "staging", "prodction"):
        policy = api_documentation_policy(classify_environment(raw))
        assert policy.environment == PRODUCTION
        assert policy.interactive is DocumentationExposure.DISABLED
        assert policy.document is not DocumentationExposure.PUBLIC


def test_every_declared_environment_has_a_policy() -> None:
    for environment in (DEVELOPMENT, TEST, PRODUCTION):
        policy = api_documentation_policy(environment)
        assert policy.environment == environment
        assert policy.rationale.strip()
        for plane in DocumentationPlane:
            assert isinstance(policy.exposure(plane), DocumentationExposure)
