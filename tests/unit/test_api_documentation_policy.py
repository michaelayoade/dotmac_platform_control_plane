"""The assembly declares the kernel-owned API-documentation policy."""

from __future__ import annotations

from dataclasses import replace

import pytest
from dotmac_kernel import create_app, settings
from dotmac_kernel.api_documentation import (
    BEARER_PLANE_GUARD,
    OPENAPI_PATH,
    PRODUCTION,
    REDOC_PATH,
    SWAGGER_OAUTH2_REDIRECT_PATH,
    SWAGGER_PATH,
    DocumentationExposure,
    documentation_arguments,
    documentation_routes,
    environment_api_documentation_policy,
    mount_bearer_protected_document,
)
from dotmac_kernel.deps import get_platform_db
from fastapi import FastAPI
from fastapi.testclient import TestClient

from vendor_cp.assembly import build_spec


def test_build_spec_declares_the_kernel_owned_policy() -> None:
    spec = build_spec()

    assert spec.api_documentation is not None
    assert spec.api_documentation.environment == PRODUCTION
    assert spec.api_documentation.interactive is DocumentationExposure.DISABLED
    assert spec.api_documentation.document is DocumentationExposure.PLATFORM_BEARER


def test_kernel_policy_fails_closed_when_environment_is_not_declared() -> None:
    policy = environment_api_documentation_policy("staging")

    assert policy.environment == PRODUCTION
    assert policy.interactive is DocumentationExposure.DISABLED


def test_composed_production_app_has_only_a_bearer_guarded_openapi_route() -> None:
    app = create_app(build_spec())
    served = {route.path: route for route in documentation_routes(app)}

    assert SWAGGER_PATH not in served
    assert SWAGGER_OAUTH2_REDIRECT_PATH not in served
    assert REDOC_PATH not in served
    assert OPENAPI_PATH in served
    assert BEARER_PLANE_GUARD in served[OPENAPI_PATH].guards


def test_openapi_route_is_host_and_bearer_protected() -> None:
    """The policy's bearer route rejects off-host and malformed credentials.

    A bare FastAPI app isolates the route from this product's tenant resolver;
    the preceding test proves the composed application has this exact route.
    """

    policy = environment_api_documentation_policy("production")
    app = FastAPI(**documentation_arguments(policy))
    mount_bearer_protected_document(app)
    app.dependency_overrides[get_platform_db] = lambda: None

    with TestClient(app) as client:
        off_platform = client.get(OPENAPI_PATH)

    assert off_platform.status_code == 404
    assert '"paths"' not in off_platform.text

    with TestClient(app, base_url=f"http://{settings.platform_root_domain}") as client:
        malformed_bearer = client.get(
            OPENAPI_PATH, headers={"Authorization": "Bearer not-a-real-token"}
        )

    assert malformed_bearer.status_code == 401
    assert '"paths"' not in malformed_bearer.text


def test_create_app_refuses_a_product_spec_without_a_documentation_policy() -> None:
    missing_policy = replace(build_spec(), api_documentation=None)

    with pytest.raises(RuntimeError, match="declares no api_documentation policy"):
        create_app(missing_policy)
