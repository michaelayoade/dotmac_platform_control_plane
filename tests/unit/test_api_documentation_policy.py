"""ADR-0016 is composed through the kernel's declared construction seam.

The policy implementation is tested by ``dotmac-kernel``. This assembly owns
the narrower integration question: does its real ``ProductAssemblySpec`` bind
the policy, does the resulting live route inventory match it, and does removing
that one binding fail closed?
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from dotmac_kernel import create_app
from dotmac_kernel.api_documentation import (
    BEARER_PLANE_GUARD,
    COOKIE_PLANE_GUARDS,
    DEVELOPMENT,
    OPENAPI_PATH,
    PRODUCTION,
    REDOC_PATH,
    SWAGGER_OAUTH2_REDIRECT_PATH,
    SWAGGER_PATH,
    TEST,
    DocumentationExposure,
    api_documentation_policy,
    audit_api_documentation,
    classify_environment,
    documentation_arguments,
    documentation_routes,
)
from fastapi import FastAPI

from vendor_cp.assembly import build_spec
from vendor_cp.deployment_profile import is_production_environment

PUBLISHING_SPELLINGS = frozenset(
    {"dev", "development", "local", "test", "testing", "ci"}
)

DOCUMENTATION_PATHS = (
    SWAGGER_PATH,
    SWAGGER_OAUTH2_REDIRECT_PATH,
    REDOC_PATH,
    OPENAPI_PATH,
)


def _app_for(environment: str) -> FastAPI:
    """Build the real assembly with one explicit documentation policy."""

    return create_app(
        replace(
            build_spec(),
            api_documentation=api_documentation_policy(environment),
        )
    )


def test_build_spec_binds_the_kernel_policy_from_the_raw_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The supported kernel surface is the real assembly input, not a plant."""

    monkeypatch.setenv("ENVIRONMENT", DEVELOPMENT)
    assert build_spec().api_documentation == api_documentation_policy(DEVELOPMENT)

    monkeypatch.delenv("ENVIRONMENT", raising=False)
    assert build_spec().api_documentation == api_documentation_policy(PRODUCTION)


def test_the_production_route_set_excludes_browser_docs_and_protects_openapi() -> (
    None
):
    app = _app_for(PRODUCTION)
    served = {route.path: route for route in documentation_routes(app)}

    assert SWAGGER_PATH not in served, served
    assert SWAGGER_OAUTH2_REDIRECT_PATH not in served, served
    assert REDOC_PATH not in served, served
    assert OPENAPI_PATH in served, served
    assert BEARER_PLANE_GUARD in served[OPENAPI_PATH].guards
    assert not set(served[OPENAPI_PATH].guards) & COOKIE_PLANE_GUARDS
    assert audit_api_documentation(app, api_documentation_policy(PRODUCTION)) == ()


def test_development_retains_the_expected_documentation() -> None:
    app = _app_for(DEVELOPMENT)
    served = {route.path for route in documentation_routes(app)}
    assert served == set(DOCUMENTATION_PATHS), served
    assert all(not route.guards for route in documentation_routes(app))
    assert audit_api_documentation(app, api_documentation_policy(DEVELOPMENT)) == ()


def test_removing_the_assembly_binding_is_refused_before_an_app_exists() -> None:
    """Sensitivity: this must be the field that makes construction succeed."""

    with pytest.raises(RuntimeError, match="api_documentation"):
        create_app(replace(build_spec(), api_documentation=None))


def test_a_planted_fastapi_default_fails_the_production_gate() -> None:
    violations = audit_api_documentation(FastAPI(), api_documentation_policy(PRODUCTION))
    assert violations
    rendered = " ".join(violations)
    for path in (SWAGGER_PATH, REDOC_PATH, OPENAPI_PATH):
        assert path in rendered, violations


def test_the_gate_refuses_underpublishing_too() -> None:
    stripped = FastAPI(**documentation_arguments(api_documentation_policy(PRODUCTION)))
    violations = audit_api_documentation(
        stripped, api_documentation_policy(DEVELOPMENT)
    )
    assert violations
    assert all("no route is mounted" in violation for violation in violations)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, PRODUCTION),
        ("", PRODUCTION),
        ("   ", PRODUCTION),
        ("dev", DEVELOPMENT),
        ("  Development ", DEVELOPMENT),
        ("test", TEST),
        ("ci", TEST),
        ("production", PRODUCTION),
        ("prod", PRODUCTION),
        ("staging", PRODUCTION),
        ("prodction", PRODUCTION),
        ("productionn", PRODUCTION),
    ],
)
def test_environment_classification_fails_closed(
    raw: str | None, expected: str
) -> None:
    assert classify_environment(raw) == expected


def test_the_two_environment_readings_disagree_only_towards_withholding() -> None:
    """ADR-0015 and ADR-0016 answer different questions, safely."""

    candidates = ("", "   ", "staging", "prod", "Production", "prodction", "ci")
    assert [
        raw
        for raw in candidates
        if is_production_environment(raw)
        is not (classify_environment(raw) == PRODUCTION)
    ]

    for raw in candidates:
        resolved = classify_environment(raw)
        if resolved != PRODUCTION:
            assert raw.strip().lower() in PUBLISHING_SPELLINGS, raw
        else:
            policy = api_documentation_policy(resolved)
            assert policy.interactive is DocumentationExposure.DISABLED
            assert policy.document is not DocumentationExposure.PUBLIC
