"""Platform consumes Kernel a100's API-documentation policy, with no local owner."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from dotmac_kernel import create_app
from dotmac_kernel.api_documentation import (
    BEARER_PLANE_GUARD,
    DEVELOPMENT,
    OPENAPI_PATH,
    PRODUCTION,
    REDOC_PATH,
    SWAGGER_OAUTH2_REDIRECT_PATH,
    SWAGGER_PATH,
    DocumentationExposure,
    api_documentation_policy,
    audit_api_documentation,
    documentation_routes,
)

from vendor_cp import assembly
from vendor_cp.deployment_profile import (
    FULL,
    PRODUCTION_COMPOSED_V1,
    deployment_profile,
)

ROOT = Path(__file__).resolve().parents[2]


def _build(monkeypatch: pytest.MonkeyPatch, environment: str):
    monkeypatch.setenv("ENVIRONMENT", environment)
    monkeypatch.setattr(
        assembly,
        "validate_runtime_configuration",
        lambda settings, *, environment: None,
    )
    monkeypatch.setattr(
        assembly, "install_runtime_licence_signers", lambda settings: None
    )
    profile = PRODUCTION_COMPOSED_V1 if environment == PRODUCTION else FULL
    return assembly.build_spec(deployment_profile(profile))


def test_build_spec_binds_the_kernel_owned_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for environment in (DEVELOPMENT, PRODUCTION):
        spec = _build(monkeypatch, environment)
        assert spec.api_documentation == api_documentation_policy(environment)


def test_the_production_application_withholds_browser_docs_and_guards_the_document(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _build(monkeypatch, PRODUCTION)
    app = create_app(spec)
    served = {route.path: route for route in documentation_routes(app)}

    for path in (SWAGGER_PATH, SWAGGER_OAUTH2_REDIRECT_PATH, REDOC_PATH):
        assert path not in served
    assert OPENAPI_PATH in served
    assert BEARER_PLANE_GUARD in served[OPENAPI_PATH].guards
    assert audit_api_documentation(app, spec.api_documentation) == ()


def test_the_development_application_still_publishes_both_planes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _build(monkeypatch, DEVELOPMENT)
    app = create_app(spec)
    served = {route.path for route in documentation_routes(app)}
    assert served == {
        SWAGGER_PATH,
        SWAGGER_OAUTH2_REDIRECT_PATH,
        REDOC_PATH,
        OPENAPI_PATH,
    }
    assert spec.api_documentation is not None
    assert spec.api_documentation.interactive is DocumentationExposure.PUBLIC
    assert spec.api_documentation.document is DocumentationExposure.PUBLIC
    assert audit_api_documentation(app, spec.api_documentation) == ()


def test_an_undeclared_policy_refuses_at_the_kernel_constructor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = replace(_build(monkeypatch, DEVELOPMENT), api_documentation=None)
    with pytest.raises(RuntimeError, match="declares no api_documentation policy"):
        create_app(spec)


def test_the_product_local_policy_owner_is_retired() -> None:
    assert not (ROOT / "src/vendor_cp/api_documentation.py").exists()
    main = (ROOT / "src/vendor_cp/main.py").read_text(encoding="utf-8")
    assert "install_api_documentation_policy" not in main
    assert "app = create_app(build_spec())" in main
