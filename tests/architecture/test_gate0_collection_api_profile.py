"""Actual assembled route/profile/auth graph, not production adoption evidence."""

from dataclasses import replace

import pytest
from dotmac_kernel import create_app
from dotmac_kernel.platform_auth import (
    require_platform_admin,
    require_platform_web_auth,
)
from fastapi.routing import APIRoute
from route_dependency_graph import dependency_calls

from vendor_cp.assembly import build_spec
from vendor_cp.deployment.gate0_collection_api import require_gate0_collection_workload
from vendor_cp.deployment_profile import (
    PRODUCTION_GATE0_COLLECTION_V1,
    PROFILES,
    ProductionProfileRefusedError,
    deployment_profile,
    validate_profile_for_environment,
)

PREFIX = "/platform/vendor/gate0/collection/windows/{window_id}"


def test_existing_profiles_withhold_and_explicit_profile_mounts_exact_reads(
    monkeypatch,
):
    monkeypatch.setenv("ENVIRONMENT", "development")
    for profile in PROFILES:
        app = create_app(build_spec(profile))
        routes = [
            r
            for r in app.routes
            if isinstance(r, APIRoute) and r.path.startswith(PREFIX)
        ]
        if profile.code != PRODUCTION_GATE0_COLLECTION_V1:
            assert "gate0_collection_reads" in profile.withheld_surfaces
            assert routes == []
            continue
        assert "gate0_collection_reads" in profile.surface_inventory
        assert {(r.path, frozenset(r.methods)) for r in routes} == {
            (PREFIX + "/approval", frozenset({"GET"})),
            (PREFIX + "/withdrawal", frozenset({"GET"})),
        }
        for route in routes:
            calls = dependency_calls(route)
            assert calls.count(require_gate0_collection_workload) == 1
            assert require_platform_admin not in calls
            assert require_platform_web_auth not in calls
        validate_profile_for_environment(
            profile, environment="production", provider_mode="fake"
        )
        with pytest.raises(ProductionProfileRefusedError):
            validate_profile_for_environment(
                replace(profile, production_accepted=False),
                environment="production",
                provider_mode="fake",
            )


def test_profile_source_acceptance_is_explicit_not_deployment_evidence():
    profile = deployment_profile(PRODUCTION_GATE0_COLLECTION_V1)
    assert profile.version == "2"
    assert profile.production_accepted is True
    assert profile.laboratory is False


def test_main_factory_handoff_uses_one_profile_selection(monkeypatch):
    from vendor_cp import assembly

    monkeypatch.setenv("ENVIRONMENT", "development")
    profile = deployment_profile(PRODUCTION_GATE0_COLLECTION_V1)
    calls = []
    monkeypatch.setattr(
        assembly, "load_deployment_profile", lambda **k: calls.append(k) or profile
    )
    spec, chosen = assembly.build_spec_with_profile()
    assert chosen is profile
    assert len(calls) == 1
    app = create_app(spec)
    assert {
        r.path
        for r in app.routes
        if isinstance(r, APIRoute) and r.path.startswith(PREFIX)
    } == {PREFIX + "/approval", PREFIX + "/withdrawal"}


def test_collection_profile_v2_adds_exact_existing_approval_surface(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    profile = deployment_profile(PRODUCTION_GATE0_COLLECTION_V1)
    assert profile.code == "production-gate0-collection-v1"
    assert "vendor_approvals" in profile.surface_inventory
    assert "vendor_approvals" not in profile.withheld_surfaces
    prior = replace(
        profile,
        version="1",
        withheld_surfaces=profile.withheld_surfaces | {"vendor_approvals"},
        surface_inventory=tuple(
            code for code in profile.surface_inventory if code != "vendor_approvals"
        ),
    )
    before = create_app(build_spec(prior))
    after = create_app(build_spec(profile))

    def signatures(app):
        return {
            (route.path, frozenset(route.methods), route.name)
            for route in app.routes
            if isinstance(route, APIRoute)
        }

    expected = {
        ("/platform/vendor/approvals/policies", frozenset({"POST"}), "publish_policy"),
        ("/platform/vendor/approvals/decisions", frozenset({"POST"}), "record_decision"),
        (
            "/platform/vendor/approvals/requests/{request_id}/withdraw",
            frozenset({"POST"}),
            "withdraw_request",
        ),
        (
            "/platform/vendor/approvals/requests/{request_id}",
            frozenset({"GET"}),
            "read_request",
        ),
    }
    assert signatures(after) - signatures(before) == expected
    assert signatures(before) - signatures(after) == set()
    for route in after.routes:
        if not isinstance(route, APIRoute):
            continue
        if (route.path, frozenset(route.methods), route.name) not in expected:
            continue
        calls = dependency_calls(route)
        assert calls.count(require_platform_admin) == 1
        assert require_platform_web_auth not in calls
        assert require_gate0_collection_workload not in calls
