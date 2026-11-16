"""Thin target-side effects factories return Foundation's own effects."""

from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from vendor_cp.deployment import target_effects
from vendor_cp.deployment.target_refusals import (
    FoundationBindingsUnavailable,
    TargetRefusal,
)


def _install_foundation(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    seen: dict[str, Any] = {}

    class ComposeHostEffects:
        def __init__(self, spec: Any, deploy_dir: Path, **kwargs: Any) -> None:
            seen["effects"] = (spec, deploy_dir, kwargs)

    class ComposeHostExposureEffects:
        def __init__(self, spec: Any, **kwargs: Any) -> None:
            seen["exposure"] = (spec, kwargs)

    def default_runner(*_a: Any, **_k: Any) -> None:  # the local runner
        return None

    def resolve_tool(configured: str, *, what: str, expected_sha256: str = "") -> str:
        seen.setdefault("resolved", []).append((what, configured))
        return configured

    modules = {
        "dotmac_deployment_foundation": ModuleType("dotmac_deployment_foundation"),
        "dotmac_deployment_foundation.providers": ModuleType("p"),
        "dotmac_deployment_foundation.providers.compose_host": ModuleType("c"),
        "dotmac_deployment_foundation.providers.exposure_host": ModuleType("e"),
        "dotmac_deployment_foundation.toolchain": ModuleType("t"),
    }
    modules[
        "dotmac_deployment_foundation.providers.compose_host"
    ].ComposeHostEffects = ComposeHostEffects  # type: ignore[attr-defined]
    modules[
        "dotmac_deployment_foundation.providers.compose_host"
    ]._default_runner = default_runner  # type: ignore[attr-defined]
    modules[
        "dotmac_deployment_foundation.providers.exposure_host"
    ].ComposeHostExposureEffects = ComposeHostExposureEffects  # type: ignore[attr-defined]
    toolchain = modules["dotmac_deployment_foundation.toolchain"]
    toolchain.DEFAULT_TOOLS = {"docker": "/usr/bin/docker", "git": "/usr/bin/git"}  # type: ignore[attr-defined]
    toolchain.resolve_tool = resolve_tool  # type: ignore[attr-defined]
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)
    seen["runner"] = default_runner
    seen["effects_type"] = ComposeHostEffects
    seen["exposure_type"] = ComposeHostExposureEffects
    return seen


def test_build_effects_returns_foundations_own_effects_with_pinned_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _install_foundation(monkeypatch)
    spec = object()
    effects = target_effects.build_target_effects(spec, "/srv/deploy")
    assert type(effects) is seen["effects_type"]
    given_spec, deploy_dir, kwargs = seen["effects"]
    assert given_spec is spec and deploy_dir == Path("/srv/deploy")
    # Same construction as Foundation's in-package provider: tools resolved
    # through Foundation's own pinned-toolchain check, and no runner supplied,
    # so Foundation's local subprocess runner is the one in force.
    assert kwargs == {"docker_bin": "/usr/bin/docker", "git_bin": "/usr/bin/git"}
    assert "runner" not in kwargs
    assert seen["resolved"] == [
        ("docker_bin", "/usr/bin/docker"),
        ("git_bin", "/usr/bin/git"),
    ]


def test_build_exposure_effects_uses_foundations_local_runner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _install_foundation(monkeypatch)
    spec = object()
    effects = target_effects.build_target_exposure_effects(spec, Path("/srv/deploy"))
    assert type(effects) is seen["exposure_type"]
    given_spec, kwargs = seen["exposure"]
    assert given_spec is spec
    assert kwargs == {"deploy_dir": Path("/srv/deploy"), "runner": seen["runner"]}


@pytest.mark.parametrize(
    "factory",
    [
        target_effects.build_target_effects,
        target_effects.build_target_exposure_effects,
    ],
)
def test_missing_foundation_refuses_typed_not_with_an_import_error(
    monkeypatch: pytest.MonkeyPatch, factory: Any
) -> None:
    for name in (
        "dotmac_deployment_foundation",
        "dotmac_deployment_foundation.providers.compose_host",
        "dotmac_deployment_foundation.providers.exposure_host",
        "dotmac_deployment_foundation.toolchain",
    ):
        monkeypatch.setitem(sys.modules, name, None)
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        factory(object(), "/srv/deploy")
    assert caught.value.code is TargetRefusal.FOUNDATION_MISSING
    assert caught.value.__cause__ is None


def test_the_module_imports_nothing_that_could_reach_another_host() -> None:
    import ast

    tree = ast.parse(Path(target_effects.__file__).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    # Foundation's own classes are the only effects; no transport, no process
    # spawning, no network client of this module's own.
    assert imported <= {
        "__future__",
        "pathlib",
        "typing",
        "vendor_cp",
        "dotmac_deployment_foundation",
    }
