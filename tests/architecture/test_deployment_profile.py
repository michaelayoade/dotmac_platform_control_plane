"""The deployment profile selects surfaces — and may not do anything else.

Three properties are worth failing the build over:

1. **A profile never drops a persistence owner.** The two module manifests carry
   migration lineages and own schemas this database already contains. A profile
   that withheld one would produce an assembly that no longer describes its own
   tables, and the composed live-catalogue audit would walk a schema nobody
   declared.
2. **`production-bootstrap` actually withholds the two routes it claims to.**
   A profile that says it hides a surface and mounts it anyway is worse than no
   profile — it is a written-down belief that is false.
3. **A withheld surface is not a disabled subsystem.** Licence signing key
   custody is still loaded at boot under the bootstrap profile. If withholding
   the routes also silently stopped the issuer from being configured, the
   profile would have changed behaviour, which is exactly what ADR-0003 forbids.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from dotmac_entitlement_allocation import module as entitlement_allocation_module
from dotmac_kernel import create_app
from dotmac_release_catalog import module as release_catalog_module

from vendor_cp import assembly
from vendor_cp.deployment_profile import (
    FULL,
    PRODUCTION_BOOTSTRAP,
    PROFILE_ENV_VAR,
    PROFILES,
    UnknownDeploymentProfileError,
    deployment_profile,
    load_deployment_profile,
)

SRC = Path(__file__).resolve().parents[2] / "src" / "vendor_cp"

LICENSING_PREFIX = "/platform/vendor/licences"
OFFERS_PREFIX = "/platform/vendor/offer-versions"
CONTRACTS_PREFIX = "/platform/vendor/contracts"


def _paths(profile_code: str) -> set[str]:
    app = create_app(assembly.build_spec(deployment_profile(profile_code)))
    return {getattr(route, "path", "") for route in app.routes}


def test_every_profile_composes_both_persistence_owners() -> None:
    for profile in PROFILES:
        modules = assembly.build_spec(profile).modules
        assert release_catalog_module in modules, profile.code
        assert entitlement_allocation_module in modules, profile.code


def test_production_bootstrap_withholds_licensing_and_offers() -> None:
    paths = _paths(PRODUCTION_BOOTSTRAP)
    assert not [p for p in paths if p.startswith(LICENSING_PREFIX)], paths
    assert not [p for p in paths if p.startswith(OFFERS_PREFIX)], paths
    # SENSITIVITY: the check must be able to see a mounted vendor surface, or it
    # would pass just as well against an assembly that mounted nothing at all.
    assert [p for p in paths if p.startswith(CONTRACTS_PREFIX)], paths


def test_the_full_profile_mounts_the_surfaces_bootstrap_withholds() -> None:
    """Proves the previous test is measuring the profile and not a route that
    was never mounted under any composition."""
    paths = _paths(FULL)
    assert [p for p in paths if p.startswith(LICENSING_PREFIX)], paths
    assert [p for p in paths if p.startswith(OFFERS_PREFIX)], paths


def test_a_withheld_surface_is_not_a_disabled_subsystem(monkeypatch) -> None:
    installed: list[object] = []
    monkeypatch.setattr(
        assembly, "install_runtime_licence_signers", lambda s: installed.append(s)
    )
    assembly.build_spec(deployment_profile(PRODUCTION_BOOTSTRAP))
    assert installed, (
        "the bootstrap profile withholds the licensing ROUTES; it must not stop "
        "the issuer's key custody from being loaded at boot"
    )


def test_an_unknown_profile_fails_closed(monkeypatch) -> None:
    monkeypatch.setenv(PROFILE_ENV_VAR, "produciton-bootstrap")
    with pytest.raises(UnknownDeploymentProfileError, match="produciton-bootstrap"):
        load_deployment_profile()


def test_an_unset_profile_composes_the_full_assembly(monkeypatch) -> None:
    monkeypatch.delenv(PROFILE_ENV_VAR, raising=False)
    assert load_deployment_profile().code == FULL


def test_the_profile_is_read_in_exactly_one_place() -> None:
    """ADR-0003: profile names are conveniences over independent axes, and no
    feature may branch on one. The composition module is the single reader; a
    second import of the loader is a feature about to read a profile string."""
    readers = [
        path.relative_to(SRC).as_posix()
        for path in SRC.rglob("*.py")
        if "__pycache__" not in path.parts
        for node in ast.walk(ast.parse(path.read_text()))
        if isinstance(node, ast.ImportFrom)
        and node.module == "vendor_cp.deployment_profile"
        and any(alias.name == "load_deployment_profile" for alias in node.names)
    ]
    assert readers == ["assembly.py"], readers
