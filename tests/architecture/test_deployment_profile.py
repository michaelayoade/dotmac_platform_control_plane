"""The deployment profile selects surfaces — and may not do anything else.

Five properties are worth failing the build over:

1. **A profile never drops a persistence owner.** Every module in
   `assembly.STATEFUL_MODULES` carries a migration lineage and owns a schema
   this database already contains. A profile that withheld one would produce an
   assembly that no longer describes its own tables, and the composed
   live-catalogue audit would walk a schema nobody declared. The assertion is
   DERIVED from that tuple rather than listing modules by hand — the previous
   version named five and the assembly composes six, so `deployment_control`
   was covered by nothing.
2. **The production profiles actually withhold the routes they claim to.** A
   profile that says it hides a surface and mounts it anyway is worse than no
   profile — it is a written-down belief that is false.
3. **A withheld surface is not a disabled subsystem.** Licence signing key
   custody is still loaded at boot under a profile that withholds the licensing
   routes. If withholding the routes also silently stopped the issuer from
   being configured, the profile would have changed behaviour, which is exactly
   what ADR-0003 forbids.
4. **Production refuses the fake provisioning laboratory** (ADR-0015), and
   refuses to reach `full` by default when no profile is configured.
5. **Withholding a route leaves the owner and the lineage.** This is the one
   most easily written vacuously, so it is written in two halves that can each
   fail: the manifest is still REGISTERED (looked up through a real
   `ModuleRegistry` built from the profile's own spec, with a probe proving an
   absent module really does disappear from it), and the lineage's HEAD
   REVISION is still resolvable in the composed Alembic graph, addressed by the
   prefix the surviving manifest itself declares.

## Both directions, everywhere

A check that only ever refuses proves nothing about what it accepts. Every
refusal below is paired with the composition that must still be accepted:
production+fake-provisioning refuses while laboratory+fake-provisioning both
validates AND mounts the routes; the missing-profile production boot refuses
while the same unset variable outside production still resolves `full`.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from alembic.script import ScriptDirectory
from dotmac_kernel import create_app
from dotmac_kernel.modules import ModuleRegistry
from import_scanner import reaches_module, scan_imports, source_files

from vendor_cp import assembly
from vendor_cp.deployment_profile import (
    FAKE_PROVIDER_MODE,
    FULL,
    PRODUCTION_BOOTSTRAP,
    PRODUCTION_COMPOSED_V1,
    PROFILE_ENV_VAR,
    PROFILES,
    PROVISIONING_SURFACE,
    VENDOR_SURFACE_CODES,
    ProductionProfileRefusedError,
    UnknownDeploymentProfileError,
    VendorDeploymentProfile,
    deployment_profile,
    load_deployment_profile,
    validate_profile_for_environment,
)
from vendor_cp.migrations import make_alembic_config

SRC = Path(__file__).resolve().parents[2] / "src"
PACKAGE = SRC / "vendor_cp"
PROFILE_MODULE = "vendor_cp.deployment_profile"

LICENSING_PREFIX = "/platform/vendor/licences"
OFFERS_PREFIX = "/platform/vendor/offer-versions"
CONTRACTS_PREFIX = "/platform/vendor/contracts"
PROVISIONING_PREFIX = "/platform/vendor/provisioning"
ALLOCATIONS_PREFIX = "/platform/vendor/allocations"
ACCOUNTS_PREFIX = "/platform/vendor/accounts"
APPROVALS_PREFIX = "/platform/vendor/approvals"

#: Never touches a database: `ScriptDirectory` builds the revision map from the
#: composed `version_locations` on disk. The DSN is a well-formed placeholder
#: because `make_alembic_config` requires one and never connects.
UNREACHABLE_DSN = "postgresql+psycopg://x@127.0.0.1:5432/y"


def _paths(profile_code: str) -> set[str]:
    app = create_app(assembly.build_spec(deployment_profile(profile_code)))
    return {getattr(route, "path", "") for route in app.routes}


def _under(paths: set[str], prefix: str) -> list[str]:
    return [path for path in paths if path.startswith(prefix)]


def _composed_script() -> ScriptDirectory:
    return ScriptDirectory.from_config(make_alembic_config(UNREACHABLE_DSN))


# ── 1 + 5: the owner and the lineage survive every profile ──────────────────


def test_every_profile_keeps_each_persistence_owner_registered_and_migratable() -> None:
    """Both halves of "the module is still composed", per profile.

    Registration is read back out of a real `ModuleRegistry` built from the
    profile's own spec, not from the tuple that was passed in — so a profile
    that somehow produced a manifest the registry rejects fails here. The
    lineage is addressed by the prefix the SURVIVING manifest declares, which
    is what makes the second half depend on the first: if the manifest were
    gone there would be no prefix to look up.
    """
    script = _composed_script()
    heads = set(script.get_heads())

    for profile in PROFILES:
        spec = assembly.build_spec(profile)
        registry = ModuleRegistry(spec.modules)
        owners = {owner.owner: owner for owner in registry.namespaces().owners()}

        for module in assembly.STATEFUL_MODULES:
            assert module in spec.modules, (profile.code, module.code)
            assert module.code in registry.codes(), (profile.code, module.code)

            declared = module.migration_owner()
            assert declared is not None, module.code
            registered = owners.get(declared.owner)
            assert registered is not None, (
                f"profile {profile.code!r} left module {module.code!r} without "
                "its namespace/migration owner"
            )
            # The IDENTITY fields, not the whole record: `provides` is a
            # capability claim that a module release may legitimately extend,
            # and a profile guard that failed on it would be failing for a
            # reason it knows nothing about.
            assert (
                registered.prefix,
                registered.branch_label,
                registered.db_schema,
            ) == (declared.prefix, declared.branch_label, declared.db_schema)

            lineage_heads = {h for h in heads if h.startswith(f"{declared.prefix}_")}
            assert lineage_heads, (
                f"profile {profile.code!r}: no head revision in the composed "
                f"graph belongs to lineage {declared.branch_label!r} "
                f"(prefix {declared.prefix!r})"
            )
            for head in lineage_heads:
                revision = script.get_revision(head)
                assert revision is not None
                assert declared.branch_label in set(revision.branch_labels), (
                    f"{head!r} does not carry the {declared.branch_label!r} "
                    "branch label"
                )


def test_the_owner_survival_check_can_actually_fail() -> None:
    """SENSITIVITY for the half above that is easiest to write vacuously.

    A registry built from the same module set MINUS the licensing module must
    lose both the code and the `mod_licensing` owner. Without this, the
    assertion above would pass just as well against a check that looked
    nothing up.
    """
    spec = assembly.build_spec(deployment_profile(PRODUCTION_COMPOSED_V1))
    licensing = assembly.licensing_module
    declared = licensing.migration_owner()
    assert declared is not None

    reduced = tuple(m for m in spec.modules if m is not licensing)
    assert len(reduced) == len(spec.modules) - 1

    probe = ModuleRegistry(reduced)
    assert licensing.code not in probe.codes()
    assert declared.owner not in {o.owner for o in probe.namespaces().owners()}
    assert "mod_licensing" not in {
        o.db_schema for o in probe.namespaces().owners() if o.db_schema
    }


def test_no_profile_may_name_a_persistence_owner_in_its_withheld_set() -> None:
    """The rule stated directly, so a future profile cannot reach one by name."""
    stateful = {module.code for module in assembly.STATEFUL_MODULES}
    for profile in PROFILES:
        assert not (profile.withheld_surfaces & stateful), profile.code


# ── 2: the production profiles withhold what they say they withhold ─────────


def test_production_bootstrap_withholds_licensing_offers_and_the_laboratory() -> None:
    paths = _paths(PRODUCTION_BOOTSTRAP)

    assert not _under(paths, LICENSING_PREFIX), paths
    assert not _under(paths, OFFERS_PREFIX), paths
    # The correction this profile version exists for: versions 1 and 2
    # published a simulated provisioning API on the production host.
    assert not _under(paths, PROVISIONING_PREFIX), paths
    # SENSITIVITY: the check must be able to see a mounted vendor surface, or it
    # would pass just as well against an assembly that mounted nothing at all.
    assert _under(paths, CONTRACTS_PREFIX), paths


def test_production_composed_v1_publishes_exactly_its_declared_inventory() -> None:
    """The target profile: the console plus read-only surfaces, nothing else."""
    profile = deployment_profile(PRODUCTION_COMPOSED_V1)
    paths = _paths(PRODUCTION_COMPOSED_V1)

    assert set(profile.surface_inventory) == {
        "console",
        "allocations",
        # Declarations only, no router.
        "release_evidence",
        # Published here for the same reason it is published everywhere: a
        # deployment that cannot say whether it is ready is one an orchestrator
        # assumes is. No profile may withhold it.
        "readiness",
    }
    # Exposed: the platform-admin console shell and the read-only allocation
    # view. `release_evidence` contributes declarations only and no router.
    assert "/platform/console" in paths, paths
    assert _under(paths, ALLOCATIONS_PREFIX), paths
    assert "/health/ready" in paths, paths
    # Withheld: every operator WRITE surface, and the laboratory.
    for prefix in (
        LICENSING_PREFIX,
        OFFERS_PREFIX,
        PROVISIONING_PREFIX,
        CONTRACTS_PREFIX,
        ACCOUNTS_PREFIX,
        APPROVALS_PREFIX,
    ):
        assert not _under(paths, prefix), (prefix, paths)


def test_the_full_profile_mounts_what_the_production_profiles_withhold() -> None:
    """Proves the two tests above measure the PROFILE and not routes that were
    never mounted under any composition."""
    paths = _paths(FULL)

    for prefix in (
        LICENSING_PREFIX,
        OFFERS_PREFIX,
        PROVISIONING_PREFIX,
        CONTRACTS_PREFIX,
        ACCOUNTS_PREFIX,
        APPROVALS_PREFIX,
        ALLOCATIONS_PREFIX,
    ):
        assert _under(paths, prefix), (prefix, paths)


def test_a_withheld_surface_keeps_its_manifest_declarations() -> None:
    """Hiding routes must not unregister vocabulary an active subsystem uses."""
    for code in (PRODUCTION_BOOTSTRAP, PRODUCTION_COMPOSED_V1):
        profile = deployment_profile(code)
        modules = {
            manifest.name: manifest for manifest in assembly.build_spec(profile).modules
        }
        for original in assembly.VENDOR_SURFACES:
            if profile.exposes(original.name):
                continue
            profiled = modules[original.name]
            assert tuple(profiled.routers) == (), (code, original.name)
            assert tuple(profiled.web_routers) == (), (code, original.name)
            assert tuple(profiled.nav) == (), (code, original.name)
            # `web_surfaces` exists only on a contract-v2 `ModuleManifest`;
            # a legacy `FeatureManifest` has no such field, and reading it
            # through `getattr` keeps the loop honest for both shapes.
            assert tuple(getattr(profiled, "web_surfaces", ())) == (), (
                code,
                original.name,
            )
            assert profiled.audit_actions == original.audit_actions
            assert profiled.capabilities == original.capabilities


# ── 3: a withheld surface is not a disabled subsystem ───────────────────────


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


# ── 4a: production refuses the fake provisioning laboratory ─────────────────


def test_production_refuses_a_profile_that_mounts_fake_provisioning() -> None:
    """PLANTED CASE — production + fake provisioning → refused."""
    laboratory = deployment_profile(FULL)
    assert laboratory.exposes(PROVISIONING_SURFACE)

    with pytest.raises(ProductionProfileRefusedError) as refusal:
        validate_profile_for_environment(
            laboratory, environment="production", provider_mode=FAKE_PROVIDER_MODE
        )
    assert PROVISIONING_SURFACE in str(refusal.value)
    assert FAKE_PROVIDER_MODE in str(refusal.value)


def test_a_laboratory_environment_accepts_fake_provisioning(monkeypatch) -> None:
    """PLANTED CASE, opposite direction — laboratory + fake provisioning →
    accepted, and accepted means the routes are genuinely MOUNTED, not merely
    that nothing raised."""
    laboratory = deployment_profile(FULL)

    for environment in ("development", "test", "staging"):
        validate_profile_for_environment(
            laboratory, environment=environment, provider_mode=FAKE_PROVIDER_MODE
        )

    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv(PROFILE_ENV_VAR, FULL)
    paths = {getattr(r, "path", "") for r in create_app(assembly.build_spec()).routes}
    assert _under(paths, PROVISIONING_PREFIX), paths


def test_production_accepts_a_production_profile(monkeypatch) -> None:
    """The other half of the refusal: a production-accepted profile validates."""
    for code in (PRODUCTION_BOOTSTRAP, PRODUCTION_COMPOSED_V1):
        profile = deployment_profile(code)
        assert profile.production_accepted
        assert not profile.exposes(PROVISIONING_SURFACE)
        validate_profile_for_environment(
            profile, environment="production", provider_mode=FAKE_PROVIDER_MODE
        )
        validate_profile_for_environment(
            profile, environment="PRODUCTION", provider_mode=FAKE_PROVIDER_MODE
        )


def test_a_laboratory_profile_is_refused_in_production_even_when_named() -> None:
    """Configuring `full` deliberately is still refused — the environment rule
    is not a defence against typos only."""
    monkeypatched = deployment_profile(FULL)
    assert not monkeypatched.production_accepted
    with pytest.raises(ProductionProfileRefusedError):
        validate_profile_for_environment(
            monkeypatched, environment="production", provider_mode=FAKE_PROVIDER_MODE
        )


# ── 4b: production never silently falls back to `full` ──────────────────────


def test_production_never_falls_back_to_full(monkeypatch) -> None:
    """PLANTED CASE — an unset (or blank) profile in production is an error."""
    monkeypatch.delenv(PROFILE_ENV_VAR, raising=False)
    with pytest.raises(ProductionProfileRefusedError, match=PROFILE_ENV_VAR):
        load_deployment_profile(environment="production")

    monkeypatch.setenv(PROFILE_ENV_VAR, "   ")
    with pytest.raises(ProductionProfileRefusedError, match=PROFILE_ENV_VAR):
        load_deployment_profile(environment="production")


def test_the_fallback_still_applies_outside_production(monkeypatch) -> None:
    """PLANTED CASE, opposite direction — the developer default is intact."""
    monkeypatch.delenv(PROFILE_ENV_VAR, raising=False)
    assert load_deployment_profile(environment="development").code == FULL
    monkeypatch.setenv("ENVIRONMENT", "development")
    assert load_deployment_profile().code == FULL


def test_a_configured_production_profile_is_the_one_loaded(monkeypatch) -> None:
    """And it is never `full`: production reads what the host declared."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    for code in (PRODUCTION_BOOTSTRAP, PRODUCTION_COMPOSED_V1):
        monkeypatch.setenv(PROFILE_ENV_VAR, code)
        loaded = load_deployment_profile()
        assert loaded.code == code
        assert loaded.code != FULL


def test_a_production_boot_without_a_profile_fails(monkeypatch) -> None:
    """The refusal reaches the actual composition entry point, not just the
    loader it happens to call."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv(PROFILE_ENV_VAR, raising=False)
    monkeypatch.setattr(
        assembly,
        "validate_runtime_configuration",
        lambda settings, *, environment: None,
    )
    with pytest.raises(ProductionProfileRefusedError):
        assembly.build_spec()


# ── Structural invariants on the declarations themselves ────────────────────


def test_the_surface_roster_matches_the_composed_assembly() -> None:
    """`VENDOR_SURFACE_CODES` is declared in `deployment_profile` because the
    assembly imports it and not the other way round. This is the sync guard
    that makes the duplication safe."""
    assert VENDOR_SURFACE_CODES == {
        feature.name for feature in assembly.VENDOR_SURFACES
    }


def test_a_profile_publishing_the_laboratory_must_declare_itself_one() -> None:
    with pytest.raises(ValueError, match="laboratory=True"):
        VendorDeploymentProfile(
            code="pretend-production",
            version="1",
            withheld_surfaces=frozenset(),
            surface_inventory=tuple(sorted(VENDOR_SURFACE_CODES)),
            laboratory=False,
            production_accepted=True,
            rationale="publishes the simulation while claiming production",
        )


def test_a_laboratory_is_never_production_accepted() -> None:
    with pytest.raises(ValueError, match="laboratory"):
        VendorDeploymentProfile(
            code="both-at-once",
            version="1",
            withheld_surfaces=frozenset({PROVISIONING_SURFACE}),
            surface_inventory=tuple(
                sorted(VENDOR_SURFACE_CODES - {PROVISIONING_SURFACE})
            ),
            laboratory=True,
            production_accepted=True,
            rationale="a laboratory that claims to be production-accepted",
        )


def test_an_inventory_that_omits_a_composed_surface_is_refused() -> None:
    """The point of the inventory: a surface cannot join a production profile
    by simply existing."""
    with pytest.raises(ValueError, match="unlisted"):
        VendorDeploymentProfile(
            code="silently-incomplete",
            version="1",
            withheld_surfaces=frozenset({"offers"}),
            surface_inventory=("console",),
            laboratory=False,
            production_accepted=True,
            rationale="an inventory that describes a fraction of what it mounts",
        )


def test_a_profile_may_not_withhold_a_surface_it_does_not_declare() -> None:
    with pytest.raises(ValueError, match="persistence owner"):
        VendorDeploymentProfile(
            code="drops-an-owner",
            version="1",
            withheld_surfaces=frozenset({"licensing"}),
            surface_inventory=tuple(sorted(VENDOR_SURFACE_CODES)),
            laboratory=False,
            production_accepted=True,
            rationale="withholds a composed module rather than a vendor surface",
        )


def test_every_declared_profile_carries_a_version_and_an_inventory() -> None:
    for profile in PROFILES:
        assert profile.version.strip(), profile.code
        assert profile.rationale.strip(), profile.code
        assert set(profile.surface_inventory) == (
            VENDOR_SURFACE_CODES - profile.withheld_surfaces
        ), profile.code


def test_an_unknown_profile_fails_closed(monkeypatch) -> None:
    monkeypatch.setenv(PROFILE_ENV_VAR, "produciton-bootstrap")
    with pytest.raises(UnknownDeploymentProfileError, match="produciton-bootstrap"):
        load_deployment_profile(environment="development")


# ── ADR-0003: exactly one reader ────────────────────────────────────────────


def test_the_profile_is_read_in_exactly_one_place() -> None:
    """ADR-0003: profile names are conveniences over independent axes, and no
    feature may branch on one. The composition module is the single reader.

    Scanned through `import_scanner`, because the earlier ImportFrom-only walk
    could not see `import vendor_cp.deployment_profile as p` followed by
    `p.load_deployment_profile()` — a second reader in every practical sense,
    invisible to the guard that forbids one.
    """
    readers = sorted(
        path.relative_to(SRC).as_posix()
        for path in source_files(PACKAGE)
        if reaches_module(scan_imports(path, source_root=SRC), PROFILE_MODULE)
    )
    assert readers == ["vendor_cp/assembly.py"], (
        "the deployment profile is read in exactly one place — composition. A "
        f"second reader is a feature about to branch on a profile name: {readers}"
    )


def test_the_profile_reader_guard_is_not_vacuous() -> None:
    """NON-VACUITY plus sensitivity for the form that was invisible.

    The assertion above is an equality against a one-element list, which a
    scanner returning nothing would fail — but only by accident of the expected
    value being non-empty. These two checks make it deliberate: the real reader
    is found, and a probe using the previously-blind `import x as y` form is
    found too.
    """
    module = PACKAGE / "assembly.py"
    assert reaches_module(scan_imports(module, source_root=SRC), PROFILE_MODULE)

    probe = ast.parse("import vendor_cp.deployment_profile as p\n")
    aliased = {
        alias.name
        for node in ast.walk(probe)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert PROFILE_MODULE in aliased
