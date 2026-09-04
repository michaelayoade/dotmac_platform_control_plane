"""The deployment profile selects surfaces — and may not do anything else.

Six properties are worth failing the build over:

1. **A profile never drops a persistence owner.** Every module in
   `assembly.STATEFUL_MODULES` carries a migration lineage and owns a schema
   this database already contains. A profile that dropped one would produce an
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
   what `dotmac_starter_mt` ADR-0003 forbids.
4. **Production refuses the fake provisioning laboratory** (ADR-0015), and
   refuses to reach `full` by default when no profile is configured.
5. **Withholding a route leaves the owner and the lineage.** This is the one
   most easily written vacuously, so it is written in two halves that can each
   fail: the manifest is still REGISTERED (looked up through a real
   `ModuleRegistry` built from the profile's own spec, with a probe proving an
   absent module really does disappear from it), and the lineage's HEAD
   REVISION is still resolvable in the composed Alembic graph, addressed by the
   prefix the surviving manifest itself declares.
6. **Admission covers every route-bearing composed module** (ADR-0019), not
   only the Vendor adapters. A composed module that ships an operator surface
   publishes routes exactly as a vendor adapter does, and until this change the
   profile never saw one: `build_spec` filtered `VENDOR_SURFACES` and spliced
   `STATEFUL_MODULES` in raw, while the completeness check compared a declared
   inventory against a hand-written roster of vendor feature names.

## Both directions, everywhere

A check that only ever refuses proves nothing about what it accepts. Every
refusal below is paired with the composition that must still be accepted:
production+fake-provisioning refuses while laboratory+fake-provisioning both
validates AND mounts the routes; the missing-profile production boot refuses
while the same unset variable outside production still resolves `full`; and the
planted uninventoried surface refuses while the SAME plant, once inventoried,
genuinely mounts its route in a real application.

## The plant is the live coverage for property 6

Zero composed modules bear a route today, so a guard written only against the
real composition would cover nothing at the instant the old rule is removed.
What carries property 6 is `_a11_shaped_module()` — the real
`deployment_control` manifest, with its real `platform_tables`,
`migration_prefix`, `migration_branch`, `requires`, `audit_actions` and
`database_catalog`, carrying the browser surface `dotmac-deployment-control` has
shipped since `0.1.0a8`. It is a11's actual shape on a11's actual module rather
than a fabrication that resembles it, and it proves the property NOW.

Property 1 and 5's registry+lineage checks are the coverage that ARRIVES with
the first real pin of a route-bearing module. They are not the same coverage and
must not be read as such.
"""

from __future__ import annotations

import ast
from dataclasses import fields, replace
from pathlib import Path

import pytest
from alembic.script import ScriptDirectory
from dotmac_kernel import create_app
from dotmac_kernel.features import FeatureManifest
from dotmac_kernel.modules import ModuleManifest, ModuleRegistry
from dotmac_kernel.web_surfaces import WebSurfaceContribution
from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from import_scanner import reaches_module, scan_imports, source_files

from vendor_cp import assembly
from vendor_cp.deployment_profile import (
    FAKE_PROVIDER_MODE,
    FULL,
    NEVER_WITHHELD_SURFACES,
    PRODUCTION_BOOTSTRAP,
    PRODUCTION_COMPOSED_V1,
    PROFILE_ENV_VAR,
    PROFILES,
    PROVISIONING_SURFACE,
    ROUTE_FIELDS,
    AdmissionRefusal,
    ProductionProfileRefusedError,
    SurfaceAdmissionError,
    UnknownDeploymentProfileError,
    VendorDeploymentProfile,
    admit_surfaces,
    bears_routes,
    deployment_profile,
    load_deployment_profile,
    route_bearing_codes,
    validate_profile_for_environment,
    withholdable_surfaces,
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
#: Control's own surface, and note it is NOT under `/platform/vendor/`: the
#: module contributes facet-relative routes to the kernel's `platform_admin`
#: facet, which owns the prefix. Spelling a vendor path here would assert a
#: layout this assembly does not control.
DEPLOYMENTS_PREFIX = "/platform/deployments"

#: The facet-relative path the planted browser surface mounts. Facet-relative
#: exactly as a11's own screens are, so the composed path carries the
#: `platform_admin` prefix the facet owns.
PLANTED_PATH = "/planted-operator-screen"
PLANTED_FULL_PATH = f"/platform{PLANTED_PATH}"

#: The retention fields the rule NAMES, as opposed to the exhaustive
#: field-by-field comparison that backs them. Ratcheted against the pinned
#: kernel's `ModuleManifest`: `database_catalog` is declared by
#: `dotmac-deployment-control` a11 and does not exist on the manifest at the
#: kernel pinned here, so it is listed and its absence is asserted rather than
#: quietly skipped.
NAMED_RETENTION_FIELDS: tuple[str, ...] = (
    "platform_tables",
    "migration_prefix",
    "migration_branch",
    "requires",
    "audit_actions",
    "database_catalog",
)

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


# ── The plants ──────────────────────────────────────────────────────────────


def _planted_router() -> APIRouter:
    router = APIRouter()

    @router.get(PLANTED_PATH, response_class=HTMLResponse, name="planted_screen")
    def planted_screen() -> str:  # pragma: no cover - existence is the assertion
        return "<!doctype html><title>planted</title>"

    return router


def _a11_shaped_module() -> ModuleManifest:
    """The real `deployment_control` manifest, wearing the surface a8 shipped.

    Not a fabricated look-alike. Every persistence declaration on it — the real
    `platform_tables`, `migration_prefix`, `migration_branch`, `requires`,
    `audit_actions` and `database_catalog` — is the composed module's own, so
    the retention proof below compares real values rather than defaults that
    would agree with anything.
    """
    return replace(
        assembly.deployment_control_module,
        web_surfaces=(
            WebSurfaceContribution(
                code="planted_deployments",
                # The same facet a11 joins, which is the same facet the console
                # already contributes to and every production profile publishes.
                facet="platform_admin",
                routers=(_planted_router(),),
                supported_ui_contract_versions=frozenset({1}),
            ),
        ),
    )


def _planted_feature() -> FeatureManifest:
    """A legacy `FeatureManifest` plant, so the guard is not shape-specific."""
    return FeatureManifest(
        name="planted_adapter",
        routers=[_planted_router()],
        core=False,
        enabled_by_default=True,
    )


Manifest = FeatureManifest | ModuleManifest


def _composition_with(manifest: Manifest) -> tuple[Manifest, ...]:
    """The real composed set with one manifest replaced or appended by code."""
    existing_codes = {existing.name for existing in assembly.COMPOSED_MANIFESTS}
    if manifest.name in existing_codes:
        return tuple(
            manifest if existing.name == manifest.name else existing
            for existing in assembly.COMPOSED_MANIFESTS
        )
    return (*assembly.COMPOSED_MANIFESTS, manifest)


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

    # `name`, not `code`: `spec.modules` holds both manifest generations, and
    # only `ModuleManifest` has `code`. `name` is the alias both carry.
    reduced = tuple(m for m in spec.modules if m.name != licensing.name)
    assert len(reduced) == len(spec.modules) - 1

    probe = ModuleRegistry(reduced)
    assert licensing.code not in probe.codes()
    assert declared.owner not in {o.owner for o in probe.namespaces().owners()}
    assert "mod_licensing" not in {
        o.db_schema for o in probe.namespaces().owners() if o.db_schema
    }


# ── 6: withholding a stateful module's SURFACE keeps everything else ────────


def test_withholding_a_stateful_module_clears_routes_and_nothing_else() -> None:
    """ADR-0019's load-bearing property, proved against the a11-shaped plant.

    This REPLACES "no profile may name a persistence owner in its withheld set".
    That rule was a proxy: it kept a stateful module out of the withheld set so
    that nothing could drop its manifest. But a module that ships an operator
    screen MUST be withholdable, or it force-publishes into every production
    profile — so the proxy had to go, and what replaces it is the property the
    proxy stood for, asserted directly.

    Field-by-field over the whole dataclass rather than a named subset: the
    named subset is what a reader wants to see, and it is checked explicitly
    below, but a field added to `ModuleManifest` tomorrow is covered only by the
    exhaustive comparison.
    """
    planted = _a11_shaped_module()
    assert bears_routes(planted), "the plant must publish something to withhold"

    withholding = VendorDeploymentProfile(
        code="withholds-the-plant",
        version="1",
        withheld_surfaces=frozenset({planted.name}),
        surface_inventory=(),
        # It withholds ONLY the plant, so it still exposes `provisioning`, and
        # ADR-0015's pairing check refuses that unless the profile says what it
        # is. Declaring it here rather than also withholding provisioning keeps
        # this test measuring one thing.
        laboratory=True,
        production_accepted=False,
        rationale="withholds the planted operator surface",
    )
    profiled = assembly._profiled_surface(planted, withholding)

    declared = {field.name for field in fields(planted)}
    for field in fields(planted):
        original = getattr(planted, field.name)
        survivor = getattr(profiled, field.name)
        if field.name in ROUTE_FIELDS:
            assert tuple(survivor) == (), (field.name, survivor)
        else:
            assert survivor == original, field.name

    # The named half, spelled out because it is what the rule promises: a
    # withheld surface keeps its manifest and its migration lineage.
    #
    # Ratcheted in BOTH directions against the PINNED kernel's field set rather
    # than assumed. `database_catalog` is declared by `dotmac-deployment-control`
    # a11 and is NOT a field of `ModuleManifest` at the kernel pinned here, so an
    # unconditional assertion on it fails and a silently-skipped one would be an
    # assertion that vanished. Recording the absence makes it visible: this fails
    # if the field appears (add the assertion) and if a named field disappears.
    absent = [name for name in NAMED_RETENTION_FIELDS if name not in declared]
    assert absent == ["database_catalog"], (
        "the pinned kernel's `ModuleManifest` field set moved. Update "
        "NAMED_RETENTION_FIELDS deliberately rather than letting a retention "
        f"assertion appear or vanish unnoticed: absent={absent}"
    )
    for name in NAMED_RETENTION_FIELDS:
        if name not in declared:
            continue
        original = getattr(planted, name)
        assert getattr(profiled, name) == original, name
        assert original, f"vacuous: the plant declares no {name}"

    # And the lineage the surviving manifest declares still resolves.
    owner = profiled.migration_owner()
    assert owner is not None
    heads = set(_composed_script().get_heads())
    assert {h for h in heads if h.startswith(f"{owner.prefix}_")}


def test_a_route_bearing_stateful_module_is_withholdable_at_all() -> None:
    """The other half of the relaxation: derivation must ALLOW it.

    The old hand-written allowlist held only vendor feature names, so a composed
    module could not have been withheld even by someone who wanted to.

    Both directions, on the same module, so the assertion is about DERIVATION
    and not about which modules happen to ship routes today: with the surface it
    is withholdable, with the surface stripped it is not.
    """
    planted = _a11_shaped_module()
    silent = replace(planted, web_surfaces=())

    assert planted.name in withholdable_surfaces(_composition_with(planted))
    assert planted.name not in withholdable_surfaces(_composition_with(silent))


# ── 6: the planted surface is refused, and the plant is real ────────────────


@pytest.mark.parametrize("code", [p.code for p in PROFILES])
def test_a_composed_module_that_mounts_a_route_is_refused_when_uninventoried(
    code: str,
) -> None:
    """PLANTED CASE — the defect ADR-0019 closes, on every declared profile.

    a11's shape: a composed stateful module carrying a contract-v2
    `WebSurfaceContribution` on the `platform_admin` facet. No profile
    inventories it, so admission must refuse.
    """
    profile = deployment_profile(code)
    with pytest.raises(SurfaceAdmissionError) as refusal:
        admit_surfaces(profile, _composition_with(_a11_shaped_module()))

    assert refusal.value.refusal is AdmissionRefusal.SURFACE_NOT_INVENTORIED
    assert refusal.value.surfaces == ("deployment_control",)


@pytest.mark.parametrize("code", [p.code for p in PROFILES])
def test_a_planted_legacy_adapter_is_refused_too(code: str) -> None:
    """PLANTED CASE, other manifest shape — the guard is not v2-specific."""
    profile = deployment_profile(code)
    with pytest.raises(SurfaceAdmissionError) as refusal:
        admit_surfaces(profile, _composition_with(_planted_feature()))

    assert refusal.value.refusal is AdmissionRefusal.SURFACE_NOT_INVENTORIED
    assert refusal.value.surfaces == ("planted_adapter",)


def test_the_refusal_reaches_the_real_composition_entry_point(monkeypatch) -> None:
    """The guard must sit on `build_spec`, not on a helper a caller may skip.

    `validate_runtime_configuration` is stubbed for the same reason the
    missing-profile boot test stubs it: this is measuring admission, not the
    provider mode.
    """
    monkeypatch.setattr(
        assembly, "COMPOSED_MANIFESTS", _composition_with(_a11_shaped_module())
    )
    monkeypatch.setattr(
        assembly,
        "validate_runtime_configuration",
        lambda settings, *, environment: None,
    )
    for code in (FULL, PRODUCTION_BOOTSTRAP, PRODUCTION_COMPOSED_V1):
        with pytest.raises(SurfaceAdmissionError) as refusal:
            assembly.build_spec(deployment_profile(code))
        assert refusal.value.refusal is AdmissionRefusal.SURFACE_NOT_INVENTORIED


def test_the_planted_surface_genuinely_mounts_once_it_is_inventoried(
    monkeypatch,
) -> None:
    """POSITIVE CONTROL — without this the refusal above could be firing on an
    inert object that mounts nothing.

    Same plant, same composition, one difference: a profile whose inventory
    names it. The application is really built, and the route really answers to a
    path that did not exist a moment ago.
    """
    planted = _a11_shaped_module()
    monkeypatch.setattr(assembly, "COMPOSED_MANIFESTS", _composition_with(planted))
    monkeypatch.setattr(
        assembly,
        "validate_runtime_configuration",
        lambda settings, *, environment: None,
    )

    base = deployment_profile(PRODUCTION_COMPOSED_V1)
    admitting = VendorDeploymentProfile(
        code="admits-the-plant",
        version="1",
        withheld_surfaces=base.withheld_surfaces,
        surface_inventory=(*base.surface_inventory, planted.name),
        laboratory=base.laboratory,
        production_accepted=base.production_accepted,
        rationale="the positive control for the planted operator surface",
    )

    paths = {
        getattr(route, "path", "")
        for route in create_app(assembly.build_spec(admitting)).routes
    }
    assert PLANTED_FULL_PATH in paths, sorted(paths)

    # And withholding it takes the same route back out — the plant is under the
    # profile's control, not merely present.
    withholding = replace(
        admitting,
        code="withholds-the-plant",
        withheld_surfaces=base.withheld_surfaces | {planted.name},
        surface_inventory=base.surface_inventory,
    )
    withheld_paths = {
        getattr(route, "path", "")
        for route in create_app(assembly.build_spec(withholding)).routes
    }
    assert PLANTED_FULL_PATH not in withheld_paths, sorted(withheld_paths)


# ── ADR-0019's surface-neutrality proof, RETIRED ────────────────────────────
#
# Two tests stood here: `test_extending_admission_to_composed_modules_mounted_
# and_removed_no_route`, which compared the ADR-0019 composition against the one
# it replaced and required identical route signatures, and its non-vacuity
# partner `test_the_neutrality_comparison_can_see_a_route`.
#
# They are deleted rather than repaired, on their own written instruction:
#
#     it holds only while no composed module bears a route. When one does,
#     DELETE it rather than repairing it — the comparison would then be
#     measuring the new module, not this change.
#
# Pinning `dotmac-deployment-control` a12 is that moment. a12 declares
# `web_surfaces`; a6 declared none, which is exactly the premise the test
# asserted first so it would fail loudly instead of quietly measuring something
# else. Repairing it — excluding `deployment_control` from the comparison — would
# have kept a green test whose subject had changed underneath it.
#
# The claim it certified is history and stays true: extending profile admission
# to composed modules moved no route ON THE COMPOSITION THAT EXISTED THEN. What
# replaces it going forward is not a re-run of that comparison but the admission
# gate itself — `admit_surfaces` now has a route-bearing composed module to rule
# on, and `test_the_admission_gate_rules_on_a_composed_module` below exercises
# it against the real one rather than against a planted probe.
#
# `_legacy_spec` and `_route_signatures` went with them: nothing else used
# either, and a helper kept for a deleted comparison is the next reader's
# false lead.


# ── 2: the production profiles withhold what they say they withhold ─────────


def test_production_bootstrap_withholds_licensing_offers_and_the_laboratory() -> None:
    paths = _paths(PRODUCTION_BOOTSTRAP)

    assert not _under(paths, LICENSING_PREFIX), paths
    assert not _under(paths, OFFERS_PREFIX), paths
    # The correction this profile version exists for: versions 1 and 2
    # published a simulated provisioning API on the production host.
    assert not _under(paths, PROVISIONING_PREFIX), paths
    # Control a12 arrives route-bearing and is withheld here; the rationale
    # states why (a plan-freezing WRITE route, before the restored-database
    # rehearsal is discharged).
    assert not _under(paths, DEPLOYMENTS_PREFIX), paths
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
        # Published here for the same reason it is published everywhere: a
        # deployment that cannot say whether it is ready is one an orchestrator
        # assumes is. No profile may withhold it.
        "readiness",
    }
    # `release_evidence` is absent because it bears no route. That absence is
    # derived, not decided: an inventory says what a deployment PUBLISHES, and a
    # declarations-only feature publishes nothing.
    assert "release_evidence" not in profile.surface_inventory
    assert not bears_routes(assembly.release_evidence_feature)
    # Exposed: the platform-admin console shell and the read-only allocation
    # view.
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
        # Control a12's fleet surface: withheld on the same operator-WRITE rule
        # as its neighbours above, not on a new one.
        DEPLOYMENTS_PREFIX,
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
        # Added with the Control a12 pin. Without it, the two production
        # profiles' new `deployment_control` withholding would be asserted
        # against routes that might never have mounted under any profile —
        # which is precisely what this test exists to rule out.
        DEPLOYMENTS_PREFIX,
    ):
        assert _under(paths, prefix), (prefix, paths)


def test_a_withheld_surface_keeps_its_manifest_declarations() -> None:
    """Hiding routes must not unregister vocabulary an active subsystem uses.

    Iterated over `COMPOSED_MANIFESTS`, not `VENDOR_SURFACES`: since ADR-0019
    every composed manifest passes through the profile, so every composed
    manifest is a candidate for this.
    """
    for code in (PRODUCTION_BOOTSTRAP, PRODUCTION_COMPOSED_V1):
        profile = deployment_profile(code)
        modules = {
            manifest.name: manifest for manifest in assembly.build_spec(profile).modules
        }
        for original in assembly.COMPOSED_MANIFESTS:
            if profile.exposes(original.name):
                continue
            profiled = modules[original.name]
            for field_name in ROUTE_FIELDS:
                assert tuple(getattr(profiled, field_name, ()) or ()) == (), (
                    code,
                    original.name,
                    field_name,
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


# ── The derivation itself ───────────────────────────────────────────────────


def test_every_declared_profile_admits_against_the_real_composition() -> None:
    """A declared-but-undeployed profile rots otherwise.

    `build_spec` admits only the ONE profile a host runs, so the profile nobody
    has switched to is exactly the one that quietly stops describing the
    assembly. Every declared profile is admitted here.
    """
    for profile in PROFILES:
        admit_surfaces(profile, assembly.COMPOSED_MANIFESTS)


def test_the_roster_is_derived_and_holds_no_silent_surface() -> None:
    route_bearing = route_bearing_codes(assembly.COMPOSED_MANIFESTS)
    assert route_bearing == {
        manifest.name
        for manifest in assembly.COMPOSED_MANIFESTS
        if bears_routes(manifest)
    }
    # Derived, so a declarations-only feature is absent without anyone saying so.
    assert "release_evidence" not in route_bearing
    assert "release_evidence" in {m.name for m in assembly.COMPOSED_MANIFESTS}
    # And every profile's inventory is exactly what it publishes.
    for profile in PROFILES:
        assert set(profile.surface_inventory) == (
            route_bearing - profile.withheld_surfaces
        ), profile.code


def test_the_admission_gate_rules_on_a_composed_module() -> None:
    """The first COMPOSED module that bears a route, ruled on for real.

    Every other admission test here plants a probe, because until Control a12
    no composed module carried one: a6 declared no `web_surfaces`. A gate whose
    only subjects are plants has never been shown to rule on the thing it was
    built for, so this drives the real manifest through the real profiles.

    The premise is asserted first and names the module, so that a future pin
    which stopped shipping the surface fails here rather than turning the three
    assertions below into three tautologies about an absent name.
    """
    route_bearing = route_bearing_codes(assembly.COMPOSED_MANIFESTS)
    assert "deployment_control" in route_bearing, sorted(route_bearing)

    published = {
        profile.code: set(profile.surface_inventory) for profile in PROFILES
    }
    withheld = {profile.code: profile.withheld_surfaces for profile in PROFILES}

    # `full` publishes it; both production profiles withhold it. This is the
    # per-profile decision recorded in each rationale, asserted rather than
    # trusted to prose.
    assert "deployment_control" in published[FULL]
    assert "deployment_control" not in withheld[FULL]
    for code in (PRODUCTION_BOOTSTRAP, PRODUCTION_COMPOSED_V1):
        assert "deployment_control" in withheld[code], code
        assert "deployment_control" not in published[code], code


def test_the_composed_module_admission_can_actually_refuse() -> None:
    """SENSITIVITY. The three assertions above are satisfied by the current
    declarations; this proves the GATE behind them still bites on this module.

    Dropping `deployment_control` from `full`'s inventory while it still mounts
    must be refused as uninventoried — the exact failure the pin would otherwise
    have produced silently, and the reason the profile change had to land in the
    same commit as the pin.
    """
    full = next(profile for profile in PROFILES if profile.code == FULL)
    uninventoried = replace(
        full,
        surface_inventory=tuple(
            name for name in full.surface_inventory if name != "deployment_control"
        ),
    )
    with pytest.raises(SurfaceAdmissionError) as refusal:
        admit_surfaces(uninventoried, assembly.COMPOSED_MANIFESTS)
    assert refusal.value.refusal is AdmissionRefusal.SURFACE_NOT_INVENTORIED
    assert refusal.value.surfaces == ("deployment_control",)


def test_bears_routes_sees_every_route_field() -> None:
    """SENSITIVITY for the predicate the whole derivation rests on.

    One probe per field. A predicate that had quietly stopped reading one of
    them would still pass a test that only ever handed it a manifest carrying
    `routers`.
    """

    class _Probe:
        def __init__(self, field: str) -> None:
            for name in ROUTE_FIELDS:
                setattr(self, name, ("something",) if name == field else ())

    for field in ROUTE_FIELDS:
        assert bears_routes(_Probe(field)), field

    class _Silent:
        pass

    assert not bears_routes(_Silent())
    assert not bears_routes(_Probe("nothing-matches-this"))


def test_readiness_is_route_bearing_and_still_not_withholdable() -> None:
    """Derivation alone would make it withholdable; the one hand-declared set
    is what stops that, and it must be doing so for a live reason."""
    assert "readiness" in route_bearing_codes(assembly.COMPOSED_MANIFESTS)
    assert "readiness" in NEVER_WITHHELD_SURFACES
    assert "readiness" not in withholdable_surfaces(assembly.COMPOSED_MANIFESTS)
    for profile in PROFILES:
        assert "readiness" in profile.surface_inventory, profile.code


# ── Typed refusals, each planted ────────────────────────────────────────────


def _profile(**overrides: object) -> VendorDeploymentProfile:
    base = dict(
        code="probe",
        version="1",
        withheld_surfaces=frozenset(),
        surface_inventory=(),
        laboratory=True,
        production_accepted=False,
        rationale="a probe profile",
    )
    base.update(overrides)
    return VendorDeploymentProfile(**base)  # type: ignore[arg-type]


def test_an_inventory_that_names_a_silent_surface_is_refused() -> None:
    published = route_bearing_codes(assembly.COMPOSED_MANIFESTS)
    with pytest.raises(SurfaceAdmissionError) as refusal:
        admit_surfaces(
            _profile(surface_inventory=(*sorted(published), "release_evidence")),
            assembly.COMPOSED_MANIFESTS,
        )
    assert refusal.value.refusal is AdmissionRefusal.INVENTORY_NAMES_A_SILENT_SURFACE
    assert refusal.value.surfaces == ("release_evidence",)


def test_withholding_a_mandatory_surface_is_refused() -> None:
    with pytest.raises(SurfaceAdmissionError) as refusal:
        admit_surfaces(
            _profile(withheld_surfaces=frozenset({"readiness"})),
            assembly.COMPOSED_MANIFESTS,
        )
    assert refusal.value.refusal is AdmissionRefusal.WITHHOLDS_A_MANDATORY_SURFACE
    assert refusal.value.surfaces == ("readiness",)


def test_withholding_something_that_publishes_nothing_is_refused() -> None:
    """A typo withholds no route, and a declaration that changes nothing reads
    to the next operator as though it did."""
    with pytest.raises(SurfaceAdmissionError) as refusal:
        admit_surfaces(
            _profile(withheld_surfaces=frozenset({"conosle"})),
            assembly.COMPOSED_MANIFESTS,
        )
    assert refusal.value.refusal is AdmissionRefusal.WITHHOLDS_A_SILENT_SURFACE
    assert refusal.value.surfaces == ("conosle",)


def test_a_correct_probe_profile_admits() -> None:
    """The direction that keeps the three refusals above from passing for the
    wrong reason."""
    published = route_bearing_codes(assembly.COMPOSED_MANIFESTS)
    admit_surfaces(
        _profile(surface_inventory=tuple(sorted(published))),
        assembly.COMPOSED_MANIFESTS,
    )


# ── Structural invariants on the declarations themselves ────────────────────


def test_a_profile_publishing_the_laboratory_must_declare_itself_one() -> None:
    with pytest.raises(ValueError, match="laboratory=True"):
        VendorDeploymentProfile(
            code="pretend-production",
            version="1",
            withheld_surfaces=frozenset(),
            surface_inventory=("console",),
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
            surface_inventory=("console",),
            laboratory=True,
            production_accepted=True,
            rationale="a laboratory that claims to be production-accepted",
        )


def test_a_profile_may_not_publish_and_withhold_the_same_surface() -> None:
    with pytest.raises(ValueError, match="publishes and withholds"):
        VendorDeploymentProfile(
            code="contradicts-itself",
            version="1",
            withheld_surfaces=frozenset({"offers"}),
            surface_inventory=("offers",),
            laboratory=True,
            production_accepted=False,
            rationale="says both things about one surface",
        )


def test_every_declared_profile_carries_a_version_and_a_rationale() -> None:
    for profile in PROFILES:
        assert profile.version.strip(), profile.code
        assert profile.rationale.strip(), profile.code


def test_an_unknown_profile_fails_closed(monkeypatch) -> None:
    monkeypatch.setenv(PROFILE_ENV_VAR, "produciton-bootstrap")
    with pytest.raises(UnknownDeploymentProfileError, match="produciton-bootstrap"):
        load_deployment_profile(environment="development")


# ── `dotmac_starter_mt` ADR-0003: exactly one reader ──────────────────────────


def test_the_profile_is_read_in_exactly_one_place() -> None:
    """`dotmac_starter_mt` ADR-0003: profile names are conveniences over
    independent axes, and no feature may branch on one. The composition module
    is the single reader.

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
