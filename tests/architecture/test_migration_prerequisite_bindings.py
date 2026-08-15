"""Bindings state facts; plane selections state intent. Neither implies the other.

Kernel `0.1.0a60` conflated them, and this assembly is the case that proved it
wrong: the Vendor Control Plane composes the kernel base lineage, so
`public.tenants` and `app_current_tenant_id()` really do exist here. Under a60,
binding that truth was itself the instruction to build a module's tenant plane,
and the only way to keep tenant tables out of a control plane with no tenants was
to withhold a binding whose effect the database plainly provides.

a61 separates the two, so this assembly binds both kernel effects and states its
installation intent separately. The tests below assert the two halves apart, so a
future edit cannot quietly re-merge them.

The selection tuple is EMPTY today because no selectable module is composed —
`dotmac-approvals` arrives with its cutover contract. `tests/migration/
test_selected_planes.py` documents exactly which part of the ADR-0028 proof that
defers, and to where.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotmac_kernel.planes import MODULE_PLANES_ENV_VAR, supported_plane_sets
from dotmac_kernel.prerequisites import (
    BINDINGS_ENV_VAR,
    MODULE_DATABASE_ROLES_V1,
    TENANT_SCOPE_CATALOG_V1,
)

from vendor_cp.assembly import build_spec
from vendor_cp.migration_bindings import (
    ASSEMBLY_MODULE_PLANES,
    ASSEMBLY_PREREQUISITE_BINDINGS,
    KERNEL_ROOT_REVISION,
)
from vendor_cp.migrations import make_alembic_config

ROOT = Path(__file__).resolve().parents[2]


def test_the_assembly_binds_every_effect_the_kernel_lineage_supplies() -> None:
    """Including the tenant catalogue. A binding is an observation, and kernel
    0001 observably creates `public.tenants` in this database."""
    assert {
        (binding.prerequisite, binding.provider_revision, binding.provider_owner)
        for binding in ASSEMBLY_PREREQUISITE_BINDINGS
    } == {
        (MODULE_DATABASE_ROLES_V1.name, KERNEL_ROOT_REVISION, "kernel"),
        (TENANT_SCOPE_CATALOG_V1.name, KERNEL_ROOT_REVISION, "kernel"),
    }


def test_a_bound_tenant_catalogue_selects_nothing_by_itself() -> None:
    """The half of ADR-0028 that is assertable with no selectable module.

    The prerequisite is bound AND the assembly installs no tenant plane. Under
    the a60 model those two facts could not both hold.
    """
    bound = {binding.prerequisite for binding in ASSEMBLY_PREREQUISITE_BINDINGS}
    assert TENANT_SCOPE_CATALOG_V1.name in bound
    assert ASSEMBLY_MODULE_PLANES == ()


def test_every_composed_module_has_an_atomic_plane_contract() -> None:
    """Why the empty selection is correct rather than merely absent.

    A selectable module composed with no selection fails `ProductAssemblySpec`
    construction. So an empty tuple is only honest while every composed module
    declares exactly one supported plane set — this asserts that premise instead
    of assuming it, and fails the moment a selectable module is composed.
    """
    selectable = [
        manifest.code
        for manifest in build_spec().modules
        if getattr(manifest, "code", None) and len(supported_plane_sets(manifest)) > 1
    ]
    assert not selectable, (
        "a selectable module is composed; declare its ModulePlaneSelection in "
        f"ASSEMBLY_MODULE_PLANES and write the full plane proof: {selectable}"
    )


def test_the_assembly_spec_carries_the_selection_for_validation() -> None:
    """Kernel-side validation only runs on what the SPEC declares. A selection
    living only in `migration_bindings` would order migrations correctly and
    still let `create_app` compose a selectable module with no stated intent."""
    assert tuple(build_spec().module_planes) == ASSEMBLY_MODULE_PLANES


def test_alembic_installs_both_declarations_before_building_the_map() -> None:
    env_source = (ROOT / "alembic" / "env.py").read_text()

    bindings_at = env_source.index(
        "install_prerequisite_bindings(ASSEMBLY_PREREQUISITE_BINDINGS)"
    )
    planes_at = env_source.index(
        "install_module_plane_selections(ASSEMBLY_MODULE_PLANES)"
    )
    configure_at = env_source.index("config = context.config")

    assert bindings_at < configure_at
    assert planes_at < configure_at


def test_graph_only_commands_see_the_same_declarations() -> None:
    """`alembic heads|history|show` never run `env.py`. Without these two
    variables they would build a revision map with no bindings and no
    selections — a graph that differs from the one an upgrade applies."""
    source = (ROOT / "src" / "vendor_cp" / "migrations.py").read_text()
    assert "BINDINGS_ENV_VAR" in source
    assert "MODULE_PLANES_ENV_VAR" in source
    assert "vendor_cp.migration_bindings:ASSEMBLY_PREREQUISITE_BINDINGS" in source
    assert "vendor_cp.migration_bindings:ASSEMBLY_MODULE_PLANES" in source


EXPECTED_BINDINGS_SPEC = "vendor_cp.migration_bindings:ASSEMBLY_PREREQUISITE_BINDINGS"
EXPECTED_PLANES_SPEC = "vendor_cp.migration_bindings:ASSEMBLY_MODULE_PLANES"


def test_the_assembly_overrides_stale_graph_environment(monkeypatch) -> None:
    """The assembly wins over ambient environment state, in both directions.

    `setdefault` preferred whatever was already exported, which is backwards for
    a value this assembly owns: a stale or foreign `DOTMAC_MIGRATION_BINDINGS`
    left by another assembly, a test or a shell would survive, and
    `make_alembic_config` would inspect a graph different from the one it
    applies.

    Preloading deliberately WRONG values is the whole test — with `setdefault`
    they survive and this fails.
    """
    monkeypatch.setenv(BINDINGS_ENV_VAR, "some_other_assembly:BINDINGS")
    monkeypatch.setenv(MODULE_PLANES_ENV_VAR, "some_other_assembly:PLANES")

    make_alembic_config("postgresql+psycopg://x@127.0.0.1:5432/y")

    assert os.environ[BINDINGS_ENV_VAR] == EXPECTED_BINDINGS_SPEC
    assert os.environ[MODULE_PLANES_ENV_VAR] == EXPECTED_PLANES_SPEC


def test_the_graph_environment_is_set_when_absent_too(monkeypatch) -> None:
    """NON-VACUITY for the test above: it must not pass merely because the
    variables happen to be set correctly already."""
    monkeypatch.delenv(BINDINGS_ENV_VAR, raising=False)
    monkeypatch.delenv(MODULE_PLANES_ENV_VAR, raising=False)

    make_alembic_config("postgresql+psycopg://x@127.0.0.1:5432/y")

    assert os.environ[BINDINGS_ENV_VAR] == EXPECTED_BINDINGS_SPEC
    assert os.environ[MODULE_PLANES_ENV_VAR] == EXPECTED_PLANES_SPEC


def test_no_graph_declaration_is_configured_with_setdefault() -> None:
    """MUTATION PROOF. The two tests above pass under `setdefault` whenever the
    variables are unset, so they cannot by themselves keep it from coming back.
    This reads the source and refuses the call shape outright."""
    source = (ROOT / "src" / "vendor_cp" / "migrations.py").read_text()
    for line in source.splitlines():
        code = line.split("#", 1)[0]
        if "setdefault" in code:
            assert "DATABASE_URL" in code and "MIGRATION_DATABASE_URL" not in code, (
                "graph declarations are assembly-owned and must be ASSIGNED, so "
                f"ambient environment state loses: {line.strip()}"
            )
