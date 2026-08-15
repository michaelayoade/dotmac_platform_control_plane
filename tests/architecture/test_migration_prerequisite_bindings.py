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

from pathlib import Path

from dotmac_kernel.planes import supported_plane_sets
from dotmac_kernel.prerequisites import (
    MODULE_DATABASE_ROLES_V1,
    TENANT_SCOPE_CATALOG_V1,
)

from vendor_cp.assembly import build_spec
from vendor_cp.migration_bindings import (
    ASSEMBLY_MODULE_PLANES,
    ASSEMBLY_PREREQUISITE_BINDINGS,
    KERNEL_ROOT_REVISION,
)

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
