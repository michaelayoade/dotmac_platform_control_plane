"""Bindings state facts; plane selections state intent. Neither implies the other.

Kernel 0.1.0a60 briefly conflated them, and this assembly is the case that
proved it wrong: the Vendor Control Plane composes the kernel base lineage, so
`public.tenants` and `app_current_tenant_id()` really do exist here, and under
a60 binding that truth would have installed tenant approval tables in a control
plane with no tenants.

The a61 declarations therefore hold four facts at once, and the tests below
assert them SEPARATELY so a future edit cannot re-merge them by accident:

1. the tenant catalogue prerequisite IS bound — we do not lie about the database;
2. the approvals plane selection is PLATFORM alone — we do not install a plane
   we have no use for;
3. the assembly spec carries that selection, so `ProductAssemblySpec` validates
   it rather than a comment asserting it;
4. Alembic installs both BEFORE it builds the revision map, and mirrors both
   into the environment variables the graph-inspection commands read.
"""

from __future__ import annotations

from pathlib import Path

from dotmac_kernel.planes import ModulePlane
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


def test_the_assembly_installs_only_the_platform_approval_plane() -> None:
    """The intent half. This is what keeps the tenant plane out — NOT the
    binding above, which is present and truthful."""
    assert {
        (selection.module, frozenset(ModulePlane(p) for p in selection.planes))
        for selection in ASSEMBLY_MODULE_PLANES
    } == {("approvals", frozenset({ModulePlane.PLATFORM}))}


def test_a_bound_tenant_catalogue_does_not_select_the_tenant_plane() -> None:
    """The distinguishing property of ADR-0028, as one assertion.

    Both facts hold simultaneously, which is exactly the combination the a60
    model could not express: the prerequisite is bound AND the tenant plane is
    not selected.
    """
    bound = {binding.prerequisite for binding in ASSEMBLY_PREREQUISITE_BINDINGS}
    selected = {
        ModulePlane(plane)
        for selection in ASSEMBLY_MODULE_PLANES
        if selection.module == "approvals"
        for plane in selection.planes
    }
    assert TENANT_SCOPE_CATALOG_V1.name in bound
    assert ModulePlane.TENANT not in selected


def test_the_assembly_spec_carries_the_selection_for_validation() -> None:
    """Kernel-side validation only runs on what the spec declares. A selection
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
