"""Bindings state facts; plane selections state intent. Neither implies the other.

Kernel `0.1.0a60` conflated them, and this assembly is the case that proved it
wrong: the Vendor Control Plane composes the kernel base lineage, so
`public.tenants` and `app_current_tenant_id()` really do exist here. Under a60,
binding that truth was itself the instruction to build a module's tenant plane,
and the only way to keep tenant tables out of a control plane with no tenants was
to withhold a binding whose effect the database plainly provides.

The separation introduced in a61 remains at a77, so this assembly binds every
kernel effect its currently composed modules require and states installation
intent separately. The tests below assert the two halves apart, so a future edit
cannot quietly re-merge them. Approvals is selectable and its platform plane is
declared explicitly; its tenant plane remains absent.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotmac_kernel.planes import (
    MODULE_PLANES_ENV_VAR,
    ModulePlane,
    supported_plane_sets,
)
from dotmac_kernel.prerequisites import (
    BINDINGS_ENV_VAR,
    IDEMPOTENCY_LEDGER_V1,
    MODULE_DATABASE_ROLES_V1,
    OUTBOX_RELAY_V1,
    PLATFORM_AUDIT_LOG_V1,
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


def test_the_assembly_binds_the_required_kernel_effects() -> None:
    """Including the tenant catalogue. A binding is an observation, and kernel
    0001 observably creates `public.tenants` in this database.

    Commercial Agreements declares the idempotency and platform-audit effects;
    Approvals a5 declares the outbox relay. Each binding names the exact
    supplying revision, which for a multi-part effect is the DESCENDANT that
    completes it, never the lineage root that begins it.
    """
    assert {
        (binding.prerequisite, binding.provider_revision, binding.provider_owner)
        for binding in ASSEMBLY_PREREQUISITE_BINDINGS
    } == {
        (MODULE_DATABASE_ROLES_V1.name, KERNEL_ROOT_REVISION, "kernel"),
        (TENANT_SCOPE_CATALOG_V1.name, KERNEL_ROOT_REVISION, "kernel"),
        (IDEMPOTENCY_LEDGER_V1.name, "0018_idempotency_one_owner", "kernel"),
        (OUTBOX_RELAY_V1.name, "0012_platform_outbox", "kernel"),
        (PLATFORM_AUDIT_LOG_V1.name, "0026_platform_audit_log", "kernel"),
    }


def test_every_effect_a_composed_module_declares_is_bound() -> None:
    """The derivation the exact set above cannot do on its own.

    Approvals wrote both relay tables from a1 and declared nothing until a5, so
    for three releases this assembly satisfied an effect no test could see it
    needed. Deriving the requirement from the composed manifests is what makes
    the next undeclared-then-declared effect fail here instead of at deploy.

    `tenant_requires` is deliberately NOT collected. It is the requirement of a
    plane this assembly does not install, and demanding a binding for it would
    reintroduce the a60 confusion in miniature — availability standing in for
    intent. `platform_requires` IS collected, because the platform plane is the
    one selected here.
    """
    bound = {binding.prerequisite for binding in ASSEMBLY_PREREQUISITE_BINDINGS}
    required: set[str] = set()
    for module in build_spec().modules:
        required.update(getattr(module, "requires", ()) or ())
        required.update(getattr(module, "platform_requires", ()) or ())
    assert required <= bound, sorted(required - bound)
    assert required, "no composed module declares a prerequisite at all"


def test_a_bound_tenant_catalogue_selects_nothing_by_itself() -> None:
    """The half of `dotmac_starter_mt` ADR-0028 assertable with no such module.

    The prerequisite is bound AND the assembly installs no tenant plane. Under
    the a60 model those two facts could not both hold.
    """
    bound = {binding.prerequisite for binding in ASSEMBLY_PREREQUISITE_BINDINGS}
    assert TENANT_SCOPE_CATALOG_V1.name in bound

    # The tenant catalogue is bound AND no tenant plane is selected. Under the
    # a60 model those two facts could not both hold.
    selected = {
        ModulePlane(plane)
        for selection in ASSEMBLY_MODULE_PLANES
        for plane in selection.planes
    }
    assert ModulePlane.TENANT not in selected


def test_every_selectable_composed_module_has_a_selection() -> None:
    """The premise that makes the selection tuple correct rather than merely
    present.

    A selectable module composed with no selection fails `ProductAssemblySpec`
    construction on its own. This asserts the inverse and cheaper half: every
    selectable module composed here appears in the declaration, and every entry
    in the declaration names a module actually composed — so the tuple cannot
    drift ahead of, or behind, the composition.
    """
    composed = {
        manifest.code: manifest
        for manifest in build_spec().modules
        if getattr(manifest, "code", None)
    }
    selectable = {
        code
        for code, manifest in composed.items()
        if len(supported_plane_sets(manifest)) > 1
    }
    declared = {selection.module for selection in ASSEMBLY_MODULE_PLANES}

    assert selectable == {"approvals"}, sorted(selectable)
    assert declared == selectable, sorted(declared ^ selectable)


def test_the_approvals_plane_selection_is_platform_only() -> None:
    """Vendor approvals are control-plane state; there is no tenant here whose
    approvals could be scoped."""
    planes = {
        selection.module: {ModulePlane(p) for p in selection.planes}
        for selection in ASSEMBLY_MODULE_PLANES
    }
    assert planes == {"approvals": {ModulePlane.PLATFORM}}


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


#: `alembic_version.version_num` is VARCHAR(32). A longer revision id is accepted
#: everywhere until the moment it is INSERTED, which is after the migration has
#: done its work — so the failure surfaces as a truncation error in the middle of
#: a schema change rather than at authoring time.
ALEMBIC_VERSION_NUM_LIMIT = 32


def test_every_revision_id_fits_the_version_table() -> None:
    """CI found this the expensive way: a 33-character id failed mid-upgrade with
    "value too long for type character varying(32)", which names neither the
    revision nor the column."""
    versions = ROOT / "alembic" / "versions"
    too_long: list[str] = []
    for path in sorted(versions.glob("*.py")):
        for line in path.read_text().splitlines():
            code = line.split("#", 1)[0].strip()
            if code.startswith("revision = "):
                revision = code.split("=", 1)[1].strip().strip("\"'")
                if len(revision) > ALEMBIC_VERSION_NUM_LIMIT:
                    too_long.append(f"{path.name}: {revision} ({len(revision)})")
    assert (
        not too_long
    ), f"revision ids must fit VARCHAR({ALEMBIC_VERSION_NUM_LIMIT}): {too_long}"


def test_the_revision_length_guard_reads_real_revisions() -> None:
    """NON-VACUITY: a reader that found no revisions would report none too long."""
    versions = ROOT / "alembic" / "versions"
    found = [
        line
        for path in versions.glob("*.py")
        for line in path.read_text().splitlines()
        if line.split("#", 1)[0].strip().startswith("revision = ")
    ]
    assert len(found) >= 14, found
