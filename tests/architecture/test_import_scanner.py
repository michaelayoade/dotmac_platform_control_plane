"""Mutation proof for the shared import scanner.

Every guard in this directory that says "no source file may reach X" is only as
good as the scanner underneath it, and the previous one matched a single import
form. So each form Python offers gets its own case here, written as a probe file
the scanner must SEE — and a negative case it must not.

If a case is ever deleted, the guard that depends on it silently loses coverage
of that form, which is exactly how the earlier blind spot survived review.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from import_scanner import (
    module_targets,
    names_from,
    possible_module_targets,
    reaches_module,
    scan_imports,
    submodule_reach_ins,
)

LEGACY = "vendor_cp.allocations.models"
MODULE_PACKAGE = "dotmac_entitlement_allocation"


def _probe(tmp_path: Path, source: str, *, relative_to: str = "") -> Path:
    """Write a probe module at a real package path, so relative imports resolve
    against a genuine package rather than an invented one."""
    package_dir = tmp_path / "src"
    for part in relative_to.split(".") if relative_to else []:
        package_dir = package_dir / part
    package_dir.mkdir(parents=True, exist_ok=True)
    probe = package_dir / "probe.py"
    probe.write_text(source)
    return probe


def _scan(tmp_path: Path, source: str, *, relative_to: str = ""):
    probe = _probe(tmp_path, source, relative_to=relative_to)
    return scan_imports(probe, source_root=tmp_path / "src")


# ── Every import form that reaches the legacy models ────────────────────────

LEGACY_FORMS = pytest.mark.parametrize(
    ("source", "package"),
    [
        pytest.param(f"import {LEGACY}\n", "", id="import-dotted"),
        pytest.param(f"import {LEGACY} as legacy\n", "", id="import-dotted-aliased"),
        pytest.param(
            f"from {LEGACY} import Allocation\n", "", id="from-module-import-name"
        ),
        pytest.param(
            f"from {LEGACY} import Allocation as A\n", "", id="from-module-aliased"
        ),
        pytest.param(
            "from vendor_cp.allocations import models\n",
            "",
            id="from-package-import-module",
        ),
        pytest.param(
            "from . import models\n",
            "vendor_cp.allocations",
            id="relative-import-module",
        ),
        pytest.param(
            "from .models import Allocation\n",
            "vendor_cp.allocations",
            id="relative-from-module",
        ),
        pytest.param(
            "from ..allocations.models import Allocation\n",
            "vendor_cp.licensing",
            id="relative-parent-walk",
        ),
    ],
)


@LEGACY_FORMS
def test_the_scanner_sees_every_legacy_import_form(
    tmp_path: Path, source: str, package: str
) -> None:
    refs = _scan(tmp_path, source, relative_to=package)
    assert reaches_module(refs, LEGACY), (
        f"import form not detected — a legacy writer path could be added this "
        f"way while the guard stays green: {source!r}"
    )


def test_the_scanner_does_not_cry_wolf(tmp_path: Path) -> None:
    """NON-VACUITY. If everything matched, every form above would pass for the
    wrong reason and the guards would flag innocent files."""
    refs = _scan(
        tmp_path,
        "import os\n"
        "from dataclasses import dataclass\n"
        "from vendor_cp.contracts.models import Contract\n"
        "from vendor_cp.allocations import service\n",
    )
    assert not reaches_module(refs, LEGACY)


# ── Reaching INTO the composed module, versus using its public surface ──────


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(f"import {MODULE_PACKAGE}.service\n", id="import-submodule"),
        pytest.param(
            f"import {MODULE_PACKAGE}.service as svc\n", id="import-submodule-aliased"
        ),
        pytest.param(
            f"from {MODULE_PACKAGE}.service import stage_allocation\n",
            id="from-submodule",
        ),
        pytest.param(
            f"from {MODULE_PACKAGE}.service import stage_allocation as go\n",
            id="from-submodule-aliased",
        ),
    ],
)
def test_the_scanner_sees_submodule_reach_ins(tmp_path: Path, source: str) -> None:
    refs = _scan(tmp_path, source)
    assert submodule_reach_ins(refs, MODULE_PACKAGE), source


def test_the_public_surface_is_not_mistaken_for_a_reach_in(tmp_path: Path) -> None:
    """The distinction the two target sets exist for.

    `from pkg import module` names an ATTRIBUTE called `module` — the manifest —
    not a submodule. Treating it as a reach-in would flag the package's own
    documented surface and make the guard unusable.
    """
    refs = _scan(
        tmp_path,
        f"from {MODULE_PACKAGE} import module, versions_dir\n",
    )
    assert not submodule_reach_ins(refs, MODULE_PACKAGE)
    assert names_from(refs, MODULE_PACKAGE) == {"module", "versions_dir"}


def test_a_name_taken_from_the_package_is_still_reported(tmp_path: Path) -> None:
    """The write surface is usually taken straight off the package, so the name
    check has to see it even though it is not a reach-in."""
    refs = _scan(tmp_path, f"from {MODULE_PACKAGE} import stage_allocation\n")
    assert "stage_allocation" in names_from(refs, MODULE_PACKAGE)
    assert not submodule_reach_ins(refs, MODULE_PACKAGE)


# ── The plain `import x` form the profile guard was blind to ────────────────


def test_the_scanner_sees_a_plain_module_import(tmp_path: Path) -> None:
    """`import vendor_cp.deployment_profile as p; p.load_deployment_profile()`
    was invisible to an ImportFrom-only walk."""
    refs = _scan(tmp_path, "import vendor_cp.deployment_profile as p\n")
    assert reaches_module(refs, "vendor_cp.deployment_profile")
    assert "vendor_cp.deployment_profile" in module_targets(refs)


def test_possible_targets_are_a_superset_of_unambiguous_ones(tmp_path: Path) -> None:
    """The two sets must not drift into disagreement: everything unambiguous is
    also possible, and the possible set adds only `module.name` pairs."""
    refs = _scan(
        tmp_path,
        "import a.b\nfrom c.d import e\n",
    )
    assert module_targets(refs) == {"a.b", "c.d"}
    assert possible_module_targets(refs) == {"a.b", "c.d", "c.d.e"}


# ── the surface, not just the parser ────────────────────────────────────────


def test_source_files_reads_a_payload_that_is_not_named_dot_py() -> None:
    """SENSITIVITY for the widened surface, in the real tree.

    Five guards ask "does any source file reach for X?" through `source_files`,
    and while it globbed `*.py` all five were blind to
    `src/vendor_cp/rotation_runtime_oracle.pyprogram` — Python, executed by the
    deployed application's interpreter, and named something else. This fails if
    the surface is narrowed back.
    """

    from import_scanner import SRC, source_files

    found = {path.relative_to(SRC).as_posix() for path in source_files(SRC)}
    payloads = sorted(name for name in found if not name.endswith(".py"))
    assert payloads, (
        "`source_files` is `.py`-only again. A file the product's interpreter "
        "executes is Python whatever it is named."
    )
    assert "vendor_cp/rotation_runtime_oracle.pyprogram" in payloads


def test_source_files_refuses_what_no_python_interpreter_runs() -> None:
    """NEAR-MISS, permanent. Widening must not turn every file into `source`:
    the shell oracle and the SQL catalogue live in the same directory tree and
    must stay out, or a guard reports having checked text it cannot parse."""

    from import_scanner import SRC, source_files

    found = {path.relative_to(SRC).as_posix() for path in source_files(SRC)}
    assert "vendor_cp/rotation_database_auth_oracle.shprogram" not in found
    assert "vendor_cp/recovery/capture_catalog.sql" not in found
