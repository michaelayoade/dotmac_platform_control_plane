"""Commercial Agreements is the one agreement owner in this assembly.

The cutover is complete only when the published module is exact-pinned and
composed, Vendor reaches its lifecycle through one typed adapter, the retired
local writer is absent, and the activation consumer follows the module's
versioned fact rather than the legacy event spelling.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from dotmac_commercial_agreements import (
    AGREEMENT_ACTIVATED_V1,
    AUDIT_ACTION_TRANSITIONED,
)
from dotmac_commercial_agreements import (
    module as commercial_agreements_module,
)
from dotmac_commercial_agreements import (
    versions_dir as commercial_agreements_versions_dir,
)
from import_scanner import reaches_module, scan_imports, source_files

from vendor_cp.assembly import build_spec
from vendor_cp.contracts_authority import (
    ADAPTER_MODULE,
    AUTHORITY,
    RETIRED_LOCAL_MODELS,
    RETIRED_LOCAL_WRITER,
)
from vendor_cp.migrations import composed_version_locations

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
PACKAGE = SRC / "vendor_cp"

PERMITTED_NAMERS = {
    "vendor_cp/assembly.py",
    "vendor_cp/contracts/adapter.py",
    "vendor_cp/migrations.py",
}


def _refs(path: Path):
    return scan_imports(path, source_root=SRC)


def test_the_published_module_is_exact_pinned_and_composed() -> None:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert config["tool"]["poetry"]["dependencies"][AUTHORITY.replace("_", "-")] == {
        "version": "0.1.0a1",
        "source": "forgejo",
    }
    assert commercial_agreements_module in build_spec().modules
    assert (
        str(commercial_agreements_versions_dir())
        in composed_version_locations().split()
    )


def test_the_legacy_contract_owner_is_gone() -> None:
    assert not (PACKAGE / "contracts" / "service.py").exists()
    assert not (PACKAGE / "contracts" / "models.py").exists()


def test_no_source_file_reaches_the_retired_owner() -> None:
    retired = (RETIRED_LOCAL_WRITER, RETIRED_LOCAL_MODELS)
    callers = sorted(
        f"{path.relative_to(SRC).as_posix()} -> {target}"
        for path in source_files(PACKAGE)
        for target in retired
        if reaches_module(_refs(path), target)
    )
    assert callers == [], callers


def test_the_retired_owner_guard_can_see_a_regression(tmp_path: Path) -> None:
    package = tmp_path / "src" / "vendor_cp" / "somewhere"
    package.mkdir(parents=True)
    probe = package / "probe.py"
    probe.write_text(f"from {RETIRED_LOCAL_WRITER} import activate\n")
    assert reaches_module(
        scan_imports(probe, source_root=tmp_path / "src"), RETIRED_LOCAL_WRITER
    )


def test_only_the_adapter_and_composition_name_the_module() -> None:
    namers = {
        path.relative_to(SRC).as_posix()
        for path in source_files(PACKAGE)
        if reaches_module(_refs(path), AUTHORITY)
    }
    assert namers == PERMITTED_NAMERS, sorted(namers ^ PERMITTED_NAMERS)


def test_the_adapter_is_typed_and_is_the_real_seam() -> None:
    adapter_path = PACKAGE / "contracts" / "adapter.py"
    source = adapter_path.read_text()
    assert (
        ADAPTER_MODULE.replace(".", "/") + ".py"
        == adapter_path.relative_to(SRC).as_posix()
    )
    assert ": Any" not in source
    assert "-> Any" not in source
    assert "module_open_draft" in source
    assert "module_activate" in source


def test_the_activation_consumer_uses_the_published_versioned_fact() -> None:
    from vendor_cp.allocations.consumer import ACTIVATED_EVENT_TYPE

    assert ACTIVATED_EVENT_TYPE == AGREEMENT_ACTIVATED_V1
    assert ACTIVATED_EVENT_TYPE != "contract.activated"


def test_the_module_owns_the_installed_audit_action() -> None:
    owners = [
        manifest.name
        for manifest in build_spec().modules
        if AUDIT_ACTION_TRANSITIONED in manifest.audit_actions
    ]
    assert owners == [commercial_agreements_module.name]
