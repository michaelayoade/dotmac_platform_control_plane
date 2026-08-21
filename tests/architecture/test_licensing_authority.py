"""Licensing is the one issuer owner in this assembly.

Vendor keeps key custody and delivery.  The released module owns licence
lineage, immutable issuance, public verification keys, lifecycle,
acknowledgements and revocation.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from dotmac_licensing import (
    AUDIT_ACTION_ACKNOWLEDGED,
    AUDIT_ACTION_ISSUED,
    AUDIT_ACTION_TRANSITIONED,
)
from dotmac_licensing import module as licensing_module
from dotmac_licensing import versions_dir as licensing_versions_dir
from import_scanner import reaches_module, scan_imports, source_files

from vendor_cp.assembly import build_spec
from vendor_cp.licensing.delivery_models import LicenceDelivery
from vendor_cp.licensing_authority import (
    ADAPTER_MODULE,
    AUTHORITY,
    RETIRED_LOCAL_MODULES,
)
from vendor_cp.migrations import composed_version_locations

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
PACKAGE = SRC / "vendor_cp"

PERMITTED_NAMERS = {
    "vendor_cp/assembly.py",
    "vendor_cp/licensing/adapter.py",
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
    assert licensing_module in build_spec().modules
    assert str(licensing_versions_dir()) in composed_version_locations().split()


def test_the_legacy_issuer_is_gone() -> None:
    for module in RETIRED_LOCAL_MODULES:
        path = SRC / (module.replace(".", "/") + ".py")
        assert not path.exists(), path


def test_no_source_file_reaches_a_retired_issuer_module() -> None:
    callers = sorted(
        f"{path.relative_to(SRC).as_posix()} -> {target}"
        for path in source_files(PACKAGE)
        for target in RETIRED_LOCAL_MODULES
        if reaches_module(_refs(path), target)
    )
    assert callers == [], callers


def test_the_retired_owner_guard_can_see_a_regression(tmp_path: Path) -> None:
    package = tmp_path / "src" / "vendor_cp" / "somewhere"
    package.mkdir(parents=True)
    probe = package / "probe.py"
    probe.write_text("from vendor_cp.licensing.service import issue_licence\n")
    assert reaches_module(
        scan_imports(probe, source_root=tmp_path / "src"),
        "vendor_cp.licensing.service",
    )


def test_only_the_adapter_and_composition_name_the_module() -> None:
    namers = {
        path.relative_to(SRC).as_posix()
        for path in source_files(PACKAGE)
        if reaches_module(_refs(path), AUTHORITY)
    }
    assert namers == PERMITTED_NAMERS, sorted(namers ^ PERMITTED_NAMERS)


def test_the_adapter_is_typed_and_is_the_real_seam() -> None:
    adapter_path = PACKAGE / "licensing" / "adapter.py"
    source = adapter_path.read_text()
    assert (
        ADAPTER_MODULE.replace(".", "/") + ".py"
        == adapter_path.relative_to(SRC).as_posix()
    )
    assert ": Any" not in source
    assert "-> Any" not in source
    assert "module_issue_licence" in source
    assert "module_acknowledge" in source


def test_delivery_keeps_only_an_opaque_issuance_reference() -> None:
    assert LicenceDelivery.__table__.c.issuance_id.foreign_keys == set()


def test_the_module_owns_the_issuer_audit_vocabulary() -> None:
    module_actions = {
        AUDIT_ACTION_ISSUED,
        AUDIT_ACTION_TRANSITIONED,
        AUDIT_ACTION_ACKNOWLEDGED,
    }
    owners = {
        action: [
            manifest.name
            for manifest in build_spec().modules
            if action in manifest.audit_actions
        ]
        for action in module_actions
    }
    assert owners == {action: [licensing_module.name] for action in module_actions}

    vendor = next(
        manifest
        for manifest in build_spec().modules
        if manifest.name == "licence_delivery"
    )
    assert not module_actions.intersection(vendor.audit_actions)
