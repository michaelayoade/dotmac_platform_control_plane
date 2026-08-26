"""Billing and Subscriptions are schema shadows, not runtime authorities."""

from __future__ import annotations

from pathlib import Path

from import_scanner import reaches_module, scan_imports, source_files

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
PACKAGE = SRC / "vendor_cp"

COMPOSITION_FILES = {
    "vendor_cp/assembly.py",
    "vendor_cp/migrations.py",
}


def _namers(module: str) -> set[str]:
    return {
        path.relative_to(SRC).as_posix()
        for path in source_files(PACKAGE)
        if reaches_module(scan_imports(path, source_root=SRC), module)
    }


def test_only_composition_plumbing_imports_the_commercial_modules() -> None:
    assert _namers("dotmac_billing") == COMPOSITION_FILES
    assert _namers("dotmac_subscriptions") == COMPOSITION_FILES


def test_no_runtime_commercial_authority_binding_lands_with_the_schema() -> None:
    sources = "\n".join(
        path.read_text() for path in source_files(PACKAGE) if path.suffix == ".py"
    )
    assert "bind_commercial_authority" not in sources
    assert "CommercialAuthority" not in sources
