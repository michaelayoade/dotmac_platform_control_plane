"""The published Release Catalog is an explicit assembly dependency.

These are assembly canaries, not module tests: they prove the vendor control
plane pins the exact reviewed distributions, composes the module manifest, and
uses only the module's public migration locator.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from dotmac_release_catalog import module as release_catalog_module
from dotmac_release_catalog import versions_dir as release_catalog_versions_dir

from vendor_cp.assembly import build_spec
from vendor_cp.migrations import composed_version_locations

ROOT = Path(__file__).resolve().parents[2]


def test_shared_dependencies_are_exact_published_pins() -> None:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    dependencies = config["tool"]["poetry"]["dependencies"]

    assert dependencies["dotmac-kernel"]["version"] == "0.1.0a45"
    assert dependencies["dotmac-kernel"]["source"] == "forgejo"
    assert dependencies["dotmac-release-catalog"] == {
        "version": "0.1.0a2",
        "source": "forgejo",
    }


def test_release_catalog_manifest_is_composed() -> None:
    assert release_catalog_module in build_spec().modules


def test_release_catalog_public_migration_lineage_is_composed() -> None:
    locations = composed_version_locations().split()
    assert str(release_catalog_versions_dir()) in locations
    assert len(locations) == 4
