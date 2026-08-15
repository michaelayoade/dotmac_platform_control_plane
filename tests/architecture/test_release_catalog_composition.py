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
from vendor_cp.migrations import approvals_versions_dir, composed_version_locations

ROOT = Path(__file__).resolve().parents[2]


def test_shared_dependencies_are_exact_published_pins() -> None:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    dependencies = config["tool"]["poetry"]["dependencies"]

    assert dependencies["dotmac-kernel"]["version"] == "0.1.0a61"
    assert dependencies["dotmac-kernel"]["source"] == "forgejo"
    # BOTH module pins are asserted. Only the release catalogue was, which is
    # how the entitlement-allocation pin could have drifted to a range or to a
    # path dependency without a single test noticing.
    assert dependencies["dotmac-release-catalog"] == {
        "version": "0.1.0a4",
        "source": "forgejo",
    }
    assert dependencies["dotmac-entitlement-allocation"] == {
        "version": "0.1.0a4",
        "source": "forgejo",
    }
    assert dependencies["dotmac-approvals"] == {
        "version": "0.1.0a3",
        "source": "forgejo",
    }


def test_release_catalog_manifest_is_composed() -> None:
    assert release_catalog_module in build_spec().modules


def test_vendor_ingestion_adapter_owns_its_audit_vocabulary() -> None:
    manifests = {manifest.name: manifest for manifest in build_spec().modules}
    assert manifests["release_evidence"].audit_actions == (
        "vendor.release_evidence.catalogued",
    )


def test_release_catalog_public_migration_lineage_is_composed() -> None:
    locations = composed_version_locations().split()
    assert str(release_catalog_versions_dir()) in locations
    # kernel + release catalog + entitlement allocation + approvals + vendor
    assert len(locations) == 5


def test_the_approvals_locator_shim_is_still_needed() -> None:
    """DELETE ME the moment `dotmac-approvals` ships a public locator.

    Every other installable module exposes `versions_dir()`, so a consumer
    never reconstructs a foreign package's layout. `dotmac-approvals` 0.1.0a3
    does not, and `vendor_cp.migrations.approvals_versions_dir` is this
    repository's only such reconstruction.

    This test FAILS once the locator appears, which is the point: a workaround
    whose removal depends on someone remembering is a workaround that becomes
    permanent. When it goes red, delete the shim and this test together.
    """
    import dotmac_approvals
    import dotmac_approvals.migrations as approvals_migrations

    assert not hasattr(dotmac_approvals, "versions_dir")
    assert not hasattr(approvals_migrations, "versions_dir")


def test_the_approvals_lineage_is_composed_despite_the_missing_locator() -> None:
    """Whatever the locator situation, the lineage must actually be composed:
    the assembly installs the module's PLATFORM plane, and a plane whose
    migrations never run is a declaration with no database behind it."""
    assert str(approvals_versions_dir()) in composed_version_locations().split()
    assert (approvals_versions_dir() / "ap_0001_approvals.py").is_file()
