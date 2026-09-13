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

    assert dependencies["dotmac-kernel"]["version"] == "0.1.0a100"
    assert dependencies["dotmac-kernel"]["source"] == "forgejo"
    # Every authority module pin is asserted. Only the release catalogue was, which is
    # how the entitlement-allocation pin could have drifted to a range or to a
    # path dependency without a single test noticing.
    #
    # `dotmac-deployment-control` was the exception that outlived the comment:
    # the one authority pin this programme actually moves had no literal guard,
    # under a sentence claiming there were none left. Asserted now, exactly like
    # its siblings — the shape matters as much as the number, because a dict
    # comparison refuses a caret, a range and a path dependency in one assertion.
    assert dependencies["dotmac-deployment-control"] == {
        "version": "0.1.0a12",
        "source": "forgejo",
    }
    assert dependencies["dotmac-release-catalog"] == {
        "version": "0.1.0a4",
        "source": "forgejo",
    }
    assert dependencies["dotmac-entitlement-allocation"] == {
        "version": "0.1.0a6",
        "source": "forgejo",
    }
    assert dependencies["dotmac-approvals"] == {
        "version": "0.1.0a5",
        "source": "forgejo",
    }
    assert dependencies["dotmac-commercial-agreements"] == {
        "version": "0.1.0a2",
        "source": "forgejo",
    }
    assert dependencies["dotmac-licensing"] == {
        "version": "0.1.0a1",
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
    # kernel + release catalog + allocation + approvals + agreements
    # + licensing + vendor
    assert len(locations) == 8
