"""Entitlement Allocation's installed-but-not-cut-over boundary.

This slice deliberately composes the independent owner without lying about the
consumer transition: the legacy writer stays authoritative until contracts own
``product_code`` and the historical-data preflight passes.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from dotmac_entitlement_allocation import module as allocation_module
from dotmac_entitlement_allocation import versions_dir as allocation_versions_dir
from sqlalchemy.orm import configure_mappers

from vendor_cp.allocations import service as legacy_allocation_service
from vendor_cp.allocations.feature import feature as legacy_allocation_feature
from vendor_cp.assembly import build_spec
from vendor_cp.migrations import composed_version_locations

ROOT = Path(__file__).resolve().parents[2]


def test_entitlement_allocation_is_exact_pinned_from_forgejo() -> None:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    dependency = config["tool"]["poetry"]["dependencies"][
        "dotmac-entitlement-allocation"
    ]
    assert dependency == {"version": "0.1.0a3", "source": "forgejo"}


def test_module_manifest_and_public_lineage_are_composed() -> None:
    assert allocation_module in build_spec().modules
    locations = composed_version_locations().split()
    assert str(allocation_versions_dir()) in locations
    assert len(locations) == 4


def test_shadow_install_does_not_silently_switch_the_writer() -> None:
    """No dual-write or invented product identity before the cutover gate."""
    assert legacy_allocation_feature in build_spec().modules
    assert legacy_allocation_service.stage_allocation.__module__.startswith(
        "vendor_cp.allocations"
    )


def test_legacy_and_independent_allocation_mappers_coexist() -> None:
    """A shadow phase requires both models to load in the same process."""
    configure_mappers()
