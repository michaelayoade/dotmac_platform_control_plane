"""Entitlement Allocation's installed-but-not-cut-over boundary.

This slice deliberately composes the independent owner without lying about the
consumer transition: the legacy writer stays authoritative until contracts own
``product_code`` and the historical-data preflight passes.
"""

from __future__ import annotations

import inspect
import tomllib
from pathlib import Path
from typing import get_type_hints

from dotmac_entitlement_allocation import CapabilityCatalogueReader
from dotmac_entitlement_allocation import module as allocation_module
from dotmac_entitlement_allocation import versions_dir as allocation_versions_dir
from sqlalchemy.orm import configure_mappers

from vendor_cp.allocations import service as legacy_allocation_service
from vendor_cp.allocations.feature import feature as legacy_allocation_feature
from vendor_cp.allocations.preflight import preflight_allocation_cutover
from vendor_cp.assembly import build_spec
from vendor_cp.contracts import router as contract_router
from vendor_cp.contracts import service as contract_service
from vendor_cp.migrations import composed_version_locations
from vendor_cp.offers import catalog as offer_catalogue
from vendor_cp.offers import router as offer_router
from vendor_cp.offers import service as offer_service
from vendor_cp.shadow_overlaps import AUTHORITATIVE_WRITER, overlapped_legacy_tables

ROOT = Path(__file__).resolve().parents[2]


def test_entitlement_allocation_is_exact_pinned_from_forgejo() -> None:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    dependency = config["tool"]["poetry"]["dependencies"][
        "dotmac-entitlement-allocation"
    ]
    assert dependency == {"version": "0.1.0a4", "source": "forgejo"}


def test_the_module_owns_a_platform_plane_and_the_shadow_is_declared() -> None:
    """a4 is what makes the shadow state auditable rather than merely tolerated.

    Through a3 the module declared its tables under the TENANT contract while
    its migration built platform-shaped ones, so the composed live-catalogue
    audit could not hold `mod_ealloc` to any true contract. At a4 the tables are
    `platform_tables`, the audit is meaningful, and the one thing it legitimately
    reports — the legacy `public` tables shadowing the module's names — is
    declared in `vendor_cp.shadow_overlaps` with an owner, a ratchet and an end.
    """
    assert allocation_module.tables == ()
    assert set(allocation_module.platform_tables) == {
        "allocations",
        "allocation_entries",
    }
    assert overlapped_legacy_tables() == {
        "public.allocations",
        "public.allocation_entries",
    }
    assert AUTHORITATIVE_WRITER == "vendor_cp.allocations.service"


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


def test_commercial_services_consume_the_module_owned_catalogue_port() -> None:
    assert (
        get_type_hints(offer_service.publish_offer_version)["catalogues"]
        is CapabilityCatalogueReader
    )
    assert (
        get_type_hints(contract_service.submit)["catalogues"]
        is CapabilityCatalogueReader
    )
    source = inspect.getsource(offer_catalogue)
    assert "class ProductCapabilityCatalogueReader" not in source
    assert "active_capabilities" not in source


def test_catalogue_module_errors_are_mapped_at_both_http_boundaries() -> None:
    for endpoint in (offer_router.publish, contract_router.submit):
        source = inspect.getsource(endpoint)
        assert "except AllocationError" in source
        assert "catalogue_domain_error" in source


def test_cutover_preflight_has_no_write_calls() -> None:
    source = inspect.getsource(preflight_allocation_cutover)
    for forbidden in ("db.add(", "db.flush(", "db.commit(", "db.delete("):
        assert forbidden not in source
