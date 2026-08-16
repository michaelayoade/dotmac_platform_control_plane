"""Entitlement Allocation is composed, pinned, and the AUTHORITY.

This file used to assert the shadow boundary — that the module was installed
while the legacy writer stayed authoritative. That phase ended with `v014`, so
the shadow-specific assertions are gone and the durable ones remain: the pin is
exact, the manifest and public lineage are composed, the commercial services
consume the module's typed catalogue PORT rather than a duplicate protocol, and
both HTTP boundaries map its refusals.
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

from vendor_cp.assembly import build_spec
from vendor_cp.contracts import router as contract_router
from vendor_cp.contracts import service as contract_service
from vendor_cp.migrations import composed_version_locations
from vendor_cp.offers import catalog as offer_catalogue
from vendor_cp.offers import router as offer_router
from vendor_cp.offers import service as offer_service

ROOT = Path(__file__).resolve().parents[2]


def test_entitlement_allocation_is_exact_pinned_from_forgejo() -> None:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    dependency = config["tool"]["poetry"]["dependencies"][
        "dotmac-entitlement-allocation"
    ]
    assert dependency == {"version": "0.1.0a4", "source": "forgejo"}


def test_the_module_owns_a_platform_plane_and_the_names_are_free() -> None:
    """a4 declares its tables on the PLATFORM plane. With `v014` dropping the
    vendor-local `allocations` / `allocation_entries`, the module's names no
    longer collide with anything in `public` — which is why the composed audit
    needs no exemption at all now."""
    assert allocation_module.tables == ()
    assert set(allocation_module.platform_tables) == {
        "allocations",
        "allocation_entries",
    }


def test_module_manifest_and_public_lineage_are_composed() -> None:
    assert allocation_module in build_spec().modules
    locations = composed_version_locations().split()
    assert str(allocation_versions_dir()) in locations
    # kernel + release catalog + entitlement allocation + approvals + vendor
    assert len(locations) == 5


def test_the_module_mappers_load_in_this_process() -> None:
    """The module's ORM is the only allocation ORM now, and it must configure
    cleanly alongside the assembly's own models."""
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
