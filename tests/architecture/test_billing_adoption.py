"""Vendor CP prepares Billing's platform plane without activating money flows."""

from __future__ import annotations

import ast
import inspect
import tomllib
from pathlib import Path
from typing import Any, get_type_hints

import pytest
from dotmac_billing import (
    BillingPlane,
    CommercialAuthority,
    bind_commercial_authority,
)
from dotmac_billing import (
    module as billing_module,
)
from dotmac_kernel.planes import ModulePlane

from vendor_cp.assembly import STATEFUL_MODULES, build_spec
from vendor_cp.billing.authority import (
    PlatformBillingRepository,
    install_billing_authority,
)
from vendor_cp.migration_bindings import ASSEMBLY_MODULE_PLANES
from vendor_cp.migrations import composed_version_locations

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "alembic/versions/v015_billing_platform_prep.py"


def test_billing_and_its_kernel_floor_are_exact_release_candidate_pins() -> None:
    dependencies = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"][
        "poetry"
    ]["dependencies"]
    assert dependencies["dotmac-billing"] == {
        "version": "0.1.0a1",
        "source": "forgejo",
    }
    assert dependencies["dotmac-kernel"]["version"] == "0.1.0a69"


def test_billing_is_composed_and_selects_only_the_platform_plane() -> None:
    assert billing_module in STATEFUL_MODULES
    assert billing_module in build_spec().modules
    selections = {
        selection.module: {ModulePlane(plane) for plane in selection.planes}
        for selection in ASSEMBLY_MODULE_PLANES
    }
    assert selections["billing"] == {ModulePlane.PLATFORM}
    assert ModulePlane.TENANT not in selections["billing"]


def test_the_billing_lineage_is_in_the_only_composed_migration_graph() -> None:
    locations = composed_version_locations().split()
    assert any("dotmac_billing" in location for location in locations)
    assert len(locations) == len(set(locations))


def test_internal_authority_is_bound_to_a_typed_platform_repository() -> None:
    binding = install_billing_authority()
    repository = binding.repository_factory()
    assert binding.authority is CommercialAuthority.INTERNAL
    assert binding.plane is BillingPlane.PLATFORM
    assert isinstance(repository, PlatformBillingRepository)
    assert repository.plane is BillingPlane.PLATFORM
    with pytest.raises(ValueError, match="already bound"):
        bind_commercial_authority(
            CommercialAuthority.EXTERNAL_FINANCE,
            platform_repository_factory=PlatformBillingRepository,
        )


def test_vendor_billing_boundary_is_fully_typed() -> None:
    hints = get_type_hints(PlatformBillingRepository)
    assert hints == {"plane": BillingPlane}
    return_type = get_type_hints(install_billing_authority)["return"]
    assert return_type not in {Any, object}
    assert inspect.signature(install_billing_authority).parameters == {}


def test_product_links_use_only_the_platform_helper() -> None:
    source = MIGRATION.read_text(encoding="utf-8")
    assert source.count("link_platform_billing_account(") == 2
    assert "link_tenant_billing_account" not in source
    assert "tenant_id" not in source
    assert "fake_tenant" not in source.lower()
    assert "sentinel" not in source.lower()


def test_preparation_adds_no_route_or_second_money_writer() -> None:
    billing_root = ROOT / "src/vendor_cp/billing"
    tree = ast.parse("\n".join(path.read_text() for path in billing_root.glob("*.py")))
    imported = {
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }
    assert "dotmac_billing.service" not in imported
    assert not (billing_root / "router.py").exists()
    assert not (billing_root / "service.py").exists()


def test_kernel_a69_audit_vocabulary_is_declared_by_each_vendor_owner() -> None:
    expected = {
        "accounts": {"vendor.account.created"},
        "offers": {"vendor.offer_version.published"},
        "contracts": {
            "vendor.contract.activated",
            "vendor.contract.approved",
            "vendor.contract.cancelled",
            "vendor.contract.drafted",
            "vendor.contract.expired",
            "vendor.contract.reinstated",
            "vendor.contract.rejected",
            "vendor.contract.submitted",
            "vendor.contract.suspended",
            "vendor.contract.terminated",
        },
        "licensing": {
            "vendor.licence.ack_quarantined",
            "vendor.licence.ack_received",
            "vendor.licence.bundle_exported",
            "vendor.licence.delivered",
            "vendor.licence.delivery_attempt_failed",
            "vendor.licence.delivery_mapped",
            "vendor.licence.delivery_parked",
            "vendor.licence.delivery_resumed",
            "vendor.licence.delivery_target_registered",
            "vendor.licence.delivery_target_updated",
            "vendor.licence.issued",
            "vendor.licence.revocation_list_published",
            "vendor.licence.revoked",
        },
    }
    manifests = {
        manifest.name: manifest
        for manifest in build_spec().modules
        if hasattr(manifest, "name")
    }
    assert {name: set(manifests[name].audit_actions) for name in expected} == expected
