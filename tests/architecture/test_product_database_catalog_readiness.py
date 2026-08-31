"""The build-once database catalogue gap is exact and cannot drift quietly."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from check_product_database_catalog_readiness import (  # noqa: E402
    MODULE_DATABASE_CATALOG_DEBT,
    OPEN_PRODUCT_DATABASE_CATALOG_BLOCKERS,
    ProductDatabaseCatalogBlockerCode,
    accepted_descriptor_identity,
    missing_module_database_catalogs,
)


def test_module_database_catalog_debt_matches_the_pinned_composition_both_ways() -> (
    None
):
    assert missing_module_database_catalogs() == MODULE_DATABASE_CATALOG_DEBT


@dataclass(frozen=True, slots=True)
class _Module:
    code: str
    database_catalog: object | None


def test_debt_detector_is_sensitive_to_presence_and_absence() -> None:
    modules = (
        _Module(code="missing", database_catalog=None),
        _Module(code="published", database_catalog=object()),
    )

    assert missing_module_database_catalogs(modules) == frozenset({"missing"})


def test_every_unautomated_product_obligation_is_explicit() -> None:
    """Module completeness must never be misreported as product readiness.

    These controls depend on unpublished APIs or on release-time held bytes, so
    a source-only detector cannot derive them honestly.  Their register stays
    exact and fail-closed until the proving integration lands with each removal.
    """

    codes = tuple(blocker.code for blocker in OPEN_PRODUCT_DATABASE_CATALOG_BLOCKERS)
    assert len(codes) == len(set(codes))
    assert set(codes) == set(ProductDatabaseCatalogBlockerCode)
    assert all(
        blocker.retire_when for blocker in OPEN_PRODUCT_DATABASE_CATALOG_BLOCKERS
    )


def test_release_catalogue_and_release_artifact_obligations_fail_closed() -> None:
    blockers = {
        blocker.code: blocker.retire_when
        for blocker in OPEN_PRODUCT_DATABASE_CATALOG_BLOCKERS
    }

    assert ProductDatabaseCatalogBlockerCode.RELEASE_CATALOG_ATTESTATIONS in blockers
    assert ProductDatabaseCatalogBlockerCode.RELEASE_ARTIFACT_BINDING in blockers
    assert (
        "module and product"
        in blockers[ProductDatabaseCatalogBlockerCode.RELEASE_CATALOG_ATTESTATIONS]
    )
    assert (
        "same image or artifact"
        in blockers[ProductDatabaseCatalogBlockerCode.RELEASE_ARTIFACT_BINDING]
    )


def test_accepted_descriptor_facts_expose_the_current_binding_gap() -> None:
    """Record facts, without inventing Foundation v2's unpublished parser.

    The lexical product identities differ.  That is not itself declared an
    error: the frozen descriptor coordinate may legitimately differ from the
    assembly name.  What is missing is the explicit typed mapping consumed by
    the future product snapshot factory.
    """

    identity = accepted_descriptor_identity()
    assert identity.schema == "ProductDeploymentSpec.v1"
    assert identity.descriptor_product == "dotmac_vendor_control_plane"
    assert identity.assembly_name == "dotmac-vendor-control-plane"
    assert identity.descriptor_product != identity.assembly_name
    assert identity.has_database_catalog_coordinates is False
