#!/usr/bin/env python3
"""Enumerate what blocks a verified product database catalogue.

This check does not define a database schema and does not inspect a database.
It asks the exact module manifests composed by this checkout whether they carry
the kernel-owned typed contribution.  The declared debt is a two-directional
ratchet: adding an owner or publishing one contribution requires the checked-in
set to change in the same review.

The remaining product-level obligations cannot yet be derived safely: the
observer/comparator, canonical factory, held artifact verifier and descriptor
v2 parser are unpublished.  They are therefore a separate typed, fail-closed
register.  A reviewer may remove an entry only with the integration that makes
its retirement machine-provable.  Merely publishing every module contribution
can never make this command report product readiness.
"""

from __future__ import annotations

import tomllib
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final, Protocol

from vendor_cp.assembly import ASSEMBLY_NAME, STATEFUL_MODULES

ROOT: Final = Path(__file__).resolve().parents[1]
ACCEPTED_DESCRIPTOR: Final = ROOT / "deploy" / "product.toml"

MODULE_DATABASE_CATALOG_DEBT: Final[frozenset[str]] = frozenset(
    {
        "approvals",
        "commercial_agreements",
        "deployment_control",
        "entitlement_allocation",
        "licensing",
        "release_catalog",
    }
)


class ProductDatabaseCatalogBlockerCode(StrEnum):
    """Stable codes for product-level obligations not yet machine-provable."""

    OBSERVER_COMPARATOR = "observer_comparator_unavailable"
    HELD_SNAPSHOT = "held_snapshot_digest_unverified"
    PRODUCT_IDENTITY = "product_identity_mapping_absent"
    COMPLETE_COVERAGE = "complete_schema_coverage_unproved"
    RELEASE_CATALOG_ATTESTATIONS = "release_catalog_attestations_unavailable"
    RELEASE_ARTIFACT_BINDING = "product_catalog_release_artifact_unbound"
    DESCRIPTOR_V2 = "accepted_descriptor_v2_coordinate_unbound"


@dataclass(frozen=True, slots=True)
class ProductDatabaseCatalogBlocker:
    """One explicit fail-closed integration debt item."""

    code: ProductDatabaseCatalogBlockerCode
    retire_when: str


OPEN_PRODUCT_DATABASE_CATALOG_BLOCKERS: Final[
    tuple[ProductDatabaseCatalogBlocker, ...]
] = (
    ProductDatabaseCatalogBlocker(
        code=ProductDatabaseCatalogBlockerCode.OBSERVER_COMPARATOR,
        retire_when=(
            "the exact-pinned kernel exposes the supported observer and comparator "
            "and Platform CP invokes them over held bytes"
        ),
    ),
    ProductDatabaseCatalogBlocker(
        code=ProductDatabaseCatalogBlockerCode.HELD_SNAPSHOT,
        retire_when=(
            "the release path holds canonical snapshot bytes and verifies their "
            "digest before attestation or comparison"
        ),
    ),
    ProductDatabaseCatalogBlocker(
        code=ProductDatabaseCatalogBlockerCode.PRODUCT_IDENTITY,
        retire_when=(
            "the product snapshot factory receives an explicit reviewed mapping "
            "between assembly and descriptor product identities"
        ),
    ),
    ProductDatabaseCatalogBlocker(
        code=ProductDatabaseCatalogBlockerCode.COMPLETE_COVERAGE,
        retire_when=(
            "the product factory proves every selected stateful module and every "
            "host-owned schema fragment are present exactly once"
        ),
    ),
    ProductDatabaseCatalogBlocker(
        code=ProductDatabaseCatalogBlockerCode.RELEASE_CATALOG_ATTESTATIONS,
        retire_when=(
            "the exact-pinned Release Catalog supports distinct typed, singular "
            "module and product database-catalogue attestations"
        ),
    ),
    ProductDatabaseCatalogBlocker(
        code=ProductDatabaseCatalogBlockerCode.RELEASE_ARTIFACT_BINDING,
        retire_when=(
            "the release path emits canonical product-catalogue bytes beside the "
            "product manifest and attests both to the same image or artifact"
        ),
    ),
    ProductDatabaseCatalogBlocker(
        code=ProductDatabaseCatalogBlockerCode.DESCRIPTOR_V2,
        retire_when=(
            "the accepted ProductDeploymentSpec.v2 embeds a verified coordinate "
            "for the held product snapshot and promotion binds it atomically"
        ),
    ),
)


@dataclass(frozen=True, slots=True)
class AcceptedDescriptorIdentity:
    """Locally observable identity facts; not a proposed alias policy."""

    schema: str
    descriptor_product: str
    assembly_name: str
    has_database_catalog_coordinates: bool


def accepted_descriptor_identity(
    path: Path = ACCEPTED_DESCRIPTOR,
) -> AcceptedDescriptorIdentity:
    """Read only facts whose mismatch a future typed mapping must resolve.

    This deliberately does not guess the unpublished v2 coordinate shape.  A
    non-empty ``database.catalogs`` value is an observation, not validation;
    only Foundation's published parser may establish that the coordinates are
    well-typed and digest-bound.
    """

    descriptor = tomllib.loads(path.read_text())
    database = descriptor.get("database")
    coordinates = database.get("catalogs") if isinstance(database, dict) else None
    return AcceptedDescriptorIdentity(
        schema=str(descriptor.get("schema", "")),
        descriptor_product=str(descriptor.get("product", "")),
        assembly_name=ASSEMBLY_NAME,
        has_database_catalog_coordinates=bool(coordinates),
    )


class ModuleIdentity(Protocol):
    """The stable identity needed by this transitional readiness check."""

    @property
    def code(self) -> str: ...


def missing_module_database_catalogs(
    modules: Iterable[ModuleIdentity] = STATEFUL_MODULES,
) -> frozenset[str]:
    """Return stateful module codes whose pinned manifest has no contribution."""

    return frozenset(
        module.code
        for module in modules
        if getattr(module, "database_catalog", None) is None
    )


def main() -> int:
    missing = missing_module_database_catalogs()
    if missing:
        print(
            "product database catalogue is blocked by module contributions: "
            + ", ".join(sorted(missing))
        )
    else:
        print("all composed stateful modules publish database catalogue contributions")

    identity = accepted_descriptor_identity()
    print(
        "accepted descriptor facts: "
        f"schema={identity.schema!r}, "
        f"descriptor_product={identity.descriptor_product!r}, "
        f"assembly_name={identity.assembly_name!r}, "
        "database_catalog_coordinates="
        f"{identity.has_database_catalog_coordinates}"
    )
    for blocker in OPEN_PRODUCT_DATABASE_CATALOG_BLOCKERS:
        print(f"blocked: {blocker.code.value}: {blocker.retire_when}")
    return 2 if missing or OPEN_PRODUCT_DATABASE_CATALOG_BLOCKERS else 0


if __name__ == "__main__":
    raise SystemExit(main())
