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

The module half of that ratchet is currently DORMANT, and saying so is the
point.  ``missing_module_database_catalogs`` asks each composed manifest for a
``database_catalog`` attribute, and the EXACT-PINNED kernel's ``ModuleManifest``
declares no such field — so no module could carry one even if its own release
published it.  Today the probe therefore reports all six for a reason about the
KERNEL rather than about the modules, and only its composition half can fail.
``pinned_manifest_declares_contribution_field`` states that premise so a test
can hold it: when the pin moves to a kernel carrying the field, the premise dies
and the review that raised the pin has to confirm the probe now measures the
thing its name claims (``AGENTS.md`` rule 13 — a guard premise is enforceable or
the region is unmonitored rather than exempt).
"""

from __future__ import annotations

import dataclasses
import tomllib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final, Protocol

from dotmac_kernel import ModuleManifest

from vendor_cp.assembly import ASSEMBLY_NAME, STATEFUL_MODULES

ROOT: Final = Path(__file__).resolve().parents[1]
ACCEPTED_DESCRIPTOR: Final = ROOT / "deploy" / "product.toml"

#: The manifest attribute a module publishes its typed database-catalogue
#: contribution through.  Named ONCE: the probe below and the premise check
#: that says why the probe is dormant have to be asking about one attribute,
#: and two literals is exactly how they would stop being about the same one.
CONTRIBUTION_FIELD: Final = "database_catalog"

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
        if getattr(module, CONTRIBUTION_FIELD, None) is None
    )


def pinned_manifest_declares_contribution_field(
    manifest: type = ModuleManifest,
) -> bool:
    """Whether the EXACT-PINNED kernel's manifest type can carry a contribution.

    This is the premise the module probe above rests on, made observable.  While
    it is False, ``missing_module_database_catalogs`` cannot report anything but
    every composed stateful module, because the attribute it reads is one no
    manifest of this generation has: a module release that published a
    contribution could not even be constructed against this kernel.  The probe is
    a FORWARD probe, and its "all six" is not evidence about the six.

    Kept next to the probe rather than in the test, so the two read the same
    ``CONTRIBUTION_FIELD`` and cannot drift into asking about different
    attributes.
    """

    return CONTRIBUTION_FIELD in {field.name for field in dataclasses.fields(manifest)}


def main(
    modules: Iterable[ModuleIdentity] = STATEFUL_MODULES,
    blockers: Sequence[ProductDatabaseCatalogBlocker] = (
        OPEN_PRODUCT_DATABASE_CATALOG_BLOCKERS
    ),
    descriptor: Path = ACCEPTED_DESCRIPTOR,
) -> int:
    """Report the two registers and exit 2 while either still holds anything.

    The three parameters exist so the exit contract can be EXERCISED.  Nothing
    calls this command — not CI, not the Makefile, not a test — so until now its
    ``return 2`` was a sentence in a document rather than an observed behaviour,
    and the zero branch had never been reached by anything at all.  A reader of
    the operations note is told the command "continues to exit 2"; that claim is
    worth what the command does.  Defaults are the real registers, so the CLI is
    unchanged.
    """

    missing = missing_module_database_catalogs(modules)
    if missing:
        print(
            "product database catalogue is blocked by module contributions: "
            + ", ".join(sorted(missing))
        )
    else:
        print("all composed stateful modules publish database catalogue contributions")

    if not pinned_manifest_declares_contribution_field():
        print(
            "note: the pinned kernel's ModuleManifest declares no "
            f"{CONTRIBUTION_FIELD!r} field, so the line above reports the "
            "composition and not any module's publication state"
        )

    identity = accepted_descriptor_identity(descriptor)
    print(
        "accepted descriptor facts: "
        f"schema={identity.schema!r}, "
        f"descriptor_product={identity.descriptor_product!r}, "
        f"assembly_name={identity.assembly_name!r}, "
        "database_catalog_coordinates="
        f"{identity.has_database_catalog_coordinates}"
    )
    for blocker in blockers:
        print(f"blocked: {blocker.code.value}: {blocker.retire_when}")
    return 2 if missing or blockers else 0


if __name__ == "__main__":
    raise SystemExit(main())
