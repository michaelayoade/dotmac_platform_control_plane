"""The build-once database catalogue gap is exact and cannot drift quietly."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from check_product_database_catalog_readiness import (  # noqa: E402
    CONTRIBUTION_FIELD,
    MODULE_DATABASE_CATALOG_DEBT,
    OPEN_PRODUCT_DATABASE_CATALOG_BLOCKERS,
    ProductDatabaseCatalogBlockerCode,
    accepted_descriptor_identity,
    main,
    missing_module_database_catalogs,
    pinned_manifest_declares_contribution_field,
)


def test_module_database_catalog_debt_matches_the_pinned_composition_both_ways() -> (
    None
):
    assert missing_module_database_catalogs() == MODULE_DATABASE_CATALOG_DEBT


@dataclass(frozen=True, slots=True)
class _Module:
    code: str
    database_catalog: object | None


@dataclass(frozen=True, slots=True)
class _ManifestGenerationWithoutContributions:
    """A manifest type of the generation this assembly is pinned to."""

    code: str


def test_debt_detector_is_sensitive_to_presence_and_absence() -> None:
    modules = (
        _Module(code="missing", database_catalog=None),
        _Module(code="published", database_catalog=object()),
    )

    assert missing_module_database_catalogs(modules) == frozenset({"missing"})


def test_the_module_probe_is_dormant_because_the_pinned_kernel_carries_no_field() -> (
    None
):
    """Say why the probe reports all six, because it is not about the six.

    ``missing_module_database_catalogs`` reads a manifest attribute that the
    EXACT-PINNED kernel's ``ModuleManifest`` does not declare.  While that holds,
    no module release could publish a contribution even in principle — the
    manifest could not be constructed — so the probe's composition half is the
    only half that can fail, and "all six are missing" is a fact about the kernel
    generation rather than about any module owner.

    The operations note previously claimed that "adopting a contribution cannot
    pass silently".  Half of that was true and half was not, and nothing said
    which.  This assertion is the premise made enforceable (``AGENTS.md`` rule
    13): the moment the pin moves to a kernel whose manifest carries the field,
    this test fails, and the review that raised the pin has to confirm that the
    probe now measures what its name says.  Had the kernel named the field
    anything else, the ratchet would have sat at all-six for ever and a repin
    would have passed over it in silence.
    """

    assert not pinned_manifest_declares_contribution_field(), (
        f"the pinned kernel's ModuleManifest now declares {CONTRIBUTION_FIELD!r}. "
        "The module probe is no longer dormant: confirm in this same change that "
        "each composed module's pinned release either publishes a contribution or "
        "is still recorded in MODULE_DATABASE_CATALOG_DEBT for a reason about "
        "that module, then delete this test with the premise it was holding."
    )


def test_the_dormancy_premise_is_sensitive_to_the_field_appearing() -> None:
    """A premise nobody has seen flip is not a premise.

    The assertion above passes today; on its own it cannot distinguish "the field
    is absent" from "this helper never finds anything".
    """

    assert pinned_manifest_declares_contribution_field(_Module)
    assert not pinned_manifest_declares_contribution_field(
        _ManifestGenerationWithoutContributions
    )


def test_the_commands_exit_code_is_observed_in_both_directions() -> None:
    """Execute the command, rather than repeating what the note says it does.

    Nothing else calls this script — not CI, not the Makefile, not a test — so
    ``main`` was unreached code whose documented ``exit 2`` had never been run,
    and whose zero branch had never been reached by anything at all.  Both are
    driven here, and the zero branch is reached by handing the command empty
    registers rather than by emptying the real ones.
    """

    assert main() == 2

    contributing = (_Module(code="published", database_catalog=object()),)
    assert main(modules=contributing, blockers=()) == 0

    # Either register alone holds the exit at 2, so neither can be quietly
    # emptied on the strength of the other still being full.
    assert main(modules=contributing) == 2
    assert main(blockers=()) == 2


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
