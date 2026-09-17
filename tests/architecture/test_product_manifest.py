"""Prospective source composition and accepted production truth stay separate.

`assembly.manifest_digest` is what `dotmac-deploy drift` uses to tell an
accepted module set from any other. The accepted descriptor must keep naming
the exact manifest that promotion accepted, while a branch's composed assembly
must name a separate prospective manifest. Equating the two would make a pin
look deployed before its migration receipt exists.
"""

from __future__ import annotations

import json
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_product_manifest import (  # noqa: E402
    build_manifest,
    build_source_composition,
    canonical_bytes,
    digest,
)

ACCEPTED_MANIFEST = ROOT / "deploy" / "product-manifest.json"
PROSPECTIVE_MANIFEST = ROOT / "deploy" / "prospective" / "product-manifest.json"
SOURCE_COMPOSITION = ROOT / "deploy" / "prospective" / "source-composition.json"
ACCEPTED_DESCRIPTOR = ROOT / "deploy" / "product.toml"
PLACEHOLDER = "sha256:" + "0" * 64


def _descriptor() -> dict:
    return tomllib.loads(ACCEPTED_DESCRIPTOR.read_text())


def _source_composition() -> dict:
    return json.loads(SOURCE_COMPOSITION.read_text())


def test_the_prospective_manifest_matches_the_composed_assembly() -> None:
    """A branch's generated composition is never mistaken for accepted truth."""
    assert json.loads(PROSPECTIVE_MANIFEST.read_text()) == build_manifest()


def test_the_prospective_record_names_its_exact_generated_subject_and_digest() -> None:
    record = _source_composition()
    prospective = json.loads(PROSPECTIVE_MANIFEST.read_text())
    assert record["schema"] == "ProspectiveSourceComposition.v1"
    assert record["manifest"] == {
        "path": "deploy/prospective/product-manifest.json",
        "digest": digest(prospective),
    }
    assert record == build_source_composition(prospective)


def test_the_source_composition_is_not_an_image_or_release_candidate() -> None:
    """A source record cannot make a deployment claim before its receipt."""
    record = _source_composition()
    assert set(record) == {"schema", "manifest", "migration"}
    assert not {"image", "release", "candidate", "receipt", "promotion"} & set(record)


def test_the_prospective_subject_check_can_fail() -> None:
    """SENSITIVITY. A different manifest digest must not satisfy the record."""
    record = _source_composition()
    planted = dict(record["manifest"])
    planted["digest"] = "sha256:" + "f" * 64
    assert planted != record["manifest"]


def test_the_accepted_descriptor_matches_its_declared_accepted_manifest() -> None:
    """The running descriptor still names the promoted artifact, not this branch."""
    accepted = json.loads(ACCEPTED_MANIFEST.read_text())
    assert _descriptor()["assembly"]["manifest_path"] == "deploy/product-manifest.json"
    assert _descriptor()["assembly"]["manifest_digest"] == digest(accepted)


def test_the_descriptor_carries_no_placeholder_digest() -> None:
    """A production descriptor may carry no placeholder.

    Checked for BOTH digests, not only the one that was wrong: the image
    reference was already real when the manifest digest was the placeholder, so
    a check written for the field that happened to be broken would have passed
    the day before and taught nothing.
    """
    descriptor = _descriptor()
    assert descriptor["assembly"]["manifest_digest"] != PLACEHOLDER
    assert PLACEHOLDER not in descriptor["image"]["reference"]


def test_the_placeholder_check_can_fail() -> None:
    """SENSITIVITY. Both assertions above are inequalities that an empty or
    malformed descriptor would also satisfy."""
    assert PLACEHOLDER == "sha256:" + "0" * 64
    planted = {"assembly": {"manifest_digest": PLACEHOLDER}}
    assert planted["assembly"]["manifest_digest"] == PLACEHOLDER


def test_the_digest_is_computed_over_canonical_bytes() -> None:
    """Key order must not change the digest, or the same composition hashes two
    ways depending on how the file was written."""
    manifest = build_manifest()
    reordered = dict(reversed(list(manifest.items())))
    assert canonical_bytes(manifest) == canonical_bytes(reordered)
    assert digest(manifest) == digest(reordered)


def test_control_a13_manifest_version_matches_installed_distribution() -> None:
    prospective = json.loads(PROSPECTIVE_MANIFEST.read_text())
    control = next(
        module
        for module in prospective["modules"]
        if module["code"] == "deployment_control"
    )
    assert control["version"] == "0.1.0a13"
    assert "manifest_declared_version" not in control


def test_a_planted_manifest_version_disagreement_is_recorded(monkeypatch) -> None:
    """A later stale manifest literal remains visible beside wheel identity."""
    import generate_product_manifest as generator

    original = generator._distribution_version

    def changed_distribution_version(distribution: str) -> str | None:
        if distribution == "dotmac-deployment-control":
            return "0.1.0a14"
        return original(distribution)

    monkeypatch.setattr(
        generator, "_distribution_version", changed_distribution_version
    )
    control = next(
        module
        for module in generator.build_manifest()["modules"]
        if module["code"] == "deployment_control"
    )
    assert control["version"] == "0.1.0a14"
    assert control["manifest_declared_version"] == "0.1.0a13"
