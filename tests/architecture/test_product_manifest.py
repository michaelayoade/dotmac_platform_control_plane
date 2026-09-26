"""Prospective source composition and accepted production truth stay separate.

`assembly.manifest_digest` is what `dotmac-deploy drift` uses to tell an
accepted module set from any other. The accepted descriptor must keep naming
the exact manifest its promotion accepted, while a branch's composed assembly
names a separate prospective manifest. Equating the two would make a pin look
deployed before any deployment receipt exists. (Shape from CP PR #187; adopted
here by the 2026-09-25 Gate-0 composition adoption, whose descriptor promotion
is a composition change that carries the application half unchanged.)
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
    """Regenerating must reproduce the prospective bytes. Composing a new module
    without regenerating fails here rather than at a drift check in production."""
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
    """A source record cannot make a deployment claim before its receipt.

    Migration heads are deliberately absent: they live once, in the accepted
    descriptor's composition-change promotion, not in a second copy here.
    """
    record = _source_composition()
    assert set(record) == {"schema", "manifest"}
    assert not {"image", "release", "candidate", "receipt", "promotion"} & set(record)


def test_the_prospective_subject_check_can_fail() -> None:
    """SENSITIVITY. A changed manifest must produce a record that no longer
    equals the committed one, so the equality above can actually fail."""
    record = _source_composition()
    prospective = json.loads(PROSPECTIVE_MANIFEST.read_text())
    planted = json.loads(json.dumps(prospective))
    planted["modules"][0]["code"] = "planted-module"
    assert build_source_composition(planted) != record
    assert build_source_composition(prospective) == record


def test_the_accepted_descriptor_matches_its_declared_accepted_manifest() -> None:
    """The running descriptor still names the promoted artifact, not this branch."""
    accepted = json.loads(ACCEPTED_MANIFEST.read_text())
    assert _descriptor()["assembly"]["manifest_path"] == "deploy/product-manifest.json"
    assert _descriptor()["assembly"]["manifest_digest"] == digest(accepted)


def test_the_accepted_and_prospective_manifests_differ_only_by_the_adoption() -> None:
    """The split is not a way to hide drift: apart from the two adopted module
    versions (and Control's retired stale literal), the manifests agree."""
    accepted = json.loads(ACCEPTED_MANIFEST.read_text())
    prospective = json.loads(PROSPECTIVE_MANIFEST.read_text())
    assert {k: v for k, v in accepted.items() if k != "modules"} == {
        k: v for k, v in prospective.items() if k != "modules"
    }
    before = {m["code"]: m for m in accepted["modules"]}
    after = {m["code"]: m for m in prospective["modules"]}
    assert set(before) == set(after)
    changed = sorted(code for code in before if before[code] != after[code])
    assert changed == ["approvals", "deployment_control"]


def test_the_descriptor_carries_no_placeholder_digest() -> None:
    """A production descriptor may carry no placeholder, for BOTH digests."""
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
    """Key order must not change the digest."""
    manifest = build_manifest()
    reordered = dict(reversed(list(manifest.items())))
    assert canonical_bytes(manifest) == canonical_bytes(reordered)
    assert digest(manifest) == digest(reordered)


def test_control_a15_manifest_version_matches_installed_distribution() -> None:
    prospective = json.loads(PROSPECTIVE_MANIFEST.read_text())
    control = next(
        module
        for module in prospective["modules"]
        if module["code"] == "deployment_control"
    )
    assert control["version"] == "0.1.0a15"
    assert "manifest_declared_version" not in control


def test_a_planted_manifest_version_disagreement_is_recorded(monkeypatch) -> None:
    """A later stale manifest literal remains visible beside wheel identity."""
    import generate_product_manifest as generator

    original = generator._distribution_version

    def changed_distribution_version(distribution: str) -> str | None:
        if distribution == "dotmac-deployment-control":
            return "0.1.0a16"
        return original(distribution)

    monkeypatch.setattr(
        generator, "_distribution_version", changed_distribution_version
    )
    control = next(
        module
        for module in generator.build_manifest()["modules"]
        if module["code"] == "deployment_control"
    )
    assert control["version"] == "0.1.0a16"
    assert control["manifest_declared_version"] == "0.1.0a15"
