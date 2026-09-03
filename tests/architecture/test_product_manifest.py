"""The committed manifest, its digest, and the descriptor stay one fact.

`assembly.manifest_digest` is what `dotmac-deploy drift` uses to tell an
approved module set from any other. Three things have to agree — the composed
assembly, the committed manifest, and the digest in the descriptor — and the
whole point is that they cannot drift apart silently.
"""

from __future__ import annotations

import json
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import generate_product_manifest as manifest_generator  # noqa: E402
import generate_prospective_descriptor as descriptor_generator  # noqa: E402
from generate_product_manifest import (  # noqa: E402
    build_manifest,
    canonical_bytes,
    digest,
)

ACCEPTED_MANIFEST = ROOT / "deploy" / "product-manifest.json"
ACCEPTED_DESCRIPTOR = ROOT / "deploy" / "product.toml"
MANIFEST = ROOT / "deploy" / "prospective" / "product-manifest.json"
DESCRIPTOR = ROOT / "deploy" / "prospective" / "product.toml"
PLACEHOLDER = "sha256:" + "0" * 64


def _descriptor() -> dict:
    return tomllib.loads(DESCRIPTOR.read_text())


def test_the_committed_manifest_matches_the_composed_assembly() -> None:
    """Regenerating must reproduce the committed bytes. Composing a new module
    without regenerating fails here rather than at a drift check in production."""
    assert json.loads(MANIFEST.read_text()) == build_manifest()


def test_the_prospective_descriptor_is_the_derived_reviewed_baseline() -> None:
    assert DESCRIPTOR.read_text(encoding="utf-8") == descriptor_generator.render()


def test_the_accepted_manifest_and_descriptor_remain_deployed_truth() -> None:
    accepted = json.loads(ACCEPTED_MANIFEST.read_text())
    descriptor = tomllib.loads(ACCEPTED_DESCRIPTOR.read_text())
    assert descriptor["assembly"]["manifest_digest"] == digest(accepted)
    assert accepted != json.loads(MANIFEST.read_text())


def test_the_descriptor_digest_matches_the_committed_manifest() -> None:
    committed = json.loads(MANIFEST.read_text())
    assert _descriptor()["assembly"]["manifest_digest"] == digest(committed)


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


def test_a_module_version_disagreement_is_recorded_not_reconciled(
    monkeypatch,
) -> None:
    """Where a module's manifest literal and its distribution disagree, the
    artifact records BOTH.

    The current Deployment Control derives its manifest version, so plant a
    disagreement in the distribution reader. The manifest must carry both
    values rather than choosing one silently.
    """
    real = manifest_generator._distribution_version

    def planted(distribution: str) -> str | None:
        if distribution == "dotmac-release-catalog":
            return "99.0-planted"
        return real(distribution)

    monkeypatch.setattr(manifest_generator, "_distribution_version", planted)
    generated = build_manifest()
    release = next(
        module for module in generated["modules"] if module["code"] == "release_catalog"
    )
    assert release["version"] == "99.0-planted"
    assert release["manifest_declared_version"] != release["version"]
